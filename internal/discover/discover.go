// Package discover finds and authenticates backups for an account. It is
// shared by verify and restore. Order of trust:
//
//  1. DID anchor (state, no history needed) -> manifest tx -> chunks.
//  2. Full account_tx scan for manifest memos, authenticated one by one.
//
// The scan always runs so a moved or deleted anchor cannot hide a newer
// backup. The newest authenticated (epoch, seq) wins.
package discover

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/justinnevins/xrplbak/internal/anchor"
	"github.com/justinnevins/xrplbak/internal/chunk"
	"github.com/justinnevins/xrplbak/internal/container"
	"github.com/justinnevins/xrplbak/internal/crypto"
	"github.com/justinnevins/xrplbak/internal/manifest"
	"github.com/justinnevins/xrplbak/internal/xrpl"
)

// Keys supplies epoch keys. A key file knows one epoch; a root key knows all.
type Keys interface {
	Epoch(e uint32) (crypto.EpochKey, bool)
}

// RootKeys derives any epoch from the root key.
type RootKeys struct{ Root crypto.RootKey }

func (r RootKeys) Epoch(e uint32) (crypto.EpochKey, bool) { return r.Root.DeriveEpochKey(e), true }

// FileKeys knows exactly one epoch.
type FileKeys struct {
	E   uint32
	Key crypto.EpochKey
}

func (f FileKeys) Epoch(e uint32) (crypto.EpochKey, bool) {
	if e != f.E {
		return crypto.EpochKey{}, false
	}
	return f.Key, true
}

// Candidate is one authenticated manifest and where it came from.
type Candidate struct {
	Manifest   *manifest.Manifest
	BackupID   [16]byte
	Epoch      uint32
	TxHash     string
	Ledger     uint32
	Plain      []byte
	FromAnchor bool
}

// Result of a discovery run.
type Result struct {
	Account    string
	Range      xrpl.Range
	Anchor     *anchor.Record
	AnchorOK   bool
	Candidates []*Candidate
	Latest     *Candidate
	Warnings   []string
	Rejected   int // manifests that failed authentication
}

// maxEpochProbe bounds how many epochs the scan tries per manifest when
// the epoch is not known from an anchor.
const maxEpochProbe = 64

// Run performs discovery. epochHint is where to start probing (the key
// file epoch, or 0).
func Run(c xrpl.Client, keys Keys, account string, epochHint uint32) (*Result, error) {
	res := &Result{Account: account}

	// 1. Anchor.
	if data, err := c.LedgerEntryDID(account); err == nil {
		if rec, perr := anchor.Parse(data); perr == nil {
			res.Anchor = rec
			if k, ok := keys.Epoch(rec.Epoch); ok && anchor.Verify(k, data) {
				res.AnchorOK = true
				if rec.Epoch > epochHint {
					epochHint = rec.Epoch
				}
			} else {
				res.Warnings = append(res.Warnings, "DID anchor present but its MAC does not verify with the available key; ignoring it")
			}
		} else {
			res.Warnings = append(res.Warnings, "DID entry exists but is not an xrplbak anchor; ignoring it")
		}
	} else if !errors.Is(err, xrpl.ErrNotFound) {
		return nil, fmt.Errorf("read DID anchor: %w", err)
	}

	// 2. History scan.
	txs, rng, err := c.AccountTx(account)
	if err != nil {
		return nil, fmt.Errorf("account_tx for %s: %w", account, err)
	}
	res.Range = rng
	parts := map[[16]byte]map[uint16]memoPart{}
	totals := map[[16]byte]uint16{}
	for _, t := range txs {
		if t.Account != account || t.Result != "tesSUCCESS" {
			continue
		}
		for _, m := range t.Memos {
			p, ok := chunk.Decode(m)
			if !ok || p.Type != chunk.TypeManifest {
				continue
			}
			if parts[p.BackupID] == nil {
				parts[p.BackupID] = map[uint16]memoPart{}
			}
			parts[p.BackupID][p.Index] = memoPart{ct: p.Ciphertext, tx: t.Hash, ledger: t.LedgerIndex}
			totals[p.BackupID] = p.Total
		}
	}
	for id, pm := range parts {
		total := totals[id]
		if int(total) != len(pm) {
			res.Warnings = append(res.Warnings, fmt.Sprintf("manifest %s: only %d of %d parts in searched range", hex.EncodeToString(id[:8]), len(pm), total))
			continue
		}
		cand, ok := openManifest(keys, id, pm, total, epochHint)
		if !ok {
			res.Rejected++
			continue
		}
		if res.Anchor != nil && res.AnchorOK && res.Anchor.BackupID == id {
			cand.FromAnchor = true
		}
		res.Candidates = append(res.Candidates, cand)
	}
	sort.Slice(res.Candidates, func(i, j int) bool {
		return manifest.Newer(res.Candidates[i].Manifest, res.Candidates[j].Manifest)
	})
	if len(res.Candidates) > 0 {
		res.Latest = res.Candidates[0]
	}
	if res.AnchorOK && res.Latest != nil && !res.Latest.FromAnchor {
		res.Warnings = append(res.Warnings, fmt.Sprintf("DID anchor points at seq %d but seq %d exists and authenticates; possible rollback by a writer-key holder. Using seq %d.", res.Anchor.Seq, res.Latest.Manifest.Seq, res.Latest.Manifest.Seq))
	}
	if res.AnchorOK && res.Latest == nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("DID anchor names manifest tx %s (ledger %d) but that transaction is not in the searched range %d to %d", res.Anchor.TxHashHex(), res.Anchor.ManifestLedger, rng.Min, rng.Max))
	}
	return res, nil
}

type memoPart struct {
	ct     []byte
	tx     string
	ledger uint32
}

func openManifest(keys Keys, id [16]byte, pm map[uint16]memoPart, total uint16, hint uint32) (*Candidate, bool) {
	for _, e := range probeOrder(hint) {
		k, ok := keys.Epoch(e)
		if !ok {
			continue
		}
		kb := k.BackupKey(id[:])
		var plain []byte
		good := true
		for i := uint16(0); i < total; i++ {
			p, err := crypto.OpenManifest(kb, id[:], i, total, pm[i].ct)
			if err != nil {
				good = false
				break
			}
			plain = append(plain, p...)
		}
		if !good {
			continue
		}
		m, err := manifest.Unmarshal(plain)
		if err != nil || m.BackupID != hex.EncodeToString(id[:]) || m.Epoch != e {
			continue
		}
		return &Candidate{Manifest: m, BackupID: id, Epoch: e, TxHash: pm[0].tx, Ledger: pm[0].ledger, Plain: plain}, true
	}
	return nil, false
}

func probeOrder(hint uint32) []uint32 {
	var out []uint32
	for e := int64(hint); e >= 0 && len(out) < maxEpochProbe; e-- {
		out = append(out, uint32(e))
	}
	for e := hint + 1; e <= hint+8; e++ {
		out = append(out, e)
	}
	return out
}

// Fetch pulls and authenticates every chunk of a candidate and returns the
// decoded container entries. It reads by tx hash first and falls back to
// the account scan so a dump or a partial-history server still works.
func Fetch(c xrpl.Client, keys Keys, res *Result, cand *Candidate) ([]container.Entry, error) {
	m := cand.Manifest
	if m.Tombstone {
		return nil, errors.New("backup is a tombstone (no data)")
	}
	k, _ := keys.Epoch(cand.Epoch)
	kb := k.BackupKey(cand.BackupID[:])
	total := uint16(len(m.OnChain.Chunks))
	var packed []byte
	var scanned map[string]xrpl.TxRecord
	for _, ch := range m.OnChain.Chunks {
		rec, err := c.Tx(ch.TxHash)
		if errors.Is(err, xrpl.ErrNotFound) {
			if scanned == nil {
				scanned = map[string]xrpl.TxRecord{}
				txs, _, _ := c.AccountTx(res.Account)
				for _, t := range txs {
					scanned[strings.ToUpper(t.Hash)] = t
				}
			}
			if t, ok := scanned[strings.ToUpper(ch.TxHash)]; ok {
				rec = &t
			} else {
				return nil, &chunk.MissingError{Kind: "chunk", Index: ch.Index, Total: int(total), Account: res.Account, MinLgr: res.Range.Min, MaxLgr: res.Range.Max}
			}
		} else if err != nil {
			return nil, err
		}
		var found bool
		for _, memo := range rec.Memos {
			p, ok := chunk.Decode(memo)
			if !ok || p.Type != chunk.TypeChunk || p.BackupID != cand.BackupID || int(p.Index) != ch.Index {
				continue
			}
			sum := sha256.Sum256(p.Ciphertext)
			if hex.EncodeToString(sum[:]) != ch.SHA256 {
				return nil, fmt.Errorf("chunk %d ciphertext hash does not match the manifest", ch.Index)
			}
			plain, err := crypto.OpenChunk(kb, cand.BackupID[:], p.Index, total, p.Ciphertext)
			if err != nil {
				return nil, fmt.Errorf("chunk %d: %w", ch.Index, err)
			}
			packed = append(packed, plain...)
			found = true
		}
		if !found {
			return nil, fmt.Errorf("tx %s does not carry chunk %d of backup %s", ch.TxHash, ch.Index, m.BackupID)
		}
	}
	raw, err := container.Unpack(packed)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != m.OnChain.PlainSHA256 {
		return nil, errors.New("reassembled container hash does not match the manifest")
	}
	return container.Decode(raw)
}

// OpenBundle decrypts a bundle file for a candidate and checks it against
// the manifest.
func OpenBundle(keys Keys, cand *Candidate, stream []byte) ([]container.Entry, error) {
	id, err := crypto.BundleID(stream)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(id, cand.BackupID[:]) {
		return nil, fmt.Errorf("bundle belongs to backup %s, but the selected backup is %s", hex.EncodeToString(id), cand.Manifest.BackupID)
	}
	sum := sha256.Sum256(stream)
	if hex.EncodeToString(sum[:]) != cand.Manifest.Bundle.CipherSHA256 {
		return nil, errors.New("bundle file hash does not match the manifest; the file is altered or from another run")
	}
	k, _ := keys.Epoch(cand.Epoch)
	packed, err := crypto.OpenBundle(k.BundleKey(cand.BackupID[:]), cand.BackupID[:], stream)
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	raw, err := container.Unpack(packed)
	if err != nil {
		return nil, err
	}
	psum := sha256.Sum256(raw)
	if hex.EncodeToString(psum[:]) != cand.Manifest.Bundle.PlainSHA256 {
		return nil, errors.New("bundle plaintext hash does not match the manifest")
	}
	return container.Decode(raw)
}
