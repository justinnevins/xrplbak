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
	// RejectedAfter counts rejected manifests that landed after Latest.
	// One of them may be a newer backup this key cannot open.
	RejectedAfter int
	// Conflict is set, and Latest left nil, when two different backups
	// authenticate at the newest (epoch, seq). The tool never picks one.
	Conflict string
}

// maxEpochProbe bounds how many epochs the scan tries below the starting
// epoch, and how far above the newest epoch found it keeps looking. Epochs
// only advance one at a time (init --rotate), so the upward search follows
// a chain of rotations as long as no 64 rotations in a row went without a
// backup. Anything still unopened is reported, never dropped in silence.
const maxEpochProbe = 64

// Run performs discovery. epochHint is where to start probing (the key
// file epoch, or 0).
func Run(c xrpl.Client, keys Keys, account string, epochHint uint32) (*Result, error) {
	res := &Result{Account: account}
	keys = &cachedKeys{k: keys, m: map[uint32]cachedKey{}}

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

	// 2. History scan. Parts are grouped by (backup_id, nonce prefix) and
	// every ciphertext seen for an index is kept, so a later junk memo
	// cannot shadow a real part.
	txs, rng, err := c.AccountTx(account)
	if err != nil {
		return nil, fmt.Errorf("account_tx for %s: %w", account, err)
	}
	res.Range = rng
	type setKey struct {
		id    [16]byte
		nonce [crypto.ManifestNonceLen]byte
	}
	sets := map[setKey]*partSet{}
	var order []setKey
	for _, t := range txs {
		if t.Account != account || t.Result != "tesSUCCESS" {
			continue
		}
		for _, m := range t.Memos {
			p, ok := chunk.Decode(m)
			if !ok || p.Type != chunk.TypeManifest || p.Total > maxManifestParts {
				continue
			}
			k := setKey{p.BackupID, p.Nonce}
			ps := sets[k]
			if ps == nil {
				ps = &partSet{total: p.Total, parts: map[uint16][]memoPart{}}
				sets[k] = ps
				order = append(order, k)
			}
			if p.Total != ps.total {
				continue
			}
			ps.parts[p.Index] = append(ps.parts[p.Index], memoPart{ct: p.Ciphertext, tx: t.Hash, ledger: t.LedgerIndex})
		}
	}
	var pending []setKey
	for _, k := range order {
		ps := sets[k]
		if int(ps.total) != len(ps.parts) {
			res.Warnings = append(res.Warnings, fmt.Sprintf("manifest %s: only %d of %d parts in searched range", hex.EncodeToString(k.id[:8]), len(ps.parts), ps.total))
			continue
		}
		cand, ok := openManifest(keys, k.id, k.nonce[:], ps, probeOrder(epochHint))
		if !ok {
			pending = append(pending, k)
			continue
		}
		res.Candidates = append(res.Candidates, cand)
	}
	// A manifest from a later epoch than the search reached stays closed
	// above. Each epoch found moves the search up, so keep going until a
	// pass finds nothing new.
	upper := int64(epochHint) + maxEpochProbe
	for len(pending) > 0 {
		top := int64(epochHint)
		for _, c := range res.Candidates {
			if int64(c.Epoch) > top {
				top = int64(c.Epoch)
			}
		}
		next := top + maxEpochProbe
		if next > 0xFFFFFFFF {
			next = 0xFFFFFFFF
		}
		if next <= upper {
			break
		}
		var more []uint32
		for e := upper + 1; e <= next; e++ {
			more = append(more, uint32(e))
		}
		upper = next
		var still []setKey
		for _, k := range pending {
			if cand, ok := openManifest(keys, k.id, k.nonce[:], sets[k], more); ok {
				res.Candidates = append(res.Candidates, cand)
			} else {
				still = append(still, k)
			}
		}
		pending = still
	}
	var rejectedLedgers []uint32
	for _, k := range pending {
		res.Rejected++
		rejectedLedgers = append(rejectedLedgers, sets[k].lastLedger())
		if res.AnchorOK && res.Anchor.BackupID == k.id {
			res.Warnings = append(res.Warnings, fmt.Sprintf("a manifest for the anchored backup %s failed authentication; someone with the writer key may be posting junk", hex.EncodeToString(k.id[:8])))
		}
	}
	sort.SliceStable(res.Candidates, func(i, j int) bool {
		a, b := res.Candidates[i], res.Candidates[j]
		if a.Manifest.Epoch != b.Manifest.Epoch || a.Manifest.Seq != b.Manifest.Seq {
			return manifest.Newer(a.Manifest, b.Manifest)
		}
		return a.Ledger > b.Ledger
	})
	// The same backup sealed twice (a resumed run) is one backup: keep the
	// first landing. Two different backups at one (epoch, seq) are a
	// conflict the tool refuses to resolve on its own.
	var uniq []*Candidate
	seen := map[[16]byte]bool{}
	for i := len(res.Candidates) - 1; i >= 0; i-- {
		c := res.Candidates[i]
		if !seen[c.BackupID] {
			seen[c.BackupID] = true
			uniq = append([]*Candidate{c}, uniq...)
		}
	}
	res.Candidates = uniq
	// The anchor names a backup; its (epoch, seq) must agree with the
	// manifest it names or the anchor is not trusted for anything.
	if res.AnchorOK {
		for _, c := range res.Candidates {
			if c.BackupID != res.Anchor.BackupID {
				continue
			}
			if c.Manifest.Epoch != res.Anchor.Epoch || c.Manifest.Seq != res.Anchor.Seq {
				res.AnchorOK = false
				res.Warnings = append(res.Warnings, fmt.Sprintf("DID anchor claims epoch %d seq %d but the manifest it names is epoch %d seq %d; ignoring the anchor", res.Anchor.Epoch, res.Anchor.Seq, c.Manifest.Epoch, c.Manifest.Seq))
				break
			}
			c.FromAnchor = true
		}
	}
	if len(res.Candidates) > 0 {
		a := res.Candidates[0]
		if len(res.Candidates) > 1 {
			b := res.Candidates[1]
			if a.Manifest.Epoch == b.Manifest.Epoch && a.Manifest.Seq == b.Manifest.Seq {
				res.Conflict = fmt.Sprintf("two different backups share epoch %d seq %d (ids %s at ledger %d and %s at ledger %d). Someone else may hold the writer key. Refusing to pick one; pass --backup-id to choose, and rotate the key", a.Manifest.Epoch, a.Manifest.Seq, a.Manifest.BackupID[:16], a.Ledger, b.Manifest.BackupID[:16], b.Ledger)
			}
		}
		if res.Conflict == "" {
			res.Latest = a
		}
	}
	if res.AnchorOK && res.Latest != nil && !res.Latest.FromAnchor {
		res.Warnings = append(res.Warnings, fmt.Sprintf("DID anchor points at seq %d but seq %d exists and authenticates; possible rollback by a writer-key holder. Using seq %d.", res.Anchor.Seq, res.Latest.Manifest.Seq, res.Latest.Manifest.Seq))
	}
	if res.AnchorOK && res.Latest == nil && res.Conflict == "" {
		where := fmt.Sprintf("ledger %d", res.Anchor.ManifestLedger)
		if res.Anchor.ManifestLedger == 0 {
			where = "batched with the anchor"
		}
		res.Warnings = append(res.Warnings, fmt.Sprintf("DID anchor names manifest tx %s (%s) but that transaction is not in the searched range %d to %d", res.Anchor.TxHashHex(), where, rng.Min, rng.Max))
	}
	if res.Rejected > 0 && res.Latest == nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%d manifest(s) present but none authenticate: wrong recovery key, wrong epoch, or junk from a writer-key thief", res.Rejected))
	}
	// A rejected manifest that landed before the selected backup is
	// expected after a rotation: the key file cannot read old epochs. One
	// that landed after it may be the newest backup, so say so.
	if res.Latest != nil {
		for _, l := range rejectedLedgers {
			if l == 0 || res.Latest.Ledger == 0 || l > res.Latest.Ledger {
				res.RejectedAfter++
			}
		}
	}
	if res.RejectedAfter > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%d manifest(s) landed after the selected backup (epoch %d seq %d) but do not open with this key. One may be a newer backup from another epoch, or junk from someone holding the writer key. The selected backup may not be the newest. Check with the recovery words, or with the newest key file", res.RejectedAfter, res.Latest.Manifest.Epoch, res.Latest.Manifest.Seq))
	}
	return res, nil
}

// maxManifestParts bounds memory on hostile memos. A real manifest is
// under 4 KB, so 16 parts is far above any legitimate total.
const maxManifestParts = 16

type memoPart struct {
	ct     []byte
	tx     string
	ledger uint32
}

type partSet struct {
	total uint16
	parts map[uint16][]memoPart
}

// lastLedger is the newest ledger any part of the set landed in, or 0 when
// the source gives no ledger index.
func (ps *partSet) lastLedger() uint32 {
	var l uint32
	for _, mp := range ps.parts {
		for _, p := range mp {
			if p.ledger > l {
				l = p.ledger
			}
		}
	}
	return l
}

// cachedKeys derives each epoch key once per run. The upward search can try
// many epochs for every manifest that does not open.
type cachedKeys struct {
	k Keys
	m map[uint32]cachedKey
}

type cachedKey struct {
	key crypto.EpochKey
	ok  bool
}

func (c *cachedKeys) Epoch(e uint32) (crypto.EpochKey, bool) {
	if v, hit := c.m[e]; hit {
		return v.key, v.ok
	}
	k, ok := c.k.Epoch(e)
	c.m[e] = cachedKey{k, ok}
	return k, ok
}

// openManifest tries each epoch in order, and for each index every
// ciphertext seen, until a full manifest authenticates.
func openManifest(keys Keys, id [16]byte, nonce []byte, ps *partSet, epochs []uint32) (*Candidate, bool) {
	for _, e := range epochs {
		k, ok := keys.Epoch(e)
		if !ok {
			continue
		}
		kb := k.BackupKey(id[:])
		var plain []byte
		var first memoPart
		good := true
		for i := uint16(0); i < ps.total && good; i++ {
			opened := false
			for _, cand := range ps.parts[i] {
				p, err := crypto.OpenManifest(kb, id[:], nonce, i, ps.total, cand.ct)
				if err != nil {
					continue
				}
				plain = append(plain, p...)
				if i == 0 {
					first = cand
				}
				opened = true
				break
			}
			good = opened
		}
		if !good {
			continue
		}
		m, err := manifest.Unmarshal(plain)
		if err != nil || m.BackupID != hex.EncodeToString(id[:]) || m.Epoch != e {
			continue
		}
		return &Candidate{Manifest: m, BackupID: id, Epoch: e, TxHash: first.tx, Ledger: first.ledger, Plain: plain}, true
	}
	return nil, false
}

// probeOrder tries the hint, then earlier epochs, then later ones.
func probeOrder(hint uint32) []uint32 {
	var out []uint32
	for e := int64(hint); e >= 0 && len(out) < maxEpochProbe; e-- {
		out = append(out, uint32(e))
	}
	for e := int64(hint) + 1; e <= int64(hint)+maxEpochProbe && e <= 0xFFFFFFFF; e++ {
		out = append(out, uint32(e))
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
