// Package discover finds and authenticates backups for an account. It is
// shared by verify and restore.
//
// Backups are found by one account_tx scan for manifest memos, each
// authenticated with the key. The DID anchor (state, no history needed)
// does not fetch anything on its own: when it authenticates, it raises the
// epoch the search starts at, it must agree with the manifest it names,
// and a backup it names that the scan did not find makes the result
// incomplete. Its manifest tx hash appears only in messages.
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
	// AnchorMissing is set when the anchor names a backup that was not
	// found and nothing newer than it was found either. Latest is still the
	// newest backup found, for callers that name it with --backup-id;
	// without that, callers refuse.
	AnchorMissing string
}

// NetworkError is a transport or server failure while reading the ledger.
// It is not an authentication failure: nothing was checked and found
// wrong, the answer simply did not arrive. Callers map it to the network
// exit code.
type NetworkError struct {
	Op  string
	Err error
}

func (e *NetworkError) Error() string { return e.Op + ": " + e.Err.Error() }
func (e *NetworkError) Unwrap() error { return e.Err }

// newerThanAnchor reports whether m is a later (epoch, seq) than the anchor
// names. A backup newer than the anchor means the anchor is stale, not
// that the current backup is missing.
func newerThanAnchor(m *manifest.Manifest, a *anchor.Record) bool {
	return m.Epoch > a.Epoch || (m.Epoch == a.Epoch && m.Seq > a.Seq)
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
	// The operator's starting epoch (--epoch, or the key file) keeps its
	// own window below it whatever the anchor says. The anchor can raise
	// where the search starts, never the floor it reaches down to.
	floor := epochHint

	// 1. Anchor.
	epochHint, err := readAnchor(c, keys, res, epochHint)
	if err != nil {
		return nil, err
	}

	// 2. History scan.
	txs, rng, err := c.AccountTx(account)
	if err != nil {
		return nil, fmt.Errorf("account_tx for %s: %w", account, err)
	}
	res.Range = rng
	sc := scanManifests(txs, account)
	pending := openSets(res, keys, sc, epochHint, floor)
	pending = searchUpward(res, keys, sc, pending, epochHint)
	rejectedLedgers := countRejected(res, sc, pending)

	// 3. Select.
	sortAndDedup(res)
	checkAnchorAgreement(res)
	selectLatest(res)
	anchorFindings(res)
	rejectedWarnings(res, rejectedLedgers)
	return res, nil
}

// readAnchor reads the DID anchor into res and returns the epoch to start
// probing at: the anchor's epoch when it authenticates and is higher.
func readAnchor(c xrpl.Client, keys Keys, res *Result, epochHint uint32) (uint32, error) {
	data, err := c.LedgerEntryDID(res.Account)
	if err != nil {
		if !errors.Is(err, xrpl.ErrNotFound) {
			return epochHint, fmt.Errorf("read DID anchor: %w", err)
		}
		return epochHint, nil
	}
	rec, perr := anchor.Parse(data)
	if perr != nil {
		res.Warnings = append(res.Warnings, "DID entry exists but is not an xrplbak anchor; ignoring it")
		return epochHint, nil
	}
	res.Anchor = rec
	if k, ok := keys.Epoch(rec.Epoch); ok && anchor.Verify(k, data) {
		res.AnchorOK = true
		if rec.Epoch > epochHint {
			epochHint = rec.Epoch
		}
	} else {
		res.Warnings = append(res.Warnings, "DID anchor present but its MAC does not verify with the available key; ignoring it")
	}
	return epochHint, nil
}

// setKey names one manifest part set. The part count is in the key: a junk
// memo that copies an id and nonce with another count makes its own set,
// and cannot hide the real one by being listed first.
type setKey struct {
	id    [16]byte
	nonce [crypto.ManifestNonceLen]byte
	total uint16
}

// manifestScan is the manifest memos found in the account history.
type manifestScan struct {
	sets      map[setKey]*partSet
	order     []setKey
	oversized map[setKey]uint16
}

// scanManifests groups manifest parts by (backup_id, nonce prefix, part
// count). Every ciphertext seen for an index is kept, so a later junk memo
// cannot shadow a real part.
func scanManifests(txs []xrpl.TxRecord, account string) *manifestScan {
	sc := &manifestScan{sets: map[setKey]*partSet{}, oversized: map[setKey]uint16{}}
	for _, t := range txs {
		if t.Account != account || t.Result != "tesSUCCESS" {
			continue
		}
		for _, m := range t.Memos {
			p, ok := chunk.Decode(m)
			if !ok || p.Type != chunk.TypeManifest {
				continue
			}
			if p.Total > chunk.MaxManifestParts {
				// Never opened: say so, rather than let an older backup
				// pass as the newest.
				sc.oversized[setKey{p.BackupID, p.Nonce, p.Total}] = p.Total
				continue
			}
			k := setKey{p.BackupID, p.Nonce, p.Total}
			ps := sc.sets[k]
			if ps == nil {
				ps = &partSet{total: p.Total, parts: map[uint16][]memoPart{}}
				sc.sets[k] = ps
				sc.order = append(sc.order, k)
			}
			ps.parts[p.Index] = append(ps.parts[p.Index], memoPart{ct: p.Ciphertext, tx: t.Hash, ledger: t.LedgerIndex})
		}
	}
	return sc
}

// openSets tries every complete set in the first probe window and returns
// the sets that did not open.
func openSets(res *Result, keys Keys, sc *manifestScan, epochHint, floor uint32) []setKey {
	var pending []setKey
	for _, k := range sc.order {
		ps := sc.sets[k]
		if int(ps.total) != len(ps.parts) {
			res.Warnings = append(res.Warnings, fmt.Sprintf("manifest %s: only %d of %d parts in searched range", hex.EncodeToString(k.id[:8]), len(ps.parts), ps.total))
			continue
		}
		cand, ok := openManifest(keys, k.id, k.nonce[:], ps, probeOrder(epochHint, floor))
		if !ok {
			pending = append(pending, k)
			continue
		}
		res.Candidates = append(res.Candidates, cand)
	}
	return pending
}

// searchUpward retries the pending sets above the first window. A manifest
// from a later epoch than the search reached stays closed in openSets. Each
// epoch found moves the search up, so keep going until a pass finds nothing
// new. It returns the sets that still did not open.
func searchUpward(res *Result, keys Keys, sc *manifestScan, pending []setKey, epochHint uint32) []setKey {
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
			if cand, ok := openManifest(keys, k.id, k.nonce[:], sc.sets[k], more); ok {
				res.Candidates = append(res.Candidates, cand)
			} else {
				still = append(still, k)
			}
		}
		pending = still
	}
	return pending
}

// countRejected counts the oversized and unopened manifests and returns the
// ledger each unopened one landed in.
func countRejected(res *Result, sc *manifestScan, pending []setKey) []uint32 {
	var rejectedLedgers []uint32
	for k, total := range sc.oversized {
		res.Rejected++
		res.Warnings = append(res.Warnings, fmt.Sprintf("manifest %s has %d parts, above the limit of %d, and was not opened; it may be a newer backup made by a tool without this limit, or junk from someone holding the writer key", hex.EncodeToString(k.id[:8]), total, chunk.MaxManifestParts))
	}
	for _, k := range pending {
		res.Rejected++
		rejectedLedgers = append(rejectedLedgers, sc.sets[k].lastLedger())
		if res.AnchorOK && res.Anchor.BackupID == k.id {
			res.Warnings = append(res.Warnings, fmt.Sprintf("a manifest for the anchored backup %s failed authentication; someone with the writer key may be posting junk", hex.EncodeToString(k.id[:8])))
		}
	}
	return rejectedLedgers
}

// sortAndDedup orders the candidates newest first. The same backup sealed
// twice (a resumed run) is one backup: keep the first landing. Two
// different backups at one (epoch, seq) are a conflict the tool refuses to
// resolve on its own.
func sortAndDedup(res *Result) {
	sort.SliceStable(res.Candidates, func(i, j int) bool {
		a, b := res.Candidates[i], res.Candidates[j]
		if a.Manifest.Epoch != b.Manifest.Epoch || a.Manifest.Seq != b.Manifest.Seq {
			return manifest.Newer(a.Manifest, b.Manifest)
		}
		return a.Ledger > b.Ledger
	})
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
}

// checkAnchorAgreement marks the candidate the anchor names. The anchor
// names a backup; its (epoch, seq) must agree with the manifest it names or
// the anchor is not trusted for anything.
func checkAnchorAgreement(res *Result) {
	if !res.AnchorOK {
		return
	}
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

// selectLatest sets Latest to the newest candidate, or Conflict when two
// different backups share the newest (epoch, seq).
func selectLatest(res *Result) {
	if len(res.Candidates) == 0 {
		return
	}
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

// anchorWhere says where the anchored manifest landed.
func anchorWhere(a *anchor.Record) string {
	if a.ManifestLedger == 0 {
		return "batched with the anchor"
	}
	return fmt.Sprintf("ledger %d", a.ManifestLedger)
}

// anchorFindings compares the selection with an authenticated anchor.
func anchorFindings(res *Result) {
	if !res.AnchorOK {
		return
	}
	rng := res.Range
	if res.Latest != nil && !res.Latest.FromAnchor {
		if !newerThanAnchor(res.Latest.Manifest, res.Anchor) {
			// The anchor names a backup that was not found, and nothing
			// newer than it was found either. The current backup is out of
			// reach here. That is not a rollback and not a complete result;
			// the caller refuses unless the operator names a backup.
			res.AnchorMissing = fmt.Sprintf("DID anchor names backup %s (epoch %d seq %d, manifest tx %s, %s) but that manifest is not in the searched range %d to %d. The newest backup found is %s (epoch %d seq %d), which is not newer. Read from a server with full history, or the dump written at that backup; or pass --backup-id %s to use the older backup deliberately", hex.EncodeToString(res.Anchor.BackupID[:])[:16], res.Anchor.Epoch, res.Anchor.Seq, res.Anchor.TxHashHex(), anchorWhere(res.Anchor), rng.Min, rng.Max, res.Latest.Manifest.BackupID[:16], res.Latest.Manifest.Epoch, res.Latest.Manifest.Seq, res.Latest.Manifest.BackupID[:16])
		} else {
			res.Warnings = append(res.Warnings, fmt.Sprintf("DID anchor points at seq %d but seq %d exists and authenticates; possible rollback by a writer-key holder. Using seq %d.", res.Anchor.Seq, res.Latest.Manifest.Seq, res.Latest.Manifest.Seq))
		}
	}
	if res.Latest != nil || res.Conflict != "" {
		return
	}
	if res.Rejected > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("DID anchor names manifest tx %s (%s) but no manifest that opens with this key is in the searched range %d to %d", res.Anchor.TxHashHex(), anchorWhere(res.Anchor), rng.Min, rng.Max))
		return
	}
	// The anchor authenticated with this key, so the key is right. What
	// is missing is the backup it names: no manifest is in the history
	// read, not even one that fails to open, and nothing else was found
	// to offer instead. That is an incomplete result, not a wrong key.
	// When a manifest is there and does not open, the answer stays an
	// authentication failure.
	res.AnchorMissing = fmt.Sprintf("DID anchor names backup %s (epoch %d seq %d, manifest tx %s, %s) but that manifest is not in the searched range %d to %d, and no backup at all was found there. The key is the right one: it authenticated the anchor. Read from a server with full history, or the dump written at that backup", hex.EncodeToString(res.Anchor.BackupID[:])[:16], res.Anchor.Epoch, res.Anchor.Seq, res.Anchor.TxHashHex(), anchorWhere(res.Anchor), rng.Min, rng.Max)
}

// rejectedWarnings reports manifests that did not open. A rejected
// manifest that landed before the selected backup is expected after a
// rotation: the key file cannot read old epochs. One that landed after it
// may be the newest backup, so say so.
func rejectedWarnings(res *Result, rejectedLedgers []uint32) {
	if res.Rejected > 0 && res.Latest == nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%d manifest(s) present but none authenticate: wrong recovery key, wrong epoch, or junk from a writer-key thief", res.Rejected))
	}
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
}

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
// probeOrder lists epochs to try: from hint down to maxEpochProbe below
// floor (floor is the operator's own starting epoch, at most hint), then
// maxEpochProbe above hint.
func probeOrder(hint, floor uint32) []uint32 {
	if floor > hint {
		floor = hint
	}
	var out []uint32
	for e := int64(hint); e >= 0 && e >= int64(floor)-maxEpochProbe+1; e-- {
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
				// A scan that failed is a network failure, not a missing
				// chunk: the two send the operator to different fixes.
				txs, _, err := c.AccountTx(res.Account)
				if err != nil {
					return nil, &NetworkError{Op: "scan the account for chunk " + fmt.Sprint(ch.Index+1), Err: err}
				}
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
			return nil, &NetworkError{Op: "fetch chunk " + fmt.Sprint(ch.Index+1), Err: err}
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
