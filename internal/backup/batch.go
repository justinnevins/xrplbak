package backup

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/justinnevins/xrplbak/internal/anchor"
	"github.com/justinnevins/xrplbak/internal/crypto"
	"github.com/justinnevins/xrplbak/internal/dump"
	"github.com/justinnevins/xrplbak/internal/manifest"
	"github.com/justinnevins/xrplbak/internal/xrpl"
	"github.com/justinnevins/xrplbak/internal/xrpl/codec"
)

// Batched submission (XLS-56, amendment BatchV1_1).
//
// The sequential path sends every chunk, every manifest part, and the
// anchor as its own transaction and waits for each. Between the last
// manifest part and the anchor there is a window in which the ledger holds
// a complete manifest and no anchor, and between two manifest parts a
// window in which it holds half a manifest. A crash or a dropped connection
// in either window leaves work for the resume logic.
//
// A Batch with tfAllOrNothing closes both windows: its inner transactions
// apply in one ledger or not at all. rippled allows 2 to 8 inner
// transactions (kMaxBatchTxCount), and the tool needs c + k + 1 of them: c
// chunks (at most chunk.MaxChunks, 8), k manifest parts, one anchor. When
// they fit, the whole backup is one transaction. When they do not, the
// chunks go first, then the manifest parts and the anchor, in batches cut
// so that the anchor always shares its batch with the last manifest part
// and no batch is ever a single transaction.
//
// An inner transaction has no signature of its own, so its hash is known
// before the batch is sent. The manifest can therefore name a chunk that
// lands in the same batch, and the anchor can name a manifest part that
// does. Ledger numbers are not known until validation, so a batched
// manifest records ledger 0 for a chunk in its own batch and a batched
// anchor records manifest ledger 0. Nothing reads those numbers except
// the operator's report.

// batchItem is one inner transaction the backup needs, in order.
type batchItem struct {
	kind  string // "chunk", "manifest", "anchor"
	index int    // chunk or part index
	tx    *codec.Tx
}

// submitBatched is Submit's batched path. recorded and manifestParts come
// from the dump, so a resumed run does not resend what already landed.
func (s *Submitter) submitBatched(p *Plan, recorded map[string]dump.Tx, manifestParts map[[crypto.ManifestNonceLen]byte]map[uint16]landed) error {
	m := p.Manifest

	// Chunks already on the ledger keep their recorded hash and ledger.
	var pending []int
	for i := range p.ChunkMemos {
		if t, ok := recorded[m.OnChain.Chunks[i].SHA256]; ok {
			m.OnChain.Chunks[i].TxHash, m.OnChain.Chunks[i].Ledger = t.Hash, t.LedgerIndex
			s.Log("chunk %d of %d already on ledger (tx %s)", i+1, len(p.ChunkMemos), t.Hash)
			continue
		}
		pending = append(pending, i)
	}

	// A complete manifest already on the ledger is reused as is; only the
	// anchor is left, and a batch cannot carry one transaction.
	for _, parts := range manifestParts {
		if first, ok := parts[0]; ok && int(first.total) == len(parts) {
			if len(pending) > 0 {
				return errors.New("the dump records a complete manifest but not every chunk it names; refusing to guess. Start a new backup")
			}
			s.Log("manifest already on ledger (tx %s)", first.tx.Hash)
			return s.sendAnchor(p, first.tx.Hash, first.tx.LedgerIndex)
		}
	}

	// Draft count of manifest parts. Chunk hashes are fixed-length hex and
	// a batched chunk records ledger 0, so a draft sealed with placeholder
	// hashes has the real part count for the single-batch case.
	draft := *m
	draft.OnChain.Chunks = append([]manifest.Chunk(nil), m.OnChain.Chunks...)
	for _, i := range pending {
		draft.OnChain.Chunks[i].TxHash, draft.OnChain.Chunks[i].Ledger = strings.Repeat("0", 64), 0
	}
	draftMemos, _, err := ManifestMemos(s.Key.Key, p.BackupID, &draft)
	if err != nil {
		return err
	}
	k := len(draftMemos)

	if len(pending)+k+1 <= codec.MaxBatchInner {
		// Everything in one transaction.
		s.Log("submitting %d chunk(s), %d manifest part(s) and the DID anchor as one batch", len(pending), k)
		recs, ledger, err := s.sendBatch(func(seq uint32) ([]batchItem, error) {
			var items []batchItem
			for _, i := range pending {
				items = append(items, batchItem{kind: "chunk", index: i, tx: &codec.Tx{Type: codec.TxAccountSet, Memos: []codec.Memo{p.ChunkMemos[i]}}})
			}
			s.assignInner(items, seq)
			for _, it := range items {
				h, err := codec.InnerHash(it.tx)
				if err != nil {
					return nil, err
				}
				m.OnChain.Chunks[it.index].TxHash, m.OnChain.Chunks[it.index].Ledger = h, 0
			}
			tail, err := s.tailItems(p, m, seq+uint32(len(items)))
			if err != nil {
				return nil, err
			}
			return append(items, tail...), nil
		})
		if err != nil {
			return err
		}
		return s.finishBatched(p, recs, ledger)
	}

	// Chunks first. c is at most 8, so they are one batch, or one plain
	// transaction when a single chunk is left.
	switch {
	case len(pending) == 1:
		i := pending[0]
		s.Log("submitting chunk %d of %d", i+1, len(p.ChunkMemos))
		hash, ledger, err := s.send(&codec.Tx{Type: codec.TxAccountSet, Memos: []codec.Memo{p.ChunkMemos[i]}})
		if err != nil {
			return fmt.Errorf("chunk %d: %w", i, err)
		}
		m.OnChain.Chunks[i].TxHash, m.OnChain.Chunks[i].Ledger = hash, ledger
	case len(pending) > 1:
		s.Log("submitting %d chunk(s) as one batch", len(pending))
		recs, ledger, err := s.sendBatch(func(seq uint32) ([]batchItem, error) {
			var items []batchItem
			for _, i := range pending {
				items = append(items, batchItem{kind: "chunk", index: i, tx: &codec.Tx{Type: codec.TxAccountSet, Memos: []codec.Memo{p.ChunkMemos[i]}}})
			}
			s.assignInner(items, seq)
			return items, nil
		})
		if err != nil {
			return fmt.Errorf("chunks: %w", err)
		}
		for j, i := range pending {
			m.OnChain.Chunks[i].TxHash, m.OnChain.Chunks[i].Ledger = recs[j].Hash, ledger
		}
	}

	// Then the manifest and the anchor. The anchor shares the last batch
	// with the last manifest part(s); earlier parts go in earlier batches.
	memos, _, err := ManifestMemos(s.Key.Key, p.BackupID, m)
	if err != nil {
		return err
	}
	groups := splitBatches(len(memos) + 1)
	var manifestHash string
	var manifestLedger uint32
	next := 0
	for g, size := range groups {
		last := g == len(groups)-1
		first, count := next, size
		next += size
		var recs []xrpl.TxRecord
		var ledger uint32
		if count == 1 {
			// Only possible for a lone leading part; never the anchor.
			s.Log("submitting manifest part %d of %d", first+1, len(memos))
			hash, lgr, err := s.send(&codec.Tx{Type: codec.TxAccountSet, Memos: []codec.Memo{memos[first]}})
			if err != nil {
				return fmt.Errorf("manifest part %d: %w", first, err)
			}
			recs, ledger = []xrpl.TxRecord{{Hash: hash, LedgerIndex: lgr}}, lgr
		} else {
			if last {
				s.Log("submitting manifest part(s) %d to %d of %d and the DID anchor as one batch", first+1, len(memos), len(memos))
			} else {
				s.Log("submitting manifest part(s) %d to %d of %d as one batch", first+1, first+count, len(memos))
			}
			recs, ledger, err = s.sendBatch(func(seq uint32) ([]batchItem, error) {
				var items []batchItem
				for i := first; i < first+count && i < len(memos); i++ {
					items = append(items, batchItem{kind: "manifest", index: i, tx: &codec.Tx{Type: codec.TxAccountSet, Memos: []codec.Memo{memos[i]}}})
				}
				s.assignInner(items, seq)
				if !last {
					return items, nil
				}
				// The anchor names manifest part 0: landed earlier, or in
				// this very batch.
				h, lgr := manifestHash, manifestLedger
				if first == 0 {
					h, err = codec.InnerHash(items[0].tx)
					if err != nil {
						return nil, err
					}
					lgr = 0
				}
				a, err := s.anchorItem(p, m, h, lgr)
				if err != nil {
					return nil, err
				}
				a.tx.Sequence = seq + 1 + uint32(len(items))
				return append(items, a), nil
			})
			if err != nil {
				return fmt.Errorf("manifest: %w", err)
			}
		}
		if first == 0 {
			manifestHash, manifestLedger = recs[0].Hash, ledger
		}
		if last {
			return s.finishBatched(p, recs, ledger)
		}
	}
	return errors.New("batched submit ended without an anchor") // unreachable
}

// tailItems builds the manifest parts and the anchor for the single-batch
// case, with sequences starting at seq+1.
func (s *Submitter) tailItems(p *Plan, m *manifest.Manifest, seq uint32) ([]batchItem, error) {
	memos, _, err := ManifestMemos(s.Key.Key, p.BackupID, m)
	if err != nil {
		return nil, err
	}
	var items []batchItem
	for i, memo := range memos {
		items = append(items, batchItem{kind: "manifest", index: i, tx: &codec.Tx{Type: codec.TxAccountSet, Memos: []codec.Memo{memo}}})
	}
	s.assignInner(items, seq)
	h, err := codec.InnerHash(items[0].tx)
	if err != nil {
		return nil, err
	}
	a, err := s.anchorItem(p, m, h, 0)
	if err != nil {
		return nil, err
	}
	a.tx.Sequence = seq + 1 + uint32(len(items))
	return append(items, a), nil
}

// anchorItem builds the DIDSet inner transaction naming the manifest.
func (s *Submitter) anchorItem(p *Plan, m *manifest.Manifest, manifestHash string, manifestLedger uint32) (batchItem, error) {
	rec := &anchor.Record{ManifestLedger: manifestLedger, Epoch: m.Epoch, Seq: m.Seq}
	copy(rec.BackupID[:], p.BackupID)
	hb, err := hex.DecodeString(manifestHash)
	if err != nil || len(hb) != 32 {
		return batchItem{}, fmt.Errorf("manifest hash %q is not 32 bytes of hex", manifestHash)
	}
	copy(rec.ManifestTxHash[:], hb)
	data := anchor.Encode(s.Key.Key, rec)
	tx := &codec.Tx{Type: codec.TxDIDSet, Data: data, Flags: codec.FlagInnerBatchTxn, Account: s.Writer.AccountID()}
	return batchItem{kind: "anchor", tx: tx}, nil
}

// assignInner marks items as inner transactions with consecutive sequences
// after the outer one.
func (s *Submitter) assignInner(items []batchItem, outerSeq uint32) {
	for i, it := range items {
		it.tx.Flags |= codec.FlagInnerBatchTxn
		it.tx.Account = s.Writer.AccountID()
		it.tx.Sequence = outerSeq + 1 + uint32(i)
		it.tx.FeeDrops = 0
	}
}

// finishBatched records the anchor from the batch that carried it.
func (s *Submitter) finishBatched(p *Plan, recs []xrpl.TxRecord, ledger uint32) error {
	last := recs[len(recs)-1]
	if last.TxType != "DIDSet" && last.TxType != "" {
		return fmt.Errorf("last inner transaction of the tail batch is %s, not the anchor", last.TxType)
	}
	data, err := s.Client.LedgerEntryDID(s.Writer.Address())
	if err != nil {
		return fmt.Errorf("anchor batch validated but the DID entry cannot be read: %w", err)
	}
	s.Dump.DID = &dump.DID{LedgerIndex: ledger, Data: strings.ToUpper(hex.EncodeToString(data))}
	return s.saveDump()
}

// sendAnchor is the sequential anchor, used when a resumed run finds the
// manifest already complete on the ledger.
func (s *Submitter) sendAnchor(p *Plan, manifestHash string, manifestLedger uint32) error {
	m := p.Manifest
	rec := &anchor.Record{ManifestLedger: manifestLedger, Epoch: m.Epoch, Seq: m.Seq}
	copy(rec.BackupID[:], p.BackupID)
	hb, _ := hex.DecodeString(manifestHash)
	copy(rec.ManifestTxHash[:], hb)
	data := anchor.Encode(s.Key.Key, rec)
	s.Log("submitting DID anchor")
	_, ledger, err := s.send(&codec.Tx{Type: codec.TxDIDSet, Data: data})
	if err != nil {
		return fmt.Errorf("anchor: %w", err)
	}
	s.Dump.DID = &dump.DID{LedgerIndex: ledger, Data: strings.ToUpper(hex.EncodeToString(data))}
	return s.saveDump()
}

// splitBatches cuts n inner transactions into batch sizes of at most
// codec.MaxBatchInner, as even as possible, so that no batch after the
// first has a single transaction. n is at least 2 here (one part and the
// anchor). The last group is never smaller than the first.
func splitBatches(n int) []int {
	if n <= 1 {
		return []int{n}
	}
	groups := (n + codec.MaxBatchInner - 1) / codec.MaxBatchInner
	base, extra := n/groups, n%groups
	sizes := make([]int, groups)
	for i := range sizes {
		sizes[i] = base
		if i >= groups-extra {
			sizes[i]++
		}
	}
	return sizes
}

// sendBatch builds, signs, submits and validates one Batch. build is
// called with the outer sequence on every attempt, because an expired
// attempt gets fresh sequences and therefore fresh inner hashes. It
// returns one validated record per inner transaction, in order, and the
// ledger they share.
func (s *Submitter) sendBatch(build func(outerSeq uint32) ([]batchItem, error)) ([]xrpl.TxRecord, uint32, error) {
	s.defaults()
	for attempt := 0; attempt < 3; attempt++ {
		st, err := s.Client.ServerInfo()
		if err != nil {
			return nil, 0, err
		}
		acct, err := s.Client.AccountInfo(s.Writer.Address())
		if errors.Is(err, xrpl.ErrNotFound) {
			return nil, 0, fmt.Errorf("account %s does not exist on this network yet. Fund it with at least 1.5 XRP and retry", s.Writer.Address())
		} else if err != nil {
			return nil, 0, err
		}
		items, err := build(acct.Sequence)
		if err != nil {
			return nil, 0, err
		}
		if len(items) < 2 || len(items) > codec.MaxBatchInner {
			return nil, 0, fmt.Errorf("a batch carries 2 to %d transactions, not %d", codec.MaxBatchInner, len(items))
		}
		// rippled charges the outer base fee, one more base fee for the
		// batch itself, and each inner transaction's base fee: (n+2) times
		// the rate. --max-fee caps the rate, as it does for a single
		// transaction.
		rate := st.OpenLedgerFee
		if rate < st.BaseFeeDrops {
			rate = st.BaseFeeDrops
		}
		if rate > s.MaxFee {
			return nil, 0, fmt.Errorf("network fee is %d drops, above the %d drop cap. Retry later or raise --max-fee", rate, s.MaxFee)
		}
		fee := rate * uint64(len(items)+2)
		if acct.BalanceDrops < 1_200_000+fee {
			return nil, 0, fmt.Errorf("account %s holds %d drops; it needs the 1.2 XRP reserve plus fees", s.Writer.Address(), acct.BalanceDrops)
		}
		outer := &codec.Tx{Type: codec.TxBatch, Flags: codec.FlagAllOrNothing, Sequence: acct.Sequence, LastLedgerSequence: st.ValidatedLedger + 20, FeeDrops: fee, SigningPubKey: s.Writer.PublicKey(), Account: s.Writer.AccountID()}
		var hashes []string
		for _, it := range items {
			if it.tx.Sequence != acct.Sequence+1+uint32(len(hashes)) {
				return nil, 0, fmt.Errorf("inner transaction %d has sequence %d, want %d", len(hashes), it.tx.Sequence, acct.Sequence+1+uint32(len(hashes)))
			}
			h, err := codec.InnerHash(it.tx)
			if err != nil {
				return nil, 0, err
			}
			hashes = append(hashes, h)
			outer.Inner = append(outer.Inner, it.tx)
		}
		payload, err := codec.SigningPayload(outer)
		if err != nil {
			return nil, 0, err
		}
		outer.TxnSignature = s.Writer.Sign(payload)
		blob, err := codec.Serialize(outer, true)
		if err != nil {
			return nil, 0, err
		}
		hash := codec.Hash(blob)
		code, err := s.Client.Submit(blob)
		if err != nil {
			return nil, 0, err
		}
		switch {
		case code == "tesSUCCESS" || code == "terQUEUED":
		case code == "tefPAST_SEQ" || code == "terPRE_SEQ":
			s.Sleep(4 * time.Second)
			continue
		default:
			return nil, 0, fmt.Errorf("submit returned %s for batch %s", code, hash)
		}
		for i := 0; i < 45; i++ {
			s.Sleep(2 * time.Second)
			rec, err := s.Client.Tx(hash)
			if err == nil && rec.Validated {
				if rec.Result != "tesSUCCESS" {
					return nil, 0, fmt.Errorf("batch %s validated with result %s", hash, rec.Result)
				}
				// The outer transaction validating does not mean the inner
				// ones applied. Under tfAllOrNothing they all did or none
				// did, and the ledger is the only witness.
				var recs []xrpl.TxRecord
				for j, h := range hashes {
					in, err := s.Client.Tx(h)
					if err != nil || !in.Validated || in.Result != "tesSUCCESS" {
						return nil, 0, fmt.Errorf("batch %s validated but inner transaction %d of %d (%s) did not apply; under all-or-nothing nothing from this batch is on the ledger. Retry the backup", hash, j+1, len(hashes), h)
					}
					recs = append(recs, *in)
				}
				for _, in := range recs {
					s.Dump.Txs = append(s.Dump.Txs, dump.Tx{Hash: in.Hash, LedgerIndex: in.LedgerIndex, Result: in.Result, TxJSON: in.Raw})
				}
				if err := s.saveDump(); err != nil {
					return nil, 0, err
				}
				return recs, rec.LedgerIndex, nil
			}
			cur, err := s.Client.ServerInfo()
			if err == nil && cur.ValidatedLedger > outer.LastLedgerSequence {
				break // expired; rebuild with fresh sequences
			}
		}
	}
	return nil, 0, errors.New("batch did not validate after 3 attempts")
}
