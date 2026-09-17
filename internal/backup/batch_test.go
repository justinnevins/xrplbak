package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/chunk"
	"github.com/justinnevins/xrplbak/internal/discover"
	"github.com/justinnevins/xrplbak/internal/dump"
	"github.com/justinnevins/xrplbak/internal/restore"
)

// memosOnLedger counts xrplbak memos the account has on the fake.
func memosOnLedger(t *testing.T, e *env) int {
	t.Helper()
	txs, _, _ := e.ledger.AccountTx(e.writer.Address())
	n := 0
	for _, tx := range txs {
		for _, m := range tx.Memos {
			if _, ok := chunk.Decode(m); ok {
				n++
			}
		}
	}
	return n
}

// TestBatchTailIsAtomic pins the point of Batch for this tool: the manifest
// and the DID anchor land in one all-or-nothing transaction, so the ledger
// never holds an anchor without the manifest it names. Chunks go first, in
// batches of up to eight, and everything the sequential path produced
// (discovery, restore, the dump, the offline path) reads the same.
func TestBatchTailIsAtomic(t *testing.T) {
	e := newEnv(t)
	e.ledger.Batch = true
	p, err := Build(e.opts(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Batch: true, Sleep: func(time.Duration) {}, DumpOut: filepath.Join(e.dir, p.Manifest.BackupID+".dump.json")}
	if err := s.Submit(p); err != nil {
		t.Fatal(err)
	}
	// One chunk, two manifest parts, one anchor: four inner transactions,
	// one batch, one round trip.
	if e.ledger.Batches != 1 || e.ledger.Submitted != 1 {
		t.Fatalf("submitted %d transactions in %d batches; want one batch", e.ledger.Submitted, e.ledger.Batches)
	}

	keys := discover.RootKeys{Root: e.root}
	res, err := discover.Run(e.ledger, keys, e.writer.Address(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !res.AnchorOK || res.Latest == nil || !res.Latest.FromAnchor || len(res.Warnings) != 0 {
		t.Fatalf("discovery: anchorOK=%v latest=%v warnings=%v", res.AnchorOK, res.Latest, res.Warnings)
	}
	// The anchor and the manifest share a ledger: that is what atomic means
	// on the ledger itself.
	if res.Latest.Ledger != s.Dump.DID.LedgerIndex {
		t.Fatalf("manifest in ledger %d, anchor in ledger %d; the tail was not one transaction", res.Latest.Ledger, s.Dump.DID.LedgerIndex)
	}
	// A batched anchor cannot know the manifest's ledger when it is built,
	// so it records 0, and discovery must not read that as a problem.
	if res.Anchor.ManifestLedger != 0 {
		t.Fatalf("batched anchor recorded manifest ledger %d, want 0", res.Anchor.ManifestLedger)
	}
	entries, err := discover.Fetch(e.ledger, keys, res, res.Latest)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := discover.OpenBundle(keys, res.Latest, p.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := restore.Build(res.Latest.Manifest, entries, bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range plan.Files {
		if !f.Complete {
			t.Fatalf("%s incomplete after a batched backup", f.Path)
		}
	}
	// The manifest names each chunk by the hash its inner transaction got.
	for _, ch := range res.Latest.Manifest.OnChain.Chunks {
		if _, err := e.ledger.Tx(ch.TxHash); err != nil {
			t.Fatalf("manifest names chunk tx %s which the ledger does not have", ch.TxHash)
		}
	}
	// Offline: the dump holds the inner transactions, so it restores alone.
	d, err := dump.Load(s.DumpOut)
	if err != nil {
		t.Fatal(err)
	}
	off := &dump.Client{D: d}
	res2, err := discover.Run(off, keys, e.writer.Address(), 0)
	if err != nil || res2.Latest == nil || !res2.AnchorOK {
		t.Fatalf("dump discovery: %v %+v", err, res2)
	}
	if entries2, err := discover.Fetch(off, keys, res2, res2.Latest); err != nil || len(entries2) != len(entries) {
		t.Fatal("dump fetch", err)
	}
}

// TestBatchFailureLeavesNoHalfManifest: when the batch does not apply, the
// ledger holds nothing from it, Submit says so, and a second Submit
// finishes the job.
func TestBatchFailureLeavesNoHalfManifest(t *testing.T) {
	e := newEnv(t)
	e.ledger.Batch = true
	p, err := Build(e.opts(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	dumpPath := filepath.Join(e.dir, "b.dump.json")
	s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Batch: true, Sleep: func(time.Duration) {}, DumpOut: dumpPath}
	e.ledger.FailInner = 1
	err = s.Submit(p)
	if err == nil || !strings.Contains(err.Error(), "did not apply") {
		t.Fatalf("a failed batch must be reported as not applied, got %v", err)
	}
	if _, derr := e.ledger.LedgerEntryDID(e.writer.Address()); derr == nil {
		t.Fatal("anchor landed although the batch failed")
	}
	if n := memosOnLedger(t, e); n != 0 {
		t.Fatalf("%d memo(s) on the ledger after a failed batch", n)
	}
	if len(s.Dump.Txs) != 0 {
		t.Fatalf("dump records %d transaction(s) that never applied", len(s.Dump.Txs))
	}
	before := e.ledger.Submitted
	s2 := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Batch: true, Sleep: func(time.Duration) {}, DumpOut: dumpPath}
	if err := s2.Submit(p); err != nil {
		t.Fatal(err)
	}
	if e.ledger.Submitted-before != 1 {
		t.Fatalf("retry sent %d transactions, want 1", e.ledger.Submitted-before)
	}
	res, err := discover.Run(e.ledger, discover.RootKeys{Root: e.root}, e.writer.Address(), 0)
	if err != nil || res.Latest == nil || !res.AnchorOK {
		t.Fatalf("after retry: %v %+v", err, res)
	}
}

// bigConfig writes a config that needs several chunks.
func bigConfig(t *testing.T, lines int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "big.cfg")
	var sb strings.Builder
	sb.WriteString("[sntp_servers]\n")
	for i := 0; i < lines; i++ {
		sum := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		sb.WriteString(hex.EncodeToString(sum[:16]) + ".example.com\n")
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestBatchChunksFirstThenAtomicTail covers a backup too big for one batch:
// the chunks go in a batch of their own, then the manifest parts and the
// anchor land together. The manifest names chunks by the hashes their
// inner transactions got in the first batch.
func TestBatchChunksFirstThenAtomicTail(t *testing.T) {
	e := newEnv(t)
	e.ledger.Batch = true
	o := e.opts(t, 1)
	o.ConfigPath, o.ValidatorsPath = bigConfig(t, 330), ""
	p, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.ChunkMemos) < 6 {
		t.Fatalf("fixture makes %d chunks; the test needs at least 6 so the backup does not fit one batch", len(p.ChunkMemos))
	}
	s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Batch: true, Sleep: func(time.Duration) {}, DumpOut: filepath.Join(e.dir, "big.dump.json")}
	if err := s.Submit(p); err != nil {
		t.Fatal(err)
	}
	if e.ledger.Batches != 2 || e.ledger.Submitted != 2 {
		t.Fatalf("submitted %d transactions in %d batches; want a chunk batch and a tail batch", e.ledger.Submitted, e.ledger.Batches)
	}
	keys := discover.RootKeys{Root: e.root}
	res, err := discover.Run(e.ledger, keys, e.writer.Address(), 0)
	if err != nil || res.Latest == nil || !res.AnchorOK || len(res.Warnings) != 0 {
		t.Fatalf("discovery: %v %+v", err, res)
	}
	if res.Latest.Ledger != s.Dump.DID.LedgerIndex {
		t.Fatalf("manifest in ledger %d, anchor in ledger %d", res.Latest.Ledger, s.Dump.DID.LedgerIndex)
	}
	for _, ch := range res.Latest.Manifest.OnChain.Chunks {
		rec, err := e.ledger.Tx(ch.TxHash)
		if err != nil {
			t.Fatalf("manifest names chunk tx %s which the ledger does not have", ch.TxHash)
		}
		if ch.Ledger != rec.LedgerIndex || ch.Ledger >= res.Latest.Ledger {
			t.Fatalf("chunk %d: manifest says ledger %d, ledger says %d, manifest is in %d", ch.Index, ch.Ledger, rec.LedgerIndex, res.Latest.Ledger)
		}
	}
	entries, err := discover.Fetch(e.ledger, keys, res, res.Latest)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := restore.Build(res.Latest.Manifest, entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	orig, _ := os.ReadFile(o.ConfigPath)
	if !plan.Files[0].Complete || string(plan.Files[0].Data) != string(orig) {
		t.Fatalf("restored config differs (complete=%v)", plan.Files[0].Complete)
	}
}

// TestSplitBatches pins the cut: never a lone transaction after the first
// group, never more than eight in one.
func TestSplitBatches(t *testing.T) {
	for n := 2; n <= 25; n++ {
		sizes := splitBatches(n)
		sum := 0
		for i, sz := range sizes {
			sum += sz
			if sz > 8 || sz < 2 {
				t.Fatalf("n=%d: group %d has size %d: %v", n, i, sz, sizes)
			}
		}
		if sum != n {
			t.Fatalf("n=%d: sizes %v sum to %d", n, sizes, sum)
		}
	}
}
