package backup

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/anchor"
	"github.com/justinnevins/xrplbak/internal/discover"
	"github.com/justinnevins/xrplbak/internal/dump"
	"github.com/justinnevins/xrplbak/internal/restore"
	"github.com/justinnevins/xrplbak/internal/xrpl"
)

// cutAt lets the first n-1 submits through and fails every one after, the
// way a connection that drops mid-run does.
type cutAt struct {
	xrpl.Client
	n, failFrom int
}

func (c *cutAt) Submit(blob []byte) (string, error) {
	c.n++
	if c.n >= c.failFrom {
		return "", errors.New("connection reset")
	}
	return c.Client.Submit(blob)
}

// interruptedBeforeAnchor runs a one-at-a-time backup that loses the
// connection on its last transaction, the DID anchor. It returns the dump
// that run left behind: every chunk and the whole manifest, no anchor.
func interruptedBeforeAnchor(t *testing.T, e *env) *dump.Dump {
	t.Helper()
	// A twin run counts the transactions, so the cut lands on the anchor.
	twin := newEnv(t)
	tp, _ := Build(twin.opts(t, 1))
	twin.submit(t, tp)
	total := twin.ledger.Submitted

	p, _ := Build(e.opts(t, 1))
	out := filepath.Join(e.dir, "interrupted.dump.json")
	first := &Submitter{Client: &cutAt{Client: e.ledger, failFrom: total}, Writer: e.writer, Key: e.key, Sleep: func(time.Duration) {}, DumpOut: out}
	if err := first.Submit(p); err == nil || !strings.Contains(err.Error(), "anchor") {
		t.Fatalf("the first run must stop at the anchor, got: %v", err)
	}
	if _, err := e.ledger.LedgerEntryDID(e.writer.Address()); err == nil {
		t.Fatal("setup: the anchor landed; the cut missed it")
	}
	d, err := dump.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Txs) != total-1 || d.DID != nil {
		t.Fatalf("setup: dump holds %d txs (want %d) and DID %v", len(d.Txs), total-1, d.DID)
	}
	return d
}

// A backup written one transaction at a time and cut off before the anchor
// is resumed with Batch on. Every chunk and the whole manifest are already
// on the ledger, so the only thing left is the anchor, sent on its own.
// No test ran this path (Submitter.sendAnchor) before: coverage 0%.
func TestResumeBatchedSendsOnlyTheAnchor(t *testing.T) {
	e := newEnv(t)
	d := interruptedBeforeAnchor(t, e)

	e.ledger.Batch = true
	again, _ := Build(e.opts(t, 1))
	var log []string
	s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Dump: d, Batch: true, Sleep: func(time.Duration) {},
		DumpOut: filepath.Join(e.dir, "resumed.dump.json"),
		Log:     func(f string, a ...any) { log = append(log, f) }}
	before, batches := e.ledger.Submitted, e.ledger.Batches
	if err := s.Submit(again); err != nil {
		t.Fatal(err)
	}
	if got := e.ledger.Submitted - before; got != 1 {
		t.Fatalf("resume sent %d transactions; only the anchor was missing", got)
	}
	if e.ledger.Batches != batches {
		t.Fatal("resume sent a Batch; one anchor cannot ride in a batch")
	}
	if !strings.Contains(strings.Join(log, "\n"), "manifest already on ledger") {
		t.Fatalf("resume did not report the manifest it reused: %q", log)
	}

	// The anchor names manifest part 0 as it landed in the first run.
	var part0 dump.Tx
	for _, tx := range d.Txs[len(again.ChunkMemos):] {
		part0 = tx
		break
	}
	data, err := e.ledger.LedgerEntryDID(e.writer.Address())
	if err != nil {
		t.Fatal(err)
	}
	rec, err := anchor.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(rec.TxHashHex(), part0.Hash) {
		t.Fatalf("anchor names tx %s; manifest part 1 is tx %s", rec.TxHashHex(), part0.Hash)
	}
	if rec.ManifestLedger != part0.LedgerIndex {
		t.Fatalf("anchor names ledger %d; manifest part 1 is in ledger %d", rec.ManifestLedger, part0.LedgerIndex)
	}
	everyTxOn(t, e.ledger, again, e.writer.Address())

	// And the backup restores: discovery finds it through the anchor and
	// every file comes back complete.
	keys := discover.RootKeys{Root: e.root}
	res, err := discover.Run(e.ledger, keys, e.writer.Address(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !res.AnchorOK || res.Latest == nil || !res.Latest.FromAnchor || len(res.Warnings) != 0 {
		t.Fatalf("discovery: anchorOK=%v latest=%v warnings=%v", res.AnchorOK, res.Latest, res.Warnings)
	}
	entries, err := discover.Fetch(e.ledger, keys, res, res.Latest)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := discover.OpenBundle(keys, res.Latest, again.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := restore.Build(res.Latest.Manifest, entries, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Files) != 2 {
		t.Fatalf("restored %d files, want 2", len(plan.Files))
	}
	for _, f := range plan.Files {
		if !f.Complete() {
			t.Fatalf("%s is not complete after the resumed backup", f.Path)
		}
	}
	if s.Dump.DID == nil {
		t.Fatal("the resumed dump does not record the anchor")
	}
}

// The dump shows a whole manifest but is missing a chunk that manifest
// names. A batched resume must refuse: the manifest on the ledger carries
// the old chunk's tx hash, and a resent chunk would get a new one.
func TestResumeBatchedRefusesAManifestWithoutItsChunks(t *testing.T) {
	e := newEnv(t)
	d := interruptedBeforeAnchor(t, e)
	d.Txs = d.Txs[1:] // forget the first chunk

	e.ledger.Batch = true
	again, _ := Build(e.opts(t, 1))
	s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Dump: d, Batch: true, Sleep: func(time.Duration) {}, DumpOut: filepath.Join(e.dir, "resumed.dump.json")}
	before := e.ledger.Submitted
	err := s.Submit(again)
	if err == nil || !strings.Contains(err.Error(), "refusing to guess") {
		t.Fatalf("want the refusal, got: %v", err)
	}
	if e.ledger.Submitted != before {
		t.Fatalf("the refused resume still sent %d transaction(s)", e.ledger.Submitted-before)
	}
	if _, err := e.ledger.LedgerEntryDID(e.writer.Address()); err == nil {
		t.Fatal("the refused resume wrote an anchor")
	}
}

// F-076: the anchor was built in three places and only one checked that
// the manifest tx hash is 32 bytes of hex. The two others dropped the
// decode error, so a hash that is not hex became an anchor naming
// transaction 000...0, published as if it were good.
func TestF076AnchorRefusesAManifestHashThatIsNotHex(t *testing.T) {
	for _, bad := range []string{"", "not hex", "ABCD", strings.Repeat("A", 63), strings.Repeat("A", 66), strings.Repeat("Z", 64)} {
		e := newEnv(t)
		p, _ := Build(e.opts(t, 1))
		s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Sleep: func(time.Duration) {}, DumpOut: filepath.Join(e.dir, "x.dump.json")}
		s.defaults()
		before := e.ledger.Submitted
		err := s.sendAnchor(p, bad, 7)
		if err == nil {
			t.Errorf("manifest hash %q: sendAnchor published an anchor", bad)
		}
		if e.ledger.Submitted != before {
			t.Errorf("manifest hash %q: %d transaction(s) sent", bad, e.ledger.Submitted-before)
		}
	}
}
