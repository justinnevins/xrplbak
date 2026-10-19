package backup

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/anchor"
	"github.com/justinnevins/xrplbak/internal/dump"
	"github.com/justinnevins/xrplbak/internal/xrpl"
	"github.com/justinnevins/xrplbak/internal/xrpl/fake"
)

// A dump is a record of what landed somewhere. The ledger the operator is
// writing to now is the only witness to what landed there. A resume that
// skips a chunk because the dump lists it, without asking that ledger,
// reports a backup complete on a ledger that may hold none of it.

// resumeWith runs the first backup against e.ledger, then submits the same
// plan again against target with the dump the first run wrote.
func resumeWith(t *testing.T, e *env, target xrpl.Client, batch bool) (*Plan, error) {
	t.Helper()
	e.ledger.Batch = batch
	p, _ := Build(e.opts(t, 1))
	first := e.submit(t, p)
	first.Batch = batch
	d, err := dump.Load(first.DumpOut)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := Build(e.opts(t, 1))
	s := &Submitter{Client: target, Writer: e.writer, Key: e.key, Dump: d, Batch: batch, Sleep: func(time.Duration) {}, DumpOut: filepath.Join(e.dir, "resumed.json")}
	return again, s.Submit(again)
}

// everyTxOn checks that the manifest's chunk transactions and the manifest
// transaction itself are on l, validated, successful, and by the writer.
func everyTxOn(t *testing.T, l *fake.Ledger, p *Plan, writer string) {
	t.Helper()
	hashes := map[string]string{}
	for i, c := range p.Manifest.OnChain.Chunks {
		hashes[c.TxHash] = fmt.Sprintf("chunk %d", i+1)
	}
	data, err := l.LedgerEntryDID(writer)
	if err != nil {
		t.Fatalf("anchor: %v", err)
	}
	rec, err := anchor.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	hashes[rec.TxHashHex()] = "manifest"
	for h, what := range hashes {
		rec, err := l.Tx(h)
		if err != nil {
			t.Fatalf("%s tx %s is not on the ledger the backup was written to: %v", what, h, err)
		}
		if rec.Result != "tesSUCCESS" || rec.Account != writer {
			t.Fatalf("%s tx %s: result %s account %s", what, h, rec.Result, rec.Account)
		}
	}
}

func TestResumeOnAnotherLedgerResendsEverything(t *testing.T) {
	for _, batch := range []bool{false, true} {
		e := newEnv(t)
		other := fake.New()
		other.Batch = batch
		other.Fund(e.writer.Address(), 5_000_000)
		p, err := resumeWith(t, e, other, batch)
		if err != nil {
			t.Fatalf("batch=%v: %v", batch, err)
		}
		everyTxOn(t, other, p, e.writer.Address())
	}
}

func TestResumeIgnoresRecordedTxThatFailedOnTheLedger(t *testing.T) {
	e := newEnv(t)
	p, _ := Build(e.opts(t, 1))
	first := e.submit(t, p)
	// The ledger now says the first chunk's transaction did not apply.
	for i := range e.ledger.Txs {
		if strings.EqualFold(e.ledger.Txs[i].Hash, p.Manifest.OnChain.Chunks[0].TxHash) {
			e.ledger.Txs[i].Result = "tecINSUFFICIENT_FEE"
		}
	}
	d, _ := dump.Load(first.DumpOut)
	again, _ := Build(e.opts(t, 1))
	s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Dump: d, Sleep: func(time.Duration) {}, DumpOut: filepath.Join(e.dir, "resumed.json")}
	if err := s.Submit(again); err != nil {
		t.Fatal(err)
	}
	if again.Manifest.OnChain.Chunks[0].TxHash == p.Manifest.OnChain.Chunks[0].TxHash {
		t.Fatal("resume kept a chunk tx the ledger reports as failed")
	}
	everyTxOn(t, e.ledger, again, e.writer.Address())
}

func TestResumeIgnoresRecordedTxNotYetValidated(t *testing.T) {
	e := newEnv(t)
	p, _ := Build(e.opts(t, 1))
	first := e.submit(t, p)
	for i := range e.ledger.Txs {
		if strings.EqualFold(e.ledger.Txs[i].Hash, p.Manifest.OnChain.Chunks[0].TxHash) {
			e.ledger.Txs[i].Validated = false
		}
	}
	d, _ := dump.Load(first.DumpOut)
	again, _ := Build(e.opts(t, 1))
	s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Dump: d, Sleep: func(time.Duration) {}, DumpOut: filepath.Join(e.dir, "resumed.json")}
	if err := s.Submit(again); err != nil {
		t.Fatal(err)
	}
	if again.Manifest.OnChain.Chunks[0].TxHash == p.Manifest.OnChain.Chunks[0].TxHash {
		t.Fatal("resume kept a chunk tx the ledger has not validated")
	}
}

func TestResumeIgnoresRecordedTxByAnotherAccount(t *testing.T) {
	e := newEnv(t)
	p, _ := Build(e.opts(t, 1))
	first := e.submit(t, p)
	for i := range e.ledger.Txs {
		if strings.EqualFold(e.ledger.Txs[i].Hash, p.Manifest.OnChain.Chunks[0].TxHash) {
			e.ledger.Txs[i].Account = "rrrrrrrrrrrrrrrrrrrrrhoLvTp"
		}
	}
	d, _ := dump.Load(first.DumpOut)
	again, _ := Build(e.opts(t, 1))
	s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Dump: d, Sleep: func(time.Duration) {}, DumpOut: filepath.Join(e.dir, "resumed.json")}
	if err := s.Submit(again); err != nil {
		t.Fatal(err)
	}
	if again.Manifest.OnChain.Chunks[0].TxHash == p.Manifest.OnChain.Chunks[0].TxHash {
		t.Fatal("resume kept a chunk tx that another account sent")
	}
	everyTxOn(t, e.ledger, again, e.writer.Address())
}

// txDown answers every Tx lookup with a network error.
type txDown struct{ *fake.Ledger }

func (txDown) Tx(string) (*xrpl.TxRecord, error) { return nil, errors.New("connection refused") }

func TestResumeRefusesWhenTheLedgerCannotBeAsked(t *testing.T) {
	e := newEnv(t)
	p, _ := Build(e.opts(t, 1))
	first := e.submit(t, p)
	d, _ := dump.Load(first.DumpOut)
	again, _ := Build(e.opts(t, 1))
	before := e.ledger.Submitted
	s := &Submitter{Client: txDown{e.ledger}, Writer: e.writer, Key: e.key, Dump: d, Sleep: func(time.Duration) {}, DumpOut: filepath.Join(e.dir, "resumed.json")}
	err := s.Submit(again)
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("an unanswerable ledger must stop the resume, got %v", err)
	}
	if e.ledger.Submitted != before {
		t.Fatal("nothing may be submitted before the recorded transactions are confirmed")
	}
}
