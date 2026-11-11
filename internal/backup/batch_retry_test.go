package backup

import (
	"strings"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/testsupport/fake"
	"github.com/justinnevins/xrplbak/internal/xrpl/codec"
)

// These tests pin the retry paths of sendBatch: a submit the server turns
// away, a queued submit, a slow validation, an expired batch, an inner
// result that is not tesSUCCESS, and the exact fee, expiry ledger, reserve
// and batch size the tool sends. The fake ledger drives each path (Reject,
// Queue, Delay, Stall, Expire, InnerResult).

// batchRun runs one batched backup of the fixture config. setup changes
// the fake ledger before the run. It returns every sleep the run asked
// for and the run's error.
func batchRun(t *testing.T, setup func(*fake.Ledger)) (*env, []time.Duration, error) {
	t.Helper()
	e := newEnv(t)
	e.ledger.Batch = true
	p, err := Build(e.opts(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	if setup != nil {
		setup(e.ledger)
	}
	var sleeps []time.Duration
	s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Batch: true, Sleep: func(d time.Duration) { sleeps = append(sleeps, d) }}
	err = s.Submit(p)
	return e, sleeps, err
}

func count(ds []time.Duration, d time.Duration) int {
	n := 0
	for _, x := range ds {
		if x == d {
			n++
		}
	}
	return n
}

// The fixture fits one batch. A plain run is the baseline the others
// differ from: one submit, one batch, one 2 s wait.
func TestBatchBaselineOneSubmit(t *testing.T) {
	e, sleeps, err := batchRun(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e.ledger.Submitted != 1 || e.ledger.Batches != 1 || len(sleeps) != 1 || sleeps[0] != 2*time.Second {
		t.Fatalf("submitted %d, batches %d, sleeps %v", e.ledger.Submitted, e.ledger.Batches, sleeps)
	}
}

// tefPAST_SEQ and terPRE_SEQ mean the sequence moved under the run: wait
// 4 s, rebuild with fresh sequences, and submit again.
func TestBatchRetriesASequenceRace(t *testing.T) {
	for _, code := range []string{"tefPAST_SEQ", "terPRE_SEQ"} {
		e, sleeps, err := batchRun(t, func(l *fake.Ledger) { l.Reject = []string{code} })
		if err != nil {
			t.Fatalf("%s: %v", code, err)
		}
		if e.ledger.Submitted != 2 || e.ledger.Batches != 1 {
			t.Fatalf("%s: submitted %d, batches %d; want 2 and 1", code, e.ledger.Submitted, e.ledger.Batches)
		}
		if len(sleeps) != 2 || sleeps[0] != 4*time.Second || sleeps[1] != 2*time.Second {
			t.Fatalf("%s: sleeps %v; want [4s 2s]", code, sleeps)
		}
	}
}

// Any other engine code ends the run at once and names the code.
func TestBatchStopsOnARejectedSubmit(t *testing.T) {
	e, _, err := batchRun(t, func(l *fake.Ledger) { l.Reject = []string{"temMALFORMED"} })
	if err == nil || !strings.Contains(err.Error(), "submit returned temMALFORMED for batch") {
		t.Fatalf("err = %v", err)
	}
	if e.ledger.Submitted != 1 {
		t.Fatalf("submitted %d times; a rejected batch is not retried", e.ledger.Submitted)
	}
}

// terQUEUED is accepted: the batch applies when its ledger closes.
func TestBatchAcceptsAQueuedSubmit(t *testing.T) {
	e, _, err := batchRun(t, func(l *fake.Ledger) { l.Queue = true })
	if err != nil {
		t.Fatal(err)
	}
	if e.ledger.Submitted != 1 || e.ledger.Batches != 1 {
		t.Fatalf("submitted %d, batches %d", e.ledger.Submitted, e.ledger.Batches)
	}
}

// Three attempts, then the run gives up and says so.
func TestBatchGivesUpAfterThreeAttempts(t *testing.T) {
	e, _, err := batchRun(t, func(l *fake.Ledger) {
		l.Reject = []string{"tefPAST_SEQ", "tefPAST_SEQ", "tefPAST_SEQ", "tefPAST_SEQ", "tefPAST_SEQ"}
	})
	if err == nil || !strings.Contains(err.Error(), "batch did not validate after 3 attempts") {
		t.Fatalf("err = %v", err)
	}
	if e.ledger.Submitted != 3 {
		t.Fatalf("submitted %d times, want 3", e.ledger.Submitted)
	}
}

// A batch that is slow to validate is waited for, every 2 s, and never
// sent twice.
func TestBatchWaitsForValidation(t *testing.T) {
	e, sleeps, err := batchRun(t, func(l *fake.Ledger) { l.Delay = 3 })
	if err != nil {
		t.Fatal(err)
	}
	if e.ledger.Submitted != 1 || e.ledger.Batches != 1 {
		t.Fatalf("submitted %d, batches %d", e.ledger.Submitted, e.ledger.Batches)
	}
	if len(sleeps) != 3 || count(sleeps, 2*time.Second) != 3 {
		t.Fatalf("sleeps %v; want three of 2s", sleeps)
	}
}

// The batch carries LastLedgerSequence = validated + 20. A validated
// ledger equal to it is not yet past it: the batch can still land there,
// so the run keeps waiting rather than send a second batch.
func TestBatchKeepsWaitingAtItsLastLedger(t *testing.T) {
	// Each lookup closes one ledger. The batch lands one ledger after the
	// submit, so the 19th lookup sees the validated ledger reach exactly
	// its LastLedgerSequence; it validates on the 20th.
	e, _, err := batchRun(t, func(l *fake.Ledger) { l.Delay = 20 })
	if err != nil {
		t.Fatal(err)
	}
	if e.ledger.Submitted != 1 || e.ledger.Batches != 1 {
		t.Fatalf("submitted %d, batches %d; the run gave up on a batch that could still land", e.ledger.Submitted, e.ledger.Batches)
	}
}

// With no ledger closing, the run polls 45 times, 90 s, then tries again.
func TestBatchPollsFortyFiveTimesBeforeTryingAgain(t *testing.T) {
	e, sleeps, err := batchRun(t, func(l *fake.Ledger) { l.Delay = 46; l.Stall = true })
	if err != nil {
		t.Fatal(err)
	}
	// The first batch stays unvalidated through 45 polls; the second
	// attempt sends a new batch, which validates on its first poll.
	if e.ledger.Submitted != 2 || e.ledger.Batches != 2 {
		t.Fatalf("submitted %d, batches %d; want 2 and 2", e.ledger.Submitted, e.ledger.Batches)
	}
	if len(sleeps) != 46 || count(sleeps, 2*time.Second) != 46 {
		t.Fatalf("%d sleeps; want 45 polls for the first batch and 1 for the second", len(sleeps))
	}
}

// An expired batch is rebuilt at once, with fresh sequences and a fresh
// LastLedgerSequence, not after 90 s of polling.
func TestBatchRebuildsAnExpiredBatchAtOnce(t *testing.T) {
	e, sleeps, err := batchRun(t, func(l *fake.Ledger) { l.Expire = 1 })
	if err != nil {
		t.Fatal(err)
	}
	if e.ledger.Submitted != 2 || e.ledger.Batches != 1 {
		t.Fatalf("submitted %d, batches %d", e.ledger.Submitted, e.ledger.Batches)
	}
	if len(sleeps) != 2 {
		t.Fatalf("sleeps %v; want one poll for the expired batch and one for the new one", sleeps)
	}
}

// Under all-or-nothing an inner transaction that validates with any result
// but tesSUCCESS means nothing from the batch applied.
func TestBatchChecksEveryInnerResult(t *testing.T) {
	_, _, err := batchRun(t, func(l *fake.Ledger) { l.InnerResult = "tecFAILED_PROCESSING" })
	if err == nil || !strings.Contains(err.Error(), "but inner transaction 1 of ") {
		t.Fatalf("err = %v", err)
	}
}

// The outer transaction pays (inner + 2) times the rate and expires 20
// ledgers after the validated ledger it was built against.
func TestBatchFeeAndLastLedger(t *testing.T) {
	e, _, err := batchRun(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	tx := e.ledger.LastSubmitted
	if tx == nil || tx.Type != codec.TxBatch {
		t.Fatal("no batch submitted")
	}
	if want := e.ledger.Fee * uint64(len(tx.Inner)+2); tx.FeeDrops != want {
		t.Fatalf("fee %d, want %d", tx.FeeDrops, want)
	}
	if tx.LastLedgerSequence != 1000+20 {
		t.Fatalf("LastLedgerSequence %d, want 1020 (validated 1000 + 20)", tx.LastLedgerSequence)
	}
}

// The account must hold the 1.2 XRP reserve plus the batch fee. Exactly
// that much is enough; one drop less is refused before anything is sent.
func TestBatchReserveBoundary(t *testing.T) {
	twin, _, err := batchRun(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	fee := twin.ledger.LastSubmitted.FeeDrops
	for _, tc := range []struct {
		drops uint64
		ok    bool
	}{{1_200_000 + fee, true}, {1_200_000 + fee - 1, false}} {
		e, _, err := batchRun(t, func(l *fake.Ledger) {
			for _, a := range l.Accounts {
				a.BalanceDrops = tc.drops
			}
		})
		if tc.ok && err != nil {
			t.Fatalf("%d drops: %v", tc.drops, err)
		}
		if !tc.ok && (err == nil || !strings.Contains(err.Error(), "needs the 1.2 XRP reserve plus fees") || e.ledger.Submitted != 0) {
			t.Fatalf("%d drops: err %v, submitted %d", tc.drops, err, e.ledger.Submitted)
		}
	}
}

// sendBatch itself refuses a batch outside 2 to 8 inner transactions, and
// inner sequences that do not follow the outer one, before signing.
func TestSendBatchShapeChecks(t *testing.T) {
	items := func(n int) func(uint32) ([]batchItem, error) {
		return func(seq uint32) ([]batchItem, error) {
			var out []batchItem
			for i := 0; i < n; i++ {
				out = append(out, batchItem{kind: "chunk", index: i, tx: &codec.Tx{Type: codec.TxAccountSet, Memos: []codec.Memo{{Data: []byte{byte(i)}}}}})
			}
			return out, nil
		}
	}
	for _, tc := range []struct {
		n    int
		want string
	}{{1, "a batch carries 2 to 8 transactions, not 1"}, {9, "a batch carries 2 to 8 transactions, not 9"}, {2, ""}, {8, ""}} {
		e := newEnv(t)
		e.ledger.Batch = true
		s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Batch: true, Sleep: func(time.Duration) {}}
		build := items(tc.n)
		_, _, err := s.sendBatch(func(seq uint32) ([]batchItem, error) {
			out, _ := build(seq)
			s.assignInner(out, seq)
			return out, nil
		})
		if tc.want == "" && err != nil {
			t.Fatalf("%d items: %v", tc.n, err)
		}
		if tc.want != "" && (err == nil || err.Error() != tc.want || e.ledger.Submitted != 0) {
			t.Fatalf("%d items: err %v, submitted %d", tc.n, err, e.ledger.Submitted)
		}
	}

	e := newEnv(t)
	e.ledger.Batch = true
	s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Batch: true, Sleep: func(time.Duration) {}}
	build := items(2)
	_, _, err := s.sendBatch(func(seq uint32) ([]batchItem, error) {
		out, _ := build(seq)
		s.assignInner(out, seq+1)
		return out, nil
	})
	if err == nil || err.Error() != "inner transaction 0 has sequence 3, want 2" || e.ledger.Submitted != 0 {
		t.Fatalf("err %v, submitted %d", err, e.ledger.Submitted)
	}
}
