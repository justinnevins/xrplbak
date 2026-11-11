package backup

import (
	"strings"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/testsupport/fake"
	"github.com/justinnevins/xrplbak/internal/xrpl/codec"
)

// These tests pin the retry paths of send, the one-transaction submit:
// the same paths batch_retry_test.go pins for sendBatch.

// sendOne sends one AccountSet through send. setup changes the fake
// ledger first. It returns every sleep the call asked for and its error.
func sendOne(t *testing.T, setup func(*fake.Ledger)) (*env, []time.Duration, error) {
	t.Helper()
	e := newEnv(t)
	if setup != nil {
		setup(e.ledger)
	}
	var sleeps []time.Duration
	s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Sleep: func(d time.Duration) { sleeps = append(sleeps, d) }}
	_, _, err := s.send(&codec.Tx{Type: codec.TxAccountSet, Memos: []codec.Memo{{Data: []byte("x")}}})
	return e, sleeps, err
}

// accountSets counts the AccountSet transactions on the fake ledger.
func accountSets(l *fake.Ledger) int {
	n := 0
	for _, t := range l.Txs {
		if t.TxType == "AccountSet" {
			n++
		}
	}
	return n
}

func TestSendBaselineOneSubmit(t *testing.T) {
	e, sleeps, err := sendOne(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e.ledger.Submitted != 1 || accountSets(e.ledger) != 1 || len(sleeps) != 1 || sleeps[0] != 2*time.Second {
		t.Fatalf("submitted %d, on ledger %d, sleeps %v", e.ledger.Submitted, accountSets(e.ledger), sleeps)
	}
}

// tefPAST_SEQ and terPRE_SEQ: wait 4 s, take a fresh sequence, submit again.
func TestSendRetriesASequenceRace(t *testing.T) {
	for _, code := range []string{"tefPAST_SEQ", "terPRE_SEQ"} {
		e, sleeps, err := sendOne(t, func(l *fake.Ledger) { l.Reject = []string{code} })
		if err != nil {
			t.Fatalf("%s: %v", code, err)
		}
		if e.ledger.Submitted != 2 || accountSets(e.ledger) != 1 {
			t.Fatalf("%s: submitted %d, on ledger %d", code, e.ledger.Submitted, accountSets(e.ledger))
		}
		if len(sleeps) != 2 || sleeps[0] != 4*time.Second || sleeps[1] != 2*time.Second {
			t.Fatalf("%s: sleeps %v; want [4s 2s]", code, sleeps)
		}
	}
}

// Any other engine code ends the call at once and names the code.
func TestSendStopsOnARejectedSubmit(t *testing.T) {
	e, _, err := sendOne(t, func(l *fake.Ledger) { l.Reject = []string{"temMALFORMED"} })
	if err == nil || !strings.Contains(err.Error(), "submit returned temMALFORMED for tx") || e.ledger.Submitted != 1 {
		t.Fatalf("err %v, submitted %d", err, e.ledger.Submitted)
	}
}

func TestSendAcceptsAQueuedSubmit(t *testing.T) {
	e, _, err := sendOne(t, func(l *fake.Ledger) { l.Queue = true })
	if err != nil || e.ledger.Submitted != 1 || accountSets(e.ledger) != 1 {
		t.Fatalf("err %v, submitted %d", err, e.ledger.Submitted)
	}
}

func TestSendGivesUpAfterThreeAttempts(t *testing.T) {
	e, _, err := sendOne(t, func(l *fake.Ledger) {
		l.Reject = []string{"tefPAST_SEQ", "tefPAST_SEQ", "tefPAST_SEQ", "tefPAST_SEQ", "tefPAST_SEQ"}
	})
	if err == nil || err.Error() != "transaction did not validate after 3 attempts" || e.ledger.Submitted != 3 {
		t.Fatalf("err %v, submitted %d; want 3 submits", err, e.ledger.Submitted)
	}
}

func TestSendWaitsForValidation(t *testing.T) {
	e, sleeps, err := sendOne(t, func(l *fake.Ledger) { l.Delay = 3 })
	if err != nil || e.ledger.Submitted != 1 || accountSets(e.ledger) != 1 {
		t.Fatalf("err %v, submitted %d, on ledger %d", err, e.ledger.Submitted, accountSets(e.ledger))
	}
	if len(sleeps) != 3 || count(sleeps, 2*time.Second) != 3 {
		t.Fatalf("sleeps %v; want three of 2s", sleeps)
	}
}

// A validated ledger equal to LastLedgerSequence is not past it.
func TestSendKeepsWaitingAtItsLastLedger(t *testing.T) {
	e, _, err := sendOne(t, func(l *fake.Ledger) { l.Delay = 20 })
	if err != nil || e.ledger.Submitted != 1 || accountSets(e.ledger) != 1 {
		t.Fatalf("err %v, submitted %d, on ledger %d; the call gave up on a transaction that could still land", err, e.ledger.Submitted, accountSets(e.ledger))
	}
}

// With no ledger closing, 45 polls of 2 s, then a new attempt.
func TestSendPollsFortyFiveTimesBeforeTryingAgain(t *testing.T) {
	e, sleeps, err := sendOne(t, func(l *fake.Ledger) { l.Delay = 46; l.Stall = true })
	if err != nil {
		t.Fatal(err)
	}
	if e.ledger.Submitted != 2 {
		t.Fatalf("submitted %d, want 2", e.ledger.Submitted)
	}
	if len(sleeps) != 46 || count(sleeps, 2*time.Second) != 46 {
		t.Fatalf("%d sleeps; want 45 polls for the first attempt and 1 for the second", len(sleeps))
	}
}

// An expired transaction is resubmitted at once with a fresh sequence.
func TestSendResubmitsAnExpiredTransactionAtOnce(t *testing.T) {
	e, sleeps, err := sendOne(t, func(l *fake.Ledger) { l.Expire = 1 })
	if err != nil || e.ledger.Submitted != 2 || accountSets(e.ledger) != 1 {
		t.Fatalf("err %v, submitted %d, on ledger %d", err, e.ledger.Submitted, accountSets(e.ledger))
	}
	if len(sleeps) != 2 {
		t.Fatalf("sleeps %v; want one poll for the expired attempt and one for the new one", sleeps)
	}
}

func TestSendFeeAndLastLedger(t *testing.T) {
	e, _, err := sendOne(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	tx := e.ledger.LastSubmitted
	if tx.FeeDrops != e.ledger.Fee || tx.LastLedgerSequence != 1000+20 {
		t.Fatalf("fee %d, LastLedgerSequence %d; want %d and 1020", tx.FeeDrops, tx.LastLedgerSequence, e.ledger.Fee)
	}
}

// The reserve plus one fee is enough; one drop less is refused unsent.
func TestSendReserveBoundary(t *testing.T) {
	for _, tc := range []struct {
		less uint64
		ok   bool
	}{{0, true}, {1, false}} {
		e, _, err := sendOne(t, func(l *fake.Ledger) {
			for _, a := range l.Accounts {
				a.BalanceDrops = 1_200_000 + l.Fee - tc.less
			}
		})
		if tc.ok && err != nil {
			t.Fatalf("exact balance: %v", err)
		}
		if !tc.ok && (err == nil || !strings.Contains(err.Error(), "needs the 1.2 XRP reserve plus fees") || e.ledger.Submitted != 0) {
			t.Fatalf("one drop short: err %v, submitted %d", err, e.ledger.Submitted)
		}
	}
}
