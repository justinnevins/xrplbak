package backup

import (
	"strings"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/xrpl"
	"github.com/justinnevins/xrplbak/internal/xrpl/fake"
)

// spikyLedger reports a high open-ledger fee for the first `high` reads of
// server_info, then the base fee. It is the 2026-11-07 Mainnet run in
// miniature: a 5063 drop fee for a moment, then 10 drops again.
type spikyLedger struct {
	*fake.Ledger
	high  int
	reads int
}

func (s *spikyLedger) ServerInfo() (*xrpl.ServerState, error) {
	s.reads++
	if s.reads <= s.high {
		s.Ledger.Fee = 5063
	} else {
		s.Ledger.Fee = 10
	}
	return s.Ledger.ServerInfo()
}

// TestFeeWaitOutlastsASpike pins that a fee above the cap is waited out,
// for both the batched and the one-at-a-time path, and that nothing is
// submitted while the fee is above the cap.
func TestFeeWaitOutlastsASpike(t *testing.T) {
	for _, batch := range []bool{true, false} {
		e := newEnv(t)
		e.ledger.Batch = batch
		p, err := Build(e.opts(t, 1))
		if err != nil {
			t.Fatal(err)
		}
		spiky := &spikyLedger{Ledger: e.ledger, high: 3}
		var slept time.Duration
		var log strings.Builder
		s := &Submitter{Client: spiky, Writer: e.writer, Key: e.key, MaxFee: 100, Batch: batch,
			FeeWait: 10 * time.Minute,
			Sleep:   func(d time.Duration) { slept += d },
			Log:     func(f string, a ...any) { log.WriteString(f + "\n") }}
		if err := s.Submit(p); err != nil {
			t.Fatalf("batch=%v: a spike shorter than --fee-wait must be waited out: %v", batch, err)
		}
		if slept < 3*FeePoll {
			t.Errorf("batch=%v: slept %v, want at least 3 polls of %v", batch, slept, FeePoll)
		}
		if !strings.Contains(log.String(), "waiting") {
			t.Errorf("batch=%v: the wait must be logged:\n%s", batch, log.String())
		}
	}
}

// TestFeeWaitGivesUpAndSubmitsNothing pins that a spike longer than
// --fee-wait still refuses, with nothing submitted, and that a zero wait
// refuses at once, as before v1.1.7.
func TestFeeWaitGivesUpAndSubmitsNothing(t *testing.T) {
	for _, wait := range []time.Duration{0, 2 * time.Minute} {
		e := newEnv(t)
		e.ledger.Batch = true
		p, err := Build(e.opts(t, 1))
		if err != nil {
			t.Fatal(err)
		}
		spiky := &spikyLedger{Ledger: e.ledger, high: 1 << 30}
		var slept time.Duration
		s := &Submitter{Client: spiky, Writer: e.writer, Key: e.key, MaxFee: 100, Batch: true,
			FeeWait: wait, Sleep: func(d time.Duration) { slept += d }}
		err = s.Submit(p)
		if err == nil || !strings.Contains(err.Error(), "above the 100 drop cap") {
			t.Fatalf("wait %v: want a fee cap refusal, got %v", wait, err)
		}
		if e.ledger.Submitted != 0 {
			t.Errorf("wait %v: %d submit(s) reached the ledger while the fee was above the cap", wait, e.ledger.Submitted)
		}
		if slept > wait {
			t.Errorf("wait %v: slept %v, longer than the limit", wait, slept)
		}
		if wait == 0 && slept != 0 {
			t.Errorf("--fee-wait 0 must refuse at once, slept %v", slept)
		}
	}
}
