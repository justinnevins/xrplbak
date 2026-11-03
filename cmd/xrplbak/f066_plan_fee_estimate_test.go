package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/backup"
)

// feesPaid sums the Fee field over the transactions the fake recorded from
// index from on (newWorld itself submits a first backup).
func feesPaid(w *world, from int) (n int, total uint64) {
	for _, tx := range w.ledger.Txs[from:] {
		var raw struct{ Fee uint64 }
		_ = json.Unmarshal(tx.Raw, &raw)
		n++
		total += raw.Fee
	}
	return
}

// planFor builds a plan whose manifest needs more than one part: the config
// spans chunks and the includes have long basenames.
func planFor(t *testing.T, w *world, batch bool) *backup.Plan {
	t.Helper()
	var incs []string
	for i := 0; i < 20; i++ {
		p := filepath.Join(w.dir, fmt.Sprintf("include-with-a-long-descriptive-basename-to-grow-the-manifest-%03d.conf", i))
		must(t, os.WriteFile(p, []byte("v=1\n"), 0o600))
		incs = append(incs, p)
	}
	p, err := backup.Build(backup.Options{ConfigPath: w.cfgPath, ValidatorsPath: w.valPath, Includes: incs, Key: w.key, Now: time.Unix(1_800_000_000, 0), Seq: 1})
	must(t, err)
	return p
}

// F-066. The plan report's fee estimate must cover what the run pays at the
// base rate: one transaction per chunk, per manifest part and for the
// anchor, and in batch mode (inner + 2) times the rate for the one Batch.
// The part count is projected with the chunk tx fields at their longest,
// so the sealed manifest may need one part fewer, never more: the estimate
// is a ceiling within a few base fees of the truth. Before the fix the
// report said (chunks + 2) * 10, which counts the manifest as a single
// transaction and knows nothing about batching.
func TestF066PlanFeeEstimateMatchesFeesPaid(t *testing.T) {
	for _, batch := range []bool{false, true} {
		w := newWorld(t, 21)
		w.ledger.Batch = batch
		p := planFor(t, w, batch)

		var buf bytes.Buffer
		old := stdout
		stdout = &buf
		planReport(p, backup.Options{})
		stdout = old

		seq := regexp.MustCompile(`up to (\d+) drops`).FindStringSubmatch(buf.String())
		bat := regexp.MustCompile(`(\d+) drops with --batch`).FindStringSubmatch(buf.String())
		if seq == nil || bat == nil {
			t.Fatalf("report lacks the sequential or the batch estimate:\n%s", buf.String())
		}
		est, _ := strconv.ParseUint(seq[1], 10, 64)
		if batch {
			est, _ = strconv.ParseUint(bat[1], 10, 64)
		}
		before := len(w.ledger.Txs)

		s := &backup.Submitter{Client: w.ledger, Writer: w.writer, Key: w.key, Sleep: func(time.Duration) {}, Batch: batch}
		must(t, s.Submit(p))
		n, paid := feesPaid(w, before)
		t.Logf("batch=%v: estimate %d drops, %d transactions, %d drops paid (%d chunks)", batch, est, n, paid, len(p.Chunks))
		// One projected part fewer at sealing time costs at most one
		// transaction sequentially; batched it can also merge two
		// groups, so allow three base fees of slack, never an underrun.
		if paid > est || est-paid > 30 {
			t.Fatalf("batch=%v: report estimates %d drops, the run paid %d (%d chunks, %d transactions)\n%s", batch, est, paid, len(p.Chunks), n, buf.String())
		}
	}
}
