package backup

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/xrpl"
)

type otherDID struct{ xrpl.Client }

func (otherDID) LedgerEntryDID(string) ([]byte, error) {
	return []byte("not the anchor this run sent"), nil
}

// After a batched submit the dump took whatever the server said the
// anchor was. A different anchor went into the dump, the offline restore
// source, and the run reported success.
func TestBatchedSubmitChecksTheAnchorItReadsBack(t *testing.T) {
	e := newEnv(t)
	e.ledger.Batch = true
	p, err := Build(e.opts(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	s := &Submitter{Client: otherDID{e.ledger}, Writer: e.writer, Key: e.key, Batch: true, Sleep: func(time.Duration) {}, DumpOut: filepath.Join(e.dir, "d.json")}
	if err := s.Submit(p); err == nil {
		t.Fatalf("Submit succeeded; the dump holds anchor %q", s.Dump.DID.Data)
	}
}
