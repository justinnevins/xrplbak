package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/backup"
	"github.com/justinnevins/xrplbak/internal/chunk"
	"github.com/justinnevins/xrplbak/internal/discover"
)

// TestFetchFailMapsEachKind pins the one mapping from a discover.Fetch
// error to an exit code: a missing chunk is incomplete (5), a network
// failure is a network error (2), anything else failed authentication
// (4). The prefix starts the message of the first and last, and a
// network error is reported as it is. Each kind is also tried wrapped.
func TestFetchFailMapsEachKind(t *testing.T) {
	missing := &chunk.MissingError{Kind: "chunk", Index: 0, Total: 2, Account: "rX", MinLgr: 1, MaxLgr: 9}
	network := &discover.NetworkError{Op: "tx ABC", Err: errors.New("connection refused")}
	other := errors.New("manifest does not authenticate")
	for _, tc := range []struct {
		err  error
		code int
		msg  string
	}{
		{missing, exitIncomplete, "P: " + missing.Error()},
		{fmt.Errorf("fetch: %w", missing), exitIncomplete, "P: fetch: " + missing.Error()},
		{network, exitNetwork, network.Error()},
		{fmt.Errorf("fetch: %w", network), exitNetwork, "fetch: " + network.Error()},
		{other, exitAuth, "P: " + other.Error()},
	} {
		got := fetchFail(tc.err, "P: ")
		if c := exitCode(got); c != tc.code || got.Error() != tc.msg {
			t.Errorf("fetchFail(%v): exit %d %q, want exit %d %q", tc.err, c, got.Error(), tc.code, tc.msg)
		}
	}
}

// TestReadBackFailureSaysReadBack pins the read-back's own prefix on a
// missing chunk, so the operator sees which step failed.
func TestReadBackFailureSaysReadBack(t *testing.T) {
	noSleep(t)
	w := newWorld(t, 53)
	w.ledger.Batch = true
	holey := &holeyLedger{Ledger: w.ledger, before: len(w.ledger.Txs)}
	o := backup.Options{ConfigPath: w.cfgPath, ValidatorsPath: w.valPath, Key: w.key, Seq: 2}
	_, err := captureStdout(t, func() error {
		return doSubmit(o, holey, "fake", w.writer, t.TempDir(), 0, false, true, "auto", "", "", nil, nil, "", "testnet", w.keyFile, submitExtras{ReadBack: true})
	})
	if err == nil || !strings.HasPrefix(err.Error(), "read-back FAILED: ") || exitCode(err) != exitIncomplete {
		t.Fatalf("err %v (exit %d); want exit %d starting \"read-back FAILED: \"", err, exitCode(err), exitIncomplete)
	}
}
