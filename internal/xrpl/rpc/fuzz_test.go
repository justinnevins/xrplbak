package rpc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/xrpl"
)

// rpcSeeds are rippled-shaped and rippled-malformed responses. The operator
// names the server on the command line, so every byte here is chosen by
// whoever runs that endpoint.
var rpcSeeds = []string{
	``,
	`{}`,
	`null`,
	`{"result":null}`,
	`{"result":{}}`,
	`{"result":{"status":"success"}}`,
	`{"result":{"status":"error","error":"txnNotFound"}}`,
	// rippled reports some failures without a status field.
	`{"result":{"error":"lgrNotFound","error_message":"ledgerNotFound"}}`,
	`{"result":{"error":"amendmentBlocked"}}`,
	`{"result":{"status":"success","info":{}}}`,
	`{"result":{"status":"success","info":{"validated_ledger":{"seq":0,"base_fee_xrp":0}}}}`,
	`{"result":{"status":"success","info":{"validated_ledger":{"seq":90,"base_fee_xrp":0.00001},"complete_ledgers":"1-90"}}}`,
	`{"result":{"status":"success","info":{"validated_ledger":{"seq":90,"base_fee_xrp":-1}}}}`,
	`{"result":{"status":"success","info":{"validated_ledger":{"seq":90,"base_fee_xrp":1e308}}}}`,
	`{"result":{"status":"success","node":{"Data":""}}}`,
	`{"result":{"status":"success","node":{"Data":"zz"}}}`,
	`{"result":{"status":"success","node":{"Data":"ABC"}}}`,
	`{"result":{"status":"success","account_data":{"Sequence":1,"Balance":"5000000"}}}`,
	`{"result":{"status":"success","account_data":{"Sequence":1,"Balance":"-1"}}}`,
	`{"result":{"status":"success","transactions":[],"ledger_index_min":1,"ledger_index_max":9}}`,
	`{"result":{"status":"success","transactions":[{"validated":true,"hash":"AA","tx":{"Account":"r1"}}]}}`,
	`{"result":{"status":"success","transactions":[{"validated":true}],"marker":{"a":1}}}`,
	`{"result":{"status":"success","engine_result":"tesSUCCESS"}}`,
	`{"result":{"status":"success","engine_result":""}}`,
	`{"result":{"status":"success","drops":{"open_ledger_fee":"999999999999999999999"}}}`,
}

// One server and one transport for the whole worker process. A server per
// iteration exhausts ephemeral ports within a minute of fuzzing, and the
// listener failure that follows looks like a counterexample when it is not.
var (
	srvOnce sync.Once
	srv     *httptest.Server
	srvBody atomic.Pointer[string]
	srvHTTP = &http.Client{Timeout: 5 * time.Second}
)

// canned answers every method with the same body.
func canned(t *testing.T, body string) *Client {
	t.Helper()
	srvOnce.Do(func() {
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if b := srvBody.Load(); b != nil {
				_, _ = w.Write([]byte(*b))
			}
		}))
	})
	srvBody.Store(&body)
	return &Client{URL: srv.URL, HTTP: srvHTTP}
}

// FuzzResponseParsingNoPanic asserts that no server response makes a method
// panic or hand back a result alongside an error.
func FuzzResponseParsingNoPanic(f *testing.F) {
	for _, s := range rpcSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		c := canned(t, body)

		if rec, err := c.Tx("AA"); err != nil && rec != nil {
			t.Fatalf("Tx returned a record alongside error %v", err)
		}
		if st, err := c.AccountInfo("r1"); err != nil && st != nil {
			t.Fatalf("AccountInfo returned state alongside error %v", err)
		}
		if st, err := c.ServerInfo(); err != nil && st != nil {
			t.Fatalf("ServerInfo returned state alongside error %v", err)
		}
		if recs, _, err := c.AccountTx("r1"); err != nil && recs != nil {
			t.Fatalf("AccountTx returned %d records alongside error %v", len(recs), err)
		}
		if data, err := c.LedgerEntryDID("r1"); err != nil && data != nil {
			t.Fatalf("LedgerEntryDID returned %d bytes alongside error %v", len(data), err)
		}
		if code, err := c.Submit([]byte{1}); err != nil && code != "" {
			t.Fatalf("Submit returned %q alongside error %v", code, err)
		}
	})
}

// FuzzServerInfoRefusesEmptyAnswer asserts that ServerInfo fails closed. It
// is the only method whose fields all have usable zero values, so a response
// that carries no server info at all would otherwise be reported as success
// with a validated ledger of 0. backup turns that into
// LastLedgerSequence = 20, which every submit then rejects for a reason that
// points at the wrong thing.
func FuzzServerInfoRefusesEmptyAnswer(f *testing.F) {
	for _, s := range rpcSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		st, err := canned(t, body).ServerInfo()
		if err != nil {
			return
		}
		if st.ValidatedLedger == 0 {
			t.Fatalf("ServerInfo reported success with no validated ledger for %q", body)
		}
	})
}

// FuzzErrorResultIsNeverSuccess asserts that a result object carrying an
// error key is never read as an answer, whether or not the server also sent
// the status field rippled normally sends.
func FuzzErrorResultIsNeverSuccess(f *testing.F) {
	for _, s := range rpcSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		var probe struct {
			Result map[string]json.RawMessage `json:"result"`
		}
		if json.Unmarshal([]byte(body), &probe) != nil || probe.Result == nil {
			return
		}
		if _, hasErr := probe.Result["error"]; !hasErr {
			return
		}
		c := canned(t, body)
		for name, call := range map[string]func() error{
			"tx":            func() error { _, e := c.Tx("AA"); return e },
			"account_info":  func() error { _, e := c.AccountInfo("r1"); return e },
			"server_info":   func() error { _, e := c.ServerInfo(); return e },
			"ledger_entry":  func() error { _, e := c.LedgerEntryDID("r1"); return e },
			"account_tx":    func() error { _, _, e := c.AccountTx("r1"); return e },
			"submit_method": func() error { _, e := c.Submit([]byte{1}); return e },
		} {
			if err := call(); err == nil {
				t.Fatalf("%s reported success for an error result: %q", name, body)
			}
		}
	})
}

// FuzzFeeIsBounded asserts that a fee taken from the server is a number the
// caller can compare against its cap. An out-of-range float conversion is
// implementation defined in Go, so a negative or enormous base_fee_xrp must
// be refused at the parse, not turned into a uint64 nobody chose.
func FuzzFeeIsBounded(f *testing.F) {
	for _, s := range rpcSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		st, err := canned(t, body).ServerInfo()
		if err != nil {
			return
		}
		// One XRP in drops. No network has ever charged a base fee near this.
		const sane = 1_000_000
		if st.BaseFeeDrops > sane || st.OpenLedgerFee > sane {
			t.Fatalf("ServerInfo accepted base=%d open=%d drops from %q", st.BaseFeeDrops, st.OpenLedgerFee, body)
		}
	})
}

// FuzzNotFoundIsDistinct asserts that the three not-found errors stay
// distinguishable from every other failure, since discovery treats a missing
// anchor as "no backup yet" and anything else as a reason to stop.
func FuzzNotFoundIsDistinct(f *testing.F) {
	f.Add(`{"result":{"status":"error","error":"entryNotFound"}}`)
	f.Add(`{"result":{"status":"error","error":"actNotFound"}}`)
	f.Add(`{"result":{"status":"error","error":"txnNotFound"}}`)
	f.Add(`{"result":{"status":"error","error":"noNetwork"}}`)
	f.Fuzz(func(t *testing.T, body string) {
		c := canned(t, body)
		_, err := c.LedgerEntryDID("r1")
		if err == nil {
			return
		}
		// The key lookup is exact, the way call() reads it. Unmarshalling
		// into a struct would match "erroR" as well, which JSON does not.
		var probe struct {
			Result map[string]json.RawMessage `json:"result"`
		}
		_ = json.Unmarshal([]byte(body), &probe)
		var code string
		_ = json.Unmarshal(probe.Result["error"], &code)
		notFound := code == "entryNotFound" || code == "actNotFound" || code == "txnNotFound"
		if got := errorsIsNotFound(err); got != notFound {
			t.Fatalf("error %q: ErrNotFound=%v, want %v", code, got, notFound)
		}
	})
}

func errorsIsNotFound(err error) bool {
	for e := err; e != nil; {
		if e == xrpl.ErrNotFound {
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}
