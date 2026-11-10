package rpc

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// F-074: AccountTx ignored a parse failure on ledger_index_min and
// ledger_index_max. An answer without them became the range 0 to 0, and
// every "searched ledgers X to Y" message downstream named a range no
// server had searched.
func TestF074AccountTxRefusesAnAnswerWithoutARange(t *testing.T) {
	for name, body := range map[string]string{
		"both absent": `{"status":"success","transactions":[]}`,
		"min absent":  `{"status":"success","transactions":[],"ledger_index_max":9}`,
		"max absent":  `{"status":"success","transactions":[],"ledger_index_min":1}`,
		"min null":    `{"status":"success","transactions":[],"ledger_index_min":null,"ledger_index_max":9}`,
		"max null":    `{"status":"success","transactions":[],"ledger_index_min":1,"ledger_index_max":null}`,
		"min string":  `{"status":"success","transactions":[],"ledger_index_min":"1","ledger_index_max":9}`,
		"max object":  `{"status":"success","transactions":[],"ledger_index_min":1,"ledger_index_max":{}}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body)
			io.WriteString(w, `{"result":`+body+`}`)
		}))
		txs, rng, err := New(srv.URL).AccountTx("rExample")
		srv.Close()
		if err == nil {
			t.Errorf("%s: no error; AccountTx reported ledgers %d to %d and %d transactions", name, rng.Min, rng.Max, len(txs))
			continue
		}
		if !strings.Contains(err.Error(), "ledger_index_m") {
			t.Errorf("%s: the error does not name the field: %v", name, err)
		}
	}

	// A complete answer still works and reports the server's own range.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, `{"result":{"status":"success","transactions":[],"ledger_index_min":7,"ledger_index_max":9}}`)
	}))
	defer srv.Close()
	_, rng, err := New(srv.URL).AccountTx("rExample")
	if err != nil || rng.Min != 7 || rng.Max != 9 {
		t.Fatalf("complete answer: range %d to %d, err %v; want 7 to 9", rng.Min, rng.Max, err)
	}
}
