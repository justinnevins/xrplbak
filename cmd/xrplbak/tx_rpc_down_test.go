package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A server that answers account_tx and ledger_entry but fails every tx
// call is a network problem, not an authentication one. A script that
// retries on exit 2 must see exit 2, and one that alarms on exit 4 must
// not.

// ledgerServer serves the world's fake ledger over JSON-RPC. With failTx
// the tx method answers HTTP 500.
func ledgerServer(w *world, failTx bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string           `json:"method"`
			Params []map[string]any `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		p := req.Params[0]
		res := map[string]any{"status": "success"}
		switch req.Method {
		case "tx":
			if failTx {
				rw.WriteHeader(http.StatusInternalServerError)
				return
			}
			rec, err := w.ledger.Tx(p["transaction"].(string))
			if err != nil {
				res = map[string]any{"status": "error", "error": "txnNotFound"}
				break
			}
			var body map[string]any
			json.Unmarshal(rec.Raw, &body)
			for k, v := range body {
				res[k] = v
			}
			res["meta"] = map[string]any{"TransactionResult": rec.Result}
			res["validated"] = true
		case "account_tx":
			txs, rng, _ := w.ledger.AccountTx(p["account"].(string))
			var list []map[string]any
			for _, t := range txs {
				var body map[string]any
				json.Unmarshal(t.Raw, &body)
				list = append(list, map[string]any{"tx": body, "meta": map[string]any{"TransactionResult": t.Result}, "validated": true})
			}
			res["transactions"] = list
			res["ledger_index_min"] = rng.Min
			res["ledger_index_max"] = rng.Max
		case "ledger_entry":
			d, err := w.ledger.LedgerEntryDID(p["did"].(string))
			if err != nil {
				res = map[string]any{"status": "error", "error": "entryNotFound"}
			} else {
				res["node"] = map[string]any{"Data": strings.ToUpper(hex.EncodeToString(d))}
			}
		}
		json.NewEncoder(rw).Encode(map[string]any{"result": res})
	}))
}

func TestChunkFetchFailureExitsAsNetwork(t *testing.T) {
	w := newWorld(t, 63)
	srv := ledgerServer(w, true)
	defer srv.Close()
	r := w.run("", "verify", "--rpc", srv.URL, "--words-file", w.words, "--account", w.writer.Address())
	if r.code != exitNetwork {
		t.Fatalf("verify exit %d, want %d (network)", r.code, exitNetwork)
	}
	r = w.run("", "restore", "--rpc", srv.URL, "--words-file", w.words, "--account", w.writer.Address(), "--bundle", w.bundle)
	if r.code != exitNetwork {
		t.Fatalf("restore exit %d, want %d (network)", r.code, exitNetwork)
	}
}

func TestChunkFetchOverRPCControl(t *testing.T) {
	w := newWorld(t, 63)
	srv := ledgerServer(w, false)
	defer srv.Close()
	r := w.run("", "verify", "--rpc", srv.URL, "--words-file", w.words, "--account", w.writer.Address(), "--bundle", w.bundle)
	if r.code != exitOK {
		t.Fatalf("verify over the same server with tx working: exit %d", r.code)
	}
}
