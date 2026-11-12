package rpc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// F-097. When the fee lookup failed, ServerInfo used the base fee without a
// word. The open ledger fee is what the fee-spike guard (--max-fee and
// --fee-wait) reads, so a failed lookup turned the guard off for the run.
// A failed fee lookup is now an error.
func TestF097FailedFeeLookupIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Method string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method == "fee" {
			_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"status": "error", "error": "tooBusy"}})
			return
		}
		res := map[string]any{"status": "success", "info": map[string]any{"complete_ledgers": "1-2", "validated_ledger": map[string]any{"seq": 5, "base_fee_xrp": 0.00001}}}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": res})
	}))
	defer srv.Close()
	st, err := New(srv.URL).ServerInfo()
	if err == nil {
		t.Fatalf("a failed fee lookup gave open ledger fee %d drops; want an error", st.OpenLedgerFee)
	}
	if !strings.Contains(err.Error(), "fee") {
		t.Errorf("the error does not name the fee lookup: %v", err)
	}
}
