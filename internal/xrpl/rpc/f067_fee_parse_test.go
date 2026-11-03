package rpc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// feeServer answers server_info and fee with the given raw values.
func feeServer(baseFeeXRP any, openLedgerFee any) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Method string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		res := map[string]any{"status": "success"}
		switch req.Method {
		case "server_info":
			res["info"] = map[string]any{"complete_ledgers": "1-2", "validated_ledger": map[string]any{"seq": 5, "base_fee_xrp": baseFeeXRP}}
		case "fee":
			d := map[string]any{}
			if openLedgerFee != nil {
				d["open_ledger_fee"] = openLedgerFee
			}
			res["drops"] = d
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": res})
	}))
}

// F-067. open_ledger_fee is a decimal string of drops. A value that is not
// one is refused, never read as a prefix ("1e6" is not 1 drop) and never
// silently replaced by the base fee. Before the fix Sscanf("%d") read "1e6"
// as 1 and fell back to base on anything it could not read at all.
func TestF067OpenLedgerFeeMalformedIsRefused(t *testing.T) {
	for _, open := range []string{"1e6", "1e3", "12abc", "-5", "0.00001", " 12", "12 ", "+12", "0x10", "18446744073709551616"} {
		srv := feeServer(0.00001, open)
		st, err := New(srv.URL).ServerInfo()
		srv.Close()
		if err == nil {
			t.Errorf("open_ledger_fee %q accepted as %d drops; want a refusal", open, st.OpenLedgerFee)
			continue
		}
		if !strings.Contains(err.Error(), "open_ledger_fee") {
			t.Errorf("open_ledger_fee %q: error does not name the field: %v", open, err)
		}
	}
}

// Well-formed values still read as the number meant, and a missing field
// (an older server) still falls back to the base fee.
func TestF067OpenLedgerFeeWellFormed(t *testing.T) {
	cases := []struct {
		open any
		want uint64
	}{
		{"12", 12},
		{"0", 10},              // zero is "no open ledger fee": base applies
		{"1000000", 1_000_000}, // exactly the sanity bound: accepted
		{nil, 10},              // field absent: base applies
	}
	for _, c := range cases {
		srv := feeServer(0.00001, c.open)
		st, err := New(srv.URL).ServerInfo()
		srv.Close()
		if err != nil {
			t.Errorf("open_ledger_fee %v: %v", c.open, err)
			continue
		}
		if st.OpenLedgerFee != c.want {
			t.Errorf("open_ledger_fee %v read as %d, want %d", c.open, st.OpenLedgerFee, c.want)
		}
	}
	srv := feeServer(0.00001, "1000001")
	defer srv.Close()
	if _, err := New(srv.URL).ServerInfo(); err == nil {
		t.Fatalf("open_ledger_fee one drop above the sanity bound was accepted")
	}
}

// F-067 companion. base_fee_xrp 1.0 is exactly 1,000,000 drops, the same
// bound open_ledger_fee "1000000" is allowed to reach. Before the fix the
// +0.5 rounding term was added before the compare, so 1.0 XRP was refused
// while "1000000" drops was accepted.
func TestF067BaseFeeBoundAgreesWithOpenFeeBound(t *testing.T) {
	srv := feeServer(1.0, "12")
	defer srv.Close()
	st, err := New(srv.URL).ServerInfo()
	if err != nil {
		t.Fatalf("base_fee_xrp 1.0 (exactly the 1000000 drop bound) refused: %v", err)
	}
	if st.BaseFeeDrops != 1_000_000 {
		t.Fatalf("base_fee_xrp 1.0 read as %d drops", st.BaseFeeDrops)
	}
	srv2 := feeServer(1.000001, "12")
	defer srv2.Close()
	if _, err := New(srv2.URL).ServerInfo(); err == nil {
		t.Fatalf("base_fee_xrp 1.000001 (one drop over the bound) accepted")
	}
}

// Same seam, same pattern: account_info Balance is a decimal string of
// drops. A malformed one is refused rather than read as 0 or as a prefix.
func TestF067AccountBalanceMalformedIsRefused(t *testing.T) {
	for _, bal := range []string{"1e6", "5abc", "-1", "", "18446744073709551616"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"status": "success", "account_data": map[string]any{"Sequence": 7, "Balance": bal}}})
		}))
		st, err := New(srv.URL).AccountInfo("rrrrrrrrrrrrrrrrrrrrrhoLvTp")
		srv.Close()
		if err == nil {
			t.Errorf("Balance %q accepted as %d drops; want a refusal", bal, st.BalanceDrops)
		}
	}
}
