package rpc

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/xrpl"
)

func answering(t *testing.T, body string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, `{"result":`+body+`}`)
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL)
}

// An answer about another transaction was accepted as the answer to the
// hash that was asked for.
func TestTxRefusesAnAnswerAboutAnotherTransaction(t *testing.T) {
	const tx = `"validated":true,"Account":"rWriter","TransactionType":"AccountSet","meta":{"TransactionResult":"tesSUCCESS"}`
	if rec, err := answering(t, `{"status":"success","hash":"BBBB",`+tx+`}`).Tx("AAAA"); err == nil {
		t.Errorf("asked for AAAA, accepted an answer for %s", rec.Hash)
	}
	for _, body := range []string{`{"status":"success","hash":"aaaa",` + tx + `}`, `{"status":"success",` + tx + `}`} {
		rec, err := answering(t, body).Tx("AAAA")
		if err != nil || !strings.EqualFold(rec.Hash, "AAAA") {
			t.Errorf("%s: a matching or absent hash was refused: %v", body, err)
		}
	}
}

// account_info without a Sequence became sequence 0, which the tool then
// signed with.
func TestAccountInfoNeedsASequence(t *testing.T) {
	if st, err := answering(t, `{"status":"success","account_data":{"Balance":"5000000"}}`).AccountInfo("rExample"); err == nil {
		t.Errorf("no Sequence in the answer, got %+v", st)
	}
	st, err := answering(t, `{"status":"success","account_data":{"Balance":"5000000","Sequence":7}}`).AccountInfo("rExample")
	if err != nil || st.Sequence != 7 {
		t.Errorf("a full answer: %+v %v", st, err)
	}
}

// A transaction entry the tool cannot read was skipped, so a damaged
// answer read as "nothing found in ledgers 1 to 9".
func TestAccountTxRefusesAnEntryItCannotRead(t *testing.T) {
	for name, entry := range map[string]string{
		"no tx":             `{"validated":true}`,
		"tx is a string":    `{"validated":true,"tx":"oops"}`,
		"memo is not hex":   `{"validated":true,"tx":{"Account":"r1","hash":"AA","Memos":[{"Memo":{"MemoData":"0102030G"}}]}}`,
		"memos not a list":  `{"validated":true,"tx":{"Account":"r1","hash":"AA","Memos":{"Memo":1}}}`,
		"memo type not hex": `{"validated":true,"tx":{"Account":"r1","hash":"AA","Memos":[{"Memo":{"MemoType":"zz","MemoData":"01"}}]}}`,
	} {
		txs, rng, err := answering(t, `{"status":"success","ledger_index_min":1,"ledger_index_max":9,"transactions":[`+entry+`]}`).AccountTx("r1")
		if err == nil {
			t.Errorf("%s: no error; %d transactions in ledgers %d to %d", name, len(txs), rng.Min, rng.Max)
		}
	}
	txs, _, err := answering(t, `{"status":"success","ledger_index_min":1,"ledger_index_max":9,"transactions":[{"validated":true,"tx":{"Account":"r1","hash":"AA","Memos":[{"Memo":{"MemoData":"0102"}}]}}]}`).AccountTx("r1")
	if err != nil || len(txs) != 1 || len(txs[0].Memos) != 1 {
		t.Errorf("a good entry: %v %v", txs, err)
	}
}

// Keys inside tx_json replaced the keys beside it, so an inner
// "validated" or "hash" won over the outer one.
func TestParseKeepsTheTwoLevelsApart(t *testing.T) {
	rec, err := xrpl.ParseTxJSON([]byte(`{"validated":false,"hash":"OUTER","tx_json":{"validated":true,"hash":"INNER","Account":"r1"}}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Validated || rec.Hash != "OUTER" || rec.Account != "r1" {
		t.Errorf("outer said validated=false hash=OUTER; got validated=%v hash=%s account=%s", rec.Validated, rec.Hash, rec.Account)
	}
}
