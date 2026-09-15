package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/anchor"
	"github.com/justinnevins/xrplbak/internal/backup"
	"github.com/justinnevins/xrplbak/internal/crypto"
	"github.com/justinnevins/xrplbak/internal/discover"
	"github.com/justinnevins/xrplbak/internal/xrpl"
	"github.com/justinnevins/xrplbak/internal/xrpl/fake"
	"github.com/justinnevins/xrplbak/internal/xrpl/sign"
)

// serve wraps the fake ledger in a rippled-shaped JSON-RPC server so the
// real HTTP client and response parsing get exercised.
func serve(l *fake.Ledger) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string           `json:"method"`
			Params []map[string]any `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		p := map[string]any{}
		if len(req.Params) > 0 {
			p = req.Params[0]
		}
		res := map[string]any{"status": "success"}
		switch req.Method {
		case "submit":
			blob, _ := hex.DecodeString(p["tx_blob"].(string))
			code, err := l.Submit(blob)
			if err != nil {
				res = map[string]any{"status": "error", "error": "invalidTransaction"}
			} else {
				res["engine_result"] = code
			}
		case "tx":
			rec, err := l.Tx(p["transaction"].(string))
			if errors.Is(err, xrpl.ErrNotFound) {
				res = map[string]any{"status": "error", "error": "txnNotFound"}
			} else {
				var body map[string]any
				json.Unmarshal(rec.Raw, &body)
				for k, v := range body {
					res[k] = v
				}
				res["meta"] = map[string]any{"TransactionResult": rec.Result}
				res["validated"] = true
				res["ledger_index"] = rec.LedgerIndex
				res["hash"] = rec.Hash
			}
		case "account_tx":
			txs, rng, _ := l.AccountTx(p["account"].(string))
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
			d, err := l.LedgerEntryDID(p["did"].(string))
			if err != nil {
				res = map[string]any{"status": "error", "error": "entryNotFound"}
			} else {
				res["node"] = map[string]any{"Data": strings.ToUpper(hex.EncodeToString(d))}
			}
		case "account_info":
			a, err := l.AccountInfo(p["account"].(string))
			if err != nil {
				res = map[string]any{"status": "error", "error": "actNotFound"}
			} else {
				res["account_data"] = map[string]any{"Sequence": a.Sequence, "Balance": jsonNum(a.BalanceDrops)}
			}
		case "server_info":
			res["info"] = map[string]any{"complete_ledgers": "1000-2000", "validated_ledger": map[string]any{"seq": l.Seq, "base_fee_xrp": 0.00001}}
		case "fee":
			res["drops"] = map[string]any{"open_ledger_fee": "12"}
		}
		json.NewEncoder(w).Encode(map[string]any{"result": res})
	}))
}

func jsonNum(v uint64) string { return strconv.FormatUint(v, 10) }

func TestOverHTTP(t *testing.T) {
	l := fake.New()
	writer, _ := sign.KeyFromSeed(bytes.Repeat([]byte{9}, 16))
	l.Fund(writer.Address(), 3_000_000)
	srv := serve(l)
	defer srv.Close()
	c := New(srv.URL)

	st, err := c.ServerInfo()
	if err != nil || st.ValidatedLedger != 1000 || st.OpenLedgerFee != 12 {
		t.Fatalf("server_info %+v %v", st, err)
	}
	if _, err := c.AccountInfo("rrrrrrrrrrrrrrrrrrrrBZbvji"); !errors.Is(err, xrpl.ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
	if _, err := c.LedgerEntryDID(writer.Address()); !errors.Is(err, xrpl.ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}

	var root crypto.RootKey
	root[3] = 7
	kf := &crypto.KeyFile{Epoch: 0, Key: root.DeriveEpochKey(0)}
	copy(kf.AccountID[:], writer.AccountID())
	copy(kf.WriterSeed[:], writer.Seed())
	p, err := backup.Build(backup.Options{ConfigPath: "../../../tests/fixtures/validator-full.cfg", Key: kf, Seq: 1, Now: time.Unix(1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	s := &backup.Submitter{Client: c, Writer: writer, Key: kf, Sleep: func(time.Duration) {}}
	if err := s.Submit(p); err != nil {
		t.Fatal(err)
	}
	res, err := discover.Run(c, discover.RootKeys{Root: root}, writer.Address(), 0)
	if err != nil || res.Latest == nil || !res.AnchorOK {
		t.Fatalf("discover over http: %v %+v", err, res)
	}
	entries, err := discover.Fetch(c, discover.RootKeys{Root: root}, res, res.Latest)
	if err != nil || len(entries) != 1 {
		t.Fatal("fetch over http", err)
	}
	rec, _ := anchor.Parse(l.DID[writer.Address()])
	if rec.Seq != 1 {
		t.Fatal("anchor seq")
	}
	if len(s.Dump.Txs) < len(p.Chunks)+2 {
		t.Fatal("dump should hold chunks, manifest, and anchor")
	}
}
