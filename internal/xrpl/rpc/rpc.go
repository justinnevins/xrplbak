// Package rpc is the only network code in xrplbak. It speaks JSON-RPC over
// HTTP(S) to the one server URL the operator passes on the command line.
package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/justinnevins/xrplbak/internal/xrpl"
)

// Client talks to one xrpld/rippled JSON-RPC endpoint.
type Client struct {
	URL  string
	HTTP *http.Client
}

// New builds a client with a 30 second timeout.
func New(url string) *Client {
	return &Client{URL: url, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
}

func (c *Client) call(method string, params map[string]any) (map[string]json.RawMessage, error) {
	if params == nil {
		params = map[string]any{}
	}
	body, err := json.Marshal(map[string]any{"method": method, "params": []any{params}})
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Post(c.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("rpc %s: %w", method, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("rpc %s: HTTP %d", method, resp.StatusCode)
	}
	var r rpcResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("rpc %s: bad JSON: %w", method, err)
	}
	var res map[string]json.RawMessage
	if err := json.Unmarshal(r.Result, &res); err != nil {
		return nil, fmt.Errorf("rpc %s: bad result: %w", method, err)
	}
	var status string
	_ = json.Unmarshal(res["status"], &status)
	if status == "error" {
		var e string
		_ = json.Unmarshal(res["error"], &e)
		if e == "txnNotFound" || e == "entryNotFound" || e == "actNotFound" {
			return res, xrpl.ErrNotFound
		}
		var msg string
		_ = json.Unmarshal(res["error_message"], &msg)
		return nil, fmt.Errorf("rpc %s: %s %s", method, e, msg)
	}
	return res, nil
}

// Submit sends a signed blob and returns the engine result code.
func (c *Client) Submit(blob []byte) (string, error) {
	res, err := c.call("submit", map[string]any{"tx_blob": strings.ToUpper(hex.EncodeToString(blob))})
	if err != nil {
		return "", err
	}
	var code string
	_ = json.Unmarshal(res["engine_result"], &code)
	if code == "" {
		return "", errors.New("submit: no engine_result in response")
	}
	return code, nil
}

// Tx fetches one transaction by hash.
func (c *Client) Tx(hash string) (*xrpl.TxRecord, error) {
	res, err := c.call("tx", map[string]any{"transaction": hash})
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(res)
	rec, err := xrpl.ParseTxJSON(raw, res["meta"])
	if err != nil {
		return nil, err
	}
	if rec.Hash == "" {
		rec.Hash = hash
	}
	return rec, nil
}

// maxAccountTxPages bounds a misbehaving server: 5000 pages of 200 is one
// million transactions, far beyond any writer account.
const maxAccountTxPages = 5000

// AccountTx pages through the whole validated history the server holds.
func (c *Client) AccountTx(account string) ([]xrpl.TxRecord, xrpl.Range, error) {
	var out []xrpl.TxRecord
	rng := xrpl.Range{Min: -1, Max: -1}
	var marker json.RawMessage
	for page := 0; ; page++ {
		if page >= maxAccountTxPages {
			return nil, rng, fmt.Errorf("account_tx: more than %d pages; the server keeps paging without end", maxAccountTxPages)
		}
		params := map[string]any{"account": account, "ledger_index_min": -1, "ledger_index_max": -1, "forward": true, "limit": 200}
		if marker != nil {
			params["marker"] = marker
		}
		res, err := c.call("account_tx", params)
		if err != nil {
			return nil, rng, err
		}
		var lo, hi int64
		_ = json.Unmarshal(res["ledger_index_min"], &lo)
		_ = json.Unmarshal(res["ledger_index_max"], &hi)
		if rng.Min < 0 || lo < rng.Min {
			rng.Min = lo
		}
		if hi > rng.Max {
			rng.Max = hi
		}
		var txs []struct {
			Tx        json.RawMessage `json:"tx"`
			TxJSON    json.RawMessage `json:"tx_json"`
			Meta      json.RawMessage `json:"meta"`
			Validated bool            `json:"validated"`
			Hash      string          `json:"hash"`
			Ledger    uint32          `json:"ledger_index"`
		}
		if err := json.Unmarshal(res["transactions"], &txs); err != nil {
			return nil, rng, fmt.Errorf("account_tx: bad transactions: %w", err)
		}
		for _, t := range txs {
			raw := t.Tx
			if raw == nil {
				raw = t.TxJSON
			}
			rec, err := xrpl.ParseTxJSON(raw, t.Meta)
			if err != nil {
				continue
			}
			rec.Validated = t.Validated
			if rec.Hash == "" {
				rec.Hash = t.Hash
			}
			if rec.LedgerIndex == 0 {
				rec.LedgerIndex = t.Ledger
			}
			if rec.Validated {
				out = append(out, *rec)
			}
		}
		marker = res["marker"]
		if marker == nil || string(marker) == "null" {
			return out, rng, nil
		}
	}
}

// LedgerEntryDID reads the DID entry's Data field from the validated ledger.
func (c *Client) LedgerEntryDID(account string) ([]byte, error) {
	res, err := c.call("ledger_entry", map[string]any{"did": account, "ledger_index": "validated"})
	if err != nil {
		return nil, err
	}
	var node struct {
		Data string `json:"Data"`
	}
	if err := json.Unmarshal(res["node"], &node); err != nil {
		return nil, fmt.Errorf("ledger_entry: bad node: %w", err)
	}
	if node.Data == "" {
		return nil, xrpl.ErrNotFound
	}
	return hex.DecodeString(node.Data)
}

// AccountInfo returns sequence and balance from the validated ledger.
func (c *Client) AccountInfo(account string) (*xrpl.AccountState, error) {
	res, err := c.call("account_info", map[string]any{"account": account, "ledger_index": "validated"})
	if err != nil {
		return nil, err
	}
	var data struct {
		Sequence uint32 `json:"Sequence"`
		Balance  string `json:"Balance"`
	}
	if err := json.Unmarshal(res["account_data"], &data); err != nil {
		return nil, fmt.Errorf("account_info: bad account_data: %w", err)
	}
	var bal uint64
	fmt.Sscanf(data.Balance, "%d", &bal)
	return &xrpl.AccountState{Sequence: data.Sequence, BalanceDrops: bal}, nil
}

// ServerInfo returns the validated ledger, history range, and fees.
func (c *Client) ServerInfo() (*xrpl.ServerState, error) {
	res, err := c.call("server_info", nil)
	if err != nil {
		return nil, err
	}
	var info struct {
		Info struct {
			CompleteLedgers string `json:"complete_ledgers"`
			ValidatedLedger struct {
				Seq     uint32  `json:"seq"`
				BaseFee float64 `json:"base_fee_xrp"`
			} `json:"validated_ledger"`
		} `json:"info"`
	}
	raw, _ := json.Marshal(res)
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, err
	}
	st := &xrpl.ServerState{ValidatedLedger: info.Info.ValidatedLedger.Seq, CompleteLedgers: info.Info.CompleteLedgers}
	st.BaseFeeDrops = uint64(info.Info.ValidatedLedger.BaseFee*1_000_000 + 0.5)
	if st.BaseFeeDrops == 0 {
		st.BaseFeeDrops = 10
	}
	st.OpenLedgerFee = st.BaseFeeDrops
	if fee, err := c.call("fee", nil); err == nil {
		var d struct {
			OpenLedgerFee string `json:"open_ledger_fee"`
		}
		_ = json.Unmarshal(fee["drops"], &d)
		var v uint64
		if _, err := fmt.Sscanf(d.OpenLedgerFee, "%d", &v); err == nil && v > 0 {
			st.OpenLedgerFee = v
		}
	}
	return st, nil
}
