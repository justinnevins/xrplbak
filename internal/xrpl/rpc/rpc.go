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
	"math"
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
	// rippled normally marks a failure with status "error", but an
	// intermediary or a non-rippled endpoint can answer with the error field
	// alone. An answer carrying an error is never read as an answer.
	var status string
	_ = json.Unmarshal(res["status"], &status)
	_, hasError := res["error"]
	if status == "error" || hasError {
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

// AmendmentEnabled asks the feature RPC about one amendment. A server that
// does not know the id, or refuses the call, answers with an error, which
// the caller reads as "not enabled".
func (c *Client) AmendmentEnabled(id string) (bool, error) {
	res, err := c.call("feature", map[string]any{"feature": id})
	if err != nil {
		return false, err
	}
	// The answer is keyed by the amendment id: {"<id>": {"enabled": bool, ...}}.
	var f struct {
		Enabled *bool `json:"enabled"`
	}
	raw, ok := res[id]
	if !ok {
		raw, ok = res[strings.ToUpper(id)]
	}
	if !ok {
		return false, fmt.Errorf("rpc feature: no entry for %s", id)
	}
	if err := json.Unmarshal(raw, &f); err != nil || f.Enabled == nil {
		return false, fmt.Errorf("rpc feature: entry for %s has no enabled field", id)
	}
	return *f.Enabled, nil
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
	// hex.DecodeString hands back the prefix it managed to decode next to
	// its error. A truncated anchor is not an anchor, so nothing is returned.
	b, err := hex.DecodeString(node.Data)
	if err != nil {
		return nil, fmt.Errorf("ledger_entry: anchor Data is not hex: %w", err)
	}
	return b, nil
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
	// Every other method has a required field whose absence is an error.
	// ServerInfo's fields all have usable zero values, so without this it
	// would report success for a response carrying no server info at all,
	// and backup would build LastLedgerSequence from a validated ledger of 0.
	if info.Info.ValidatedLedger.Seq == 0 {
		return nil, errors.New("server_info: the response carries no validated ledger")
	}
	st := &xrpl.ServerState{ValidatedLedger: info.Info.ValidatedLedger.Seq, CompleteLedgers: info.Info.CompleteLedgers}
	base, err := feeDrops(info.Info.ValidatedLedger.BaseFee)
	if err != nil {
		return nil, fmt.Errorf("server_info: base_fee_xrp: %w", err)
	}
	st.BaseFeeDrops = base
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
			if v > MaxSaneFeeDrops {
				return nil, fmt.Errorf("fee: open_ledger_fee is %d drops, above the %d drop sanity bound", v, MaxSaneFeeDrops)
			}
			st.OpenLedgerFee = v
		}
	}
	return st, nil
}

// MaxSaneFeeDrops is one XRP. No network has charged a base fee near it, and
// a server reporting more is refused rather than handed on: the caller's own
// --max-fee cap is a policy choice and this is a parse bound.
const MaxSaneFeeDrops = 1_000_000

// feeDrops converts base_fee_xrp to drops. Converting an out-of-range float
// to uint64 is implementation defined in Go, so the range is checked first
// rather than being discovered as a number nobody chose.
func feeDrops(xrp float64) (uint64, error) {
	if math.IsNaN(xrp) || math.IsInf(xrp, 0) {
		return 0, errors.New("not a number")
	}
	if xrp < 0 {
		return 0, fmt.Errorf("negative (%g)", xrp)
	}
	drops := xrp*1_000_000 + 0.5
	if drops > MaxSaneFeeDrops {
		return 0, fmt.Errorf("%g XRP is above the %d drop sanity bound", xrp, MaxSaneFeeDrops)
	}
	return uint64(drops), nil
}
