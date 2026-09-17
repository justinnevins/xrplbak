// Package xrpl defines the small client interface the rest of the tool
// talks to. Two implementations exist: rpc (network) and dump (offline).
// Tests use a fake. Nothing outside internal/xrpl/rpc opens a socket.
package xrpl

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/justinnevins/xrplbak/internal/xrpl/codec"
)

// ErrNotFound means the server does not have that transaction or entry.
var ErrNotFound = errors.New("not found")

// TxRecord is a validated transaction as the tool needs it.
type TxRecord struct {
	Hash        string
	LedgerIndex uint32
	Validated   bool
	Result      string // meta TransactionResult, e.g. tesSUCCESS
	Account     string
	TxType      string
	Sequence    uint32
	Memos       []codec.Memo
	// Raw is the transaction JSON as returned, kept for the dump file.
	Raw json.RawMessage
}

// Range is the ledger span a search actually covered.
type Range struct {
	Min int64
	Max int64
}

// AccountState is what the tool needs before signing.
type AccountState struct {
	Sequence     uint32
	BalanceDrops uint64
}

// ServerState is what the tool needs to pick LastLedgerSequence and fees.
type ServerState struct {
	ValidatedLedger uint32
	CompleteLedgers string
	BaseFeeDrops    uint64
	OpenLedgerFee   uint64
}

// Client is the whole surface xrplbak uses.
type Client interface {
	Submit(blob []byte) (engineResult string, err error)
	Tx(hash string) (*TxRecord, error)
	// AccountTx returns every validated transaction for the account, oldest
	// first, and the range the server actually searched.
	AccountTx(account string) ([]TxRecord, Range, error)
	LedgerEntryDID(account string) (data []byte, err error)
	AccountInfo(account string) (*AccountState, error)
	ServerInfo() (*ServerState, error)
	// AmendmentEnabled reports whether the server has the named amendment
	// enabled. An error means the answer is unknown; callers treat unknown
	// as not enabled.
	AmendmentEnabled(id string) (bool, error)
}

// AmendmentBatchV1_1 is the amendment id of Batch (XLS-56), from the
// feature RPC on mainnet, 2026-09-17.
const AmendmentBatchV1_1 = "9F287AED3CDB50A7BD1ACEC24296A30C9B5230CCD136219317AC790E3B884377"

// ParseTxJSON extracts the fields the tool needs from a transaction JSON
// object in either api_version 1 (fields at top level) or 2 (tx_json).
func ParseTxJSON(raw json.RawMessage, meta json.RawMessage) (*TxRecord, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, err
	}
	body := top
	if inner, ok := top["tx_json"]; ok {
		if err := json.Unmarshal(inner, &body); err != nil {
			return nil, err
		}
	}
	r := &TxRecord{Raw: raw}
	str := func(m map[string]json.RawMessage, k string) string {
		var s string
		_ = json.Unmarshal(m[k], &s)
		return s
	}
	num := func(m map[string]json.RawMessage, k string) uint32 {
		var n uint32
		_ = json.Unmarshal(m[k], &n)
		return n
	}
	r.Hash = str(top, "hash")
	if r.Hash == "" {
		r.Hash = str(body, "hash")
	}
	r.LedgerIndex = num(top, "ledger_index")
	if r.LedgerIndex == 0 {
		r.LedgerIndex = num(body, "ledger_index")
	}
	var v bool
	_ = json.Unmarshal(top["validated"], &v)
	r.Validated = v
	r.Account = str(body, "Account")
	r.TxType = str(body, "TransactionType")
	r.Sequence = num(body, "Sequence")
	if meta == nil {
		meta = top["meta"]
	}
	if meta != nil {
		var m struct {
			TransactionResult string `json:"TransactionResult"`
		}
		_ = json.Unmarshal(meta, &m)
		r.Result = m.TransactionResult
	}
	if memos, ok := body["Memos"]; ok {
		var list []struct {
			Memo struct {
				MemoType   string `json:"MemoType"`
				MemoData   string `json:"MemoData"`
				MemoFormat string `json:"MemoFormat"`
			} `json:"Memo"`
		}
		if err := json.Unmarshal(memos, &list); err == nil {
			for _, e := range list {
				t, _ := hex.DecodeString(e.Memo.MemoType)
				d, _ := hex.DecodeString(e.Memo.MemoData)
				f, _ := hex.DecodeString(e.Memo.MemoFormat)
				r.Memos = append(r.Memos, codec.Memo{Type: t, Data: d, Format: f})
			}
		}
	}
	return r, nil
}

// MemosToJSON renders memos the way the JSON API expects (upper hex).
func MemosToJSON(memos []codec.Memo) []map[string]map[string]string {
	var out []map[string]map[string]string
	for _, m := range memos {
		e := map[string]string{"MemoType": strings.ToUpper(hex.EncodeToString(m.Type)), "MemoData": strings.ToUpper(hex.EncodeToString(m.Data))}
		if len(m.Format) > 0 {
			e["MemoFormat"] = strings.ToUpper(hex.EncodeToString(m.Format))
		}
		out = append(out, map[string]map[string]string{"Memo": e})
	}
	return out
}
