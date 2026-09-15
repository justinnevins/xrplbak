// Package fake is an in-memory XRPL for tests. It validates every submitted
// transaction instantly and keeps a per-account DID entry. It is not a
// consensus engine: sequence checks are the only rule it enforces.
package fake

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/justinnevins/xrplbak/internal/xrpl"
	"github.com/justinnevins/xrplbak/internal/xrpl/codec"
	"github.com/justinnevins/xrplbak/internal/xrpl/sign"
)

// Ledger is the fake state.
type Ledger struct {
	Seq       uint32
	Accounts  map[string]*xrpl.AccountState
	Txs       []xrpl.TxRecord
	DID       map[string][]byte
	Fee       uint64
	Submitted int
	// Prune drops history below this ledger index to simulate online_delete.
	Prune uint32
	// FailSubmit forces the next submit to return this engine code.
	FailSubmit string
	// DropDID makes the DID read fail as not found.
	DropDID bool
}

// New starts at ledger 1000 with a 10 drop fee.
func New() *Ledger {
	return &Ledger{Seq: 1000, Accounts: map[string]*xrpl.AccountState{}, DID: map[string][]byte{}, Fee: 10}
}

// Fund creates an account with a balance and sequence 1.
func (l *Ledger) Fund(addr string, drops uint64) {
	l.Accounts[addr] = &xrpl.AccountState{Sequence: 1, BalanceDrops: drops}
}

func (l *Ledger) Submit(blob []byte) (string, error) {
	l.Submitted++
	if l.FailSubmit != "" {
		code := l.FailSubmit
		l.FailSubmit = ""
		return code, nil
	}
	tx, err := codec.Deserialize(blob)
	if err != nil {
		return "", err
	}
	addr := sign.EncodeAddress(tx.Account)
	acct, ok := l.Accounts[addr]
	if !ok {
		return "terNO_ACCOUNT", nil
	}
	if tx.Sequence != acct.Sequence {
		return "tefPAST_SEQ", nil
	}
	payload, _ := codec.SigningPayload(tx)
	if !sign.VerifyEd25519(tx.SigningPubKey, payload, tx.TxnSignature) {
		return "temBAD_SIGNATURE", nil
	}
	acct.Sequence++
	acct.BalanceDrops -= tx.FeeDrops
	l.Seq++
	rec := xrpl.TxRecord{Hash: codec.Hash(blob), LedgerIndex: l.Seq, Validated: true, Result: "tesSUCCESS", Account: addr, Sequence: tx.Sequence, Memos: tx.Memos}
	switch tx.Type {
	case codec.TxAccountSet:
		rec.TxType = "AccountSet"
	case codec.TxDIDSet:
		rec.TxType = "DIDSet"
		l.DID[addr] = tx.Data
	case codec.TxDIDDelete:
		rec.TxType = "DIDDelete"
		delete(l.DID, addr)
	}
	raw := map[string]any{"Account": addr, "TransactionType": rec.TxType, "Sequence": tx.Sequence, "Fee": tx.FeeDrops, "hash": rec.Hash, "ledger_index": rec.LedgerIndex, "validated": true}
	if len(tx.Memos) > 0 {
		raw["Memos"] = xrpl.MemosToJSON(tx.Memos)
	}
	if len(tx.Data) > 0 {
		raw["Data"] = strings.ToUpper(hex.EncodeToString(tx.Data))
	}
	rec.Raw, _ = json.Marshal(raw)
	l.Txs = append(l.Txs, rec)
	return "tesSUCCESS", nil
}

func (l *Ledger) Tx(hash string) (*xrpl.TxRecord, error) {
	for i := range l.Txs {
		if strings.EqualFold(l.Txs[i].Hash, hash) && l.Txs[i].LedgerIndex >= l.Prune {
			t := l.Txs[i]
			return &t, nil
		}
	}
	return nil, xrpl.ErrNotFound
}

func (l *Ledger) AccountTx(account string) ([]xrpl.TxRecord, xrpl.Range, error) {
	var out []xrpl.TxRecord
	rng := xrpl.Range{Min: int64(l.Prune), Max: int64(l.Seq)}
	if rng.Min < 1000 {
		rng.Min = 1000
	}
	for _, t := range l.Txs {
		if t.Account == account && t.LedgerIndex >= l.Prune {
			out = append(out, t)
		}
	}
	return out, rng, nil
}

func (l *Ledger) LedgerEntryDID(account string) ([]byte, error) {
	d, ok := l.DID[account]
	if !ok || l.DropDID {
		return nil, xrpl.ErrNotFound
	}
	return d, nil
}

func (l *Ledger) AccountInfo(account string) (*xrpl.AccountState, error) {
	a, ok := l.Accounts[account]
	if !ok {
		return nil, xrpl.ErrNotFound
	}
	c := *a
	return &c, nil
}

func (l *Ledger) ServerInfo() (*xrpl.ServerState, error) {
	if l.Fee == 0 {
		return nil, errors.New("fake: no fee")
	}
	return &xrpl.ServerState{ValidatedLedger: l.Seq, CompleteLedgers: "1000-9999", BaseFeeDrops: 10, OpenLedgerFee: l.Fee}, nil
}
