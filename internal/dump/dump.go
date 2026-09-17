// Package dump is the offline transaction record. backup writes one after
// every run; verify and restore can read it instead of a server. It holds
// ciphertext and public data only.
package dump

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/justinnevins/xrplbak/internal/xrpl"
)

// Version of the dump format.
const Version = 1

// Tx is one recorded transaction.
type Tx struct {
	Hash        string          `json:"hash"`
	LedgerIndex uint32          `json:"ledger_index"`
	Result      string          `json:"result"`
	TxJSON      json.RawMessage `json:"tx_json"`
}

// DID is the anchor record as last written.
type DID struct {
	LedgerIndex uint32 `json:"ledger_index"`
	Data        string `json:"data"`
}

// Dump is the file body.
type Dump struct {
	V        int    `json:"v"`
	Account  string `json:"account"`
	BackupID string `json:"backup_id"`
	Txs      []Tx   `json:"txs"`
	DID      *DID   `json:"did,omitempty"`
}

// Load reads a dump file.
func Load(path string) (*Dump, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d Dump
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, errors.New("not an xrplbak dump file: " + path)
	}
	if d.V != Version {
		return nil, errors.New("unsupported dump version")
	}
	// Every entry must be a transaction object with a hash. A dump that is
	// partly unreadable is refused whole rather than silently thinned, since
	// a thinned dump reports a backup as missing when the file is at fault.
	// Two records under one hash are refused rather than picked from: Tx
	// resolves a hash case insensitively and returns the first match, so a
	// second record under that hash is unreachable and the operator cannot
	// tell which one a verify read. AccountTx would still count both.
	seen := map[string]int{}
	for i, t := range d.Txs {
		rec, err := xrpl.ParseTxJSON(t.TxJSON, nil)
		if err != nil || t.Hash == "" || rec.Account == "" {
			return nil, fmt.Errorf("not an xrplbak dump file: %s (entry %d is not a transaction)", path, i+1)
		}
		k := strings.ToUpper(t.Hash)
		if first, dup := seen[k]; dup {
			return nil, fmt.Errorf("refusing %s: entries %d and %d both claim transaction %s", path, first+1, i+1, t.Hash)
		}
		seen[k] = i
	}
	return &d, nil
}

// Save writes a dump file with mode 0600.
func (d *Dump) Save(path string) error {
	d.V = Version
	b, err := json.MarshalIndent(d, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// Merge adds transactions from another dump for the same account.
func (d *Dump) Merge(o *Dump) {
	// Keyed the way Tx resolves a hash, so a merge cannot introduce a
	// duplicate that Load would refuse on the next read.
	seen := map[string]bool{}
	for _, t := range d.Txs {
		seen[strings.ToUpper(t.Hash)] = true
	}
	for _, t := range o.Txs {
		if k := strings.ToUpper(t.Hash); !seen[k] {
			d.Txs = append(d.Txs, t)
			seen[k] = true
		}
	}
	if o.DID != nil && (d.DID == nil || o.DID.LedgerIndex >= d.DID.LedgerIndex) {
		d.DID = o.DID
	}
}

// Client serves the dump through the xrpl.Client interface. Writes fail.
type Client struct{ D *Dump }

var errOffline = errors.New("offline dump: this operation needs a live server (--rpc)")

func (c *Client) Submit([]byte) (string, error) { return "", errOffline }

func (c *Client) record(t Tx) (*xrpl.TxRecord, error) {
	r, err := xrpl.ParseTxJSON(t.TxJSON, nil)
	if err != nil {
		return nil, err
	}
	r.Hash, r.LedgerIndex, r.Validated, r.Result = t.Hash, t.LedgerIndex, true, t.Result
	return r, nil
}

func (c *Client) Tx(hash string) (*xrpl.TxRecord, error) {
	for _, t := range c.D.Txs {
		if strings.EqualFold(t.Hash, hash) {
			return c.record(t)
		}
	}
	return nil, xrpl.ErrNotFound
}

func (c *Client) AccountTx(account string) ([]xrpl.TxRecord, xrpl.Range, error) {
	rng := xrpl.Range{Min: -1, Max: -1}
	var out []xrpl.TxRecord
	for _, t := range c.D.Txs {
		r, err := c.record(t)
		if err != nil || r.Account != account {
			continue
		}
		if rng.Min < 0 || int64(t.LedgerIndex) < rng.Min {
			rng.Min = int64(t.LedgerIndex)
		}
		if int64(t.LedgerIndex) > rng.Max {
			rng.Max = int64(t.LedgerIndex)
		}
		out = append(out, *r)
	}
	return out, rng, nil
}

func (c *Client) LedgerEntryDID(string) ([]byte, error) {
	if c.D.DID == nil {
		return nil, xrpl.ErrNotFound
	}
	// hex.DecodeString hands back the prefix it managed to decode next to
	// its error. A truncated anchor is not an anchor, so nothing is returned.
	b, err := hex.DecodeString(c.D.DID.Data)
	if err != nil {
		return nil, fmt.Errorf("dump: anchor data is not hex: %w", err)
	}
	return b, nil
}

func (c *Client) AccountInfo(string) (*xrpl.AccountState, error) { return nil, errOffline }
func (c *Client) ServerInfo() (*xrpl.ServerState, error)         { return nil, errOffline }
func (c *Client) AmendmentEnabled(string) (bool, error)          { return false, errOffline }
