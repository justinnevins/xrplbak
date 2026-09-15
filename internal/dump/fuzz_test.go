package dump

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/xrpl"
)

// goodTx is one well-formed recorded transaction body.
const goodTx = `{"Account":"rH9ESAdrFfDAZtCZGa7JiwNJfKnC6CmGFQ","TransactionType":"Payment","Sequence":1,"hash":"AA","ledger_index":1001,"validated":true}`

// dumpSeeds are the dump shapes the adversarial corpus already drives
// through the command surface, plus the ambiguous ones it does not.
var dumpSeeds = []string{
	``,
	`{}`,
	`{"v":1,"account":"r1","txs":[]}`,
	`{"v":2,"account":"r1","txs":[]}`,
	`{"v":1,"account":"r1","txs":[{"hash":"AA","ledger_index":1,"tx_json":` + goodTx + `}]}`,
	`{"v":1,"account":"r1","txs":[{"hash":"","ledger_index":1,"tx_json":` + goodTx + `}]}`,
	`{"v":1,"account":"r1","txs":[{"hash":"AA","tx_json":"not an object"}]}`,
	// Two records answering to the same hash. Client.Tx matches case
	// insensitively, so the second is unreachable and the choice is silent.
	`{"v":1,"account":"r1","txs":[{"hash":"AA","ledger_index":1,"tx_json":` + goodTx + `},{"hash":"aa","ledger_index":2,"tx_json":` + goodTx + `}]}`,
	`{"v":1,"account":"r1","txs":[{"hash":"AA","ledger_index":1,"tx_json":` + goodTx + `},{"hash":"AA","ledger_index":9,"tx_json":` + goodTx + `}]}`,
	`{"v":1,"account":"r1","txs":[],"did":{"ledger_index":1,"data":"zz"}}`,
	`{"v":1,"account":"r1","txs":[],"did":{"ledger_index":1,"data":"ABC"}}`,
	`{"v":1,"account":"r1","txs":null,"did":null}`,
}

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "case.dump.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// FuzzLoadNoPanic asserts that a hostile dump file never panics, never
// returns a dump alongside an error, and never yields an entry that is not a
// transaction. A dump replaces the server for verify and restore, so its
// bytes decide whether a backup is reported complete.
func FuzzLoadNoPanic(f *testing.F) {
	for _, s := range dumpSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		d, err := Load(write(t, string(body)))
		if err != nil {
			if d != nil {
				t.Fatalf("Load returned a dump alongside error %v", err)
			}
			return
		}
		if d == nil {
			t.Fatal("Load returned nil dump and nil error")
		}
		for i, tx := range d.Txs {
			rec, perr := xrpl.ParseTxJSON(tx.TxJSON, nil)
			if perr != nil || tx.Hash == "" || rec.Account == "" {
				t.Fatalf("Load accepted entry %d that is not a transaction", i+1)
			}
		}
	})
}

// FuzzLoadRefusesAmbiguousHashes asserts that a dump never carries two
// records that answer to the same hash. Client.Tx resolves a hash case
// insensitively and returns the first match, so a second record under the
// same hash is silently unreachable: the operator cannot tell which one the
// verify read. An ambiguous input is refused, not picked from.
func FuzzLoadRefusesAmbiguousHashes(f *testing.F) {
	for _, s := range dumpSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		d, err := Load(write(t, string(body)))
		if err != nil {
			return
		}
		seen := map[string]int{}
		for i, tx := range d.Txs {
			k := strings.ToUpper(tx.Hash)
			if first, dup := seen[k]; dup {
				t.Fatalf("Load accepted entries %d and %d under the same hash %q", first+1, i+1, tx.Hash)
			}
			seen[k] = i
		}
	})
}

// FuzzLedgerEntryDIDNoDataOnError asserts the anchor bytes are never
// returned alongside an error. hex.DecodeString hands back the prefix it
// managed to decode next to its error, and a caller that reads the bytes
// first would anchor on a truncated record.
func FuzzLedgerEntryDIDNoDataOnError(f *testing.F) {
	f.Add("")
	f.Add("ABC")
	f.Add("zz")
	f.Add("00112233445566778899aabbccddeeff")
	f.Add("00112233445566778899aabbccddeefg")
	f.Fuzz(func(t *testing.T, hexData string) {
		c := &Client{D: &Dump{DID: &DID{Data: hexData}}}
		data, err := c.LedgerEntryDID("r1")
		if err != nil && data != nil {
			t.Fatalf("LedgerEntryDID returned %d bytes alongside error %v", len(data), err)
		}
	})
}

// FuzzClientAnswersOnlyForTheAccount asserts that AccountTx never hands back
// a record belonging to another account, and that every record Load accepted
// is reachable through Tx by its own hash.
func FuzzClientAnswersOnlyForTheAccount(f *testing.F) {
	for _, s := range dumpSeeds {
		f.Add([]byte(s), "rH9ESAdrFfDAZtCZGa7JiwNJfKnC6CmGFQ")
	}
	f.Fuzz(func(t *testing.T, body []byte, account string) {
		d, err := Load(write(t, string(body)))
		if err != nil {
			return
		}
		c := &Client{D: d}
		recs, _, err := c.AccountTx(account)
		if err != nil {
			t.Fatalf("AccountTx on an accepted dump failed: %v", err)
		}
		for _, r := range recs {
			if r.Account != account {
				t.Fatalf("AccountTx(%q) returned a record for %q", account, r.Account)
			}
			if !r.Validated {
				t.Fatalf("AccountTx returned an unvalidated record for %q", account)
			}
		}
		for _, tx := range d.Txs {
			got, err := c.Tx(tx.Hash)
			if err != nil {
				t.Fatalf("Tx(%q) on an accepted dump failed: %v", tx.Hash, err)
			}
			if !strings.EqualFold(got.Hash, tx.Hash) {
				t.Fatalf("Tx(%q) answered with hash %q", tx.Hash, got.Hash)
			}
		}
		if b, err := json.Marshal(d); err != nil {
			t.Fatalf("an accepted dump does not re-marshal: %v (%s)", err, b)
		}
	})
}
