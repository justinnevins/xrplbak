package backup

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/discover"
	"github.com/justinnevins/xrplbak/internal/dump"
	"github.com/justinnevins/xrplbak/internal/restore"
	"github.com/justinnevins/xrplbak/internal/xrpl"
)

// forgedDump returns a dump for backup b whose one record is a real
// transaction of backup a (so the ledger confirms its hash) with the memo
// rewritten to b's first chunk.
func forgedDump(t *testing.T, e *env, a, b *Plan, aDump *dump.Dump) *dump.Dump {
	t.Helper()
	hA := a.Manifest.OnChain.Chunks[0].TxHash
	forged := &dump.Dump{Account: aDump.Account, BackupID: b.Manifest.BackupID}
	for _, tx := range aDump.Txs {
		if tx.Hash != hA {
			continue
		}
		var top map[string]any
		if err := json.Unmarshal(tx.TxJSON, &top); err != nil {
			t.Fatal(err)
		}
		body := top
		if in, ok := top["tx_json"].(map[string]any); ok {
			body = in
		}
		body["Memos"] = xrpl.MemosToJSON(b.ChunkMemos[:1])
		raw, err := json.Marshal(top)
		if err != nil {
			t.Fatal(err)
		}
		tx.TxJSON = raw
		forged.Txs = append(forged.Txs, tx)
	}
	if len(forged.Txs) != 1 {
		t.Fatalf("setup: forged %d records, want 1", len(forged.Txs))
	}
	return forged
}

// F-078: a resume matched a dump record to a chunk by the memo inside the
// dump, and asked the ledger only whether that hash was a validated success
// by the writer. A record with a real old hash and this backup's memo made
// Submit skip a chunk the ledger never held, name the old transaction in
// the manifest, and report success. What a recorded transaction carries is
// now read from the ledger's own answer.
func TestF078ResumeCreditsOnlyWhatTheLedgerHolds(t *testing.T) {
	for name, batch := range map[string]bool{"batched": true, "one at a time": false} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.ledger.Batch = batch
			a, _ := Build(e.opts(t, 1))
			first := e.submit(t, a)
			aDump, err := dump.Load(first.DumpOut)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := Build(e.opts(t, 2))
			s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Dump: forgedDump(t, e, a, b, aDump), Batch: batch, Sleep: func(time.Duration) {}, DumpOut: filepath.Join(e.dir, "b.dump.json")}
			if err := s.Submit(b); err != nil {
				t.Fatal(err)
			}
			if got, old := b.Manifest.OnChain.Chunks[0].TxHash, a.Manifest.OnChain.Chunks[0].TxHash; got == old {
				t.Fatalf("the new backup's manifest names the old backup's chunk transaction %s", old)
			}
			held := false
			for _, rec := range e.ledger.Txs {
				for _, m := range rec.Memos {
					if bytes.Equal(m.Data, b.ChunkMemos[0].Data) {
						held = true
					}
				}
			}
			if !held {
				t.Fatal("Submit reported success, but chunk 1 of the new backup is not on the ledger")
			}

			// The backup the forged dump tried to hollow out restores whole.
			keys := discover.RootKeys{Root: e.root}
			res, err := discover.Run(e.ledger, keys, e.writer.Address(), 0)
			if err != nil {
				t.Fatal(err)
			}
			if res.Latest == nil || res.Latest.Manifest.BackupID != b.Manifest.BackupID {
				t.Fatalf("discovery did not select the new backup: %+v", res.Latest)
			}
			entries, err := discover.Fetch(e.ledger, keys, res, res.Latest)
			if err != nil {
				t.Fatal(err)
			}
			bundle, err := discover.OpenBundle(keys, res.Latest, b.Bundle)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := restore.Build(res.Latest.Manifest, entries, bundle)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range plan.Files {
				if !f.Complete() {
					t.Fatalf("%s is not complete", f.Path)
				}
			}
		})
	}
}
