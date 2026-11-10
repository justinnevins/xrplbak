package backup

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/anchor"
	"github.com/justinnevins/xrplbak/internal/discover"
	"github.com/justinnevins/xrplbak/internal/dump"
	"github.com/justinnevins/xrplbak/internal/restore"
	"github.com/justinnevins/xrplbak/internal/xrpl"
)

// forgedDump returns a dump for backup b whose one record is a real
// transaction of backup a (so the ledger confirms its hash) with the memo
// rewritten to b's first chunk. With all set, every record of a's dump is
// forged that way, its manifest parts included.
func forgedDump(t *testing.T, e *env, a, b *Plan, aDump *dump.Dump, all bool) *dump.Dump {
	t.Helper()
	hA := a.Manifest.OnChain.Chunks[0].TxHash
	forged := &dump.Dump{Account: aDump.Account, BackupID: b.Manifest.BackupID}
	for _, tx := range aDump.Txs {
		if !all && tx.Hash != hA {
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
	if want := map[bool]int{false: 1, true: len(aDump.Txs)}[all]; len(forged.Txs) != want {
		t.Fatalf("setup: forged %d records, want %d", len(forged.Txs), want)
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
	type mode struct{ batch, all bool }
	for name, md := range map[string]mode{
		"batched, one record":         {true, false},
		"one at a time, one record":   {false, false},
		"batched, every record":       {true, true},
		"one at a time, every record": {false, true},
	} {
		t.Run(name, func(t *testing.T) {
			batch := md.batch
			e := newEnv(t)
			e.ledger.Batch = batch
			a, _ := Build(e.opts(t, 1))
			first := e.submit(t, a)
			aDump, err := dump.Load(first.DumpOut)
			if err != nil {
				t.Fatal(err)
			}
			old := map[string]bool{}
			for _, tx := range aDump.Txs {
				old[tx.Hash] = true
			}
			b, _ := Build(e.opts(t, 2))
			s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Dump: forgedDump(t, e, a, b, aDump, md.all), Batch: batch, Sleep: func(time.Duration) {}, DumpOut: filepath.Join(e.dir, "b.dump.json")}
			if err := s.Submit(b); err != nil {
				t.Fatal(err)
			}
			for i, c := range b.Manifest.OnChain.Chunks {
				if old[c.TxHash] {
					t.Fatalf("the new backup's manifest names the old backup's transaction %s for chunk %d", c.TxHash, i+1)
				}
			}
			data, err := e.ledger.LedgerEntryDID(e.writer.Address())
			if err != nil {
				t.Fatal(err)
			}
			arec, err := anchor.Parse(data)
			if err != nil {
				t.Fatal(err)
			}
			if old[arec.TxHashHex()] {
				t.Fatalf("the new backup's anchor names the old backup's manifest transaction %s", arec.TxHashHex())
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

// A manifest counts as already on the ledger only when every part from 0
// to total-1 is there with one total. Counting parts was not enough: part
// 0 of 2 plus part 5 of 6 are two parts, and no manifest.
func TestF078CompleteManifestNeedsEveryPart(t *testing.T) {
	part := func(total uint16) landed { return landed{tx: dump.Tx{Hash: "AB"}, total: total} }
	for name, c := range map[string]struct {
		parts map[uint16]landed
		want  bool
	}{
		"one of one":          {map[uint16]landed{0: part(1)}, true},
		"both of two":         {map[uint16]landed{0: part(2), 1: part(2)}, true},
		"first of two":        {map[uint16]landed{0: part(2)}, false},
		"second of two":       {map[uint16]landed{1: part(2)}, false},
		"0 of 2 and 5 of 6":   {map[uint16]landed{0: part(2), 5: part(6)}, false},
		"0 of 2 and 1 of 3":   {map[uint16]landed{0: part(2), 1: part(3)}, false},
		"0 and 2 of 2":        {map[uint16]landed{0: part(2), 2: part(2)}, false},
		"three where two fit": {map[uint16]landed{0: part(2), 1: part(2), 2: part(2)}, false},
		"nothing":             {map[uint16]landed{}, false},
		"zero total":          {map[uint16]landed{0: part(0)}, false},
	} {
		first, ok := completeManifest(c.parts)
		if ok != c.want {
			t.Errorf("%s: complete=%v, want %v", name, ok, c.want)
		}
		if ok && first.tx.Hash != "AB" {
			t.Errorf("%s: wrong first part returned", name)
		}
	}
}
