package main

import (
	"strings"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/chunk"
)

// dropManifest removes every manifest transaction from the world's ledger,
// leaving the chunks and the DID anchor: the anchor names a backup that the
// history read does not hold.
func dropManifest(w *world) {
	w.t.Helper()
	for {
		hit := false
		for i := range w.ledger.Txs {
			for _, m := range w.ledger.Txs[i].Memos {
				if p, ok := chunk.Decode(m); ok && p.Type == chunk.TypeManifest {
					w.dropTx(&w.ledger.Txs[i])
					hit = true
					break
				}
			}
			if hit {
				break
			}
		}
		if !hit {
			return
		}
	}
}

// F-081: the anchor authenticates with this key and names a backup, and no
// backup at all is found. That was exit 4 with "Check the account address,
// the recovery key, and the epoch". The key is right, it just opened the
// anchor; the backup is what is missing. Exit 5, the same answer the tool
// gives when an older backup is still there (F-061).
func TestF081AnchoredBackupMissingAndNothingElseIsIncomplete(t *testing.T) {
	for _, cmd := range []string{"restore", "verify"} {
		w := newWorld(t, 71)
		dropManifest(w)
		r := w.run("", cmd, "--dump", w.dumpFile("gone"), "--words-file", w.words, "--account", w.writer.Address())
		if r.code != exitIncomplete {
			t.Errorf("%s: exit %d, want %d (incomplete)\n%s", cmd, r.code, exitIncomplete, r.out)
		}
		if strings.Contains(r.out, "Check the account address, the recovery key") {
			t.Errorf("%s: the message blames the key, which just authenticated the anchor:\n%s", cmd, r.out)
		}
		if !strings.Contains(r.out, "DID anchor names backup") || !strings.Contains(r.out, "no backup at all") {
			t.Errorf("%s: the message does not say what is missing:\n%s", cmd, r.out)
		}
	}
}

// F-083: restore and verify chose a backup and said nothing about how old
// it was, and a dump file is a picture of the ledger on the day it was
// written. Both commands now print when the selected backup was made, and
// say so when they read from a dump.
func TestF083SelectedBackupShowsItsDateAndTheDumpCaveat(t *testing.T) {
	w := newWorld(t, 72)
	for _, cmd := range []string{"restore", "verify"} {
		r := w.run("", cmd, "--dump", w.dumpFile("d"), "--words-file", w.words, "--account", w.writer.Address(), "--bundle", w.bundle)
		if r.code != 0 {
			t.Fatalf("%s: exit %d\n%s", cmd, r.code, r.out)
		}
		if !strings.Contains(r.out, "  made:     "+w.plan.Manifest.Created[:10]) {
			t.Errorf("%s: no line giving the backup date %s:\n%s", cmd, w.plan.Manifest.Created[:10], r.out)
		}
		if !strings.Contains(r.out, "a dump file shows the ledger as it was when the file was written") {
			t.Errorf("%s: no caveat that a dump file can be stale:\n%s", cmd, r.out)
		}
	}
}

func TestF083BackupAge(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	for created, want := range map[string]string{
		"2026-11-10T08:00:00Z": "2026-11-10 08:00 UTC (today)",
		"2026-11-09T11:00:00Z": "2026-11-09 11:00 UTC (1 day ago)",
		"2026-10-20T12:00:00Z": "2026-10-20 12:00 UTC (21 days ago)",
		"2025-11-10T12:00:00Z": "2025-11-10 12:00 UTC (365 days ago)",
		"2026-11-12T12:00:00Z": "2026-11-12 12:00 UTC (dated after this computer's clock)",
		"not a date":           "not a date (unreadable date)",
		"":                     "(no date recorded)",
	} {
		if got := backupAge(created, now); got != want {
			t.Errorf("backupAge(%q) = %q, want %q", created, got, want)
		}
	}
}

// F-084: attest-verify answered "none found" with exit 3, the code for
// "the input holds something the tool will not handle". Nothing was
// refused. A lookup that finds no attestation is exit 5.
func TestF084AttestVerifyNoneIsIncompleteNotRefused(t *testing.T) {
	w := newWorld(t, 73)
	r := w.run("", "attest-verify", "--dump", w.dumpFile("a"), "--account", w.writer.Address())
	if r.code != exitIncomplete {
		t.Fatalf("exit %d, want %d (incomplete)\n%s", r.code, exitIncomplete, r.out)
	}
	if !strings.Contains(r.out, "result:   none") {
		t.Fatalf("the report does not say none was found:\n%s", r.out)
	}
}
