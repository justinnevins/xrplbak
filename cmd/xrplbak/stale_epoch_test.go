package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/crypto"
)

// TestBackupIDOnStaleEpochWarns pins F-043. After init --rotate the writer
// account and seed stay the same, so whoever copied the old key file can
// keep posting backups at the old epoch. Those backups authenticate with the
// recovery words. Cold read 7 showed an operator nearly picking one: it has
// the highest seq and the latest timestamp. Naming it with --backup-id
// restored the thief's file, reported complete, with no warning.
//
// Decision 2026-09-23 (Justin): warn, do not refuse. The exit code stays 0.
func TestBackupIDOnStaleEpochWarns(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	w := newWorld(t, 7) // epoch 0 seq 1, the operator's, before the rotation
	before := w.plan
	oldKey := w.key

	// The operator rotates and backs up at epoch 1.
	w.key = &crypto.KeyFile{Epoch: 1, Key: w.root.DeriveEpochKey(1), AccountID: oldKey.AccountID, WriterSeed: oldKey.WriterSeed}
	rotated := w.build(1, w.cfgPath, w.valPath)
	w.submit(rotated)

	// The thief, holding the epoch 0 key file, posts after the rotation.
	w.key = oldKey
	must(t, os.WriteFile(w.valPath, []byte("[validator_list_sites]\nhttps://vl.attacker.example\n"), 0o644))
	thief := w.build(2, w.cfgPath, w.valPath)
	w.submit(thief)

	// The operator backs up again at epoch 1. "After the rotation" must be
	// measured from the FIRST epoch 1 backup, not the latest one.
	w.key = &crypto.KeyFile{Epoch: 1, Key: w.root.DeriveEpochKey(1), AccountID: oldKey.AccountID, WriterSeed: oldKey.WriterSeed}
	rotated2 := w.build(2, w.cfgPath, w.valPath)
	w.submit(rotated2)
	w.key = oldKey

	const stale = "is from epoch 0, but a backup from epoch 1 exists"
	const after = "landed on the ledger after the first epoch 1 backup"

	// Default: the newest epoch wins and no stale-epoch warning appears.
	must(t, os.WriteFile(w.bundle, rotated2.Bundle, 0o600))
	r := w.restore()
	if r.code != exitOK || !strings.Contains(r.out, "* epoch 1 seq 2") {
		t.Fatalf("default restore must pick epoch 1 seq 2, got exit %d", r.code)
	}
	if strings.Contains(r.out, stale) {
		t.Fatal("the newest epoch must not carry the stale-epoch warning")
	}

	// Naming an older backup of the NEWEST epoch is an ordinary rollback,
	// not a stale epoch.
	must(t, os.WriteFile(w.bundle, rotated.Bundle, 0o600))
	r = w.restore("--backup-id", rotated.Manifest.BackupID[:12])
	if r.code != exitOK || strings.Contains(r.out, "is from epoch") || strings.Contains(r.out, "landed on the ledger after") {
		t.Fatalf("--backup-id on an epoch 1 backup must restore without the stale-epoch warning, got exit %d:\n%s", r.code, r.out)
	}

	// Naming the thief's backup still restores (warn, not refuse), but says why it is suspect.
	must(t, os.WriteFile(w.bundle, thief.Bundle, 0o600))
	r = w.restore("--backup-id", thief.Manifest.BackupID[:12])
	if r.code != exitOK {
		t.Fatalf("--backup-id on a stale epoch must still restore, got exit %d", r.code)
	}
	if !strings.Contains(r.out, stale) || !strings.Contains(r.out, after) {
		t.Fatalf("--backup-id on a post-rotation stale-epoch backup must warn with both lines, got:\n%s", r.out)
	}
	// The reference point is the first epoch 1 manifest, by ledger.
	saved := w.plan
	w.plan = rotated
	firstLedger := w.manifestTx(0).LedgerIndex
	w.plan = saved
	if want := fmt.Sprintf(", after %d)", firstLedger); !strings.Contains(r.out, want) {
		t.Fatalf("the post-rotation warning must measure from the first epoch 1 backup (%q), got:\n%s", want, r.out)
	}

	// Naming the operator's own pre-rotation backup warns about the epoch,
	// but not about landing after the rotation, because it did not.
	must(t, os.WriteFile(w.bundle, before.Bundle, 0o600))
	r = w.restore("--backup-id", before.Manifest.BackupID[:12])
	if r.code != exitOK {
		t.Fatalf("--backup-id on the pre-rotation backup must restore, got exit %d", r.code)
	}
	if !strings.Contains(r.out, stale) {
		t.Fatalf("a pre-rotation backup is still an older epoch and must say so, got:\n%s", r.out)
	}
	if strings.Contains(r.out, after) {
		t.Fatal("a backup that landed before the rotation must not be called post-rotation")
	}

	// verify takes the same path through choose and must warn the same way.
	r = w.run("", "verify", "--dump", w.dumpFile("v"), "--words-file", w.words, "--account", w.writer.Address(), "--backup-id", thief.Manifest.BackupID[:12])
	if r.code != exitOK || !strings.Contains(r.out, stale) || !strings.Contains(r.out, after) {
		t.Fatalf("verify --backup-id on the thief's backup must warn, got exit %d:\n%s", r.code, r.out)
	}
}
