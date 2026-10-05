package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/backup"
	"github.com/justinnevins/xrplbak/internal/crypto"
)

// These tests pin how discovery handles manifests from epochs the search
// has not reached yet. The recovery words can open every epoch, but a
// manifest does not say its epoch in the clear, so discovery has to try
// keys. A manifest it cannot open must never be dropped in silence: it may
// be the newest backup.

const unopenedAfter = "landed after the selected backup"

// keyAt is the key file for epoch e of the world's recovery key.
func (w *world) keyAt(e uint32) *crypto.KeyFile {
	return &crypto.KeyFile{Epoch: e, Key: w.root.DeriveEpochKey(e), AccountID: w.key.AccountID, WriterSeed: w.key.WriterSeed}
}

// postAt builds and submits a backup (or tombstone) with key k.
func (w *world) postAt(k *crypto.KeyFile, seq uint32, tomb bool) *backup.Plan {
	w.t.Helper()
	old := w.key
	w.key = k
	defer func() { w.key = old }()
	p, err := backup.Build(backup.Options{ConfigPath: w.cfgPath, ValidatorsPath: w.valPath, Key: k, Now: time.Unix(1_800_000_000+int64(seq), 0), Seq: seq, Tombstone: tomb})
	must(w.t, err)
	w.submit(p)
	return p
}

// dropAnchor removes the DID anchor, as backup --tombstone --delete-anchor
// does, or anyone holding the writer key can.
func (w *world) dropAnchor() { delete(w.ledger.DID, w.writer.Address()) }

// restoredFile returns the named file from a dry-run restore's temp dir.
func restoredFile(t *testing.T, out, name string) string {
	t.Helper()
	const lead = "files written under "
	i := strings.Index(out, lead)
	if i < 0 {
		t.Fatalf("no dry-run directory in output:\n%s", out)
	}
	dir := strings.TrimSpace(strings.SplitN(out[i+len(lead):], "\n", 2)[0])
	var got []byte
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() && filepath.Base(p) == name {
			got, _ = os.ReadFile(p)
		}
		return nil
	})
	return string(got)
}

func (w *world) restoreWords(extra ...string) result {
	w.t.Helper()
	args := []string{"restore", "--dump", w.dumpFile("words"), "--words-file", w.words, "--account", w.writer.Address()}
	return w.run("", append(args, extra...)...)
}

// A backup at epoch 12 with the anchor gone used to fall outside the
// search (it stopped 8 epochs above the start), and the epoch 0 backup was
// restored with exit 0.
func TestWordsRestoreFindsEpochAboveStart(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	w := newWorld(t, 61)
	must(t, os.WriteFile(w.valPath, []byte("[validator_list_sites]\nhttps://epoch-12.example\n"), 0o644))
	w.postAt(w.keyAt(12), 1, false)
	w.dropAnchor()
	r := w.restoreWords()
	if r.code != exitOK || !strings.Contains(r.out, "* epoch 12 seq 1") {
		t.Fatalf("restore must select the epoch 12 backup, got exit %d:\n%s", r.code, r.out)
	}
	if got := restoredFile(t, r.out, "validators.txt"); !strings.Contains(got, "epoch-12.example") {
		t.Fatalf("restored validators.txt is not the epoch 12 backup:\n%s", got)
	}
}

// Same shape with a tombstone at epoch 12: the tombstone must win.
func TestWordsRestoreFindsTombstoneAboveStart(t *testing.T) {
	w := newWorld(t, 62)
	w.postAt(w.keyAt(12), 1, true)
	w.dropAnchor()
	r := w.restoreWords()
	if r.code != exitIncomplete || !strings.Contains(r.out, "the newest backup is a tombstone") {
		t.Fatalf("restore must refuse on the epoch 12 tombstone, got exit %d:\n%s", r.code, r.out)
	}
}

// Each epoch found moves the search up, so a chain of rotations is
// followed past any fixed window: 0, 60, 120.
func TestWordsRestoreFollowsRotationChain(t *testing.T) {
	w := newWorld(t, 63)
	w.postAt(w.keyAt(60), 1, false)
	w.postAt(w.keyAt(120), 1, false)
	w.dropAnchor()
	r := w.restoreWords()
	if r.code != exitOK || !strings.Contains(r.out, "* epoch 120 seq 1") || !strings.Contains(r.out, "0 rejected") {
		t.Fatalf("restore must find all three epochs and select epoch 120, got exit %d:\n%s", r.code, r.out)
	}
}

// A manifest the search cannot reach (more than 64 epochs above the newest
// one found) still opens nothing, but it landed after the selected backup,
// so the operator is told.
func TestWordsRestoreWarnsOnUnopenedNewerManifest(t *testing.T) {
	w := newWorld(t, 64)
	w.postAt(w.keyAt(200), 1, false)
	w.dropAnchor()
	r := w.restoreWords()
	if !strings.Contains(r.out, "* epoch 0 seq 1") || !strings.Contains(r.out, "WARNING: 1 manifest(s) "+unopenedAfter) {
		t.Fatalf("restore must warn that an unopened manifest landed after the selected backup, got exit %d:\n%s", r.code, r.out)
	}
}

// After a rotation the key file cannot open the older epochs. Those landed
// before the selected backup and are expected: no warning.
func TestRotatedKeyFileDoesNotWarnOnOlderEpochs(t *testing.T) {
	w := newWorld(t, 65)
	k1 := w.keyAt(1)
	w.postAt(k1, 1, false)
	must(t, os.WriteFile(w.keyFile, k1.Encode(), 0o600))
	r := w.run("", "restore", "--dump", w.dumpFile("k"), "--key", w.keyFile)
	if r.code != exitOK || !strings.Contains(r.out, "* epoch 1 seq 1") || !strings.Contains(r.out, "1 rejected") {
		t.Fatalf("key file restore must select epoch 1 and reject the epoch 0 manifest, got exit %d:\n%s", r.code, r.out)
	}
	if strings.Contains(r.out, unopenedAfter) {
		t.Fatalf("an older epoch is expected after a rotation and must not warn:\n%s", r.out)
	}
}

// backup plans the next seq from what its key file can open. With an old
// key file and a newer epoch on the ledger, the new backup would never be
// the one a restore selects, so the plan must say so.
func TestBackupPlanWarnsOnUnopenedNewerManifest(t *testing.T) {
	w := newWorld(t, 66)
	w.postAt(w.keyAt(1), 1, false)
	w.dropAnchor()
	k0 := w.keyAt(0)
	o := backup.Options{ConfigPath: w.cfgPath, ValidatorsPath: w.valPath, Key: k0}
	warns, err := bindPlan(&o, w.ledger, k0, w.writer.Address())
	must(t, err)
	if !strings.Contains(strings.Join(warns, "\n"), unopenedAfter) {
		t.Fatalf("an epoch 0 key file plans seq %d with no warning although an epoch 1 backup landed later; warnings: %q", o.Seq, warns)
	}
}

// --allow-tombstoned falls back to an older backup. That fallback must give
// the same stale-epoch warning as --backup-id: here the only real backup
// newer than the operator's is one posted with the old key after rotating.
func TestAllowTombstonedWarnsOnStaleEpoch(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	w := newWorld(t, 67)
	w.postAt(w.keyAt(1), 1, true) // the operator rotates and retires everything
	must(t, os.WriteFile(w.valPath, []byte("[validator_list_sites]\nhttps://vl.attacker.example\n"), 0o644))
	w.postAt(w.keyAt(0), 9, false) // old-key holder posts after the rotation
	r := w.restoreWords("--allow-tombstoned")
	if r.code != exitOK || !strings.Contains(r.out, "is from epoch 0, but a backup from epoch 1 exists") || !strings.Contains(r.out, "landed on the ledger after the first epoch 1 backup") {
		t.Fatalf("--allow-tombstoned onto a post-rotation epoch 0 backup must warn, got exit %d:\n%s", r.code, r.out)
	}
}

// --backup-id naming a tombstone, with --allow-tombstoned, restores the
// newest real backup older than that tombstone, never a newer one. The
// seq 1 bundle makes the restore byte-exact.
func TestAllowTombstonedHonoursBackupID(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	w := newWorld(t, 68)
	before, _ := os.ReadFile(w.valPath)
	tomb := w.postAt(w.key, 2, true)
	must(t, os.WriteFile(w.valPath, []byte("[validator_list_sites]\nhttps://after-the-tombstone.example\n"), 0o644))
	w.postAt(w.key, 3, false)
	r := w.restoreWords("--backup-id", tomb.Manifest.BackupID[:12], "--allow-tombstoned", "--bundle", w.bundle)
	if r.code != exitOK || !strings.Contains(r.out, "using backup "+w.plan.Manifest.BackupID[:16]) {
		t.Fatalf("must restore seq 1, the backup older than the named tombstone, got exit %d:\n%s", r.code, r.out)
	}
	if got := restoredFile(t, r.out, "validators.txt"); got != string(before) {
		t.Fatalf("restored validators.txt is not the seq 1 backup:\n%s", got)
	}
}
