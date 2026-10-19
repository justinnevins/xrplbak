package main

import (
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/crypto"
)

// The recovery words derive every epoch key, so a backup from any epoch
// can be opened. The anchor may move the search up to the newest epoch;
// it must not pull the floor up with it. An operator naming a backup from
// epoch 0 under an epoch 70 anchor is asking for something the words can
// open.

// withAnchorFarAbove backs up at epoch 70 on top of the epoch 0 backup,
// so the anchor names epoch 70. It returns the epoch 0 backup id.
func withAnchorFarAbove(t *testing.T) (*world, string) {
	t.Helper()
	w := newWorld(t, 64)
	w.key = &crypto.KeyFile{Epoch: 70, Key: w.root.DeriveEpochKey(70)}
	copy(w.key.AccountID[:], w.writer.AccountID())
	copy(w.key.WriterSeed[:], w.writer.Seed())
	w.submit(w.build(1, w.cfgPath, w.valPath))
	return w, w.plan.Manifest.BackupID
}

func TestBackupIDReachesAnEpochFarBelowTheAnchor(t *testing.T) {
	for _, extra := range [][]string{nil, {"--epoch", "0"}} {
		w, id0 := withAnchorFarAbove(t)
		r := w.restore(append([]string{"--backup-id", id0[:16]}, extra...)...)
		if r.code != exitOK {
			t.Fatalf("%v: exit %d, want 0: the words open epoch 0", extra, r.code)
		}
		if !strings.Contains(r.out, "is from epoch 0, but a backup from epoch 70 exists") {
			t.Fatal("the stale-epoch warning must still be given")
		}
	}
}

func TestEpochFlagKeepsTheSixtyFourEpochWindow(t *testing.T) {
	// --epoch 64 reaches down to epoch 1, so epoch 0 stays closed.
	// --epoch 63 reaches epoch 0. The window is 64 epochs including the
	// start, as documented.
	for _, c := range []struct {
		epoch string
		code  int
	}{{"64", exitAuth}, {"63", exitOK}} {
		w, id0 := withAnchorFarAbove(t)
		r := w.restore("--backup-id", id0[:16], "--epoch", c.epoch)
		if r.code != c.code {
			t.Fatalf("--epoch %s: exit %d, want %d", c.epoch, r.code, c.code)
		}
	}
}
