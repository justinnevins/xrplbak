package main

import (
	"os"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/chunk"
)

// The DID anchor is the operator's statement of which backup is current.
// When that backup's manifest is not in the history being read (a thinned
// dump, a server with partial history) but an older backup is, the tool
// must not quietly restore the older one with exit 0. The current backup
// is unreachable here, and that is an incomplete result.

// withAnchoredManifestGone backs up seq 2 on top of seq 1, then removes
// every manifest part of seq 2 from the ledger. The anchor still names
// seq 2.
func withAnchoredManifestGone(t *testing.T) (*world, string) {
	t.Helper()
	w := newWorld(t, 61)
	p2 := w.build(2, w.cfgPath, w.valPath)
	p2.Manifest.Supersedes = w.plan.Manifest.BackupID
	w.submit(p2)
	for i := len(w.ledger.Txs) - 1; i >= 0; i-- {
		for _, m := range w.ledger.Txs[i].Memos {
			if p, ok := chunk.Decode(m); ok && p.Type == chunk.TypeManifest && p.BackupID == [16]byte(p2.BackupID) {
				w.dropTx(&w.ledger.Txs[i])
				break
			}
		}
	}
	return w, p2.Manifest.BackupID
}

func TestRestoreRefusesWhenAnchoredBackupIsMissing(t *testing.T) {
	w, id2 := withAnchoredManifestGone(t)
	target := w.dir + "/out"
	r := w.restore("--write", "--target", target, "--yes")
	if r.code != exitIncomplete {
		t.Fatalf("exit %d, want %d (incomplete): the anchor names seq 2 and seq 2 is not here", r.code, exitIncomplete)
	}
	if !strings.Contains(r.out, "seq 2") || !strings.Contains(r.out, id2[:16]) {
		t.Fatal("the refusal must name the anchored backup")
	}
	if strings.Contains(r.out, "rollback") {
		t.Fatal("a missing manifest is not a rollback")
	}
	if entries, _ := os.ReadDir(target); len(entries) != 0 {
		t.Fatalf("nothing may be written, found %d entries", len(entries))
	}
}

func TestRestoreWithBackupIDUsesTheOlderBackupDeliberately(t *testing.T) {
	w, _ := withAnchoredManifestGone(t)
	target := w.dir + "/out"
	r := w.restore("--write", "--target", target, "--yes", "--backup-id", w.plan.Manifest.BackupID[:16])
	if r.code != exitOK {
		t.Fatalf("exit %d: --backup-id is the explicit choice of the older backup", r.code)
	}
}

func TestVerifyRefusesWhenAnchoredBackupIsMissing(t *testing.T) {
	w, id2 := withAnchoredManifestGone(t)
	r := w.run("", "verify", "--dump", w.dumpFile("v"), "--words-file", w.words, "--account", w.writer.Address(), "--bundle", w.bundle)
	if r.code != exitIncomplete {
		t.Fatalf("exit %d, want %d", r.code, exitIncomplete)
	}
	if !strings.Contains(r.out, id2[:16]) {
		t.Fatal("the refusal must name the anchored backup")
	}
}

// A sibling at the anchor's own seq is not the anchored backup either.
func TestRestoreRefusesWhenOnlyASiblingAtTheAnchoredSeqRemains(t *testing.T) {
	w := newWorld(t, 62)
	sibling := w.build(2, fixtures+"validator-full.cfg", w.valPath)
	w.submit(sibling)
	anchored := w.build(2, w.cfgPath, w.valPath)
	w.submit(anchored)
	if sibling.Manifest.BackupID == anchored.Manifest.BackupID {
		t.Fatal("the two seq 2 backups must differ")
	}
	for i := len(w.ledger.Txs) - 1; i >= 0; i-- {
		for _, m := range w.ledger.Txs[i].Memos {
			if p, ok := chunk.Decode(m); ok && p.Type == chunk.TypeManifest && p.BackupID == [16]byte(anchored.BackupID) {
				w.dropTx(&w.ledger.Txs[i])
				break
			}
		}
	}
	r := w.restore("--write", "--target", w.dir+"/out", "--yes")
	if r.code != exitIncomplete || !strings.Contains(r.out, anchored.Manifest.BackupID[:16]) {
		t.Fatalf("exit %d: the anchored backup is gone and the one at its seq is a different backup", r.code)
	}
}
