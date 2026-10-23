package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestRestoreSaysOwnerIsNotRestored pins the note from the first Mainnet run
// (2026-10-20). A backup keeps each file's mode but not its owner or group.
// xrpld runs as its own user, so a restored config owned by root and made
// unreadable to that user stops xrpld at its next start. Both the dry run
// and --write say so.
func TestRestoreSaysOwnerIsNotRestored(t *testing.T) {
	w := newWorld(t, 0x51)
	dry := w.restore()
	if dry.code != exitOK {
		t.Fatalf("dry run exit %d", dry.code)
	}
	if !strings.Contains(dry.out, "Owner and group are not restored") {
		t.Errorf("dry run does not say owner and group are not restored:\n%s", dry.out)
	}
	wr := w.restore("--write", "--target", filepath.Join(w.dir, "out"), "--yes")
	if wr.code != exitOK {
		t.Fatalf("--write exit %d", wr.code)
	}
	for _, want := range []string{"not its owner or group", "systemctl show -p User", "restore-ceremony.md step 9"} {
		if !strings.Contains(wr.out, want) {
			t.Errorf("--write output lacks %q:\n%s", want, wr.out)
		}
	}
}
