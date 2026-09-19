package main

import (
	"strings"
	"testing"
)

// TestBundlelessRestoreExitsZeroAndSaysPartial pins the exit-code contract the
// README described ambiguously (F-038, fifth cold read). A restore without the
// bundle is the expected, documented case: it exits 0 and prints PARTIAL. Exit
// code 5 is a different case, a chunk missing from the ledger, and the corpus
// pins that one. An operator scripting on the exit code must be able to trust
// that 0 here does not mean "nothing missing"; the word PARTIAL and the steps
// carry that, and the README now says so.
func TestBundlelessRestoreExitsZeroAndSaysPartial(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	w := newWorld(t, 0)
	// A dump restore with the words and the account but no --bundle.
	args := []string{"restore", "--dump", w.dumpFile("case"),
		"--words-file", w.words, "--account", w.writer.Address()}
	r := w.run("yes\n", args...)
	if r.code != exitOK {
		t.Fatalf("bundle-less restore exit %d, want 0 (exitOK):\n%s", r.code, r.out)
	}
	if !strings.Contains(r.out, "PARTIAL") {
		t.Fatalf("bundle-less restore did not print PARTIAL:\n%s", r.out)
	}
	if !strings.Contains(r.out, "kept only in the bundle") {
		t.Fatalf("bundle-less restore did not explain the missing content:\n%s", r.out)
	}
}
