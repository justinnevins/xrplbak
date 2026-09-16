package main

import (
	"strings"
	"testing"
)

// TestNoAccountSaysWhatIsMissing pins the one message both cold-read
// evaluators hit. With no --account and no key file, the tool prompted,
// read nothing from a script's stdin, and reported "not a valid XRPL
// classic address: " with nothing after the colon. It named a malformed
// address when no address had been supplied at all.
func TestNoAccountSaysWhatIsMissing(t *testing.T) {
	w := newWorld(t, 0)
	r := w.run("", "restore", "--dump", w.dumpFile("case"), "--words-file", w.words)
	if r.code != exitUsage {
		t.Fatalf("exit %d, want %d:\n%s", r.code, exitUsage, r.out)
	}
	if !strings.Contains(r.out, "--account") {
		t.Errorf("the message does not name the flag that fixes it:\n%s", r.out)
	}
	if strings.Contains(r.out, "not a valid XRPL classic address: \n") {
		t.Errorf("the message still blames a malformed address:\n%s", r.out)
	}
}

// TestBundleMissingIsNotCalledIncomplete pins a word that meant two things.
// The per-file label said INCOMPLETE for the ordinary, expected case of a
// restore without the bundle, while exit code 5 is documented as
// "incomplete: a chunk is missing from the searched history". The second
// evaluator read the exit-code table twice, unsure whether it had broken
// something, because the run said INCOMPLETE and exited 0.
func TestBundleMissingIsNotCalledIncomplete(t *testing.T) {
	w := newWorld(t, 0)
	r := w.run("yes\n", "restore", "--dump", w.dumpFile("case"),
		"--words-file", w.words, "--account", w.writer.Address())
	if r.code != exitOK {
		t.Fatalf("exit %d, want %d:\n%s", r.code, exitOK, r.out)
	}
	if strings.Contains(r.out, "INCOMPLETE") {
		t.Errorf("a bundle-less restore still uses the exit-5 word:\n%s", r.out)
	}
	if !strings.Contains(r.out, "bundle missing") {
		t.Errorf("the report does not say what is missing:\n%s", r.out)
	}
	// And it says the content is not somewhere else to be found.
	if !strings.Contains(r.out, "only in the bundle") {
		t.Errorf("the report does not say the content exists nowhere else:\n%s", r.out)
	}
}
