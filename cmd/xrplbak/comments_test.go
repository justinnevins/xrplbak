package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCommentsOnChainNeedsAnAcknowledgment pins the override's guard rail.
// Putting the operator's own prose into the on-chain ciphertext is a
// deliberate act: the bytes are public and permanent. The safe destination is
// the default, and the override is confirmed by hand.
func TestCommentsOnChainNeedsAnAcknowledgment(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	w := newWorld(t, 0)
	args := []string{"backup", "--config", w.cfgPath, "--key", w.keyFile,
		"--out", filepath.Join(w.dir, "out"), "--comments=onchain"}

	// Nothing typed: refused, and the run stops.
	r := w.run("\n", args...)
	if r.code != exitUsage {
		t.Fatalf("exit %d, want %d", r.code, exitUsage)
	}
	if !strings.Contains(r.out, "not confirmed") {
		t.Fatalf("output lacks the refusal: %s", r.out)
	}

	// The wrong words are not an acknowledgment either.
	if r := w.run("yes\n", args...); r.code != exitUsage {
		t.Fatalf("a casual yes was accepted: exit %d", r.code)
	}

	// The phrase itself goes through, and the run says so.
	r = w.run(ackPhrase+"\n", args...)
	if r.code != exitOK {
		t.Fatalf("exit %d, want %d:\n%s", r.code, exitOK, r.out)
	}
	if !strings.Contains(r.out, "acknowledged") {
		t.Fatalf("an acknowledged run must say so: %s", r.out)
	}
}

// TestCommentsFlagRejectsUnknownValues keeps a typo from silently choosing a
// destination for the operator.
func TestCommentsFlagRejectsUnknownValues(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	w := newWorld(t, 0)
	for _, v := range []string{"on-chain", "ledger", "drop", ""} {
		r := w.run("", "redact", "--config", w.cfgPath, "--comments="+v)
		if r.code != exitUsage {
			t.Fatalf("--comments=%q was accepted: exit %d", v, r.code)
		}
	}
}

// TestRedactShowsWhereCommentsGo is the operator's way to see the split
// before anything is encrypted. redact publishes nothing, so it needs no
// acknowledgment, and the two modes must visibly differ.
func TestRedactShowsWhereCommentsGo(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	w := newWorld(t, 0)
	const note = "# rebuilt after the March load test\n"
	raw, err := os.ReadFile(w.cfgPath)
	must(t, err)
	must(t, os.WriteFile(w.cfgPath, append([]byte(note), raw...), 0o600))

	read := func(mode, sub string) string {
		dir := filepath.Join(w.dir, "split-"+mode)
		r := w.run("", "redact", "--config", w.cfgPath, "--comments="+mode, "--out", dir)
		if r.code != exitOK {
			t.Fatalf("redact --comments=%s: exit %d\n%s", mode, r.code, r.out)
		}
		b, err := os.ReadFile(filepath.Join(dir, sub, "xrpld.cfg"))
		must(t, err)
		return string(b)
	}

	if on := read("bundle", "onchain"); strings.Contains(on, "March load test") {
		t.Fatalf("the default put a comment on-chain:\n%s", on)
	}
	if b := read("bundle", "bundle"); !strings.Contains(b, "March load test") {
		t.Fatalf("the comment was not kept in the bundle:\n%s", b)
	}
	if on := read("onchain", "onchain"); !strings.Contains(on, "March load test") {
		t.Fatalf("--comments=onchain did not keep the comment on-chain:\n%s", on)
	}
}
