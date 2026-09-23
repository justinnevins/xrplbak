package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteCanBeConfirmedUpFront pins that --write and --submit can be
// confirmed up front. Both stop on a yes/no question that their own flag
// help does not mention, so a script that pipes no answer gets "cancelled;
// nothing was written", which reads as the operator's mistake rather than
// the tool's. init already has --yes; restore and backup did not.
func TestWriteCanBeConfirmedUpFront(t *testing.T) {
	w := newWorld(t, 0)
	target := filepath.Join(w.dir, "placed")
	must(t, os.MkdirAll(target, 0o700))

	args := []string{"restore", "--dump", w.dumpFile("case"), "--words-file", w.words,
		"--account", w.writer.Address(), "--bundle", w.bundle,
		"--write", "--target", target, "--yes"}

	// Empty stdin, the way a script runs it.
	r := w.run("", args...)
	if r.code != exitOK {
		t.Fatalf("exit %d, want %d:\n%s", r.code, exitOK, r.out)
	}
	names, err := os.ReadDir(target)
	must(t, err)
	if len(names) == 0 {
		t.Fatal("--yes was accepted but nothing was written")
	}
}

// TestCancelMessageNamesTheWayOut pins that whoever hits the prompt from a
// script is told what to pass instead.
func TestCancelMessageNamesTheWayOut(t *testing.T) {
	w := newWorld(t, 0)
	target := filepath.Join(w.dir, "placed")
	must(t, os.MkdirAll(target, 0o700))
	r := w.run("", "restore", "--dump", w.dumpFile("case"), "--words-file", w.words,
		"--account", w.writer.Address(), "--bundle", w.bundle,
		"--write", "--target", target)
	if r.code != exitUsage {
		t.Fatalf("exit %d, want %d", r.code, exitUsage)
	}
	if !strings.Contains(r.out, "--yes") {
		t.Fatalf("the cancel message does not say how to answer in a script:\n%s", r.out)
	}
}

// TestConfirmingFlagsSayTheyAsk pins the other half: the flag that triggers
// the question says so where the operator looks for it.
func TestConfirmingFlagsSayTheyAsk(t *testing.T) {
	for _, c := range []struct{ cmd, flag string }{
		{"restore", "write"}, {"backup", "submit"},
	} {
		var out strings.Builder
		run([]string{c.cmd, "-h"}, strings.NewReader(""), &out, &out)
		help := out.String()
		// The flag entry is indented by two spaces. Matching on the bare
		// name also hits the one-line summary above ("dry run unless
		// --write"), which is not where an operator looks for the flag.
		i := strings.Index(help, "\n  -"+c.flag+"\n")
		if i < 0 {
			t.Fatalf("%s -h does not list -%s:\n%s", c.cmd, c.flag, help)
		}
		line := help[i+1:]
		if j := strings.Index(line[1:], "\n  -"); j >= 0 {
			line = line[:j+1]
		}
		if !strings.Contains(line, "--yes") {
			t.Errorf("%s -h does not say that -%s asks for confirmation:\n%s", c.cmd, c.flag, line)
		}
	}
}
