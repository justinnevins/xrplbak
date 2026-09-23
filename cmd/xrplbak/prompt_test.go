package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPromptReadsSuccessiveLines pins that consecutive prompts read
// consecutive lines of stdin. Each prompt built its own bufio.Scanner over
// stdin. A Scanner reads ahead into its own buffer, so the first prompt
// swallowed every answer that followed and the next one saw end of input.
// On a terminal each read returns a single line, so this never showed
// interactively; from a pipe or a file every command that asks twice
// failed on its second question.
func TestPromptReadsSuccessiveLines(t *testing.T) {
	defer swapStreams(strings.NewReader("first\nsecond\nthird\n"), io.Discard)()
	for i, want := range []string{"first", "second", "third"} {
		if got := prompt(""); got != want {
			t.Fatalf("answer %d = %q, want %q", i+1, got, want)
		}
	}
}

// TestTwoPromptsFromAPipe drives the same case through the real command
// surface: init --key-passphrase asks for a passphrase twice, and both
// answers must be read correctly from a pipe.
func TestTwoPromptsFromAPipe(t *testing.T) {
	dir := t.TempDir()
	var out strings.Builder
	code := run([]string{"init", "--out", dir, "--yes", "--key-passphrase"},
		strings.NewReader("correct horse battery\ncorrect horse battery\n"), &out, &out)
	if code != exitOK {
		t.Fatalf("exit %d, want %d:\n%s", code, exitOK, out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "xrplbak.key")); err != nil {
		t.Fatalf("no key file: %v", err)
	}
}

// swapStreams points the package streams at a reader and a writer and
// returns the function that puts them back.
func swapStreams(in io.Reader, out io.Writer) func() {
	oldIn, oldOut := stdin, stdout
	setStdin(in)
	stdout = out
	return func() { setStdin(oldIn); stdout = oldOut }
}
