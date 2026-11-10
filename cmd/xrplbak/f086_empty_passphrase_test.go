package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F-086: init --key-passphrase took an empty answer (end of input, or a
// bare Enter twice) and wrote a wrapped key file whose passphrase is the
// empty string. The operator asked for a protected key file and got one
// anyone can open. An empty passphrase is refused and nothing is written.
func TestF086InitRefusesAnEmptyPassphrase(t *testing.T) {
	for name, stdin := range map[string]string{"end of input": "", "bare Enter twice": "\n\n"} {
		dir := t.TempDir()
		var out strings.Builder
		code := run([]string{"init", "--yes", "--key-passphrase", "--out", dir}, strings.NewReader(stdin), &out, &out)
		if code != exitUsage {
			t.Errorf("%s: exit %d, want %d\n%s", name, code, exitUsage, out.String())
		}
		if !strings.Contains(out.String(), "empty passphrase") {
			t.Errorf("%s: the refusal does not say why:\n%s", name, out.String())
		}
		if _, err := os.Stat(filepath.Join(dir, "xrplbak.key")); err == nil {
			t.Errorf("%s: a key file was written", name)
		}
	}
}

func TestF086RotateRefusesAnEmptyPassphrase(t *testing.T) {
	w := newWorld(t, 74)
	before, err := os.ReadFile(w.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	r := w.run("\n\n", "init", "--rotate", "--out", filepath.Dir(w.keyFile), "--words-file", w.words, "--key-passphrase")
	if r.code != exitUsage || !strings.Contains(r.out, "empty passphrase") {
		t.Fatalf("exit %d, want %d with the reason\n%s", r.code, exitUsage, r.out)
	}
	after, _ := os.ReadFile(w.keyFile)
	if string(after) != string(before) {
		t.Fatal("the key file changed though the rotation was refused")
	}
}
