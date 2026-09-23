package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/crypto"
)

// These four cases cover the recovery paths: none of them writes a wrong
// byte, but each one told the operator something untrue or silently
// ignored what they asked for, during the one ceremony they cannot
// practise.

// TestThresholdWithoutSharesIsRefused pins a flag that did nothing. init
// applied --threshold only inside the --shares branch, so
// "init --threshold 5" produced the ordinary 24-word key and never said the
// threshold had been dropped.
func TestThresholdWithoutSharesIsRefused(t *testing.T) {
	dir := t.TempDir()
	var out strings.Builder
	code := run([]string{"init", "--out", dir, "--threshold", "5", "--yes"},
		strings.NewReader(""), &out, &out)
	if code != exitUsage {
		t.Fatalf("exit %d, want %d (--threshold without --shares must be refused):\n%s", code, exitUsage, out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "xrplbak.key")); err == nil {
		t.Fatal("a key file was written by a run that should have been refused")
	}
}

// TestWordsAndSharesTogetherAreRefused pins a silent priority. Passing both
// --words-file and --shares-file took the words and never opened the shares,
// so a stale or wrong words file quietly beat the correct shares. The tool
// already refuses --rpc with --dump for the same reason.
func TestWordsAndSharesTogetherAreRefused(t *testing.T) {
	w := newWorld(t, 0)
	sharesPath := filepath.Join(w.dir, "shares.txt")
	must(t, os.WriteFile(sharesPath, []byte("ignored\n"), 0o600))
	r := w.run("", "restore", "--dump", w.dumpFile("case"),
		"--words-file", w.words, "--shares-file", sharesPath,
		"--account", w.writer.Address())
	if r.code != exitUsage {
		t.Fatalf("exit %d, want %d", r.code, exitUsage)
	}
	if !strings.Contains(r.out, "not both") {
		t.Fatalf("the message does not say the two conflict:\n%s", r.out)
	}
}

// TestNegativeEpochIsRefused pins a flag that was accepted and dropped. Only
// -1 means "unset"; any other negative value was parsed, silently ignored,
// and the run continued on a different epoch than the operator named.
func TestNegativeEpochIsRefused(t *testing.T) {
	w := newWorld(t, 0)
	r := w.run("yes\n", "restore", "--dump", w.dumpFile("case"),
		"--words-file", w.words, "--account", w.writer.Address(), "--epoch", "-5")
	if r.code != exitUsage {
		t.Fatalf("exit %d, want %d:\n%s", r.code, exitUsage, r.out)
	}
}

// TestShareReentryAcceptsLookalikes pins a rule that existed twice and
// drifted. decodeShare deliberately maps O to 0 and I and L to 1, because a
// share gets copied off paper by hand. The re-entry check had its own
// normalizer without that mapping, so it rejected a re-entry that the
// decoder would have accepted, and aborted init with nothing written.
func TestShareReentryAcceptsLookalikes(t *testing.T) {
	root, err := crypto.NewRootKey()
	must(t, err)
	lines, err := root.Split(3, 2)
	must(t, err)

	// What a careful person might write down and type back.
	retyped := strings.NewReplacer("0", "O", "1", "I").Replace(lines[0])
	if retyped == lines[0] {
		t.Skip("this share has no look-alike characters in it")
	}
	if !sameShare(retyped, lines[0]) {
		t.Errorf("the re-entry check rejected a share the decoder accepts:\n  wrote %q\n  typed %q", lines[0], retyped)
	}
	// And it still catches a share that is actually different.
	if sameShare(lines[1], lines[0]) {
		t.Error("the re-entry check accepted a different share")
	}
}
