package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F-109: init parsed these flags, dropped them, and went on. The operator
// who asked for a split key got a 24-word key and no message. Each case
// must stop with a usage error that names the flag, before a key exists.
func TestInitRefusesFlagsItWouldDrop(t *testing.T) {
	cases := []struct {
		args []string
		name string
	}{
		{[]string{"--shares", "-3"}, "--shares"},
		{[]string{"--shares", "-1", "--threshold", "2"}, "--shares"},
		{[]string{"--shares", "3", "--threshold", "-2"}, "--threshold"},
		{[]string{"--words-file", "/nonexistent"}, "--words-file"},
		{[]string{"--shares-file", "/nonexistent"}, "--shares-file"},
	}
	for _, c := range cases {
		dir := t.TempDir()
		var out bytes.Buffer
		code := run(append([]string{"init", "--out", dir, "--yes"}, c.args...), strings.NewReader(""), &out, &out)
		if code != exitUsage {
			t.Errorf("init %v: exit %d, want %d (usage)", c.args, code, exitUsage)
		}
		if !strings.Contains(out.String(), c.name) {
			t.Errorf("init %v: the message does not name %s:\n%s", c.args, c.name, out.String())
		}
		if _, err := os.Stat(filepath.Join(dir, "xrplbak.key")); err == nil {
			t.Errorf("init %v: a key file was written", c.args)
		}
	}
}

// F-109, the rotate half: --rotate returned before the share checks ran,
// so --shares and --threshold were dropped and the key rotated anyway.
func TestRotateRefusesShareFlags(t *testing.T) {
	for _, extra := range [][]string{{"--shares", "5", "--threshold", "9"}, {"--shares", "3"}, {"--threshold", "2"}} {
		dir, _, keyPath, good, _ := rotateWorld(t)
		before, err := os.ReadFile(keyPath)
		must(t, err)
		var out bytes.Buffer
		args := append([]string{"init", "--rotate", "--out", dir, "--words-file", good}, extra...)
		code := run(args, strings.NewReader(""), &out, &out)
		if code != exitUsage {
			t.Errorf("init --rotate %v: exit %d, want %d (usage)\n%s", extra, code, exitUsage, out.String())
		}
		if !strings.Contains(out.String(), extra[0]) {
			t.Errorf("init --rotate %v: the message does not name %s:\n%s", extra, extra[0], out.String())
		}
		after, err := os.ReadFile(keyPath)
		must(t, err)
		if !bytes.Equal(before, after) {
			t.Errorf("init --rotate %v: the key file changed", extra)
		}
	}
}

// F-110: with --words-file or --shares-file the key file flags were never
// looked at, not even for a path that does not exist. Two recovery sources
// is a usage error (as F-028 made it for words with shares), and it must
// be refused before any ledger or dump read.
func TestKeyFileFlagsRefusedWithRecoveryKeyFlags(t *testing.T) {
	cases := [][]string{
		{"--words-file", "words.txt", "--key", "/nonexistent/x.key"},
		{"--shares-file", "shares.txt", "--key", "/nonexistent/x.key"},
		{"--words-file", "words.txt", "--key-passphrase"},
		{"--shares-file", "shares.txt", "--key-passphrase"},
	}
	for _, cmd := range []string{"restore", "verify"} {
		for _, c := range cases {
			var out bytes.Buffer
			// The dump does not exist either. A usage refusal that names
			// --key shows the check ran before the dump was opened.
			args := append([]string{cmd, "--dump", "/nonexistent/case.dump.json", "--account", "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"}, c...)
			code := run(args, strings.NewReader(""), &out, &out)
			if code != exitUsage {
				t.Errorf("%s %v: exit %d, want %d (usage)\n%s", cmd, c, code, exitUsage, out.String())
			}
			if !strings.Contains(out.String(), "--key") || !strings.Contains(out.String(), c[0]) {
				t.Errorf("%s %v: the message does not name both sources:\n%s", cmd, c, out.String())
			}
		}
	}
}

// F-111: an xrplbak.key in the working directory is picked up without
// being named. When it cannot be opened, the old message said to restore
// with the recovery words, but the next run picked up the same file and
// never reached the words prompt. xrplbak does not switch key source on
// its own (fail closed), so the error must say where the file came from
// and name the way to the recovery words that works.
func TestUnopenableKeyFileInWorkingDirNamesTheWayOut(t *testing.T) {
	w := newWorld(t, 0)
	wrapped, err := w.key.EncodeWrapped([]byte("pw"))
	must(t, err)
	damaged := w.key.Encode()
	damaged[20] ^= 1
	words := strings.Join(w.root.ToWords(), " ") + "\n"
	for name, keyBytes := range map[string][]byte{"wrapped with another passphrase": wrapped, "one byte flipped": damaged} {
		cwd := t.TempDir()
		t.Chdir(cwd)
		must(t, os.WriteFile(filepath.Join(cwd, "xrplbak.key"), keyBytes, 0o600))
		r := w.run(words, "restore", "--dump", w.dumpFile("case"), "--account", w.writer.Address(), "--bundle", w.bundle)
		if r.code != exitAuth {
			t.Errorf("%s: exit %d, want %d (auth)", name, r.code, exitAuth)
		}
		for _, want := range []string{"xrplbak.key", "working directory", "--words-file"} {
			if !strings.Contains(r.out, want) {
				t.Errorf("%s: the message does not say %q:\n%s", name, want, r.out)
			}
		}
		// The way out the message names must work from the same directory.
		r = w.run("", "restore", "--dump", w.dumpFile("case"), "--account", w.writer.Address(), "--bundle", w.bundle, "--words-file", w.words)
		if r.code != exitOK {
			t.Errorf("%s: restore with --words-file from the same directory: exit %d", name, r.code)
		}
	}
}

// F-111, the other half: a key file the operator named with --key is not a
// surprise, so its error keeps the plain message without the hint.
func TestNamedKeyFileErrorHasNoWorkingDirHint(t *testing.T) {
	w := newWorld(t, 0)
	damaged := w.key.Encode()
	damaged[20] ^= 1
	p := filepath.Join(t.TempDir(), "xrplbak.key")
	must(t, os.WriteFile(p, damaged, 0o600))
	r := w.run("", "restore", "--dump", w.dumpFile("case"), "--account", w.writer.Address(), "--bundle", w.bundle, "--key", p)
	if r.code != exitAuth {
		t.Errorf("exit %d, want %d (auth)", r.code, exitAuth)
	}
	if strings.Contains(r.out, "working directory") {
		t.Errorf("a key file named with --key was described as found in the working directory:\n%s", r.out)
	}
}
