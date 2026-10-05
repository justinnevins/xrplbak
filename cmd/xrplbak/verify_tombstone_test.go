package main

import (
	"strings"
	"testing"
)

// verify without --bundle prints the bundle hash the manifest expects. A
// tombstone has no bundle and an empty hash, and slicing it crashed verify
// with a Go stack trace (exit 2) after it had printed the tombstone line.
// The README exit-code table says a tombstone as the newest backup is
// incomplete, exit 5, the same as restore.
func TestVerifyTombstoneWithoutBundle(t *testing.T) {
	w := newWorld(t, 71)
	w.postAt(w.key, 2, true)
	var r result
	func() {
		defer func() {
			if p := recover(); p != nil {
				t.Fatalf("verify panicked on a tombstone: %v", p)
			}
		}()
		r = w.run("", "verify", "--dump", w.dumpFile("v"), "--words-file", w.words, "--account", w.writer.Address())
	}()
	if r.code != exitIncomplete || !strings.Contains(r.out, "tombstone: earlier backups are retired") {
		t.Fatalf("verify on a tombstone must say so and exit %d, got exit %d:\n%s", exitIncomplete, r.code, r.out)
	}
	if strings.Contains(r.out, "expected sha256") {
		t.Fatalf("a tombstone has no bundle; verify must not print an expected bundle hash:\n%s", r.out)
	}
}

// The manifest is authenticated, but whoever holds the epoch key writes
// it. A short bundle hash in a real backup must not crash verify either.
func TestVerifyShortBundleHashDoesNotPanic(t *testing.T) {
	w := newWorld(t, 72)
	p := w.build(2, w.cfgPath, w.valPath)
	p.Manifest.Bundle.CipherSHA256 = "abc"
	w.submit(p)
	var r result
	func() {
		defer func() {
			if p := recover(); p != nil {
				t.Fatalf("verify panicked on a short bundle hash: %v", p)
			}
		}()
		r = w.run("", "verify", "--dump", w.dumpFile("v"), "--words-file", w.words, "--account", w.writer.Address())
	}()
	if !strings.Contains(r.out, "* epoch 0 seq 2") || !strings.Contains(r.out, "expected sha256 abc") {
		t.Fatalf("verify must select seq 2 and print the short hash as it is, got exit %d:\n%s", r.code, r.out)
	}
}
