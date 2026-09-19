package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDamagedPlainKeyFileIsNamedDamaged. Same shape as F-027 for the
// wrapped file, now for the plain one: a flipped bit inside the epoch key
// used to decode cleanly into a different key, and verify then told the
// operator the ledger held no backup. The operator must be sent to the
// file, with the two ways forward (recovery words, or init --rotate).
func TestDamagedPlainKeyFileIsNamedDamaged(t *testing.T) {
	w := newWorld(t, 0)
	b, err := os.ReadFile(w.keyFile)
	must(t, err)
	bad := append([]byte{}, b...)
	bad[20] ^= 0x10 // inside the epoch key
	p := filepath.Join(w.dir, "damaged.key")
	must(t, os.WriteFile(p, bad, 0o600))
	r := w.run("", "verify", "--dump", w.dumpFile("case"), "--key", p)
	if r.code != exitAuth {
		t.Fatalf("exit %d, want %d:\n%s", r.code, exitAuth, r.out)
	}
	if strings.Contains(r.out, "no backup authenticates") {
		t.Fatalf("a damaged key file was blamed on the ledger:\n%s", r.out)
	}
	if !strings.Contains(r.out, "damaged") || !strings.Contains(r.out, "recovery words") {
		t.Fatalf("the message does not name the damage and the way forward:\n%s", r.out)
	}
}
