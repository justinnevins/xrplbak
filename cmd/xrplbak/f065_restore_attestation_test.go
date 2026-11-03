package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/backup"
	"github.com/justinnevins/xrplbak/internal/manifest"
)

// F-065 gap 2. verify prints an "attestation:" line for a backup that
// carries a team attestation (older backups still do; the write path was
// removed in PR #1). restore read the same manifest and said nothing, so
// a restore from a backup whose attestation is INVALID exited 0 silently.
// restore must print the same line verify prints, valid or INVALID.
func TestF065RestoreReportsAttestation(t *testing.T) {
	for _, valid := range []bool{true, false} {
		w := newWorld(t, 31)
		vpk, priv := validatorKey(t)
		p, err := backup.Build(backup.Options{ConfigPath: w.cfgPath, ValidatorsPath: w.valPath, Key: w.key, Now: time.Unix(1_800_000_002, 0), Seq: 2})
		must(t, err)
		sig := ed25519.Sign(priv, []byte(p.AttestText))
		if !valid {
			sig[0] ^= 0x01
		}
		p.Manifest.Attestation = &manifest.Attestation{Scheme: "ed25519", VPK: vpk, Sig: hex.EncodeToString(sig)}
		w.plan = p
		w.submit(p)
		must(t, os.WriteFile(w.bundle, p.Bundle, 0o600))

		v := w.run("", "verify", "--dump", w.dumpFile("v"), "--words-file", w.words, "--account", w.writer.Address())
		r := w.run("yes\n", "restore", "--dump", w.dumpFile("r"), "--words-file", w.words, "--account", w.writer.Address(), "--bundle", w.bundle, "--write", "--target", filepath.Join(w.dir, "out"), "--yes")
		want := "attestation:   valid ed25519 signature by " + vpk
		if !valid {
			want = "attestation:   INVALID signature for " + vpk
		}
		if !strings.Contains(v.out, want) {
			t.Fatalf("valid=%v: verify lacks %q (test setup):\n%s", valid, want, v.out)
		}
		if !strings.Contains(r.out, want) {
			t.Fatalf("valid=%v: restore lacks the line verify prints, %q:\n%s", valid, want, r.out)
		}
		if r.code != 0 {
			t.Fatalf("valid=%v: restore exit %d; the attestation is reported, not enforced", valid, r.code)
		}
	}
}
