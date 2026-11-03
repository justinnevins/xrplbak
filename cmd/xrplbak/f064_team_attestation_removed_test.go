package main

import (
	"strings"
	"testing"
)

// F-064: backup --attestation copied any hex into the encrypted manifest
// without checking it, so a signature over the wrong string, or over the
// string a seq 1 dry run printed when the ledger already held seq 1, was
// published for good and read as INVALID. The team attestation is removed:
// both flags now refuse before a plan is built or a server is opened.
func TestF064TeamAttestationFlagsRefused(t *testing.T) {
	w := newWorld(t, 64)
	vpk, _ := validatorKey(t)
	for _, extra := range [][]string{
		{"--attestation-key", vpk},
		{"--attestation", "00", "--attestation-key", vpk},
		{"--attestation", "00", "--attestation-key", vpk, "--submit", "--yes"},
	} {
		args := append([]string{"backup", "--config", w.cfgPath, "--key", w.keyFile, "--out", t.TempDir()}, extra...)
		r := w.run("", args...)
		if r.code != exitUsage || !strings.Contains(r.out, "removed in v1.1.6") || !strings.Contains(r.out, "--attest") {
			t.Errorf("backup %v must refuse with exit %d and name --attest, got exit %d:\n%s", extra, exitUsage, r.code, r.out)
		}
		if strings.Contains(r.out, "xrplbak/v1/attest ") {
			t.Errorf("backup %v still prints the team string to sign:\n%s", extra, r.out)
		}
	}
}
