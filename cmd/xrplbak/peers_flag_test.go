package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPeersOnChainNeedsTheAcknowledgment pins that backup --peers=onchain
// asks the operator to type PUBLISH PEERS, the same pattern as
// --comments=onchain, and that redact, which publishes nothing, does not ask.
func TestPeersOnChainNeedsTheAcknowledgment(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	w := newWorld(t, 0)
	cfgPath := filepath.Join(w.dir, "peers.cfg")
	must(t, os.WriteFile(cfgPath, []byte("[server]\nport_peer\n\n[port_peer]\nport = 51235\nip = 0.0.0.0\nprotocol = peer\n\n[ips_fixed]\nr.ripple.com 51235\n"), 0o600))
	base := []string{"backup", "--config", cfgPath, "--validators", w.valPath, "--key", w.keyFile, "--out", filepath.Join(w.dir, "out"), "--peers=onchain"}

	if r := w.run("", base...); r.code != exitUsage || !strings.Contains(r.out, "not confirmed") {
		t.Fatalf("--peers=onchain without the acknowledgment must stop with exit 1, got %d:\n%s", r.code, r.out)
	}
	if r := w.run("PUBLISH PEERS\n", base...); r.code != exitOK || !strings.Contains(r.out, "acknowledged: public fixed peers") {
		t.Fatalf("--peers=onchain with the acknowledgment must proceed, got %d:\n%s", r.code, r.out)
	}
	if r := w.run("", "backup", "--config", cfgPath, "--key", w.keyFile, "--peers=maybe"); r.code != exitUsage {
		t.Fatalf("--peers=maybe must be a usage error, got %d", r.code)
	}
	r := w.run("", "redact", "--config", cfgPath, "--validators", w.valPath, "--peers=onchain")
	if r.code != exitOK || strings.Contains(r.out, "PUBLISH PEERS") || strings.Contains(r.out, "[ips_fixed]") {
		t.Fatalf("redact --peers=onchain must not ask and must keep the public peer on-chain, got %d:\n%s", r.code, r.out)
	}
	r = w.run("", "redact", "--config", cfgPath, "--validators", w.valPath)
	if r.code != exitOK || !strings.Contains(r.out, "[ips_fixed]") {
		t.Fatalf("redact by default must report [ips_fixed] as moved, got %d:\n%s", r.code, r.out)
	}
}
