package redact

import (
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/cfg"
)

// TestLoopbackAdminStaysOnChain pins that an admin or secure_gateway list
// made only of loopback addresses stays on-chain. 127.0.0.1 and ::1 say
// nothing about the operator's network, and moving them made every
// bundle-less restore report a missing line for a value any operator
// would type the same way. A list with any other address still moves.
func TestLoopbackAdminStaysOnChain(t *testing.T) {
	stays := []string{
		"admin = 127.0.0.1",
		"admin = ::1",
		"admin = 127.0.0.1, ::1",
		"admin=127.0.0.1,::1",
		"admin = 127.0.0.0/8",
		"admin = 127.0.0.1 ::1",
		"secure_gateway = 127.0.0.1",
	}
	moves := []string{
		"admin = 10.0.0.5",
		"admin = 127.0.0.1, 10.0.0.5",
		"admin = 203.0.113.9",
		"admin = 0.0.0.0",
		"admin = ::",
		"admin = 127.0.0.0/7",
		"admin = ::1/127",
		"password = 127.0.0.1",
		"admin =",
		"admin = localhost",
		"user = rpcuser",
		"password = hunter2",
		"admin_password = hunter2",
	}
	for _, line := range stays {
		res, err := Split(cfg.Parse("[port_rpc_admin_local]\nport = 5005\n"+line+"\n"), Options{})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.OnChain.Render(), line+"\n") || len(res.Moves) != 0 {
			t.Fatalf("%q must stay on-chain, got moves %+v:\n%s", line, res.Moves, res.OnChain.Render())
		}
	}
	for _, line := range moves {
		res, err := Split(cfg.Parse("[port_rpc_admin_local]\nport = 5005\n"+line+"\n"), Options{})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(res.OnChain.Render(), line) || len(res.Moves) != 1 {
			t.Fatalf("%q must move to the bundle, got moves %+v:\n%s", line, res.Moves, res.OnChain.Render())
		}
	}
}

// TestPeersOnChainIsOptIn pins --peers. By default [ips_fixed] goes to the
// bundle whole. With PeersOnChain its lines go on-chain, but each line is
// still scanned: a private address, an internal name or a bare hostname
// moves anyway. The validator token and [cluster_nodes] never follow.
func TestPeersOnChainIsOptIn(t *testing.T) {
	const conf = "[ips_fixed]\nr.ripple.com 51235\n203.0.113.7 51235\n10.1.2.3 51235\nhub.corp 51235\nhubhost 51235\n" +
		"[cluster_nodes]\nn9KorY8QtTdRx7TVDpwnG9NvyxsDwHUKUEeDLY3AkiGncVaSXZi5 hub\n" +
		"[validator_token]\neyJ2YWxpZGF0aW9uX3NlY3JldF9rZXkiOiJmYWtlIn0=\n"

	def, err := Split(cfg.Parse(conf), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if on := def.OnChain.Render(); strings.Contains(on, "r.ripple.com") || strings.Contains(on, "203.0.113.7") {
		t.Fatalf("by default [ips_fixed] must go to the bundle:\n%s", on)
	}

	res, err := Split(cfg.Parse(conf), Options{PeersOnChain: true})
	if err != nil {
		t.Fatal(err)
	}
	on := res.OnChain.Render()
	for _, want := range []string{"r.ripple.com 51235\n", "203.0.113.7 51235\n"} {
		if !strings.Contains(on, want) {
			t.Fatalf("with PeersOnChain, public peer %q must be on-chain:\n%s", want, on)
		}
	}
	for _, gone := range []string{"10.1.2.3", "hub.corp", "hubhost", "n9KorY8", "eyJ2YWxp"} {
		if strings.Contains(on, gone) {
			t.Fatalf("with PeersOnChain, %q must still move to the bundle:\n%s", gone, on)
		}
	}
	// The split is still exact.
	if got := Merge(res.OnChain, res.Bundle).Render(); got != conf {
		t.Fatalf("merge is not exact:\n%q\nwant\n%q", got, conf)
	}
}
