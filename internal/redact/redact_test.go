package redact

import (
	"os"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/cfg"
)

func load(t *testing.T, name string) *cfg.File {
	t.Helper()
	b, err := os.ReadFile("../../tests/fixtures/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Parse(string(b))
}

func TestSplitValidator(t *testing.T) {
	res, err := Split(load(t, "validator-full.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Role != "validator" {
		t.Fatal("role")
	}
	on := res.OnChain.Canonical()
	for _, forbidden := range []string{"eyJ2YWxp", "10.20.30.40", "10.0.0.5", "peer.example.internal", "log_level", "admin ="} {
		if strings.Contains(on, forbidden) {
			t.Fatalf("on-chain text contains %q:\n%s", forbidden, on)
		}
	}
	for _, want := range []string{"[node_db]", "online_delete=512", "[port_peer]", "ip = 0.0.0.0", "[validator_token]\n" + MovedMarker, "[peer_private]\n" + MovedMarker} {
		if !strings.Contains(on, want) {
			t.Fatalf("on-chain text lacks %q:\n%s", want, on)
		}
	}
	b := res.Bundle
	if b.Get("validator_token") == nil || b.Get("ips_fixed") == nil || b.Get("port_ws_admin_local") == nil {
		t.Fatal("bundle stanzas")
	}
	if len(b.Get("port_ws_admin_local").Lines) != 1 {
		t.Fatalf("only the admin line moves: %v", b.Get("port_ws_admin_local").Lines)
	}
	// port_rpc_admin_local keeps ip=127.0.0.1 on-chain, moves admin line.
	if !strings.Contains(on, "[port_rpc_admin_local]\nport = 5005\nip = 127.0.0.1\n"+MovedMarker+"\nprotocol = http\n") {
		t.Fatalf("port split:\n%s", on)
	}
}

func TestRefuseNodeSeed(t *testing.T) {
	_, err := Split(load(t, "node-with-seed.cfg"))
	re, ok := err.(*RefusedError)
	if !ok || re.Stanza != "node_seed" {
		t.Fatalf("want node_seed refusal, got %v", err)
	}
}

func TestRefuseSeedPatternAnywhere(t *testing.T) {
	_, err := Split(load(t, "node-seed-in-wrong-stanza.cfg"))
	if _, ok := err.(*RefusedError); !ok {
		t.Fatalf("want refusal, got %v", err)
	}
	f := cfg.Parse("[node_size]\n-----BEGIN PRIVATE KEY-----\n")
	if _, err := Split(f); err == nil {
		t.Fatal("PEM must refuse")
	}
	f = cfg.Parse("[node_size]\nAAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH IIII JJJJ KKKK LLLL\n")
	if _, err := Split(f); err == nil {
		t.Fatal("RFC1751 must refuse")
	}
}

func TestUnknownStanzaGoesToBundle(t *testing.T) {
	res, err := Split(cfg.Parse("[mystery]\nvalue\n[node_size]\nhuge\n"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Bundle.Get("mystery") == nil || len(res.Moves) != 1 {
		t.Fatal("unknown stanza must move")
	}
	if strings.Contains(res.OnChain.Canonical(), "value") {
		t.Fatal("unknown value leaked on-chain")
	}
}

func TestValidatorsTxtAllOnChain(t *testing.T) {
	res, err := Split(load(t, "validators.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Moves) != 0 || len(res.Bundle.Stanzas) != 0 {
		t.Fatalf("validators.txt should be fully on-chain: %+v", res.Moves)
	}
}

func TestMergeRoundTrip(t *testing.T) {
	orig := load(t, "validator-full.cfg")
	res, err := Split(orig)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the on-chain copy going through text and back.
	on := cfg.Parse(res.OnChain.Canonical())
	bundle := cfg.Parse(res.Bundle.Canonical())
	merged := Merge(on, bundle)
	if merged.Canonical() != orig.Canonical() {
		t.Fatalf("merge mismatch:\n%s\n---\n%s", merged.Canonical(), orig.Canonical())
	}
	partial := Merge(on, &cfg.File{})
	if !strings.Contains(partial.Canonical(), MovedMarker) {
		t.Fatal("bundle-less merge must keep markers")
	}
}

func TestCanonicalDeterministic(t *testing.T) {
	a := cfg.Parse("[b]\n1\n\n[a]\nx # comment\n# c\n").Canonical()
	if a != "[a]\nx\n\n[b]\n1\n" {
		t.Fatalf("%q", a)
	}
}
