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
	for _, forbidden := range []string{"eyJ2YWxp", "10.20.30.40", "10.0.0.5", "peer.example.internal", "log_level", "admin =", "ntp1.lan", "xrpl-peer2"} {
		if strings.Contains(on, forbidden) {
			t.Fatalf("on-chain text contains %q:\n%s", forbidden, on)
		}
	}
	for _, want := range []string{"[node_db]", "online_delete=512", "[port_peer]", "ip = 0.0.0.0", "[validator_token]\n" + MovedMarker, "[peer_private]\n" + MovedMarker,
		"time.windows.com", "r.ripple.com 51235"} {
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

// TestHostnameHeuristic pins both halves of the rule: a special-use suffix
// is internal wherever it appears, and a single-label name in a host-valued
// stanza is internal. A public FQDN stays on-chain either way.
func TestHostnameHeuristic(t *testing.T) {
	cases := []struct {
		name  string
		text  string
		moved bool
	}{
		{"public peer stays", "[ips]\nr.ripple.com 51235\n", false},
		{"bare peer moves", "[ips]\npeer1 51235\n", true},
		{"internal suffix moves", "[ips]\nhub.internal 51235\n", true},
		{"corp suffix moves", "[ips]\nhub.corp 51235\n", true},
		{"corp mid-name stays", "[ips]\nhub.corp.example.com 51235\n", false},
		{"public sntp stays", "[sntp_servers]\npool.ntp.org\n", false},
		{"lan sntp moves", "[sntp_servers]\nntp1.lan\n", true},
		{"public vl site stays", "[validator_list_sites]\nhttps://vl.ripple.com\n", false},
		{"internal vl site moves", "[validator_list_sites]\nhttps://vl.internal/vl\n", true},
		{"bare vl site moves", "[validator_list_sites]\nhttp://vlhost:8080/vl\n", true},
		{"local path moves", "[debug_logfile]\n/var/log/xrpld.local\n", true},
		{"plain path stays", "[debug_logfile]\n/var/log/xrpld/debug.log\n", false},
		{"listen localhost stays", "[port_rpc]\nip = localhost\n", false},
		{"listen hostname moves", "[port_rpc]\nip = myvalidator\n", true},
		{"listen loopback stays", "[port_rpc]\nip = 127.0.0.1\n", false},
		{"onion moves", "[ips]\nabcdefghij.onion 51235\n", true},
	}
	for _, c := range cases {
		res, err := Split(cfg.Parse(c.text))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := len(res.Moves) > 0
		if got != c.moved {
			t.Fatalf("%s: moved=%v want %v (on-chain: %q)", c.name, got, c.moved, res.OnChain.Canonical())
		}
	}
}

func TestHostValue(t *testing.T) {
	cases := map[string]string{
		"ips|r.ripple.com 51235":                 "r.ripple.com",
		"ips|[2001:db8::1]:51235":                "",
		"validator_list_sites|https://vl.x.com/": "vl.x.com",
		"port_rpc|ip = 10.0.0.5":                 "10.0.0.5",
		"port_rpc|port = 5005":                   "5005",
		"ips|HOST1.LAN 51235":                    "host1.lan",
	}
	for in, want := range cases {
		stanza, line, _ := strings.Cut(in, "|")
		if got := hostValue(stanza, line); got != want {
			t.Fatalf("hostValue(%q, %q) = %q want %q", stanza, line, got, want)
		}
	}
}

// TestEmptyStanzaRoundTrips pins the first defect the fuzz targets found.
// An ordinary empty stanza header used to be "moved" to the bundle with no
// content, which put a marker line into the restored file that the original
// never had. Restore then reported a correct backup as changed.
func TestEmptyStanzaRoundTrips(t *testing.T) {
	for _, text := range []string{
		"[cluster_nodes]\n",
		"[ips_fixed]\n",
		"[mystery]\n[node_size]\nhuge\n",
		"[]\n[node_size]\nhuge\n",
	} {
		orig := cfg.Parse(text)
		res, err := Split(orig)
		if err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		if strings.Contains(res.OnChain.Canonical(), MovedMarker) {
			t.Fatalf("%q: an empty stanza produced a marker:\n%s", text, res.OnChain.Canonical())
		}
		for _, m := range res.Moves {
			if m.Lines == 0 {
				t.Fatalf("%q: reported a move of 0 lines for stanza %q", text, m.Stanza)
			}
		}
		merged := Merge(cfg.Parse(res.OnChain.Canonical()), cfg.Parse(res.Bundle.Canonical()))
		if merged.Canonical() != orig.Canonical() {
			t.Fatalf("%q: round trip mismatch:\nwant %q\ngot  %q", text, orig.Canonical(), merged.Canonical())
		}
	}
}

// TestEmptyValidatorTokenIsNotAValidator pins F-004. An empty
// [validator_token] stanza holds no token. Setting the role from the header
// alone published "validator" in the manifest for a host that does not
// validate, and made restore hand the operator two instructions about a
// token that never existed.
func TestEmptyValidatorTokenIsNotAValidator(t *testing.T) {
	res, err := Split(cfg.Parse("[validator_token]\n[server]\nport_rpc\n"))
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if res.Role != "node" {
		t.Fatalf("role = %q, want %q", res.Role, "node")
	}
	// A stanza that carries a token still reads as a validator.
	res, err = Split(cfg.Parse("[validator_token]\neyJ2YWxpZGF0aW9u\n"))
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if res.Role != "validator" {
		t.Fatalf("role = %q, want %q", res.Role, "validator")
	}
}

// TestInlineCommentDoesNotReachTheChain pins the redaction half of F-005.
// rippled ends a value at the first unescaped "#", with no leading space
// required, so text after it is operator prose the node never reads. It must
// not be published on a public ledger.
func TestInlineCommentDoesNotReachTheChain(t *testing.T) {
	res, err := Split(cfg.Parse("[port_rpc]\nport=5005#admin_password=hunter2\n"))
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	on := res.OnChain.Canonical()
	if strings.Contains(on, "hunter2") {
		t.Fatalf("comment text reached the on-chain copy:\n%s", on)
	}
	if !strings.Contains(on, "port=5005") {
		t.Fatalf("the setting itself was lost:\n%s", on)
	}
}
