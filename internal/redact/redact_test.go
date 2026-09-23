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
	res, err := Split(load(t, "validator-full.cfg"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Role != "validator" {
		t.Fatal("role")
	}
	on := res.OnChain.Render()
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
	// The bundle is the moved lines in the order they were taken, so it is
	// checked as text. Every assertion below is the one the stanza view
	// carried before: the token, the fixed peers and the admin line moved.
	b := res.Bundle.Render()
	for _, want := range []string{"eyJ2YWxp", "10.20.30.40", "10.0.0.5"} {
		if !strings.Contains(b, want) {
			t.Fatalf("bundle lacks %q:\n%s", want, b)
		}
	}
	// Only the admin line leaves [port_ws_admin_local]; its other settings
	// stay on-chain.
	if n := strings.Count(res.OnChain.Render(), MovedMarker); n == 0 {
		t.Fatal("nothing was moved")
	}
	for _, m := range res.Moves {
		if m.Stanza == "port_ws_admin_local" && m.Lines != 1 {
			t.Fatalf("only the admin line moves from port_ws_admin_local, got %d", m.Lines)
		}
	}
	// port_rpc_admin_local keeps ip=127.0.0.1 on-chain, moves admin line.
	if !strings.Contains(on, "[port_rpc_admin_local]\nport = 5005\nip = 127.0.0.1\n"+MovedMarker+"\nprotocol = http\n") {
		t.Fatalf("port split:\n%s", on)
	}
}

func TestRefuseNodeSeed(t *testing.T) {
	_, err := Split(load(t, "node-with-seed.cfg"), Options{})
	re, ok := err.(*RefusedError)
	if !ok || re.Stanza != "node_seed" {
		t.Fatalf("want node_seed refusal, got %v", err)
	}
}

func TestRefuseSeedPatternAnywhere(t *testing.T) {
	_, err := Split(load(t, "node-seed-in-wrong-stanza.cfg"), Options{})
	if _, ok := err.(*RefusedError); !ok {
		t.Fatalf("want refusal, got %v", err)
	}
	f := cfg.Parse("[node_size]\n-----BEGIN PRIVATE KEY-----\n")
	if _, err := Split(f, Options{}); err == nil {
		t.Fatal("PEM must refuse")
	}
	f = cfg.Parse("[node_size]\nAAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH IIII JJJJ KKKK LLLL\n")
	if _, err := Split(f, Options{}); err == nil {
		t.Fatal("RFC1751 must refuse")
	}
}

func TestUnknownStanzaGoesToBundle(t *testing.T) {
	res, err := Split(cfg.Parse("[mystery]\nvalue\n[node_size]\nhuge\n"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Bundle.Render(), "value") || len(res.Moves) != 1 {
		t.Fatalf("unknown stanza must move: moves=%+v bundle=%q", res.Moves, res.Bundle.Render())
	}
	if strings.Contains(res.OnChain.Render(), "value") {
		t.Fatal("unknown value leaked on-chain")
	}
}

// TestValidatorsTxtSettingsAllOnChain keeps the original assertion for every
// setting in validators.txt: none of them is redacted. What changed is that
// the operator's comments now go to the bundle rather than being discarded,
// so a move whose only content is comment lines is expected.
func TestValidatorsTxtSettingsAllOnChain(t *testing.T) {
	orig := load(t, "validators.txt")
	res, err := Split(orig, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range res.Bundle.Lines {
		if l.Kind != cfg.Comment && l.Raw != "" {
			t.Fatalf("a setting left validators.txt: %q", l.Raw)
		}
	}
	// With comments kept on-chain nothing moves at all.
	res, err = Split(orig, Options{Comments: CommentsOnChain})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Moves) != 0 || len(res.Bundle.Lines) != 0 {
		t.Fatalf("validators.txt should be fully on-chain: %+v", res.Moves)
	}
}

func TestMergeRoundTrip(t *testing.T) {
	orig := load(t, "validator-full.cfg")
	res, err := Split(orig, Options{})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate both halves going through text and back. The comparison is
	// over the operator's bytes, not the tool's canonical view.
	on := cfg.Parse(res.OnChain.Render())
	bundle := cfg.Parse(res.Bundle.Render())
	if got := Merge(on, bundle).Render(); got != orig.Render() {
		t.Fatalf("merge mismatch:\n%q\n---\n%q", got, orig.Render())
	}
	partial := Merge(on, &cfg.File{})
	if !strings.Contains(partial.Render(), MovedMarker) {
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
		res, err := Split(cfg.Parse(c.text), Options{})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := len(res.Moves) > 0
		if got != c.moved {
			t.Fatalf("%s: moved=%v want %v (on-chain: %q)", c.name, got, c.moved, res.OnChain.Render())
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

// TestEmptyStanzaRoundTrips pins that an empty stanza header is never
// "moved" to the bundle. Moving it with no content would put a marker line
// into the restored file that the original never had, making restore
// report a correct backup as changed.
func TestEmptyStanzaRoundTrips(t *testing.T) {
	for _, text := range []string{
		"[cluster_nodes]\n",
		"[ips_fixed]\n",
		"[mystery]\n[node_size]\nhuge\n",
		"[]\n[node_size]\nhuge\n",
	} {
		orig := cfg.Parse(text)
		res, err := Split(orig, Options{})
		if err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		if strings.Contains(res.OnChain.Render(), MovedMarker) {
			t.Fatalf("%q: an empty stanza produced a marker:\n%s", text, res.OnChain.Render())
		}
		for _, m := range res.Moves {
			if m.Lines == 0 {
				t.Fatalf("%q: reported a move of 0 lines for stanza %q", text, m.Stanza)
			}
		}
		merged := Merge(cfg.Parse(res.OnChain.Render()), cfg.Parse(res.Bundle.Render()))
		if merged.Render() != orig.Render() {
			t.Fatalf("%q: round trip mismatch:\nwant %q\ngot  %q", text, orig.Canonical(), merged.Canonical())
		}
	}
}

// TestEmptyValidatorTokenIsNotAValidator pins that an empty
// [validator_token] stanza holds no token. Setting the role from the header
// alone published "validator" in the manifest for a host that does not
// validate, and made restore hand the operator two instructions about a
// token that never existed.
func TestEmptyValidatorTokenIsNotAValidator(t *testing.T) {
	res, err := Split(cfg.Parse("[validator_token]\n[server]\nport_rpc\n"), Options{})
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if res.Role != "node" {
		t.Fatalf("role = %q, want %q", res.Role, "node")
	}
	// A stanza that carries a token still reads as a validator.
	res, err = Split(cfg.Parse("[validator_token]\neyJ2YWxpZGF0aW9u\n"), Options{})
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if res.Role != "validator" {
		t.Fatalf("role = %q, want %q", res.Role, "validator")
	}
}

// TestInlineCommentDoesNotReachTheChain pins that redaction respects
// rippled's inline-comment rule. rippled ends a value at the first
// unescaped "#", with no leading space
// required, so text after it is operator prose the node never reads. It must
// not be published on a public ledger.
func TestInlineCommentDoesNotReachTheChain(t *testing.T) {
	res, err := Split(cfg.Parse("[port_rpc]\nport=5005#admin_password=hunter2\n"), Options{})
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	on := res.OnChain.Render()
	if strings.Contains(on, "hunter2") {
		t.Fatalf("comment text reached the on-chain copy:\n%s", on)
	}
	if !strings.Contains(on, "port=5005") {
		t.Fatalf("the setting itself was lost:\n%s", on)
	}
}

// TestSeedShapedCommentIsRefused pins the refusal path over comments. The
// per-line scanners never look for seeds; only refuse does, and it has to
// read comments as well as settings. A seed an operator left in a comment is
// still a seed sitting in the config file, and it is the one thing the tool
// must never carry.
//
// Found by the mutation pass: making refuse skip comment lines survived the
// whole suite and every fuzz target.
func TestSeedShapedCommentIsRefused(t *testing.T) {
	texts := []string{
		"[node_size]\n# old seed sFAKEFAKEFAKEFAKEFAKEFAKEFAKE was rotated out\nhuge\n",
		"[node_size]\nhuge # old seed sFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n",
		"[node_size]\n# AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH IIII JJJJ KKKK LLLL\nhuge\n",
		"[node_size]\n# -----BEGIN PRIVATE KEY-----\nhuge\n",
	}
	for _, mode := range []Mode{CommentsToBundle, CommentsOnChain} {
		for _, text := range texts {
			if _, err := Split(cfg.Parse(text), Options{Comments: mode}); err == nil {
				t.Errorf("mode %d: %q was accepted", mode, text)
			} else if _, ok := err.(*RefusedError); !ok {
				t.Errorf("mode %d: %q gave %v, want a refusal", mode, text, err)
			}
		}
	}
}

// TestLineOutsideAnyStanzaMovesToTheBundle pins the rule directly, on the
// split's own output, rather than through valueReason. A line before the
// first header belongs to no stanza, so no allowlist applies to it and it
// cannot be judged. Doctrine sends it off-chain.
//
// Found by the mutation pass: FuzzOnChainIsClean calls valueReason as its
// oracle, so it cannot catch a defect inside valueReason. Same lesson as
// increment 3: an oracle must not call the helper it pins.
func TestLineOutsideAnyStanzaMovesToTheBundle(t *testing.T) {
	const text = "orphan_setting=hello\n[node_size]\nhuge\n"
	res, err := Split(cfg.Parse(text), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if on := res.OnChain.Render(); strings.Contains(on, "orphan_setting=hello") {
		t.Fatalf("a line outside any stanza stayed on-chain:\n%s", on)
	}
	if b := res.Bundle.Render(); !strings.Contains(b, "orphan_setting=hello") {
		t.Fatalf("the line was not kept in the bundle:\n%q", b)
	}
	if len(res.Moves) != 1 {
		t.Fatalf("moves: %+v", res.Moves)
	}
	// The settings inside a known stanza still stay on-chain.
	if on := res.OnChain.Render(); !strings.Contains(on, "huge") {
		t.Fatalf("a known stanza lost its setting:\n%s", on)
	}
}
