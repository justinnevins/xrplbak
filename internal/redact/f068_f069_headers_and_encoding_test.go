package redact

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/justinnevins/xrplbak/internal/cfg"
)

func refused(t *testing.T, name, text string) *RefusedError {
	t.Helper()
	for _, mode := range []Mode{CommentsToBundle, CommentsOnChain} {
		res, err := Split(cfg.Parse(text), Options{Comments: mode, PeersOnChain: mode == CommentsOnChain})
		var re *RefusedError
		if !errors.As(err, &re) {
			on := ""
			if res != nil {
				on = res.OnChain.Render()
			}
			t.Errorf("%s (mode %d): not refused (err %v); on-chain copy:\n%q", name, mode, err, on)
			return nil
		}
		for _, r := range re.Error() {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x202e || r == 0xfeff {
				t.Errorf("%s: the refusal carries a raw control or invisible character (U+%04X): %q", name, r, re.Error())
				break
			}
		}
		if mode == CommentsOnChain {
			return re
		}
	}
	return nil
}

// F-068: a stanza header line was never scanned and always stayed
// on-chain, so a seed, a PEM marker, an address or an internal host name
// written as [name] went to the ledger as written. A header is now held to
// the rules for any other line, and its name must be a plain name.
func TestF068AHeaderIsScannedLikeAnyOtherLine(t *testing.T) {
	for name, text := range map[string]string{
		"seed as a header":             "[node_size]\n[sn3nxiW7v4v2cYqZ3Uk4HrAQvYaNH]\nvalue=1\n",
		"seed header, last line":       "[node_size]\nhuge\n[sn3nxiW7v4v2cYqZ3Uk4HrAQvYaNH]\n",
		"PEM marker as a header":       "[-----BEGIN PRIVATE KEY-----]\nx\n",
		"private address as a header":  "[10.9.8.7]\nx=1\n",
		"public address as a header":   "[203.0.113.9]\nx=1\n",
		"internal host as a header":    "[db.corp.lan]\nx=1\n",
		"long hex as a header":         "[" + strings.Repeat("AB", 40) + "]\nx=1\n",
		"64 hex digits as a header":    "[" + strings.Repeat("AB", 32) + "]\nx=1\n",
		"65 letters as a header":       "[" + strings.Repeat("z", 65) + "]\nx=1\n",
		"space in the name":            "[my notes]\nx=1\n",
		"prose in the name":            "[the vault code is 4411]\n",
		"escape sequence in the name":  "[x\x1b[2A\x1b[Jcomplete\x07]\nx=1\n",
		"bidi override in the name":    "[x\u202ey]\nx=1\n",
		"C1 control in the name":       "[x\u009by]\nx=1\n",
		"non-ASCII letter in the name": "[caf\u00e9]\nx=1\n",
		"bracket in the name":          "[a][b]\nx=1\n",
	} {
		refused(t, name, text)
	}
}

// Ordinary names are untouched: every stanza the tool knows, port stanzas,
// and plain custom names.
func TestF068OrdinaryHeadersAreAccepted(t *testing.T) {
	var names []string
	for n := range onChainStanzas {
		names = append(names, n)
	}
	for n := range bundleStanzas {
		names = append(names, n)
	}
	names = append(names, strings.Repeat("z", 64))
	names = append(names, "port_rpc_admin_local", "port_peer", "port_ws_public", "my-notes", "x", "A1")
	for _, n := range names {
		if _, bad := neverStanzas[n]; bad {
			continue
		}
		if _, err := Split(cfg.Parse("["+n+"]\n"), Options{}); err != nil {
			t.Errorf("[%s]: refused: %v", n, err)
		}
	}
}

// F-069: a byte order mark, a UTF-16 encoding, or a non-ASCII space before
// a header hid a never-stanza, a seed or a key from every refusal, and the
// tool bundled what it says it never handles. rippled reads none of these
// as the operator meant, so the file is refused and named.
func TestF069EncodingsThatHideAHeaderAreRefused(t *testing.T) {
	utf16le := func(s string) string {
		b := []byte{0xff, 0xfe}
		for _, u := range utf16.Encode([]rune(s)) {
			b = append(b, byte(u), byte(u>>8))
		}
		return string(b)
	}
	seedCfg := "[validation_seed]\nssZkdwURFMBXenJPbrpE14b6noJSu\n"
	for name, text := range map[string]string{
		"BOM before a never-stanza":         "\xef\xbb\xbf" + seedCfg,
		"BOM before an ordinary stanza":     "\xef\xbb\xbf[server]\nport_rpc\n",
		"UTF-16LE config":                   utf16le(seedCfg),
		"UTF-16LE ordinary config":          utf16le("[server]\nport_rpc\n"),
		"UTF-16 mark, no NUL byte":          "\xff\xfe\x41\x41\n",
		"UTF-16BE mark, no NUL byte":        "\xfe\xff\x41\x41\n",
		"BOM before a comment line":         "\ufeff# my config\n[server]\nport_rpc\n",
		"NUL inside a line":                 "[server]\nport\x00_rpc\n",
		"no-break space before a header":    "\u00a0" + seedCfg,
		"next-line char before a header":    "\u0085" + seedCfg,
		"ideographic space before a header": "\u3000[server]\nport_rpc\n",
		"line separator after a header":     "[validation_seed]\u2028\nx\n",
		"zero-width space before a header":  "\u200b[server]\nport_rpc\n",
		"BOM in the middle of the file":     "[server]\nport_rpc\n\ufeff[validation_seed]\nx\n",
	} {
		if re := refused(t, name, text); re != nil && strings.Contains(name, "UTF-16") && !strings.Contains(re.Error(), "UTF-8") {
			t.Errorf("%s: the refusal does not say the file is not UTF-8: %v", name, re)
		}
	}
}

// F-087: "[port_rpc] # note" inside a stanza is a value line to rippled
// (the raw line does not end in a bracket), and the parser keeps its
// comment in the value so that the rendered file cannot grow a header.
// That comment then stayed on-chain in the default mode, where every
// comment goes to the bundle.
func TestF087CommentOnAHeaderShapedValueLineLeavesTheChain(t *testing.T) {
	text := "[server]\nport_rpc\n[port_rpc] # the admin port, password in vault page 12\nport_peer\n"
	res, err := Split(cfg.Parse(text), Options{})
	if err != nil {
		t.Fatal(err)
	}
	on := res.OnChain.Render()
	if strings.Contains(on, "vault page 12") {
		t.Fatalf("default mode: the comment is on-chain:\n%s", on)
	}
	if got := Merge(cfg.Parse(on), cfg.Parse(res.Bundle.Render())).Render(); got != text {
		t.Fatalf("merge does not give the file back:\n%q", got)
	}
	// On-chain comments: a harmless one stays, one a scanner or the
	// setting rule would move goes.
	keep := "[server]\nport_rpc\n[port_rpc] # the public port\n"
	res, err = Split(cfg.Parse(keep), Options{Comments: CommentsOnChain})
	if err != nil {
		t.Fatal(err)
	}
	if res.OnChain.Render() != keep {
		t.Fatalf("on-chain comments: a harmless comment was moved:\n%s", res.OnChain.Render())
	}
	addr := "[server]\nport_rpc\n[port_rpc] # reach it at 10.1.2.3\n"
	res, err = Split(cfg.Parse(addr), Options{Comments: CommentsOnChain})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.OnChain.Render(), "10.1.2.3") {
		t.Fatalf("on-chain comments: a private address in the comment stayed:\n%s", res.OnChain.Render())
	}
	leak := "[port_rpc]\nport = 5005\n[x] # password = hunter2\n"
	res, err = Split(cfg.Parse(leak), Options{Comments: CommentsOnChain})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.OnChain.Render(), "hunter2") {
		t.Fatalf("on-chain comments: a commented password stayed:\n%s", res.OnChain.Render())
	}
}
