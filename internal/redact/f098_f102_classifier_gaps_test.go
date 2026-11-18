package redact

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/cfg"
)

// F-098 to F-102: content the rules say must move, or must be refused,
// reached the on-chain copy because a scanner was bounded by \b, tried one
// spelling of an address, or stopped at the first character of a comment.
// Every round trip was byte-exact; the fault was only in what stayed.

// mustNotStay asserts that needle is not in the on-chain copy and that
// the split still merges back to the input.
func mustNotStay(t *testing.T, name, in, needle string, opt Options) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		res, err := Split(cfg.Parse(in), opt)
		if err != nil {
			// A refusal keeps it off the ledger too.
			return
		}
		on := res.OnChain.Render()
		if strings.Contains(on, needle) {
			t.Errorf("on-chain copy still carries %q\n in : %q\n out: %q", needle, in, on)
		}
		if m := Merge(cfg.Parse(on), cfg.Parse(res.Bundle.Render())).Render(); m != in {
			t.Errorf("round trip broke: %q", m)
		}
	})
}

// mustStay is the other half: the fix must not start moving or refusing
// what a real config holds.
func mustStay(t *testing.T, name, in string, opt Options) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		res, err := Split(cfg.Parse(in), opt)
		if err != nil {
			t.Fatalf("refused: %v\n in: %q", err, in)
		}
		if on := res.OnChain.Render(); on != in {
			t.Errorf("something moved\n in : %q\n out: %q", in, on)
		}
	})
}

const (
	f098Seed  = "snoPBrXtMeMyMHUVTgbuqAfg1SUTb"
	f101Token = "eyJtYW5pZmVzdCI6IkpBQUFBQUp4SWUzbWkxNnNMUkJGOEJRWmVQeFV4ekFKcjBzc0JKQ0l4Z0lHR2YxZ0h5QTNKQUJEWjhoZ1VSMHJ5a2dkZE5jNGNsNFpZN2c9PQ=="
	nodeKey   = "nHBt9fsb4849WmZiCds4r5TXyBeQjqnH5kzPtqgMAQMgi39YZRPa"
	listKey   = "ED2677ABFFD1B33AC6FBC3062B71F1E8397C1505E1C42C64D11AD1B28FF73F4734"
)

// F-098: a seed is 29 to 31 base58 characters starting with s. What
// touches it does not change that.
func TestF098SeedIsRefusedWhateverTouchesIt(t *testing.T) {
	for name, in := range map[string]string{
		"underscore before": "[node_size]\nseed_" + f098Seed + "\n",
		"underscore after":  "[node_size]\n" + f098Seed + "_old\n",
		"digit before":      "[node_size]\n1" + f098Seed + "\n",
		"zero before":       "[node_size]\n0" + f098Seed + "\n",
		"equals before":     "[node_size]\nold=" + f098Seed + "\n",
		"in a comment":      "[node_size]\n# was seed_" + f098Seed + "\n",
		"alone (control)":   "[node_size]\n" + f098Seed + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Split(cfg.Parse(in), Options{Comments: CommentsOnChain}); err == nil {
				t.Errorf("not refused: %q", in)
			}
		})
	}
}

// The seed rule reads [validators] too. A node public key is 52 base58
// characters and must never be taken for a seed: a refusal there stops
// every backup of that validator, and the operator cannot rename a key.
func TestF098NodeKeysAreNotSeeds(t *testing.T) {
	const b58 = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
	rng := rand.New(rand.NewSource(98))
	for i := 0; i < 20000; i++ {
		key := []byte("n")
		for len(key) < 52 {
			key = append(key, b58[rng.Intn(len(b58))])
		}
		// Make the dangerous shape common: an s where a seed-length tail
		// would start, after a digit as often as not.
		at := 52 - 29 - rng.Intn(3)
		key[at] = 's'
		if i%2 == 0 {
			key[at-1] = "123456789"[rng.Intn(9)]
		}
		in := "[validators]\n" + string(key) + "\n"
		if _, err := Split(cfg.Parse(in), Options{}); err != nil {
			t.Fatalf("a node key was refused: %v\n%s", err, key)
		}
	}
}

// F-099: a name under a special-use suffix is internal with an underscore
// or a non-ASCII label too.
func TestF099InternalHostnamesMove(t *testing.T) {
	d := Options{}
	mustNotStay(t, "underscore .internal", "[ips]\nmy_host.internal 51235\n", "my_host.internal", d)
	mustNotStay(t, "underscore .lan", "[ips]\nnode_1.lan 51235\n", "node_1.lan", d)
	mustNotStay(t, "cyrillic .local", "[ips]\nхост.local 51235\n", "хост.local", d)
	mustNotStay(t, "with a port", "[ips]\nmy_host.internal:51235\n", "my_host.internal", d)
	mustNotStay(t, "in a url", "[validator_list_sites]\nhttps://vl_1.corp/list\n", "vl_1.corp", d)
	mustNotStay(t, "after a comma", "[sntp_servers]\ntime.nist.gov,ntp_a.home\n", "ntp_a.home", d)
	mustStay(t, "public name (control)", "[sntp_servers]\ntime.nist.gov\n", d)
	mustStay(t, "public name with underscore (control)", "[validator_list_sites]\nhttps://vl_1.example.com/list\n", d)
}

// F-100: a private address is private in every spelling ParseIP or an
// operator would accept.
func TestF100PrivateAddressesMoveInEverySpelling(t *testing.T) {
	d := Options{}
	mustNotStay(t, "fd00::", "[ips]\nfd00:: 51235\n", "fd00::", d)
	mustNotStay(t, "fd12:3456:789a::", "[ips]\nfd12:3456:789a:: 51235\n", "fd12:3456:789a::", d)
	mustNotStay(t, "bracketed", "[ips]\n[fd12::]:51235\n", "fd12::", d)
	mustNotStay(t, "port ip", "[port_rpc]\nip = fd00::\n", "fd00::", d)
	mustNotStay(t, "link local with zone", "[ips]\nfe80::1%eth0 51235\n", "fe80::1", d)
	mustNotStay(t, "leading zeros", "[ips]\n010.000.000.005 51235\n", "010.000.000.005", d)
	mustNotStay(t, "word character after", "[ips]\n10.0.0.5_x 51235\n", "10.0.0.5_x", d)
	mustNotStay(t, "letter after", "[ips]\n192.168.1.9a 51235\n", "192.168.1.9a", d)
	mustStay(t, "public v4 (control)", "[ips]\n203.0.113.9 51235\n", d)
	mustStay(t, "public v6 (control)", "[ips]\n2001:db8::1 51235\n", d)
	mustStay(t, "loopback listen (control)", "[port_rpc]\nip = 127.0.0.1\nport = 5005\n", d)
	mustStay(t, "any-address listen (control)", "[port_peer]\nip = ::\nport = 51235\n", d)
	mustStay(t, "version number (control)", "[node_size]\n# tuned for 3.4.1 on 2026-11-17\nmedium\n", Options{Comments: CommentsOnChain})
}

// F-101: the key stanzas are exempt from the hex and base64 scanners
// because their own lines are keys. A validator token is not a key: it is
// longer than any of them, or carries characters no key has.
func TestF101TokenInAKeyStanzaMoves(t *testing.T) {
	o := Options{Comments: CommentsOnChain}
	mustNotStay(t, "commented under validators", "[validators]\n"+nodeKey+"\n#[validator_token]\n# "+f101Token+"\n", f101Token, o)
	mustNotStay(t, "commented under validator_list_keys", "[validator_list_keys]\n"+listKey+"\n# "+f101Token+"\n", f101Token, o)
	mustNotStay(t, "commented under amendments", "[amendments]\n# "+f101Token+"\n", f101Token, o)
	mustNotStay(t, "live line under validators", "[validators]\n"+f101Token+"\n", f101Token, Options{})
	// One 72-character line of a wrapped token, with no +, / or = in it.
	line72 := strings.Repeat("eyJtYW5pZmVzdCI6IkpB", 4)[:72]
	mustNotStay(t, "one wrapped line, letters and digits only", "[validators]\n"+line72+"\n", line72, Options{})
	short := "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9w+/=="
	mustNotStay(t, "short with base64-only characters", "[validators]\n"+short+"\n", short, Options{})
	mustStay(t, "node key (control)", "[validators]\n"+nodeKey+"\n"+nodeKey+" a name\n", Options{})
	mustStay(t, "list key (control)", "[validator_list_keys]\n"+listKey+"\n", Options{})
	mustStay(t, "amendment id (control)", "[amendments]\n"+strings.Repeat("A1", 32)+" SomeAmendment\n", Options{})
	mustStay(t, "commented node key (control)", "[validators]\n# "+nodeKey+"\n"+nodeKey+"\n", o)
}

// F-102: a comment stays only where a setting with the same text would.
// A second #, a dash or a word in front of the key is still that setting.
func TestF102CommentedCredentialMovesHoweverItIsCommented(t *testing.T) {
	o := Options{Comments: CommentsOnChain}
	for name, in := range map[string]string{
		"hash space hash":  "[port_rpc]\n# # password = hunter2\n",
		"hash dash":        "[port_rpc]\n#- password = hunter2\n",
		"semicolon":        "[port_rpc]\n#; password = hunter2\n",
		"three levels":     "[port_rpc]\n# # # admin_password = hunter2\n",
		"word before key":  "[port_rpc]\n# rpc password = hunter2\n",
		"inline, two hash": "[port_rpc]\nip = 127.0.0.1 # # password = hunter2\n",
		"double (control)": "[port_rpc]\n## password = hunter2\n",
	} {
		mustNotStay(t, name, in, "hunter2", o)
	}
	mustStay(t, "plain note (control)", "[port_rpc]\n# # opened for the load balancer\nport = 5005\n", o)
	mustStay(t, "note with a public setting (control)", "[port_rpc]\n# - port = 5005 was 5006\nport = 5005\n", o)
}
