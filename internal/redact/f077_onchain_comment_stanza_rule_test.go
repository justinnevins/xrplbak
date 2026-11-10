package redact

import (
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/cfg"
)

// F-077: with comments on-chain, a comment was judged by the per-line
// scanners only. The stanza rules that move a setting did not apply to it,
// so a commented-out setting stayed on-chain exactly where the live one
// would have moved: an old token under [validator_token], "#password = x"
// in a port stanza, a node key under [cluster_nodes]. The rule now is one
// sentence: a comment stays on-chain only where a setting line with the
// same text would. A comment above the first stanza has no stanza to take
// a rule from, so the line scanners alone judge it, as before.
func TestF077OnChainCommentFollowsTheRuleForASetting(t *testing.T) {
	tok := "eyJtYW5pZmVzdCI6IkpBQUFBQUZ4SWUxRkR0Y2JCU1p4ZVJpTVRKYk1Gb1pDTFVUVkE5c0xYWlpqQmQ"
	node := "n9KorY8QtTdRx7TVDpwnG9NvyxsDwHUKUEeDLY3AkiGncVaSXZi5"
	for name, c := range map[string]struct{ text, secret string }{
		"old token under validator_token":  {"[validator_token]\n# old token, rotated 2026-01\n# " + tok + "\n" + tok + "\n", tok},
		"prose under validator_token":      {"[validator_token]\n# rotated 2026-01 by the night shift\n" + tok + "\n", "night shift"},
		"token comment without a space":    {"[validator_token]\n#" + tok + "\n", tok},
		"token comment with two hashes":    {"[validator_token]\n## " + tok + "\n", tok},
		"indented token comment":           {"[validator_token]\n   \t# " + tok + "\n", tok},
		"commented password in a port":     {"[port_rpc]\nport = 5005\n#password = hunter2\n", "hunter2"},
		"indented commented password":      {"[port_rpc]\nport = 5005\n  \t# password = hunter2\n", "hunter2"},
		"commented admin_password":         {"[port_ws]\nport = 6006\n# admin_password=hunter2\n", "hunter2"},
		"commented ssl_key path":           {"[port_peer]\nport = 51235\n# ssl_key = /etc/ssl/private/node.pem\n", "/etc/ssl/private"},
		"commented cluster node":           {"[cluster_nodes]\n# " + node + " east\n", node},
		"commented fixed peer":             {"[ips_fixed]\n# r.ripple.com 51235\n", "r.ripple.com"},
		"comment in a stanza not allowed":  {"[my_private_stanza]\n# the vault code is 4411\n", "4411"},
		"inline comment naming a password": {"[port_rpc]\nport = 5005 # password = hunter2\n", "hunter2"},
	} {
		t.Run(name, func(t *testing.T) {
			f := cfg.Parse(c.text)
			res, err := Split(f, Options{Comments: CommentsOnChain})
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			on := res.OnChain.Render()
			if strings.Contains(on, c.secret) {
				t.Errorf("on-chain copy still holds %q:\n%s", c.secret, on)
			}
			if !strings.Contains(res.Bundle.Render(), c.secret) {
				t.Errorf("%q is in neither copy", c.secret)
			}
			if got := Merge(cfg.Parse(on), cfg.Parse(res.Bundle.Render())).Render(); got != c.text {
				t.Errorf("merge does not give the file back:\n%q\n%q", got, c.text)
			}
		})
	}
}

// The other half: on-chain comments still work. A comment that a setting
// line with the same text could carry on-chain stays on-chain.
func TestF077OrdinaryCommentsStillGoOnChain(t *testing.T) {
	text := "# xrpld.cfg for the east validator\n# password = see the vault, not this file\n\n[server]\n# the public ports, see the runbook\nport_rpc\nport_peer # opened 2026-03\n\n[node_size]\n# sized for the new host\nhuge\n\n[port_rpc]\n# admin stays off\nport = 5005\n"
	res, err := Split(cfg.Parse(text), Options{Comments: CommentsOnChain})
	if err != nil {
		t.Fatal(err)
	}
	if on := res.OnChain.Render(); on != text {
		t.Fatalf("ordinary comments were moved off-chain:\n%s", on)
	}
	if len(res.Moves) != 0 {
		t.Fatalf("moves reported for a file with nothing to move: %+v", res.Moves)
	}
}

// With --peers=onchain a fixed peer may go on-chain, so a comment naming a
// public peer may too. The comment follows the same opt-in the setting
// does, no more and no less.
func TestF077CommentFollowsThePeersOptIn(t *testing.T) {
	text := "[ips_fixed]\n# r.ripple.com 51235\nr.ripple.com 51235\n"
	res, err := Split(cfg.Parse(text), Options{Comments: CommentsOnChain, PeersOnChain: true})
	if err != nil {
		t.Fatal(err)
	}
	if on := res.OnChain.Render(); on != text {
		t.Fatalf("with peers on-chain the comment must stay beside its peer:\n%s", on)
	}
	res, err = Split(cfg.Parse(text), Options{Comments: CommentsOnChain})
	if err != nil {
		t.Fatal(err)
	}
	if on := res.OnChain.Render(); strings.Contains(on, "r.ripple.com") {
		t.Fatalf("without peers on-chain neither line may stay:\n%s", on)
	}
}
