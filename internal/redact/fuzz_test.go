package redact

import (
	"os"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/cfg"
)

func seedCorpus(f *testing.F) {
	f.Helper()
	for _, name := range []string{"validator-full.cfg", "validators.txt", "node-with-seed.cfg"} {
		if b, err := os.ReadFile("../../tests/fixtures/" + name); err == nil {
			f.Add(string(b))
		}
	}
	f.Add("[node_size]\nhuge\n")
	f.Add("[ips]\nr.ripple.com 51235\npeer1 51235\nhub.internal 51235\n")
	f.Add("[port_rpc]\nport = 5005\nip = 127.0.0.1\nadmin = 10.0.0.5\nprotocol = http\n")
	f.Add("[mystery]\nvalue\n[node_db]\ntype=NuDB\n")
	f.Add("")
}

// FuzzSplitMergeRoundTrip is the property the whole tool rests on: whatever
// redaction moves off-chain, merge must put back in the same place. A
// counterexample means a restore that silently reorders or drops config.
func FuzzSplitMergeRoundTrip(f *testing.F) {
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, text string) {
		orig := cfg.Parse(text)
		res, err := Split(orig)
		if err != nil {
			return // a refusal is a correct outcome, not a counterexample
		}
		// Round trip both halves through text, the way a real backup does.
		on := cfg.Parse(res.OnChain.Canonical())
		bundle := cfg.Parse(res.Bundle.Canonical())
		merged := Merge(on, bundle)
		if merged.Canonical() != orig.Canonical() {
			t.Fatalf("merge did not restore the original:\nwant %q\ngot  %q", orig.Canonical(), merged.Canonical())
		}
	})
}

// FuzzOnChainIsClean asserts that redaction is complete in one pass. Every
// line left on-chain must be a line the classifier would leave on-chain if
// it saw it again, and every on-chain stanza must be on the allowlist. A
// counterexample is a leak: content the rules meant to move reached the
// public ledger.
func FuzzOnChainIsClean(f *testing.F) {
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, text string) {
		res, err := Split(cfg.Parse(text))
		if err != nil {
			return
		}
		for _, s := range res.OnChain.Stanzas {
			allowed := s.Name != "" && (onChainStanzas[s.Name] || strings.HasPrefix(s.Name, "port_"))
			for _, l := range s.Lines {
				// A stanza off the allowlist keeps its header on-chain with
				// markers only, so a bundle-less restore shows the gap.
				if !allowed && l != MovedMarker {
					t.Fatalf("stanza %q is off the allowlist, so only markers may stay on-chain, but %q did", s.Name, l)
				}
				if l == MovedMarker {
					continue
				}
				if why := lineReason(s.Name, l); why != "" {
					t.Fatalf("line %q in stanza %q stayed on-chain but classifies as %q", l, s.Name, why)
				}
				if reSeed.MatchString(l) || reRFC1751.MatchString(l) || strings.Contains(l, "-----BEGIN") {
					t.Fatalf("refused pattern reached the on-chain copy: %q", l)
				}
			}
		}
	})
}
