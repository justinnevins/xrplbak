package redact

import (
	"os"
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
// redaction moves off-chain, merge must put back in the same place. It is
// now exact over bytes, not over the tool's own canonical view, because the
// operator's comments, blank lines and line order are part of the backup. A
// counterexample is a restore that silently changes the operator's file.
func FuzzSplitMergeRoundTrip(f *testing.F) {
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, text string) {
		for _, mode := range []Mode{CommentsToBundle, CommentsOnChain} {
			res, err := Split(cfg.Parse(text), Options{Comments: mode})
			if err != nil {
				continue // a refusal is a correct outcome, not a counterexample
			}
			// Round trip both halves through text, the way a real backup does.
			on := cfg.Parse(res.OnChain.Render())
			bundle := cfg.Parse(res.Bundle.Render())
			if got := Merge(on, bundle).Render(); got != text {
				t.Fatalf("mode %d: merge did not restore the original bytes:\nwant %q\ngot  %q", mode, text, got)
			}
		}
	})
}

// FuzzBundlelessRestoreStillParses asserts the other half of the promise.
// An operator who has lost the bundle gets a config that still reads as a
// config: every stanza that survived is the stanza it was, and the gaps show
// as markers rather than as a quietly shorter file.
func FuzzBundlelessRestoreStillParses(f *testing.F) {
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, text string) {
		res, err := Split(cfg.Parse(text), Options{})
		if err != nil {
			return
		}
		bare := Merge(cfg.Parse(res.OnChain.Render()), &cfg.File{}).Render()
		if bare != res.OnChain.Render() {
			t.Fatalf("a bundle-less merge changed the on-chain copy:\nwant %q\ngot  %q", res.OnChain.Render(), bare)
		}
		// Every stanza the operator had is still declared.
		want := cfg.Parse(text)
		got := cfg.Parse(bare)
		for _, s := range want.Stanzas {
			if s.Name != "" && got.Get(s.Name) == nil {
				t.Fatalf("stanza %q vanished from a bundle-less restore:\n%s", s.Name, bare)
			}
		}
	})
}

// FuzzOnChainIsClean asserts that redaction is complete in one pass. Every
// line left on-chain must be a line the classifier would leave on-chain if
// it saw it again. A counterexample is a leak: content the rules meant to
// move reached the public ledger.
//
// In the default mode that includes the operator's prose. A comment is free
// text the tool cannot classify, so none may stay.
func FuzzOnChainIsClean(f *testing.F) {
	seedCorpus(f)
	f.Fuzz(func(t *testing.T, text string) {
		res, err := Split(cfg.Parse(text), Options{})
		if err != nil {
			return
		}
		for _, l := range cfg.Parse(res.OnChain.Render()).Lines {
			if isMarker(l) {
				continue
			}
			switch l.Kind {
			case cfg.Blank, cfg.Header:
			case cfg.Comment:
				t.Fatalf("a comment stayed on-chain by default: %q", l.Raw)
			case cfg.Value:
				if l.Comment != "" {
					t.Fatalf("an inline comment stayed on-chain by default: %q", l.Raw)
				}
				if why := valueReason(l.Stanza, l.Value); why != "" {
					t.Fatalf("line %q in stanza %q stayed on-chain but classifies as %q", l.Value, l.Stanza, why)
				}
			}
		}
	})
}

// FuzzOnChainScannersRunOnComments asserts that the override widens what a
// deliberate operator publishes, not what the scanners let through. With
// --comments=onchain a comment is judged by the same rules as a setting, so
// one holding a key, a private address or an internal hostname still moves.
func FuzzOnChainScannersRunOnComments(f *testing.F) {
	seedCorpus(f)
	f.Add("[ips]\n# our box at hub.internal\nr.ripple.com 51235\n")
	f.Add("[node_size]\nmedium # 10.0.0.5 is the old host\n")
	f.Fuzz(func(t *testing.T, text string) {
		res, err := Split(cfg.Parse(text), Options{Comments: CommentsOnChain})
		if err != nil {
			return
		}
		for _, l := range cfg.Parse(res.OnChain.Render()).Lines {
			if isMarker(l) {
				continue
			}
			switch l.Kind {
			case cfg.Comment:
				if why := lineReason(l.Stanza, l.Raw); why != "" {
					t.Fatalf("comment %q in stanza %q stayed on-chain but classifies as %q", l.Raw, l.Stanza, why)
				}
			case cfg.Value:
				if why := valueReason(l.Stanza, l.Value); why != "" {
					t.Fatalf("line %q in stanza %q stayed on-chain but classifies as %q", l.Value, l.Stanza, why)
				}
				if l.Comment == "" {
					continue
				}
				if why := lineReason(l.Stanza, l.Comment); why != "" {
					t.Fatalf("inline comment %q in stanza %q stayed on-chain but classifies as %q", l.Comment, l.Stanza, why)
				}
			}
		}
	})
}
