package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMoveSummaryNamesTheNamelessStanzaAndSaysComment pins that the backup
// and redact plan does not print
//
//	[]: 1 line(s) -> bundle (private network address)
//
// for a comment above the first stanza that held a private address. The
// plan must say "the lines before the first stanza" and say when the moved
// line was only a comment, the same as the restore todo does. In
// --comments=onchain mode that is the one line telling the operator that a
// comment stayed off the ledger, and it must name the place and say it was
// a comment.
func TestMoveSummaryNamesTheNamelessStanzaAndSaysComment(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	w := newWorld(t, 0)
	raw, err := os.ReadFile(w.cfgPath)
	must(t, err)
	const head = "# val-07.sfo, rack B2\n# console: ipmi at 10.44.0.7 (ops vlan)\n"
	const tail = "\n[ledger_history]\n4096\n# retention agreed with 10.44.0.9's owner\n" +
		"\n[overlay]\n# the NAT side, not the public one\npublic_ip = 10.44.0.7\n"
	must(t, os.WriteFile(w.cfgPath, append(append([]byte(head), raw...), tail...), 0o600))

	for _, mode := range []string{"onchain", "bundle"} {
		dir := filepath.Join(w.dir, "split-"+mode)
		r := w.run("", "redact", "--config", w.cfgPath, "--comments="+mode, "--out", dir)
		if r.code != exitOK {
			t.Fatalf("redact --comments=%s: exit %d\n%s", mode, r.code, r.out)
		}
		if strings.Contains(r.out, "[]:") {
			t.Fatalf("--comments=%s: the plan printed an empty stanza name:\n%s", mode, r.out)
		}
		if !strings.Contains(r.out, "before the first stanza") {
			t.Fatalf("--comments=%s: the plan did not say where the nameless lines are:\n%s", mode, r.out)
		}
		if mode == "bundle" {
			// Default mode: [overlay] loses its private address and its
			// comment. Say how many of the moved lines were prose.
			if !strings.Contains(r.out, "[overlay]: 2 line(s) -> bundle, 1 of them comments") {
				t.Fatalf("--comments=bundle: a mixed move is not counted:\n%s", r.out)
			}
			continue
		}
		// On-chain mode: the only lines that moved are comments, and the
		// plan must say so for both places, so the operator knows every
		// setting is still on the ledger.
		for _, want := range []string{"comment only", "[ledger_history]"} {
			if !strings.Contains(strings.ToLower(r.out), strings.ToLower(want)) {
				t.Fatalf("--comments=onchain: the plan lacks %q:\n%s", want, r.out)
			}
		}
	}
}
