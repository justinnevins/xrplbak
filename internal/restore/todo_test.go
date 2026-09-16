package restore

import (
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/manifest"
)

// TestNamelessStanzaTodoReadsLikeEnglish pins the second thing the cold-read
// evaluation tripped over. Content that sits before the first stanza header
// has no stanza name, so the todo line came out as "Re-enter []: 2 line(s)",
// which reads like a template that failed to substitute. The evaluator had
// to reverse-engineer what it meant.
func TestNamelessStanzaTodoReadsLikeEnglish(t *testing.T) {
	m := &manifest.Manifest{}
	m.Node.Role = "node"
	m.Files = []manifest.File{{Path: "/etc/xrpld/xrpld.cfg", SHA256: "00", Where: "onchain+bundle"}}
	m.Redactions = []manifest.Redaction{
		{Stanza: "", Lines: 2, To: "bundle"},
		{Stanza: "ips_fixed", Lines: 1, To: "bundle"},
	}
	p, err := Build(m, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var todo string
	for _, l := range p.Todo {
		todo += l + "\n"
	}
	if strings.Contains(todo, "[]") {
		t.Errorf("a nameless stanza printed as []:\n%s", todo)
	}
	if !strings.Contains(todo, "[ips_fixed]") {
		t.Errorf("a named stanza lost its name:\n%s", todo)
	}
	if !strings.Contains(todo, "before the first stanza") {
		t.Errorf("the nameless case does not say what it is:\n%s", todo)
	}
}
