package restore

import (
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/manifest"
)

// TestNamelessStanzaTodoReadsLikeEnglish pins that content sitting before
// the first stanza header, which has no stanza name, does not produce a
// todo line like "Re-enter []: 2 line(s)", which reads like a template
// that failed to substitute.
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
