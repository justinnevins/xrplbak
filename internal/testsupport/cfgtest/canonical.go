// Package cfgtest is test support for package cfg. Nothing in the xrplbak
// binary imports it.
package cfgtest

import (
	"sort"
	"strings"

	"github.com/justinnevins/xrplbak/internal/cfg"
)

// Canonical renders the file in canonical form: stanzas sorted by name,
// lines in original order, LF endings, one blank line between stanzas.
// Same stanzas in => same bytes out.
func Canonical(f *cfg.File) string {
	var stanzas []*cfg.Stanza
	for _, s := range f.Stanzas {
		// A nameless stanza with no lines renders nothing, so keeping it
		// would emit a separator that re-parsing cannot recover. Dropping
		// it here is what makes canonical form a fixed point.
		if s.Name == "" && len(s.Lines) == 0 {
			continue
		}
		stanzas = append(stanzas, s)
	}
	sort.SliceStable(stanzas, func(i, j int) bool { return stanzas[i].Name < stanzas[j].Name })
	var b strings.Builder
	for i, s := range stanzas {
		if i > 0 {
			b.WriteString("\n")
		}
		if s.Name != "" {
			b.WriteString("[" + s.Name + "]\n")
		}
		for _, l := range s.Lines {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}
