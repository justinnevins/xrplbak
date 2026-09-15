// Package cfg parses xrpld.cfg / rippled.cfg / validators.txt. The format is
// INI-like: "[name]" opens a stanza, following lines belong to it, "#" starts
// a comment. Values are kept as raw lines because the tool never interprets
// them beyond classification.
package cfg

import (
	"sort"
	"strings"
)

// MarkerPrefix starts the one comment form the parser keeps: markers the
// tool itself writes so a restored file shows where content is missing.
const MarkerPrefix = "# xrplbak:"

// Stanza is one "[name]" section with its non-comment lines in order.
type Stanza struct {
	Name  string
	Lines []string
	// LineNo is the 1-based source line of the header, for error messages.
	LineNo int
}

// File is a parsed config.
type File struct {
	Stanzas []*Stanza
}

// Parse reads text into stanzas. Comments and blank lines are dropped.
// Lines before the first stanza are kept under the empty name "".
func Parse(text string) *File {
	f := &File{}
	var cur *Stanza
	for i, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || (strings.HasPrefix(line, "#") && !strings.HasPrefix(line, MarkerPrefix)) {
			continue
		}
		if idx := strings.Index(line, " #"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.TrimSpace(line[1 : len(line)-1])
			// A repeated stanza name continues the first one, so split and
			// merge see exactly one stanza per name.
			if cur = f.Get(name); cur == nil {
				cur = &Stanza{Name: name, LineNo: i + 1}
				f.Stanzas = append(f.Stanzas, cur)
			}
			continue
		}
		if cur == nil {
			cur = &Stanza{Name: "", LineNo: i + 1}
			f.Stanzas = append(f.Stanzas, cur)
		}
		cur.Lines = append(cur.Lines, line)
	}
	return f
}

// Get returns the stanza with the given name, or nil.
func (f *File) Get(name string) *Stanza {
	for _, s := range f.Stanzas {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// Canonical renders the file in canonical form: stanzas sorted by name,
// lines in original order, LF endings, one blank line between stanzas.
// Same stanzas in => same bytes out.
func (f *File) Canonical() string {
	var stanzas []*Stanza
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
