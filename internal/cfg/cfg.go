// Package cfg parses xrpld.cfg / rippled.cfg / validators.txt.
//
// The rules here are rippled's own, read from source rather than from the
// shape of the format:
//
//	XRPLF/rippled, src/xrpld/core/detail/Config.cpp       parseIniFile
//	XRPLF/rippled, src/libxrpl/config/BasicConfig.cpp     Section::append
//	XRPLF/rippled, src/libxrpl/basics/StringUtilities.cpp trimWhitespace
//
// rippled reads a config in two stages. parseIniFile ends a line at "\n",
// at "\r\n" or at a lone "\r", trims ASCII whitespace, drops a line whose
// first character is "#", and opens a new section when the trimmed line
// starts with "[" and ends with "]" -- tested on the raw line, with no
// comment stripping, and the name taken between the brackets untrimmed.
// Section::append then ends each value at the first unescaped "#", at any
// position and needing no leading space, reading "\#" as a literal "#".
//
// Parse follows both stages so that the sections and values xrplbak
// classifies are the ones the operator's node actually uses.
package cfg

import (
	"sort"
	"strings"
)

// asciiSpace is rippled's isAsciiSpace. Go's unicode definition is wider, so
// trimming with strings.TrimSpace would strip bytes rippled keeps and open a
// stanza where rippled reads a value line.
const asciiSpace = " \t\n\v\f\r"

// inlineComment returns the index of the first "#" that starts a comment, or
// -1. A "#" preceded by a backslash is an escaped literal, as Section::append
// has it.
func inlineComment(line string) int {
	for i := 0; i < len(line); i++ {
		if line[i] != '#' {
			continue
		}
		if i > 0 && line[i-1] == '\\' {
			continue
		}
		return i
	}
	return -1
}

// looksLikeHeader reports whether a line would be read as a stanza header.
func looksLikeHeader(line string) bool {
	return len(line) >= 2 && line[0] == '[' && line[len(line)-1] == ']'
}

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
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	for i, raw := range strings.Split(text, "\n") {
		line := strings.Trim(raw, asciiSpace)
		if line == "" || (strings.HasPrefix(line, "#") && !strings.HasPrefix(line, MarkerPrefix)) {
			continue
		}
		if looksLikeHeader(line) {
			name := line[1 : len(line)-1]
			// A repeated stanza name continues the first one, so split and
			// merge see exactly one stanza per name.
			if cur = f.Get(name); cur == nil {
				cur = &Stanza{Name: name, LineNo: i + 1}
				f.Stanzas = append(f.Stanzas, cur)
			}
			continue
		}
		// A value line. Drop its inline comment so operator prose never
		// reaches a public ledger, but keep the raw line when dropping the
		// comment would leave something a later parse reads as a header:
		// writing that back would move every following line into a stanza
		// the original file never had.
		if c := inlineComment(line); c > 0 {
			if v := strings.Trim(line[:c], asciiSpace); !looksLikeHeader(v) {
				line = v
			}
		}
		if line == "" {
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
