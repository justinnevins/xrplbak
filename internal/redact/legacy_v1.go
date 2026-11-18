package redact

import (
	"sort"
	"strings"
)

// MergeV1 rebuilds a file the way xrplbak v1.0 did. It exists so that a
// backup written by v1.0 still restores.
//
// v1.0 kept a config as stanzas of setting lines: no comments, no blank
// lines, no order. Its on-chain copy held one marker for all the lines
// that left a stanza, its bundle held those lines under the same stanza
// name, and the manifest hash was taken over the merged file in canonical
// form (stanzas sorted by name). v1.1 keeps every line, so its Merge
// gives one bundle line to each marker, and on a v1.0 backup that puts
// lines in the wrong stanzas.
//
// The parser, the merge and the rendering below are v1.0's own, kept as
// they were. Nothing else calls them, and a caller must not trust the
// result on its word: restore uses it only when its bytes match the
// manifest hash.
func MergeV1(onChain, bundle string) string {
	on, bun := parseV1(onChain), parseV1(bundle)
	var out []*stanzaV1
	seen := map[string]bool{}
	for _, s := range on {
		c := &stanzaV1{name: s.name}
		var bl []string
		if b := getV1(bun, s.name); b != nil {
			bl = append([]string{}, b.lines...)
		}
		markers := 0
		for _, l := range s.lines {
			if l == MovedMarker {
				markers++
			}
		}
		for _, l := range s.lines {
			if l != MovedMarker {
				c.lines = append(c.lines, l)
				continue
			}
			switch {
			case len(bl) == 0:
				c.lines = append(c.lines, MovedMarker)
			case markers == 1:
				c.lines = append(c.lines, bl...)
				bl = nil
			default:
				c.lines = append(c.lines, bl[0])
				bl = bl[1:]
			}
		}
		c.lines = append(c.lines, bl...)
		out = append(out, c)
		seen[s.name] = true
	}
	for _, b := range bun {
		if !seen[b.name] {
			out = append(out, &stanzaV1{name: b.name, lines: append([]string{}, b.lines...)})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].name < out[j].name })
	var sb strings.Builder
	for i, s := range out {
		if i > 0 {
			sb.WriteString("\n")
		}
		if s.name != "" {
			sb.WriteString("[" + s.name + "]\n")
		}
		for _, l := range s.lines {
			sb.WriteString(l + "\n")
		}
	}
	return sb.String()
}

type stanzaV1 struct {
	name  string
	lines []string
}

func getV1(f []*stanzaV1, name string) *stanzaV1 {
	for _, s := range f {
		if s.name == name {
			return s
		}
	}
	return nil
}

// parseV1 is v1.0's parser: comments and blank lines are dropped (the
// tool's own markers are kept), a repeated stanza continues the first.
func parseV1(text string) []*stanzaV1 {
	var f []*stanzaV1
	var cur *stanzaV1
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || (strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "# xrplbak:")) {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.TrimSpace(line[1 : len(line)-1])
			if cur = getV1(f, name); cur == nil {
				cur = &stanzaV1{name: name}
				f = append(f, cur)
			}
			continue
		}
		if idx := strings.Index(line, " #"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if cur == nil {
			cur = &stanzaV1{}
			f = append(f, cur)
		}
		cur.lines = append(cur.lines, line)
	}
	return f
}
