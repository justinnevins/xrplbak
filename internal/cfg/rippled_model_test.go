package cfg

import (
	"reflect"
	"strings"
	"testing"
)

// This file pins xrplbak's reading of a config against rippled's own, read
// from source rather than from memory:
//
//	XRPLF/rippled, src/xrpld/core/detail/Config.cpp    parseIniFile
//	XRPLF/rippled, src/libxrpl/config/BasicConfig.cpp  Section::append
//	XRPLF/rippled, src/libxrpl/basics/StringUtilities.cpp  trimWhitespace
//
// rippled reads a config in two stages. parseIniFile splits lines and
// assigns them to sections; it strips no comments and tests for a header on
// the raw trimmed line. Section::append then removes an inline comment from
// each line of a section: any unescaped "#", at any position, with "\#"
// meaning a literal "#".
//
// The model below is written out longhand and calls nothing from package
// cfg, so that emptying a cfg helper cannot break the model and the
// production path in the same way. (Increment 3 lesson: an oracle must not
// call the helper it pins.)

func rippledTrim(s string) string {
	sp := func(c byte) bool {
		return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
	}
	i, j := 0, len(s)
	for i < j && sp(s[i]) {
		i++
	}
	for j > i && sp(s[j-1]) {
		j--
	}
	return s[i:j]
}

// rippledRemoveComment is Section::append's removeComment lambda, longhand.
func rippledRemoveComment(val string) string {
	c := strings.IndexByte(val, '#')
	for c != -1 {
		if c == 0 {
			return ""
		}
		if val[c-1] == '\\' {
			// Escaped "#": erase the escape character and keep looking from
			// the same index, which is one past the "#" in the new string.
			val = val[:c-1] + val[c:]
			if c >= len(val) {
				return val
			}
			k := strings.IndexByte(val[c:], '#')
			if k < 0 {
				return val
			}
			c += k
			continue
		}
		return rippledTrim(val[:c])
	}
	return val
}

// rippledSections is what rippled ends up holding for a config text:
// section name to the list of value lines, comments removed, blanks gone.
func rippledSections(text string) map[string][]string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	raw := map[string][]string{"": nil}
	cur := ""
	for _, l := range strings.Split(text, "\n") {
		line := rippledTrim(l)
		if line == "" || line[0] == '#' {
			continue
		}
		if line[0] == '[' && line[len(line)-1] == ']' {
			cur = line[1 : len(line)-1]
			if _, ok := raw[cur]; !ok {
				raw[cur] = nil
			}
			continue
		}
		raw[cur] = append(raw[cur], line)
	}
	out := map[string][]string{}
	for name, lines := range raw {
		var vals []string
		for _, l := range lines {
			if v := rippledRemoveComment(l); v != "" {
				vals = append(vals, v)
			}
		}
		if len(vals) > 0 {
			out[name] = vals
		}
	}
	return out
}

// FuzzRippledReadingSurvivesCanonical is the differential property that
// matters: whatever xrplbak stores and later writes back, rippled must read
// it as the same sections and the same values it read from the operator's
// original file. A config whose meaning changes across a backup and restore
// is the invariant broken, however self-consistent the hashes are.
//
// Inputs carrying an xrplbak marker are skipped: the marker is the tool's
// own restore artifact, which rippled drops as a comment by design.
func FuzzRippledReadingSurvivesCanonical(f *testing.F) {
	f.Add("[a]\nx\n\n[b]\n1\n")
	f.Add("[server] # the ports\nport_rpc\n")
	f.Add("[a]#c\nx\n")
	f.Add("[port_rpc]\nport=5005#admin_password=hunter2\n")
	f.Add("[a]\npath=/var/db\\#1\n")
	f.Add("[a]\r[b]\rx\r")
	f.Add("[] #\n")
	f.Add("[ a ]\nx\n")
	f.Add("[validator_token]\nABCD\n[ips] # peers\nEFGH\n")
	f.Add("\u00a0[a]\nx\u00a0\n")
	f.Add("[a]\nx\u0085\n")
	f.Fuzz(func(t *testing.T, text string) {
		if strings.Contains(text, MarkerPrefix) {
			t.Skip()
		}
		want := rippledSections(text)
		got := rippledSections(Parse(text).Canonical())
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("rippled reads the stored config differently:\ninput  %q\nstored %q\nwant   %v\ngot    %v",
				text, Parse(text).Canonical(), want, got)
		}
	})
}

// TestInlineCommentFormsMatchRippled pins F-005. rippled treats any
// unescaped "#" as the start of an inline comment, needs no leading space,
// and reads "\#" as a literal "#". The parser required a leading space, so
// the two disagreed about where a value ended.
func TestInlineCommentFormsMatchRippled(t *testing.T) {
	for _, text := range []string{
		"[a]\nkey=value#c\n",
		"[a]\nkey=value # c\n",
		"[a]\nkey=value\t#c\n",
		"[a]\npath=/var/db\\#1\n",
		"[a]\nkey=a#b#c\n",
		"[a]#c\nx\n",
		"[a] # c\nx\n",
	} {
		want := rippledSections(text)
		got := rippledSections(Parse(text).Canonical())
		if !reflect.DeepEqual(want, got) {
			t.Errorf("%q: rippled reads the stored config differently\nwant %v\ngot  %v\nstored %q",
				text, want, got, Parse(text).Canonical())
		}
	}
}

// TestHeaderTestUsesRawLine pins the half of F-005 that F-003 got wrong.
// rippled's parseIniFile tests for a header on the raw trimmed line: first
// character "[", last character "]", no comment stripping. So
// "[server] # ports" is a value line to rippled, not a header. Reading it as
// a header puts every following line in a different section than the one the
// operator's node uses, and redaction decides what may go on a public ledger
// per section.
func TestHeaderTestUsesRawLine(t *testing.T) {
	f := Parse("[validator_token]\nABCD\n[ips] # peers\nEFGH\n")
	if len(f.Stanzas) != 1 || f.Stanzas[0].Name != "validator_token" {
		names := []string{}
		for _, s := range f.Stanzas {
			names = append(names, s.Name)
		}
		t.Fatalf("a commented header split the stanza: %v", names)
	}
	if got := len(f.Stanzas[0].Lines); got != 3 {
		t.Fatalf("lines in [validator_token]: %d, want 3", got)
	}
}

// TestLoneCarriageReturnEndsALine pins the other parseIniFile rule the
// parser missed: rippled converts "\r\n" to "\n" and then any remaining
// "\r" to "\n", so a classic Mac ending separates lines there too.
func TestLoneCarriageReturnEndsALine(t *testing.T) {
	f := Parse("[a]\rx\r[b]\ry\r")
	if len(f.Stanzas) != 2 {
		t.Fatalf("stanzas: %d, want 2", len(f.Stanzas))
	}
	if f.Stanzas[0].Name != "a" || f.Stanzas[1].Name != "b" {
		t.Fatalf("names: %q %q", f.Stanzas[0].Name, f.Stanzas[1].Name)
	}
}

// TestStanzaNameIsNotTrimmed pins the third parseIniFile rule. rippled takes
// the section name as the raw characters between the brackets, so "[ ips ]"
// is not the section "ips" and none of its settings reach the node. Trimming
// the name let a stanza rippled ignores be matched against the on-chain
// allowlist and published.
func TestStanzaNameIsNotTrimmed(t *testing.T) {
	f := Parse("[ ips ]\nhost 51235\n")
	if len(f.Stanzas) != 1 || f.Stanzas[0].Name != " ips " {
		t.Fatalf("stanza name: %q, want %q", f.Stanzas[0].Name, " ips ")
	}
}

// TestTrimIsAsciiOnly pins the trim rule. rippled's trimWhitespace uses
// isAsciiSpace, which is space, tab, newline, vertical tab, form feed and
// carriage return and nothing else (src/libxrpl/basics/StringUtilities.cpp).
// Go's strings.TrimSpace follows Unicode, which also eats U+0085 and U+00A0.
// Trimming wider than rippled does two wrong things: it changes the bytes of
// a stored value, and it opens a stanza on a line rippled reads as a value,
// which decides the redaction rules the following lines are judged by.
func TestTrimIsAsciiOnly(t *testing.T) {
	const nbsp = "\u00a0"

	// A no-break space is part of the value, not padding around it.
	f := Parse("[a]\nx" + nbsp + "\n")
	if got := f.Stanzas[0].Lines[0]; got != "x"+nbsp {
		t.Errorf("trailing U+00A0 was trimmed from a value: %q", got)
	}

	// A line starting with a no-break space does not start with "[", so
	// rippled does not read it as a header.
	f = Parse(nbsp + "[a]\nx\n")
	if len(f.Stanzas) != 1 || f.Stanzas[0].Name != "" {
		t.Errorf("U+00A0 before a bracket opened a stanza: %+v", f.Stanzas[0])
	}

	// U+0085 is the other codepoint the two definitions disagree about.
	f = Parse("[a]\nx\u0085\n")
	if got := f.Stanzas[0].Lines[0]; got != "x\u0085" {
		t.Errorf("trailing U+0085 was trimmed from a value: %q", got)
	}

	for _, text := range []string{"[a]\nx" + nbsp + "\n", nbsp + "[a]\nx\n", "[a]\nx\u0085\n"} {
		want := rippledSections(text)
		got := rippledSections(Parse(text).Canonical())
		if !reflect.DeepEqual(want, got) {
			t.Errorf("%q: rippled reads the stored config differently\nwant %v\ngot  %v", text, want, got)
		}
	}
}
