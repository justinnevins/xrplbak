package cfg

import "testing"

// FuzzCanonicalIsFixedPoint asserts that canonical form is stable. Parsing
// canonical text and rendering it again must return the same bytes. Every
// hash in a manifest is taken over canonical bytes, so a canonical form
// that drifts on a second pass would make a correct backup fail its own
// integrity check.
func FuzzCanonicalIsFixedPoint(f *testing.F) {
	f.Add("[a]\nx\n\n[b]\n1\n")
	f.Add("[b]\n1\n\n[a]\nx # comment\n# c\n")
	f.Add("no stanza line\n[dup]\n1\n[dup]\n2\n")
	f.Add("[port_rpc]\nip = 127.0.0.1\nadmin = 10.0.0.5\n")
	f.Add("")
	f.Add("[]\n\n[ ]\nvalue\n")
	f.Fuzz(func(t *testing.T, text string) {
		once := Parse(text).Canonical()
		twice := Parse(once).Canonical()
		if once != twice {
			t.Fatalf("canonical form drifted on the second pass:\n%q\n%q", once, twice)
		}
	})
}

// TestCanonicalDropsEmptyNamelessStanza pins the second defect the fuzz
// targets found. A "[]" line created a nameless stanza with no lines.
// Canonical wrote a bare separator for it, which re-parsing could not
// recover, so the same config hashed two different ways.
func TestCanonicalDropsEmptyNamelessStanza(t *testing.T) {
	for _, text := range []string{"[]\n[0]\n", "[ ]\n", "[]\n"} {
		once := Parse(text).Canonical()
		twice := Parse(once).Canonical()
		if once != twice {
			t.Fatalf("%q: canonical form drifted:\n%q\n%q", text, once, twice)
		}
	}
	// A nameless stanza that carries lines still keeps them.
	if got := Parse("value\n[a]\nx\n").Canonical(); got != "value\n\n[a]\nx\n" {
		t.Fatalf("nameless stanza lost its lines: %q", got)
	}
}

// TestHeaderWithTrailingComment was written on the belief that
// rippled accepts a trailing comment on a stanza header. It does not. Its
// parseIniFile tests for a header on the raw trimmed line, first character
// "[" and last character "]", before any comment is removed
// (src/xrpld/core/detail/Config.cpp). So "[server] # the ports" is a value
// line to rippled, and reading it as a header put every following line in a
// stanza the operator's node does not have. The assertion is corrected here
// rather than deleted, and the fixed-point cases it carried are kept.
func TestHeaderWithTrailingComment(t *testing.T) {
	f := Parse("[server] # the ports\nport_rpc\n")
	if len(f.Stanzas) != 1 || f.Stanzas[0].Name != "" {
		t.Fatalf("a commented header must not open a stanza: %+v", f.Stanzas[0])
	}
	if got := f.Stanzas[0].Lines; len(got) != 2 || got[0] != "[server] # the ports" {
		t.Fatalf("lines: %q", got)
	}
	// The raw line is kept because stripping its comment would leave
	// "[server]", which the next parse would read as a header.
	if got := f.Canonical(); got != "[server] # the ports\nport_rpc\n" {
		t.Fatalf("canonical: %q", got)
	}
	for _, text := range []string{"[] #", "[a] # c\nx\n", "[a]#c\n"} {
		once := Parse(text).Canonical()
		if twice := Parse(once).Canonical(); once != twice {
			t.Fatalf("%q: canonical form drifted:\n%q\n%q", text, once, twice)
		}
	}
}
