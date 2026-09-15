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

// TestHeaderWithTrailingComment pins the third defect the fuzz targets
// found. The parser tested for a stanza header before it stripped an
// inline comment, so "[server] # comment" was read as a value line, not a
// header. Canonical then wrote it back as a value line, and the next parse
// read it as a header, which silently moved every following line into the
// wrong stanza.
func TestHeaderWithTrailingComment(t *testing.T) {
	f := Parse("[server] # the ports\nport_rpc\n")
	if len(f.Stanzas) != 1 || f.Stanzas[0].Name != "server" {
		t.Fatalf("header with a trailing comment did not parse as a header: %+v", f.Stanzas[0])
	}
	if got := f.Canonical(); got != "[server]\nport_rpc\n" {
		t.Fatalf("canonical: %q", got)
	}
	for _, text := range []string{"[] #", "[a] # c\nx\n", "[a]#c\n"} {
		once := Parse(text).Canonical()
		if twice := Parse(once).Canonical(); once != twice {
			t.Fatalf("%q: canonical form drifted:\n%q\n%q", text, once, twice)
		}
	}
}
