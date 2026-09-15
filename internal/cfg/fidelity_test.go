package cfg

import (
	"strings"
	"testing"
)

// FuzzParseRenderIsExact is the fidelity property. A backup that cannot
// reproduce the operator's file is not a backup, whatever its own hashes
// say. Parse and Render must be exact inverses over arbitrary bytes:
// comments, blank lines, line order, indentation and the choice of line
// terminator all belong to the operator, not to the tool.
//
// Until 085cd96 this was false by construction. Parse skipped blank lines
// and comment lines, dropped inline comments, and Canonical sorted stanzas
// alphabetically, so the restored file was what the tool understood rather
// than what the operator wrote.
func FuzzParseRenderIsExact(f *testing.F) {
	f.Add("[a]\nx\n")
	f.Add("# why this box exists\n\n[server]   # the ports\nport_rpc\n")
	f.Add("[b]\n1\n\n[a]\nx\n")
	f.Add("[a]\r\nx\r\n")
	f.Add("[a]\rx\r")
	f.Add("no trailing newline")
	f.Add("")
	f.Add("\n\n\n")
	f.Add("   \t  \n[a]\n\tindented = 1\n")
	f.Fuzz(func(t *testing.T, text string) {
		if got := Parse(text).Render(); got != text {
			t.Fatalf("Parse and Render are not inverses:\n in  %q\n out %q", text, got)
		}
	})
}

// TestCommentsAndLayoutSurviveParsing spells out what the fuzz property
// means for a config an operator would actually recognize.
func TestCommentsAndLayoutSurviveParsing(t *testing.T) {
	const src = "# Fort Collins node, rebuilt 2026-03-02\n" +
		"# ticket OPS-4417\n" +
		"\n" +
		"[server]\n" +
		"port_rpc_admin_local\n" +
		"\n" +
		"[node_size]\n" +
		"medium   # was small until the March load test\n"

	f := Parse(src)
	if got := f.Render(); got != src {
		t.Fatalf("the file did not come back:\n%q", got)
	}

	// The classification view still reads the settings rippled reads.
	s := f.Get("node_size")
	if s == nil || len(s.Lines) != 1 || s.Lines[0] != "medium" {
		t.Fatalf("classification view: %+v", s)
	}

	// Every line is accounted for, and the comments are still there.
	var kinds [4]int
	for _, l := range f.Lines {
		kinds[l.Kind]++
	}
	if kinds[Comment] != 2 {
		t.Errorf("whole-line comments kept: %d, want 2", kinds[Comment])
	}
	if kinds[Header] != 2 {
		t.Errorf("headers: %d, want 2", kinds[Header])
	}
	var inline string
	for _, l := range f.Lines {
		if l.Comment != "" {
			inline = l.Comment
		}
	}
	if !strings.Contains(inline, "March load test") {
		t.Errorf("inline comment was not kept: %q", inline)
	}
}

// TestLineTerminatorsAreNotNormalized pins the part a normalizing parser
// loses. rippled reads all three endings the same way, so a tool is tempted
// to convert them on the way in. That changes the operator's bytes.
func TestLineTerminatorsAreNotNormalized(t *testing.T) {
	for _, src := range []string{"[a]\nx\n", "[a]\r\nx\r\n", "[a]\rx\r", "[a]\r\nx\n", "[a]\nx"} {
		if got := Parse(src).Render(); got != src {
			t.Errorf("%q came back as %q", src, got)
		}
	}
}

// TestEveryLineBelongsToAStanza pins the association the redaction step will
// rely on: a comment sitting inside a stanza is part of that stanza, and
// lines before the first header belong to the empty name.
func TestEveryLineBelongsToAStanza(t *testing.T) {
	// The seventh line is the empty segment after the final newline. It sits
	// inside [b], which is what keeps Render exact.
	f := Parse("# top\n[a]\n# about a\nx\n[b]\ny\n")
	want := []string{"", "a", "a", "a", "b", "b", "b"}
	if len(f.Lines) != len(want) {
		t.Fatalf("lines: %d, want %d", len(f.Lines), len(want))
	}
	for i, w := range want {
		if f.Lines[i].Stanza != w {
			t.Errorf("line %d (%q) is in stanza %q, want %q", i+1, f.Lines[i].Raw, f.Lines[i].Stanza, w)
		}
	}
}
