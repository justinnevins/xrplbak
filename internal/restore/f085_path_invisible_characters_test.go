package restore

import "testing"

// F-085: checkPath refused bytes under 0x20, DEL and eleven bidi marks, so
// that a path cannot rewrite the lines of the restore report. The C1
// controls (U+0080 to U+009F, which include CSI and NEL), the line and
// paragraph separators and the zero-width characters got through to the
// terminal. The codepoints are listed here, not read from the function
// under test.
func TestF085CheckPathRefusesInvisibleAndControlCharacters(t *testing.T) {
	refused := []rune{
		0x80, 0x85, 0x8d, 0x90, 0x9b, 0x9c, 0x9d, 0x9f, // C1 controls
		0x2028, 0x2029, // line and paragraph separator
		0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, // zero width
		0xad,   // soft hyphen
		0x061c, // Arabic letter mark
	}
	for _, r := range refused {
		p := "/etc/xrpld/a" + string(r) + "b.cfg"
		if err := checkPath(p); err == nil {
			t.Errorf("checkPath accepted a path holding U+%04X: %q", r, p)
		}
	}
	for _, p := range []string{
		"/etc/xrpld/xrpld.cfg",
		"/etc/xrpld/validators (old).txt",
		"/etc/xrpld/café.cfg",
		"/etc/xrpld/日本.cfg",
		"/etc/xrpld/ x.cfg", // no-break space is visible spacing, kept
		"/etc/xrpld/..config",
	} {
		if err := checkPath(p); err != nil {
			t.Errorf("checkPath refused an ordinary path %q: %v", p, err)
		}
	}
}
