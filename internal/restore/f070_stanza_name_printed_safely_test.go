package restore

import (
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/manifest"
)

// F-070: a stanza name went to the terminal as written. The name in a
// manifest comes from whoever made the backup, so a name carrying an
// escape sequence could erase or rewrite the lines above it on the
// operator's screen during a restore.
func TestF070TodoLineNeverPrintsARawControlCharacter(t *testing.T) {
	for _, name := range []string{"x\x1b[2A\x1b[Jrestore complete\x07", "x\u202ey", "x\u009b2Jy", "a\nRe-enter nothing", "x\u200by"} {
		for _, r := range []manifest.Redaction{
			{Stanza: name, Lines: 2},
			{Stanza: name, Lines: 2, Comments: 2},
			{Stanza: name, Lines: 2, Comments: 1},
		} {
			got := todoLine(r, "/etc/xrpld/xrpld.cfg")
			for _, c := range got {
				if c < 0x20 || c == 0x7f || (c >= 0x80 && c <= 0x9f) || c == 0x202e || c == 0x200b {
					t.Errorf("%q: the to-do line carries U+%04X: %q", name, c, got)
					break
				}
			}
		}
	}
	if got := todoLine(manifest.Redaction{Stanza: "ips_fixed", Lines: 1}, ""); !strings.Contains(got, "[ips_fixed]") {
		t.Errorf("an ordinary name changed: %q", got)
	}
}
