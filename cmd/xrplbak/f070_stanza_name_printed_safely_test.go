package main

import (
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/redact"
)

// F-070: the backup plan printed a stanza name as written.
func TestF070MoveLineNeverPrintsARawControlCharacter(t *testing.T) {
	for _, name := range []string{"x\x1b[2A\x1b[Jbackup complete\x07", "x\u202ey", "x\u009b2Jy", "a\n[server]: 0 line(s)"} {
		for _, m := range []redact.Move{
			{Stanza: name, Lines: 2, Reason: "r"},
			{Stanza: name, Lines: 2, Comments: 2, Reason: "r"},
			{Stanza: name, Lines: 2, Comments: 1, Reason: "r"},
		} {
			got := moveLine(m)
			for _, c := range got {
				if c < 0x20 || c == 0x7f || (c >= 0x80 && c <= 0x9f) || c == 0x202e {
					t.Errorf("%q: the plan line carries U+%04X: %q", name, c, got)
					break
				}
			}
		}
	}
	if got := moveLine(redact.Move{Stanza: "ips_fixed", Lines: 1, Reason: "r"}); !strings.HasPrefix(got, "[ips_fixed]: ") {
		t.Errorf("an ordinary name changed: %q", got)
	}
}
