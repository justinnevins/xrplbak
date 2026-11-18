package export

import (
	"regexp"
	"strings"
	"testing"
)

// backupName is the rule written a second way. BackupFile is hand-rolled,
// so the regexp is an oracle that shares no code with it.
var backupName = regexp.MustCompile(`\A[0-9a-f]{32}\.(bundle|dump\.json)\z`)

// FuzzBackupFileNameIsStrict: the name rule is the only thing that keeps
// a key file, a settings file or a path out of an export. It must accept
// exactly the names xrplbak writes and nothing near them.
func FuzzBackupFileNameIsStrict(f *testing.F) {
	id := strings.Repeat("0a", 16)
	for _, s := range []string{
		id + ".bundle", id + ".dump.json", id + ".dump.json.tmp", id + ".bundle\n", id + ".bundle\x00",
		"../" + id + ".bundle", id + "/.bundle", strings.ToUpper(id) + ".bundle", id[:31] + ".bundle",
		id + "0.bundle", id + ".dump", id + ".json", ".bundle", "", "xrplbak.key", "xrplbak.settings",
		id + ".bundle.dump.json", id + ".dump.json.bundle", " " + id + ".bundle",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		got, want := BackupFile(name), backupName.MatchString(name)
		if got != want {
			t.Fatalf("BackupFile(%q) = %v, the rule says %v", name, got, want)
		}
		if got && strings.ContainsAny(name, `/\`+"\x00\n ") {
			t.Fatalf("accepted %q, which is not a bare file name", name)
		}
	})
}

// A stream cut anywhere before its last line has no End line, so the
// receiving side can tell a short transfer from a whole one.
func TestFrameEndsWithTheEndLine(t *testing.T) {
	for _, n := range []int{0, 1, 56, 57, 58, 1000} {
		out := string(Frame(make([]byte, n)))
		if !strings.HasPrefix(out, Begin+"\n") || !strings.HasSuffix(out, "\n"+End+"\n") {
			t.Fatalf("%d bytes: frame is not Begin ... End:\n%s", n, out)
		}
		if strings.Count(out, End) != 1 || strings.Count(out, Begin) != 1 {
			t.Fatalf("%d bytes: a marker appears more than once", n)
		}
		if strings.Contains(out, "\n\n") {
			t.Fatalf("%d bytes: frame has an empty line", n)
		}
	}
}
