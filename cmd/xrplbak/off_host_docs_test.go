package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The sudo rule in the doc, the default command in both laptop scripts and
// the command the binary accepts have to be the same words: sudo matches
// arguments exactly, so one differing character is "a password is
// required" on the operator's first run.
func TestOffHostDocAndScriptsNameOneCommand(t *testing.T) {
	read := func(parts ...string) string {
		b, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, parts...)...))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	const command = "/usr/local/bin/xrplbak export --out /root/xrplbak/xrplbak-out"
	doc := read("docs", "off-host-copies.md")
	rule := regexp.MustCompile(`NOPASSWD: (\S+ export --out \S+?)\\n`).FindStringSubmatch(doc)
	if rule == nil {
		t.Fatal("docs/off-host-copies.md has no sudo rule for export")
	}
	if rule[1] != command {
		t.Errorf("the doc's sudo rule allows %q, want %q", rule[1], command)
	}
	for _, script := range []string{"Pull-XrplbakBackup.ps1", "pull-xrplbak-backup.sh"} {
		if !strings.Contains(read("contrib", "off-host-copy", script), "sudo -n "+command) {
			t.Errorf("%s does not run %q by default", script, "sudo -n "+command)
		}
	}
	// The binary takes exactly those arguments: a real folder passes,
	// one more word does not.
	dir := exportDir(t, map[string]string{exportIDa + ".bundle": "x"})
	if code, _, errOut := exportRun("--out", dir); code != exitOK {
		t.Fatalf("export --out DIR: exit %d: %s", code, errOut)
	}
}

// The README is where an operator learns the command exists and what its
// exit codes mean.
func TestReadmeCoversExport(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "## Usage")
	j := strings.Index(s[i:], "\n## ")
	if i < 0 || j < 0 {
		t.Fatal("no Usage section")
	}
	if !strings.Contains(s[i:i+j], "xrplbak export --out") {
		t.Error("the Usage block has no export line")
	}
	if !strings.Contains(s, "docs/off-host-copies.md") {
		t.Error("the README does not link docs/off-host-copies.md")
	}
	for code, word := range map[string]string{"| 3 |": "export", "| 5 |": "export"} {
		row := s[strings.Index(s, code):]
		row = row[:strings.Index(row, "\n")]
		if !strings.Contains(row, word) {
			t.Errorf("exit code row %s does not mention %s", code, word)
		}
	}
}
