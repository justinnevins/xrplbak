package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestReadmeUsageShowsTheFreshHostRestore pins that the README Usage block
// includes the fresh-host restore line (--account plus --words-file), not
// only the shape that needs a key file. A fresh host has no key file, and
// the Usage block is what an operator copies from first.
func TestReadmeUsageShowsTheFreshHostRestore(t *testing.T) {
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
	usage := s[i : i+j]
	want := regexp.MustCompile(`xrplbak restore .*--account .*--words-file`)
	if !want.MatchString(usage) {
		t.Fatalf("the Usage block has no restore line with --account and --words-file (the fresh-host shape):\n%s", usage)
	}
}

// TestEpochHelpSaysWhatMinusOneMeans. The flag package prints
// "(default -1)"; the prose next to it must say what -1 does, or an
// operator with no key file cannot tell whether epochs above 0 are probed.
func TestEpochHelpSaysWhatMinusOneMeans(t *testing.T) {
	var buf bytes.Buffer
	run([]string{"restore", "-h"}, strings.NewReader(""), &buf, &buf)
	if !strings.Contains(buf.String(), "-1 means") {
		t.Fatalf("restore -h does not explain -1 for --epoch:\n%s", buf.String())
	}
}
