package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// F-107: the demo in examples/testnet-demo was made by v1.0.0. From v1.1.0
// on, restore put its bundle lines in the wrong places and called the
// file PARTIAL with the bundle supplied, and verify (since v1.1.7) exited
// 5. The README sends a first-time reader to exactly these commands.
//
// A backup is a promise that it restores. A later version of the tool
// must keep that promise for every backup an earlier release wrote.

const (
	demoDir     = "../../examples/testnet-demo"
	demoAccount = "rw3SoiZCPvpQi2rTDKTuTC4XY9FoMQqnMf"
	// What the v1.0.0 binary restores from the demo, hashed.
	demoCfgSHA256 = "01203a6d43a37fa98485c3272b207bc2e321328b821a4564c707483b0975d3ac"
)

func demoRun(t *testing.T, cmd string, extra ...string) result {
	t.Helper()
	args := append([]string{cmd,
		"--dump", filepath.Join(demoDir, "demo.dump.json"),
		"--bundle", filepath.Join(demoDir, "demo.bundle"),
		"--words-file", filepath.Join(demoDir, "words.txt"),
		"--account", demoAccount,
	}, extra...)
	var buf bytes.Buffer
	code := run(args, strings.NewReader(""), &buf, &buf)
	return result{code: code, out: buf.String()}
}

func TestF107ShippedDemoVerifies(t *testing.T) {
	r := demoRun(t, "verify")
	if r.code != exitOK {
		t.Fatalf("verify on the shipped demo: exit %d\n%s", r.code, r.out)
	}
}

func TestF107ShippedDemoRestoresWhatV100Restored(t *testing.T) {
	r := demoRun(t, "restore")
	if r.code != exitOK {
		t.Fatalf("restore: exit %d\n%s", r.code, r.out)
	}
	if strings.Contains(r.out, "PARTIAL") {
		t.Errorf("restore calls a file PARTIAL with the bundle supplied:\n%s", r.out)
	}
	m := regexp.MustCompile(`(?m)^  files written under (.+)$`).FindStringSubmatch(r.out)
	if m == nil {
		t.Fatalf("restore did not name its directory:\n%s", r.out)
	}
	dir := strings.TrimSpace(m[1])
	defer os.RemoveAll(dir)
	var got []byte
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Name() == "xrpld.cfg" {
			got, _ = os.ReadFile(p)
		}
		return nil
	})
	if got == nil {
		t.Fatal("no xrpld.cfg was written")
	}
	sum := sha256.Sum256(got)
	if hex.EncodeToString(sum[:]) != demoCfgSHA256 {
		t.Errorf("xrpld.cfg is not the file v1.0.0 restores:\n%s", got)
	}
	if strings.Contains(string(got), "# xrplbak:") {
		t.Error("a marker is left in the restored file")
	}
	// The report says the file is in the v1.0 form, so nobody takes the
	// sorted, comment-free result for a loss.
	if !strings.Contains(r.out, "v1.0 format") {
		t.Errorf("the report does not say the backup is in the v1.0 format:\n%s", r.out)
	}
}
