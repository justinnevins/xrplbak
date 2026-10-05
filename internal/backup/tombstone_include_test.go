package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A tombstone stores no files. Build refuses an include list with it, so a
// caller below the command line cannot have a file dropped in silence.
func TestTombstoneBuildRefusesIncludes(t *testing.T) {
	e := newEnv(t)
	cfgPath := filepath.Join(e.dir, "xrpld.cfg")
	if err := os.WriteFile(cfgPath, []byte("[node_size]\nmedium\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := e.opts(t, 2)
	o.ConfigPath, o.ValidatorsPath, o.Tombstone = cfgPath, "", true
	o.Includes = []string{filepath.Join(e.dir, "notes.txt")}
	if _, err := Build(o); err == nil || !strings.Contains(err.Error(), "tombstone") {
		t.Fatalf("a tombstone with an include must be refused, got %v", err)
	}
	o.Includes = nil
	if _, err := Build(o); err != nil {
		t.Fatalf("control: a plain tombstone must build: %v", err)
	}
}
