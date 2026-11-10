package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/restore"
)

// F-071: backup accepted a file name that restore refuses, so a backup
// could be paid for and submitted that no restore would ever accept. The
// refusal belongs at plan time, before anything is sent.
func TestF071BuildRefusesAFileNameRestoreWouldRefuse(t *testing.T) {
	cfgBody, err := os.ReadFile(fixtures + "validator-full.cfg")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"x\ny.cfg", "x\x1b[2Ky.cfg", "x‮y.cfg", "x\u009by.cfg", "x​y.cfg", "x\xffy.cfg"} {
		e := newEnv(t)
		dir := t.TempDir()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, cfgBody, 0o600); err != nil {
			t.Logf("skip %q: this filesystem cannot hold the name (%v)", name, err)
			continue
		}
		if restore.CheckPath(p) == nil {
			t.Fatalf("setup: restore accepts %q", p)
		}
		for where, o := range map[string]Options{
			"as the config":   func() Options { o := e.opts(t, 1); o.ConfigPath = p; return o }(),
			"as validators":   func() Options { o := e.opts(t, 1); o.ValidatorsPath = p; return o }(),
			"as an --include": func() Options { o := e.opts(t, 1); o.Includes = []string{p}; return o }(),
		} {
			_, err := Build(o)
			if err == nil {
				t.Errorf("%q %s: Build accepted a file name restore refuses", name, where)
				continue
			}
			if !strings.Contains(err.Error(), "cannot be backed up") {
				t.Errorf("%q %s: failed for another reason: %v", name, where, err)
			}
			if strings.ContainsAny(err.Error(), "\n\x1b‮\u009b​") {
				t.Errorf("%q %s: the error carries the raw characters to the terminal: %q", name, where, err.Error())
			}
		}
	}
}
