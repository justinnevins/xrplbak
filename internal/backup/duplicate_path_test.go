package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSamePathNamedTwiceIsRefused pins that one file cannot enter a backup
// twice. An --include equal to --config once went into the bundle whole
// while its split went on-chain, and restore merged the two into a file
// with its content doubled. Every way of naming one file twice is refused,
// including a spelling that only resolves to the same path.
func TestSamePathNamedTwiceIsRefused(t *testing.T) {
	e := newEnv(t)
	cfgPath := filepath.Join(e.dir, "xrpld.cfg")
	valPath := filepath.Join(e.dir, "validators.txt")
	other := filepath.Join(e.dir, "notes.txt")
	for p, body := range map[string]string{cfgPath: "[node_size]\nmedium\n", valPath: "[validators]\nnHB\n", other: "hello\n"} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	roundabout := filepath.Join(e.dir, "sub", "..", "xrpld.cfg")
	cases := []struct {
		name       string
		cfg, val   string
		includes   []string
		wantInName string
	}{
		{"include is the config", cfgPath, "", []string{cfgPath}, cfgPath},
		{"include spells the config another way", cfgPath, "", []string{roundabout}, cfgPath},
		{"include is the validators file", cfgPath, valPath, []string{valPath}, valPath},
		{"include named twice", cfgPath, "", []string{other, other}, other},
		{"validators is the config", cfgPath, cfgPath, nil, cfgPath},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := e.opts(t, 1)
			o.ConfigPath, o.ValidatorsPath, o.Includes = c.cfg, c.val, c.includes
			p, err := Build(o)
			if err == nil {
				var paths []string
				for _, f := range p.Manifest.Files {
					paths = append(paths, f.Path+" ("+f.Where+")")
				}
				t.Fatalf("accepted; manifest lists %v", paths)
			}
			if !strings.Contains(err.Error(), c.wantInName) || !strings.Contains(err.Error(), "more than once") {
				t.Fatalf("error does not name the file or the problem: %v", err)
			}
		})
	}
	// Control: distinct files still back up.
	o := e.opts(t, 1)
	o.ConfigPath, o.ValidatorsPath, o.Includes = cfgPath, valPath, []string{other}
	if _, err := Build(o); err != nil {
		t.Fatalf("three distinct files refused: %v", err)
	}
}
