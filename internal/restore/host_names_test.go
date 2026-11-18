package restore

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// onDisk checks the invariant after a write that reported success: every
// file of the plan is on disk, under its own name, with its own bytes.
func onDisk(t *testing.T, what string, p *Plan, at func(File) string) {
	t.Helper()
	for _, f := range p.Files {
		got, err := os.ReadFile(at(f))
		if err != nil {
			t.Errorf("%s reported success, but %s is not there: %v", what, f.Path, err)
			continue
		}
		if !bytes.Equal(got, f.Data) {
			t.Errorf("%s reported success, but %s holds %q, want %q", what, f.Path, got, f.Data)
		}
	}
}

// foldsCase reports whether dir treats names that differ only by case as
// one file, as Windows and a default macOS volume do.
func foldsCase(t *testing.T, dir string) bool {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "probe"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := os.Stat(filepath.Join(dir, "PROBE"))
	os.Remove(filepath.Join(dir, "probe"))
	return err == nil
}

// Two files a Linux host keeps apart can be one file where the restore
// runs. The second write then replaces the first, and the report lists
// both as written. Restore must stop instead, before it replaces anything.
func TestNamesThatAreOneFileHereAreRefused(t *testing.T) {
	plans := map[string]*Plan{
		"same folder": {Files: []File{
			{Path: "/etc/xrpld/a.cfg", Mode: 0o600, Data: []byte("lower\n")},
			{Path: "/etc/xrpld/A.cfg", Mode: 0o600, Data: []byte("UPPER\n")},
		}},
		"folders that differ by case": {Files: []File{
			{Path: "/etc/xrpld/x.cfg", Mode: 0o600, Data: []byte("lower\n")},
			{Path: "/etc/XRPLD/x.cfg", Mode: 0o600, Data: []byte("UPPER\n")},
		}},
	}
	for name, p := range plans {
		// --write: both land in one folder by base name.
		if name == "same folder" {
			target := t.TempDir()
			folds := foldsCase(t, target)
			_, err := p.WriteTarget(target, false)
			switch {
			case folds && err == nil:
				t.Errorf("%s, --write: no error on a file system that folds case", name)
			case folds && !strings.Contains(err.Error(), "same file"):
				t.Errorf("%s, --write: error does not say the two names are the same file: %v", name, err)
			case !folds && err != nil:
				t.Errorf("%s, --write: %v", name, err)
			case !folds:
				onDisk(t, "--write", p, func(f File) string { return filepath.Join(target, filepath.Base(f.Path)) })
			}
			if folds {
				// The first file is still the first file.
				if got, _ := os.ReadFile(filepath.Join(target, "a.cfg")); string(got) != "lower\n" {
					t.Errorf("%s, --write: a.cfg holds %q after the refusal, want the first file's bytes", name, got)
				}
			}
		}
		// Dry run: the whole path is kept under a temp dir.
		probe := t.TempDir()
		folds := foldsCase(t, probe)
		dir, err := p.WriteTemp()
		if dir != "" {
			defer os.RemoveAll(dir)
		}
		switch {
		case folds && err == nil:
			t.Errorf("%s, dry run: no error on a file system that folds case", name)
		case folds && !strings.Contains(err.Error(), "same file"):
			t.Errorf("%s, dry run: error does not say the two names are the same file: %v", name, err)
		case !folds && err != nil:
			t.Errorf("%s, dry run: %v", name, err)
		case !folds:
			onDisk(t, "the dry run", p, func(f File) string { return filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(f.Path, "/"))) })
		}
	}
}

// Windows accepts some names and stores something else: NUL and COM1 are
// devices, a colon opens a named stream inside another file, and a final
// dot or space is dropped. A restore that reported such a file written
// would be wrong about what is on disk, so on Windows these are refused.
func TestWindowsRefusesNamesItWouldNotKeep(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	for _, name := range []string{"NUL", "nul", "nul.cfg", "COM1", "con.txt", "a.cfg:hidden", "a.cfg.", "a.cfg ", "LPT1"} {
		p := &Plan{Files: []File{{Path: "/etc/xrpld/" + name, Mode: 0o600, Data: []byte("data\n")}}}
		target := t.TempDir()
		if written, err := p.WriteTarget(target, false); err == nil {
			ents, _ := os.ReadDir(target)
			var have []string
			for _, e := range ents {
				have = append(have, e.Name())
			}
			t.Errorf("--write of %q reported %v; the folder holds %q", name, written, have)
		}
		dir, err := p.WriteTemp()
		if dir != "" {
			os.RemoveAll(dir)
		}
		if err == nil {
			t.Errorf("dry run of %q reported success", name)
		}
		// The same name as a folder on the way to the file.
		q := &Plan{Files: []File{{Path: "/etc/" + name + "/xrpld.cfg", Mode: 0o600, Data: []byte("data\n")}}}
		dir, err = q.WriteTemp()
		if dir != "" {
			os.RemoveAll(dir)
		}
		if err == nil {
			t.Errorf("dry run through a folder named %q reported success", name)
		}
	}
}
