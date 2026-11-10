package restore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F-079: restore --write --force wrote over an existing file in place.
// The file kept its old mode, so a config backed up as 0600 stayed 0644
// when a 0644 file was already there, although the report says files keep
// their backed-up mode. The write also went through a symlink at the
// destination to whatever it pointed at, outside the target directory.
func TestF079ForceOverwriteAppliesTheBackedUpMode(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "xrpld.cfg")
	if err := os.WriteFile(dst, []byte("old, world readable\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &Plan{Files: []File{{Path: "/etc/xrpld/xrpld.cfg", Mode: 0o600, Data: []byte("[validator_token]\nsecret\n")}}}
	if _, err := p.WriteTarget(dir, true); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode after --force is %o; the backup recorded 600", got)
	}
	if b, _ := os.ReadFile(dst); string(b) != "[validator_token]\nsecret\n" {
		t.Fatalf("content after --force: %q", b)
	}
	// Nothing but the restored file is left behind.
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("target holds %d entries after the write, want 1", len(ents))
	}
}

// The mode is the backed-up one in both directions: a file backed up as
// 0640 over an existing 0600 file ends 0640.
func TestF079ModeIsExactForNewAndExistingFiles(t *testing.T) {
	for _, mode := range []uint32{0o600, 0o640, 0o644, 0o400} {
		dir := t.TempDir()
		p := &Plan{Files: []File{{Path: "/etc/xrpld/a.cfg", Mode: mode, Data: []byte("a\n")}}}
		if _, err := p.WriteTarget(dir, false); err != nil {
			t.Fatal(err)
		}
		st, _ := os.Stat(filepath.Join(dir, "a.cfg"))
		if got := uint32(st.Mode().Perm()); got != mode {
			t.Errorf("new file: mode %o, want %o", got, mode)
		}
		if _, err := p.WriteTarget(dir, true); err != nil {
			t.Fatalf("overwrite of a %o file: %v", mode, err)
		}
		st, _ = os.Stat(filepath.Join(dir, "a.cfg"))
		if got := uint32(st.Mode().Perm()); got != mode {
			t.Errorf("overwritten file: mode %o, want %o", got, mode)
		}
	}
}

func TestF079RefusesASymlinkAtTheDestination(t *testing.T) {
	for _, force := range []bool{false, true} {
		outside := t.TempDir()
		victim := filepath.Join(outside, "victim.cfg")
		if err := os.WriteFile(victim, []byte("untouched\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		link := filepath.Join(dir, "xrpld.cfg")
		if err := os.Symlink(victim, link); err != nil {
			t.Skip("no symlinks here")
		}
		p := &Plan{Files: []File{
			{Path: "/etc/xrpld/other.cfg", Mode: 0o600, Data: []byte("other\n")},
			{Path: "/etc/xrpld/xrpld.cfg", Mode: 0o600, Data: []byte("new\n")},
		}}
		written, err := p.WriteTarget(dir, force)
		if err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("force=%v: want a refusal that names the symlink, got %v", force, err)
		}
		if len(written) != 0 {
			t.Errorf("force=%v: %d file(s) written before the refusal", force, len(written))
		}
		if b, _ := os.ReadFile(victim); string(b) != "untouched\n" {
			t.Errorf("force=%v: the file behind the symlink now holds %q", force, b)
		}
		if _, err := os.Lstat(filepath.Join(dir, "other.cfg")); err == nil {
			t.Errorf("force=%v: another file was written though the run was refused", force)
		}
		if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("force=%v: the symlink itself was replaced", force)
		}
	}
}

// A destination that is a directory is refused by name, with or without
// --force, before anything is written.
func TestF079RefusesADestinationThatIsNotAFile(t *testing.T) {
	for _, force := range []bool{false, true} {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "xrpld.cfg"), 0o700); err != nil {
			t.Fatal(err)
		}
		p := &Plan{Files: []File{{Path: "/etc/xrpld/xrpld.cfg", Mode: 0o600, Data: []byte("new\n")}}}
		if _, err := p.WriteTarget(dir, force); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("force=%v: want the refusal, got %v", force, err)
		}
	}
}

// A write that cannot finish reports the error and leaves no temporary
// file beside the destination.
func TestF079FailedWriteReportsAndCleansUp(t *testing.T) {
	dir := t.TempDir()
	blocked := filepath.Join(dir, "xrpld.cfg")
	if err := os.MkdirAll(filepath.Join(blocked, "inner"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(blocked, File{Path: "/etc/xrpld/xrpld.cfg", Mode: 0o600, Data: []byte("new\n")}); err == nil {
		t.Fatal("writeFile over a non-empty directory returned no error")
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 || ents[0].Name() != "xrpld.cfg" {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("a failed write left files behind: %v", names)
	}
}
