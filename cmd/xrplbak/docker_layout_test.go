package main

// A validator in Docker keeps its config in a host folder mounted into the
// container (the xrpllabsofficial/xrpld image mounts it at /config/). The
// operator runs xrplbak on the host against that folder. Two layouts matter:
// [validators_file] names validators.txt relative to the config, which
// resolves on the host too; or it names an absolute path that exists only
// inside the container, which the host cannot see. The second must refuse
// with the way out named, and --validators with the host path must then
// back up and restore both files byte for byte into the host folder.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/backup"
)

func dockerFolder(t *testing.T, w *world, validatorsFile string) (dir, cfgPath, valPath string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "xrpld-config")
	must(t, os.MkdirAll(dir, 0o700))
	raw, err := os.ReadFile(w.cfgPath)
	must(t, err)
	cfgPath = filepath.Join(dir, "xrpld.cfg")
	// The fixture already names validators.txt; point it where the layout says.
	conf := strings.Replace(string(raw), "[validators_file]\nvalidators.txt\n", "[validators_file]\n"+validatorsFile+"\n", 1)
	if conf == string(raw) && validatorsFile != "validators.txt" {
		t.Fatal("fixture has no [validators_file] validators.txt stanza to repoint")
	}
	must(t, os.WriteFile(cfgPath, []byte(conf), 0o600))
	val, err := os.ReadFile(w.valPath)
	must(t, err)
	valPath = filepath.Join(dir, "validators.txt")
	must(t, os.WriteFile(valPath, val, 0o644))
	return dir, cfgPath, valPath
}

func TestDockerHostFolderRelativeValidatorsFile(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	w := newWorld(t, 5)
	_, cfgPath, valPath := dockerFolder(t, w, "validators.txt")
	r := w.run("", "backup", "--config", cfgPath, "--key", w.keyFile, "--out", t.TempDir())
	if r.code != exitOK || !strings.Contains(r.out, "file:        "+valPath) {
		t.Fatalf("a relative [validators_file] must resolve beside the host config, got %d:\n%s", r.code, r.out)
	}
}

func TestDockerContainerOnlyValidatorsPath(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	w := newWorld(t, 6)
	w.ledger.Batch = true
	// A path that exists inside the container but not on the host.
	const containerPath = "/xrplbak-test-container-only/etc/xrpld/validators.txt"
	_, cfgPath, valPath := dockerFolder(t, w, containerPath)

	r := w.run("", "backup", "--config", cfgPath, "--key", w.keyFile, "--out", t.TempDir())
	if r.code != exitUsage || !strings.Contains(r.out, containerPath) || !strings.Contains(r.out, "--validators PATH") {
		t.Fatalf("a container-only [validators_file] must refuse and name --validators, got %d:\n%s", r.code, r.out)
	}
	r = w.run("", "backup", "--config", cfgPath, "--validators", valPath, "--key", w.keyFile, "--out", t.TempDir())
	if r.code != exitOK || !strings.Contains(r.out, "file:        "+valPath) {
		t.Fatalf("--validators with the host path must back up both files, got %d:\n%s", r.code, r.out)
	}

	// Submit, then restore into a fresh host folder: both files come back
	// byte for byte, the container path line included.
	o := backup.Options{ConfigPath: cfgPath, ValidatorsPath: valPath, Key: w.key, Seq: 2}
	out := t.TempDir()
	if err := doSubmit(o, w.ledger, "fake", w.writer, out, 0, false, true, "auto", "", "", nil, nil, ""); err != nil {
		t.Fatal(err)
	}
	bundles, _ := filepath.Glob(filepath.Join(out, "*.bundle"))
	if len(bundles) != 1 {
		t.Fatalf("want one bundle, got %v", bundles)
	}
	target := filepath.Join(t.TempDir(), "restored-config")
	must(t, os.MkdirAll(target, 0o700))
	r = w.run("", "restore", "--dump", w.dumpFile("docker"), "--words-file", w.words, "--account", w.writer.Address(),
		"--bundle", bundles[0], "--write", "--target", target, "--yes")
	if r.code != exitOK {
		t.Fatalf("restore into the host folder: exit %d\n%s", r.code, r.out)
	}
	for _, name := range []string{"xrpld.cfg", "validators.txt"} {
		want, _ := os.ReadFile(filepath.Join(filepath.Dir(cfgPath), name))
		got, err := os.ReadFile(filepath.Join(target, name))
		if err != nil || string(got) != string(want) {
			t.Fatalf("%s did not come back byte for byte into the host folder (%v):\n%s", name, err, r.out)
		}
	}
}

// An absolute [validators_file] that does exist on the host is used as
// named, not joined onto the config folder.
func TestDockerAbsoluteHostValidatorsFile(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	w := newWorld(t, 7)
	elsewhere := filepath.Join(t.TempDir(), "lists", "validators.txt")
	must(t, os.MkdirAll(filepath.Dir(elsewhere), 0o700))
	val, err := os.ReadFile(w.valPath)
	must(t, err)
	must(t, os.WriteFile(elsewhere, val, 0o644))
	_, cfgPath, _ := dockerFolder(t, w, elsewhere)
	r := w.run("", "backup", "--config", cfgPath, "--key", w.keyFile, "--out", t.TempDir())
	if r.code != exitOK || !strings.Contains(r.out, "file:        "+elsewhere) {
		t.Fatalf("an absolute [validators_file] that exists must be used as named, got %d:\n%s", r.code, r.out)
	}
}
