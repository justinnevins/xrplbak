package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/backup"
	"github.com/justinnevins/xrplbak/internal/crypto"
	"github.com/justinnevins/xrplbak/internal/testsupport/fake"
	"github.com/justinnevins/xrplbak/internal/xrpl/sign"
)

// The recorded backup is a complete backup written to files once, on
// Linux: the dump of the fake ledger, the bundle, the recovery words, the
// account, and the two config files it was made from. Tests that read it
// build nothing, so they run on every platform the binary ships for,
// Windows included, and they pin that a backup written by an older build
// still restores byte for byte.
//
// Regenerate it only when the wire format changes on purpose:
//
//	XRPLBAK_RECORD=/srv/xrplbak-recorded go test ./cmd/xrplbak -run TestRecordBackup
//
// The directory must be that exact path: it is stored in the backup.
const (
	recordedDir  = "testdata/recorded"
	recordedHome = "/srv/xrplbak-recorded"
)

var recordedFiles = []string{"xrpld.cfg", "validators.txt"}

func TestRecordBackup(t *testing.T) {
	home := os.Getenv("XRPLBAK_RECORD")
	if home == "" {
		t.Skip("set XRPLBAK_RECORD=" + recordedHome + " to write the recorded backup again")
	}
	if home != recordedHome {
		t.Fatalf("XRPLBAK_RECORD must be %s", recordedHome)
	}
	must(t, os.MkdirAll(home, 0o700))
	must(t, os.MkdirAll(filepath.Join(recordedDir, "expect"), 0o755))
	w := &world{t: t, dir: recordedDir}
	for i := range w.root {
		w.root[i] = byte(i)*7 + 11
	}
	w.writer, _ = sign.KeyFromSeed(bytes.Repeat([]byte{0x5a}, 16))
	w.key = &crypto.KeyFile{Epoch: 0, Key: w.root.DeriveEpochKey(0)}
	copy(w.key.AccountID[:], w.writer.AccountID())
	copy(w.key.WriterSeed[:], w.writer.Seed())
	w.ledger = fake.New()
	w.ledger.Fund(w.writer.Address(), 5_000_000)
	for name, mode := range map[string]os.FileMode{"xrpld.cfg": 0o640, "validators.txt": 0o644} {
		src := name
		if name == "xrpld.cfg" {
			src = "validator-full.cfg"
		}
		raw, err := os.ReadFile(fixtures + src)
		must(t, err)
		must(t, os.WriteFile(filepath.Join(home, name), raw, mode))
		must(t, os.Chmod(filepath.Join(home, name), mode))
		must(t, os.WriteFile(filepath.Join(recordedDir, "expect", name), raw, 0o644))
	}
	p, err := backup.Build(backup.Options{ConfigPath: filepath.Join(home, "xrpld.cfg"), ValidatorsPath: filepath.Join(home, "validators.txt"), Key: w.key, Now: time.Unix(1_800_000_001, 0), Seq: 1})
	must(t, err)
	w.plan = p
	w.submit(p)
	w.dumpFile("recorded")
	must(t, os.WriteFile(filepath.Join(recordedDir, "recorded.bundle"), p.Bundle, 0o644))
	must(t, os.WriteFile(filepath.Join(recordedDir, "words.txt"), []byte(strings.Join(w.root.ToWords(), " ")+"\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(recordedDir, "account.txt"), []byte(w.writer.Address()+"\n"), 0o644))
}

// recordedArgs is one command against the recorded backup.
func recordedArgs(t *testing.T, cmd string, extra ...string) []string {
	t.Helper()
	acct, err := os.ReadFile(filepath.Join(recordedDir, "account.txt"))
	must(t, err)
	args := []string{cmd,
		"--dump", filepath.Join(recordedDir, "recorded.dump.json"),
		"--bundle", filepath.Join(recordedDir, "recorded.bundle"),
		"--words-file", filepath.Join(recordedDir, "words.txt"),
		"--account", strings.TrimSpace(string(acct)),
	}
	return append(args, extra...)
}

func recordedRun(t *testing.T, cmd string, extra ...string) result {
	t.Helper()
	var buf bytes.Buffer
	code := run(recordedArgs(t, cmd, extra...), strings.NewReader(""), &buf, &buf)
	t.Logf("$ xrplbak %s ...\n%s(exit %d)", cmd, buf.String(), code)
	return result{code: code, out: buf.String()}
}

// sameAsRecorded compares the files restore wrote in dir with the files
// the backup was made from.
func sameAsRecorded(t *testing.T, dir string) {
	t.Helper()
	for _, name := range recordedFiles {
		want, err := os.ReadFile(filepath.Join(recordedDir, "expect", name))
		must(t, err)
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: restored bytes differ from the backed-up file (%d bytes, want %d)", name, len(got), len(want))
		}
	}
}

func TestRecordedBackupVerifies(t *testing.T) {
	r := recordedRun(t, "verify")
	if r.code != exitOK {
		t.Fatalf("verify: exit %d\n%s", r.code, r.out)
	}
}

// The dry run is the first thing a recovery does. On every platform it
// must put the exact backed-up bytes under the directory it names.
func TestRecordedBackupDryRunIsByteExact(t *testing.T) {
	r := recordedRun(t, "restore")
	if r.code != exitOK {
		t.Fatalf("restore: exit %d\n%s", r.code, r.out)
	}
	if strings.Contains(r.out, "PARTIAL") || strings.Count(r.out, " complete ") != len(recordedFiles) {
		t.Fatalf("restore did not report every file complete:\n%s", r.out)
	}
	m := regexp.MustCompile(`(?m)^  files written under (.+)$`).FindStringSubmatch(r.out)
	if m == nil {
		t.Fatalf("restore did not name its directory:\n%s", r.out)
	}
	dir := strings.TrimSpace(m[1])
	defer os.RemoveAll(dir)
	sameAsRecorded(t, filepath.Join(dir, "srv", "xrplbak-recorded"))
}

func TestRecordedBackupWriteIsByteExact(t *testing.T) {
	target := t.TempDir()
	r := recordedRun(t, "restore", "--write", "--target", target, "--yes")
	if r.code != exitOK {
		t.Fatalf("restore --write: exit %d\n%s", r.code, r.out)
	}
	sameAsRecorded(t, target)
	ents, err := os.ReadDir(target)
	must(t, err)
	if len(ents) != len(recordedFiles) {
		t.Errorf("target holds %d entries, want %d", len(ents), len(recordedFiles))
	}
	if runtime.GOOS == "windows" {
		return
	}
	for name, mode := range map[string]os.FileMode{"xrpld.cfg": 0o640, "validators.txt": 0o644} {
		st, err := os.Stat(filepath.Join(target, name))
		must(t, err)
		if st.Mode().Perm() != mode {
			t.Errorf("%s: mode %o, want the backed-up %o", name, st.Mode().Perm(), mode)
		}
	}
}

// Restore says the files keep their backed-up mode. Windows keeps no Unix
// mode, so there the report has to say that instead, and say what to do.
func TestRestoreSaysWhatHappensToModes(t *testing.T) {
	dry := recordedRun(t, "restore")
	if m := regexp.MustCompile(`(?m)^  files written under (.+)$`).FindStringSubmatch(dry.out); m != nil {
		defer os.RemoveAll(strings.TrimSpace(m[1]))
	}
	wrote := recordedRun(t, "restore", "--write", "--target", t.TempDir(), "--yes")
	for name, out := range map[string]string{"dry run": dry.out, "--write": wrote.out} {
		keeps := strings.Contains(out, "keep their backed-up mode") || strings.Contains(out, "keeps each file's mode")
		windows := strings.Contains(out, "Windows does not keep Unix file modes")
		if runtime.GOOS == "windows" {
			if keeps || !windows {
				t.Errorf("%s on Windows: the report must say modes are not kept, and must not say they are:\n%s", name, out)
			}
			continue
		}
		if !keeps || windows {
			t.Errorf("%s: the report must say files keep their mode:\n%s", name, out)
		}
	}
}
