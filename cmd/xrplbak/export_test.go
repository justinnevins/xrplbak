package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	exportIDa = "0123456789abcdef0123456789abcdef"
	exportIDb = "fedcba9876543210fedcba9876543210"
)

// exportRun runs "xrplbak export" with stdout and stderr kept apart: the
// stream on stdout is what a laptop script decodes, so a test must see
// exactly what went there.
func exportRun(args ...string) (code int, out, errOut string) {
	var o, e bytes.Buffer
	code = run(append([]string{"export"}, args...), strings.NewReader(""), &o, &e)
	return code, o.String(), e.String()
}

// exportDir writes a backup folder holding the given files.
func exportDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		must(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
	}
	return dir
}

// unframe is the laptop side written out by hand: find the two marker
// lines, decode what is between them, unpack it. It shares no code with
// the export, so it checks the format and not the helper that wrote it.
func unframe(t *testing.T, out string) (map[string][]byte, map[string]time.Time) {
	t.Helper()
	const begin, end = "XRPLBAK-EXPORT-BEGIN\n", "XRPLBAK-EXPORT-END\n"
	if !strings.HasPrefix(out, begin) {
		t.Fatalf("stdout does not start with the BEGIN line:\n%.200s", out)
	}
	if !strings.HasSuffix(out, end) {
		t.Fatalf("stdout does not end with the END line:\n%.200s", out)
	}
	b64 := strings.ReplaceAll(out[len(begin):len(out)-len(end)], "\n", "")
	raw, err := base64.StdEncoding.DecodeString(b64)
	must(t, err)
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	must(t, err)
	tr := tar.NewReader(zr)
	got, mod := map[string][]byte{}, map[string]time.Time{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		must(t, err)
		if h.Typeflag != tar.TypeReg {
			t.Fatalf("archive entry %q is not a regular file (type %q)", h.Name, h.Typeflag)
		}
		if h.Mode != 0o600 {
			t.Fatalf("archive entry %q has mode %o, want 600: the bundle is owner-only on the host", h.Name, h.Mode)
		}
		if h.Name != filepath.Base(h.Name) || strings.ContainsAny(h.Name, `/\`) {
			t.Fatalf("archive entry %q carries a path", h.Name)
		}
		if _, dup := got[h.Name]; dup {
			t.Fatalf("archive entry %q appears twice", h.Name)
		}
		body, err := io.ReadAll(tr)
		must(t, err)
		got[h.Name], mod[h.Name] = body, h.ModTime
	}
	return got, mod
}

// Every backup file comes out byte for byte, with a SHA256SUMS file the
// laptop can check each one against.
func TestExportRoundTrip(t *testing.T) {
	files := map[string]string{
		exportIDa + ".bundle":    "bundle a \x00\xff bytes",
		exportIDa + ".dump.json": `{"v":1,"txs":[]}` + "\n",
		exportIDb + ".bundle":    "a dry run leaves a bundle with no dump",
	}
	dir := exportDir(t, files)
	// Each copy keeps the time of its file, so the laptop shows when a
	// backup was made, and the newest of them dates the checksum list.
	when := map[string]time.Time{}
	var newest time.Time
	for name := range files {
		newest = time.Date(2026, 3, 4, 5, 6, len(name), 0, time.UTC)
		when[name] = newest
		must(t, os.Chtimes(filepath.Join(dir, name), newest, newest))
	}
	for _, at := range when {
		if at.After(newest) {
			newest = at
		}
	}
	when["SHA256SUMS"] = newest
	code, out, errOut := exportRun("--out", dir)
	if code != exitOK {
		t.Fatalf("exit %d, want 0\nstderr: %s", code, errOut)
	}
	got, mod := unframe(t, out)
	for name, at := range when {
		if !mod[name].Equal(at) {
			t.Errorf("%s: archive time %s, want the file's %s", name, mod[name].UTC(), at)
		}
	}
	sums, ok := got["SHA256SUMS"]
	if !ok {
		t.Fatal("archive has no SHA256SUMS")
	}
	delete(got, "SHA256SUMS")
	if len(got) != len(files) {
		t.Fatalf("archive holds %d backup files, want %d", len(got), len(files))
	}
	var names []string
	for name, body := range files {
		names = append(names, name)
		if string(got[name]) != body {
			t.Errorf("%s: archive copy differs from the file", name)
		}
	}
	sort.Strings(names)
	var want strings.Builder
	for _, name := range names {
		s := sha256.Sum256([]byte(files[name]))
		fmt.Fprintf(&want, "%s  %s\n", hex.EncodeToString(s[:]), name)
	}
	if string(sums) != want.String() {
		t.Errorf("SHA256SUMS:\n%s\nwant:\n%s", sums, want.String())
	}
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if len(line) > 76 {
			t.Fatalf("a %d-character line; a terminal or a pipe may wrap it", len(line))
		}
	}
	// The same folder gives the same stream, so two pulls can be compared.
	if _, again, _ := exportRun("--out", dir); again != out {
		t.Error("two exports of the same folder differ")
	}
}

// An empty folder is "no backup here", not a successful export of nothing.
// A missing folder is the same answer: no backup has run on this host.
func TestExportWithNoBackupFilesIsIncomplete(t *testing.T) {
	for name, dir := range map[string]string{
		"empty folder":   t.TempDir(),
		"missing folder": filepath.Join(t.TempDir(), "never-made"),
	} {
		code, out, errOut := exportRun("--out", dir)
		if code != exitIncomplete {
			t.Errorf("%s: exit %d, want %d\nstderr: %s", name, code, exitIncomplete, errOut)
		}
		if out != "" {
			t.Errorf("%s: wrote to stdout:\n%.200s", name, out)
		}
		if !strings.Contains(errOut, "no backup files") {
			t.Errorf("%s: stderr does not say there are no backup files: %s", name, errOut)
		}
	}
}

// The sudo rule lets a login user run export as root. A symlink with a
// backup's name must not turn that into "read any file as root".
func TestExportRefusesASymlink(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "shadow")
	must(t, os.WriteFile(secret, []byte("root:TOP-SECRET-HASH"), 0o600))
	for _, link := range []string{exportIDb + ".bundle", exportIDb + ".dump.json"} {
		dir := exportDir(t, map[string]string{exportIDa + ".bundle": "real"})
		if err := os.Symlink(secret, filepath.Join(dir, link)); err != nil {
			t.Skipf("cannot make a symlink here: %v", err)
		}
		code, out, errOut := exportRun("--out", dir)
		if code != exitRefused {
			t.Errorf("%s: exit %d, want %d\nstderr: %s", link, code, exitRefused, errOut)
		}
		if out != "" {
			t.Errorf("%s: wrote to stdout:\n%.200s", link, out)
		}
		if !strings.Contains(errOut, link+": a symlink") {
			t.Errorf("%s: stderr does not name the symlink as one: %s", link, errOut)
		}
	}
	// The folder itself may not be a symlink either: the rule names a
	// path, and the path must be the folder.
	real := exportDir(t, map[string]string{exportIDa + ".bundle": "real"})
	alias := filepath.Join(t.TempDir(), "alias")
	must(t, os.Symlink(real, alias))
	if code, out, errOut := exportRun("--out", alias); code != exitRefused || out != "" {
		t.Errorf("symlinked folder: exit %d, stdout %d bytes, want exit %d and nothing\nstderr: %s", code, len(out), exitRefused, errOut)
	}
}

// Anything in the folder that is not a backup file stops the export, and
// nothing is sent. The key file and the settings file are the cases that
// matter: neither may ever leave the host this way.
func TestExportRefusesForeignNames(t *testing.T) {
	const secret = "TOP-SECRET-KEY-MATERIAL"
	for _, name := range []string{
		"xrplbak.key",
		"xrplbak.settings",
		"xrplbak-attest.key",
		"notes.txt",
		exportIDb + ".dump.json.tmp",
		exportIDb + ".bundle.bak",
		strings.ToUpper(exportIDb) + ".bundle",
		exportIDb[:31] + ".bundle",
		exportIDb + "0.bundle",
		exportIDb + ".dump",
		".hidden",
		"SHA256SUMS",
	} {
		dir := exportDir(t, map[string]string{
			exportIDa + ".bundle":    "real",
			exportIDa + ".dump.json": "real",
			name:                     secret,
		})
		code, out, errOut := exportRun("--out", dir)
		if code != exitRefused {
			t.Errorf("%s: exit %d, want %d\nstderr: %s", name, code, exitRefused, errOut)
		}
		if out != "" {
			t.Errorf("%s: wrote to stdout:\n%.200s", name, out)
		}
		if !strings.Contains(errOut, name) {
			t.Errorf("%s: stderr does not name the file: %s", name, errOut)
		}
		if strings.Contains(out+errOut, secret) {
			t.Errorf("%s: the file's content was printed", name)
		}
		// A backup that died mid-write leaves a .tmp file. The operator
		// needs to hear that, not "not a backup file".
		if strings.HasSuffix(name, ".tmp") && !strings.Contains(errOut, "interrupted backup") {
			t.Errorf("%s: stderr does not say an interrupted backup left it: %s", name, errOut)
		}
	}
}

// A folder, or anything else that is not a regular file, under a backup's
// name is refused: export reads files, it does not walk.
func TestExportRefusesNonFiles(t *testing.T) {
	dir := exportDir(t, map[string]string{exportIDa + ".bundle": "real"})
	sub := filepath.Join(dir, exportIDb+".bundle")
	must(t, os.Mkdir(sub, 0o700))
	must(t, os.WriteFile(filepath.Join(sub, "xrplbak.key"), []byte("TOP-SECRET"), 0o600))
	code, out, errOut := exportRun("--out", dir)
	if code != exitRefused || out != "" {
		t.Errorf("exit %d, stdout %d bytes, want exit %d and nothing\nstderr: %s", code, len(out), exitRefused, errOut)
	}
	if !strings.Contains(errOut, exportIDb+".bundle: not a regular file") {
		t.Errorf("stderr does not say the entry is not a regular file: %s", errOut)
	}
	plain := exportDir(t, map[string]string{exportIDa + ".bundle": "real"})
	must(t, os.Mkdir(filepath.Join(plain, "old"), 0o700))
	if code, out, _ := exportRun("--out", plain); code != exitRefused || out != "" {
		t.Errorf("plain subfolder: exit %d, stdout %d bytes, want exit %d and nothing", code, len(out), exitRefused)
	}
}

// The sudo rule fixes the arguments. Anything past them is a usage error,
// and --out is not optional: there is no folder to guess.
func TestExportUsage(t *testing.T) {
	dir := exportDir(t, map[string]string{exportIDa + ".bundle": "real"})
	for name, args := range map[string][]string{
		"no --out":        {},
		"empty --out":     {"--out", ""},
		"extra argument":  {"--out", dir, "/etc"},
		"unknown flag":    {"--out", dir, "--follow"},
		"--out is a file": {"--out", filepath.Join(dir, exportIDa+".bundle")},
	} {
		code, out, errOut := exportRun(args...)
		if code != exitUsage {
			t.Errorf("%s: exit %d, want %d\nstderr: %s", name, code, exitUsage, errOut)
		}
		if out != "" {
			t.Errorf("%s: wrote to stdout:\n%.200s", name, out)
		}
	}
}

// The command list is how an operator finds export.
func TestUsageListsExport(t *testing.T) {
	var buf bytes.Buffer
	run([]string{"help"}, strings.NewReader(""), &buf, &buf)
	if !strings.Contains(buf.String(), "\n  export ") {
		t.Fatalf("the command list has no export line:\n%s", buf.String())
	}
}
