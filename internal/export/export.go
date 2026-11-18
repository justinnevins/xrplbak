// Package export packs the backup files of one folder into a single
// archive, so they can be copied off the host in one step and checked on
// arrival. It only reads, and only regular files directly inside the
// folder whose names xrplbak itself gives a backup.
package export

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"
)

// The archive travels as base64 text between these two lines. Text
// survives a terminal, ssh without a tty and a PowerShell pipe, which
// corrupts binary output. A stream that lacks the End line was cut off.
const (
	Begin = "XRPLBAK-EXPORT-BEGIN"
	End   = "XRPLBAK-EXPORT-END"
)

// SumsName is the checksum list inside the archive, in sha256sum format.
const SumsName = "SHA256SUMS"

// ErrNoBackups means the folder is missing or holds nothing.
var ErrNoBackups = errors.New("no backup files")

// ErrNotDir means the path names something that is not a folder.
var ErrNotDir = errors.New("not a folder")

// RefusedError lists every entry that stopped the export.
type RefusedError struct{ Reasons []string }

func (e *RefusedError) Error() string {
	return "export refused, nothing was sent:\n  " + strings.Join(e.Reasons, "\n  ")
}

// idLen is a backup id in hex: 16 bytes.
const idLen = 32

// BackupFile reports whether name is one xrplbak gives a backup file:
// the 32 lower-case hex digits of a backup id, then .bundle or .dump.json.
func BackupFile(name string) bool {
	for _, suffix := range []string{".bundle", ".dump.json"} {
		if id, ok := strings.CutSuffix(name, suffix); ok {
			return isID(id)
		}
	}
	return false
}

func isID(s string) bool {
	if len(s) != idLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

type file struct {
	name string
	body []byte
	mod  time.Time
}

// Archive returns a gzipped tar of every backup file in dir plus a
// SHA256SUMS file over them, and the names it packed. One entry that is
// not a regular file with a backup's name refuses the whole export: the
// caller may be a login user running this as root through sudo, and the
// folder is the only thing between that rule and every file root can read.
func Archive(dir string) ([]byte, []string, error) {
	files, err := read(dir)
	if err != nil {
		return nil, nil, err
	}
	var sums strings.Builder
	var names []string
	var newest time.Time
	for _, f := range files {
		s := sha256.Sum256(f.body)
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(s[:]), f.name)
		names = append(names, f.name)
		if f.mod.After(newest) {
			newest = f.mod
		}
	}
	files = append(files, file{name: SumsName, body: []byte(sums.String()), mod: newest})

	// No name, time or OS in the gzip header, and file times cut to the
	// second: the same folder always gives the same bytes.
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, nil, err
	}
	tw := tar.NewWriter(zw)
	for _, f := range files {
		h := &tar.Header{Typeflag: tar.TypeReg, Name: f.name, Mode: 0o600, Size: int64(len(f.body)), ModTime: f.mod.Truncate(time.Second), Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(h); err != nil {
			return nil, nil, err
		}
		if _, err := tw.Write(f.body); err != nil {
			return nil, nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), names, nil
}

// read loads every backup file in dir, sorted by name, or says why not.
func read(dir string) ([]file, error) {
	at, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: there is no folder %s", ErrNoBackups, dir)
	}
	if err != nil {
		return nil, err
	}
	if at.Mode()&fs.ModeSymlink != 0 {
		return nil, &RefusedError{Reasons: []string{dir + ": the folder is a symlink"}}
	}
	if !at.IsDir() {
		return nil, fmt.Errorf("%w: %s", ErrNotDir, dir)
	}
	// Every read below goes through root, which cannot leave the folder.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil {
		return nil, err
	}
	if !os.SameFile(at, opened) {
		return nil, &RefusedError{Reasons: []string{dir + ": the folder changed while it was opened"}}
	}
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w in %s", ErrNoBackups, dir)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	var refused []string
	infos := make([]fs.FileInfo, len(entries))
	for i, e := range entries {
		name := e.Name()
		info, err := root.Lstat(name)
		switch {
		case err != nil:
			refused = append(refused, fmt.Sprintf("%s: %v", name, err))
		case info.Mode()&fs.ModeSymlink != 0:
			refused = append(refused, name+": a symlink")
		case strings.HasSuffix(name, ".dump.json.tmp") && isID(strings.TrimSuffix(name, ".dump.json.tmp")):
			refused = append(refused, name+": left by an interrupted backup; run the backup again, then remove this file")
		case !BackupFile(name):
			refused = append(refused, name+": not a backup file (move it out of this folder)")
		case !info.Mode().IsRegular():
			refused = append(refused, name+": not a regular file")
		}
		infos[i] = info
	}
	if len(refused) > 0 {
		return nil, &RefusedError{Reasons: refused}
	}

	files := make([]file, 0, len(entries))
	for i, e := range entries {
		body, err := readFile(root, e.Name(), infos[i])
		if err != nil {
			return nil, err
		}
		files = append(files, file{name: e.Name(), body: body, mod: infos[i].ModTime()})
	}
	return files, nil
}

// readFile reads one file and confirms that what it opened is the regular
// file that was checked, not something swapped in under the same name.
func readFile(root *os.Root, name string, checked fs.FileInfo) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(checked, opened) {
		return nil, &RefusedError{Reasons: []string{name + ": changed while it was read"}}
	}
	return io.ReadAll(f)
}

// lineLen is the base64 line length of MIME, short enough for any
// terminal.
const lineLen = 76

// Frame returns the archive as text: the Begin line, base64 in short
// lines, the End line.
func Frame(archive []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString(archive)
	var out bytes.Buffer
	out.WriteString(Begin + "\n")
	for len(b64) > lineLen {
		out.WriteString(b64[:lineLen] + "\n")
		b64 = b64[lineLen:]
	}
	if b64 != "" {
		out.WriteString(b64 + "\n")
	}
	out.WriteString(End + "\n")
	return out.Bytes()
}
