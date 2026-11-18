// Package restore merges on-chain and bundle content into files and writes
// them either to a temp dir (dry run) or to the target (explicit --write).
package restore

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/justinnevins/xrplbak/internal/cfg"
	"github.com/justinnevins/xrplbak/internal/container"
	"github.com/justinnevins/xrplbak/internal/manifest"
	"github.com/justinnevins/xrplbak/internal/redact"
)

// File is one path the restore will produce.
type File struct {
	Path   string
	Mode   uint32
	Data   []byte
	Source string // "onchain", "bundle", "onchain+bundle", "onchain (bundle missing)"
	// proof is set only by checkComplete, after it compared Data with the
	// manifest hash. It is unexported, so no caller outside this package
	// can claim a file is complete.
	proof completeness
}

// completeness is the evidence that a file's bytes matched the manifest's
// SHA-256. Its zero value proves nothing. checkComplete is the only
// function that makes a non-zero one, and only after the comparison.
type completeness struct {
	digest [sha256.Size]byte
	proven bool
}

// checkComplete compares data with the manifest hash and returns proof of
// the match, or the zero value.
func checkComplete(data []byte, wantHex string) completeness {
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != wantHex {
		return completeness{}
	}
	return completeness{digest: sum, proven: true}
}

// Complete reports whether f's bytes, as they are now, are the bytes that
// matched the manifest. The digest is checked again on every call, so bytes
// changed after Build lose the proof instead of keeping a stale "complete".
func (f File) Complete() bool {
	return f.proof.proven && sha256.Sum256(f.Data) == f.proof.digest
}

// Plan is the merged result plus what the operator still has to do by hand.
type Plan struct {
	Files []File
	Todo  []string
}

// Build merges entries. bundle may be nil when the operator has no bundle.
// It refuses, before anything is written anywhere, a backup whose paths are
// not clean absolute paths or whose containers carry a file the manifest
// does not list. Manifests are authenticated, but a host-key thief could
// author one, so nothing about paths is trusted.
func Build(m *manifest.Manifest, onchain, bundle []container.Entry) (*Plan, error) {
	listed := map[string]bool{}
	for _, mf := range m.Files {
		if err := checkPath(mf.Path); err != nil {
			return nil, err
		}
		if listed[mf.Path] {
			return nil, fmt.Errorf("refused: the manifest lists %q more than once; restoring it could write merged content that matches no file", mf.Path)
		}
		listed[mf.Path] = true
	}
	for _, e := range append(append([]container.Entry{}, onchain...), bundle...) {
		if err := checkPath(e.Path); err != nil {
			return nil, err
		}
		if !listed[e.Path] {
			return nil, fmt.Errorf("refused: the backup carries %q, which is not listed in the manifest", e.Path)
		}
	}
	for _, set := range [][]container.Entry{onchain, bundle} {
		seen := map[string]bool{}
		for _, e := range set {
			if seen[e.Path] {
				return nil, fmt.Errorf("refused: the backup carries %q more than once in one container; restoring it could write content that matches no file", e.Path)
			}
			seen[e.Path] = true
		}
	}
	byPath := map[string]*File{}
	// v1 holds, for a file merged from both parts, the same merge done the
	// way xrplbak v1.0 did it. It is used only if it matches the hash.
	v1 := map[string][]byte{}
	bundleByPath := map[string]container.Entry{}
	for _, e := range bundle {
		bundleByPath[e.Path] = e
	}
	for _, e := range onchain {
		f := &File{Path: e.Path, Mode: e.Mode, Source: "onchain"}
		on := cfg.Parse(string(e.Data))
		if b, ok := bundleByPath[e.Path]; ok {
			f.Data = []byte(redact.Merge(on, cfg.Parse(string(b.Data))).Render())
			f.Source = "onchain+bundle"
			v1[e.Path] = []byte(redact.MergeV1(string(e.Data), string(b.Data)))
			delete(bundleByPath, e.Path)
		} else {
			f.Data = []byte(redact.Merge(on, &cfg.File{}).Render())
			if strings.Contains(string(f.Data), redact.MovedMarker) {
				f.Source = "onchain (bundle missing)"
			}
		}
		byPath[e.Path] = f
	}
	for _, e := range bundleByPath {
		byPath[e.Path] = &File{Path: e.Path, Mode: e.Mode, Data: e.Data, Source: "bundle"}
	}
	p := &Plan{}
	for _, mf := range m.Files {
		f, ok := byPath[mf.Path]
		if !ok {
			p.Todo = append(p.Todo, fmt.Sprintf("%s is listed in the manifest but was not recovered (stored in: %s)", mf.Path, mf.Where))
			continue
		}
		f.proof = checkComplete(f.Data, mf.SHA256)
		// A backup written by v1.0 does not rebuild line by line. The
		// manifest hash decides which reading is the backed-up file:
		// the v1.0 one replaces the current one only when it, and not
		// the current one, is the bytes the hash names.
		if old, ok := v1[mf.Path]; ok && !f.proof.proven {
			if proof := checkComplete(old, mf.SHA256); proof.proven {
				f.Data, f.proof = old, proof
				f.Source = "onchain+bundle, v1.0 format: stanzas sorted, comments not kept"
			}
		}
		p.Files = append(p.Files, *f)
		delete(byPath, mf.Path)
	}
	for _, f := range byPath {
		p.Files = append(p.Files, *f)
	}
	sort.Slice(p.Files, func(i, j int) bool { return p.Files[i].Path < p.Files[j].Path })

	if bundle == nil && len(m.Redactions) > 0 {
		if m.Node.Role == "validator" {
			p.Todo = append(p.Todo, "Regenerate the validator token from the master key (validator-keys create_token) and add [validator_token] to the config")
		}
		for _, r := range m.Redactions {
			p.Todo = append(p.Todo, todoLine(r, m.RedactionPath(r)))
		}
	}
	if m.Node.Role == "validator" {
		p.Todo = append(p.Todo, "Run only one validator with this token. Stop the old host before starting the new one")
	}
	return p, nil
}

// todoLine words one redaction for the operator. Content before the first
// header has no stanza name ("[]" reads like an unfilled template); with
// two files in a backup, an item must name which file it belongs to; and a
// comment-only move must not read as a missing setting.
func todoLine(r manifest.Redaction, path string) string {
	where := redact.PrintableStanza(r.Stanza)
	if r.Stanza == "" {
		where = "the lines before the first stanza"
	}
	if path != "" {
		where += " in " + path
	}
	switch {
	case r.Comments >= r.Lines && r.Lines > 0:
		return fmt.Sprintf("Comment only: %s: %d comment line(s) were kept only in the off-chain bundle; every setting there is present", where, r.Lines)
	case r.Comments > 0:
		return fmt.Sprintf("Re-enter %s: %d line(s) were kept only in the off-chain bundle (%d of them comments)", where, r.Lines, r.Comments)
	default:
		return fmt.Sprintf("Re-enter %s: %d line(s) were kept only in the off-chain bundle", where, r.Lines)
	}
}

// checkPath accepts only what backup itself writes: a clean absolute path
// with a real basename and no control bytes.
//
// Control bytes are refused because restore prints every path to the
// operator's terminal next to its completeness state. A newline forges a
// second line of that report and a cursor escape rewrites the line already
// printed, so a file that was never recovered can be made to read as
// complete. The bidirectional format characters are refused for the same
// reason: they reorder the displayed line without changing its bytes.
// CheckPath is checkPath for callers outside the package. backup runs it
// on every file it is asked to store, so that it never writes a backup
// restore would refuse.
func CheckPath(p string) error { return checkPath(p) }

func checkPath(p string) error {
	bad := func() error { return fmt.Errorf("refused: unsafe path %q in backup", p) }
	if p == "" {
		return bad()
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || isBidiControl(r) || isInvisible(r) {
			return bad()
		}
	}
	if !utf8.ValidString(p) {
		return bad()
	}
	slash := filepath.ToSlash(p)
	if !strings.HasPrefix(slash, "/") || slash != path.Clean(slash) {
		return bad()
	}
	base := path.Base(slash)
	if base == "/" || base == "." || base == ".." {
		return bad()
	}
	for _, part := range strings.Split(slash, "/") {
		if part == ".." {
			return bad()
		}
	}
	return nil
}

// isInvisible reports characters a terminal acts on or draws as nothing:
// the C1 controls (U+0080 to U+009F, which include CSI and NEL), the line
// and paragraph separators, the zero-width characters, the soft hyphen and
// the Arabic letter mark. Like the C0 controls, they let a path change how
// the report reads without changing what it says.
func isInvisible(r rune) bool {
	switch {
	case r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x2028 || r == 0x2029:
		return true
	case r == 0x200b || r == 0x200c || r == 0x200d || r == 0x2060 || r == 0xfeff:
		return true
	case r == 0xad || r == 0x061c:
		return true
	}
	return false
}

// isBidiControl reports the Unicode format characters that reorder or
// isolate displayed text. A path is never legitimately written with one.
func isBidiControl(r rune) bool {
	switch r {
	case 0x200e, 0x200f, // LRM, RLM
		0x202a, 0x202b, 0x202c, 0x202d, 0x202e, // LRE, RLE, PDF, LRO, RLO
		0x2066, 0x2067, 0x2068, 0x2069: // LRI, RLI, FSI, PDI
		return true
	}
	return false
}

// WriteTemp writes the plan into a fresh temp dir mirroring absolute paths.
func (p *Plan) WriteTemp() (string, error) {
	rels := make([]string, len(p.Files))
	for i, f := range p.Files {
		if err := checkPath(f.Path); err != nil {
			return "", err
		}
		rel, err := safeRelative(f.Path)
		if err != nil {
			return "", err
		}
		rels[i] = rel
	}
	for _, rel := range rels {
		if err := hostKeeps(rel); err != nil {
			return "", err
		}
	}
	dir, err := os.MkdirTemp("", "xrplbak-restore-")
	if err != nil {
		return "", err
	}
	var done placed
	for i, f := range p.Files {
		dst := filepath.Join(dir, rels[i])
		err := done.clash(dst, f.Path)
		if err == nil {
			err = writeFile(dst, f)
		}
		if err == nil {
			err = done.add(dst, f.Path)
		}
		if err != nil {
			// A partial dry run is not something to inspect.
			os.RemoveAll(dir)
			return "", err
		}
	}
	return dir, nil
}

// hostKeeps reports why this machine would not store a file under exactly
// the name rel. Linux keeps any name checkPath accepts. Windows does not:
// NUL and COM1 are devices, a colon opens a named stream inside another
// file, and a final dot or space is dropped without a word. Writing such
// a name there "succeeds" and leaves something else on disk, so it is
// refused before anything is written.
func hostKeeps(rel string) error {
	bad := func(why string) error {
		return fmt.Errorf("refused: this system cannot store the file name %q (%s); restore on Linux or macOS", rel, why)
	}
	if !filepath.IsLocal(rel) {
		return bad("a device name, or a name with a colon")
	}
	if runtime.GOOS != "windows" {
		return nil
	}
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return bad("Windows drops a final dot or space")
		}
		if windowsDevice(part) {
			return bad("a device name on some versions of Windows")
		}
	}
	return nil
}

// windowsDevice reports a name that Windows, in some version, opens as a
// device whatever its extension: NUL, nul.cfg, COM1.txt. Windows 11 stores
// nul.cfg as a file and Windows 10 does not, and filepath.IsLocal follows
// the newer rule. A restore cannot know which one it is on, so the name
// is refused on both.
func windowsDevice(part string) bool {
	stem, _, _ := strings.Cut(part, ".")
	stem = strings.ToUpper(strings.TrimRight(stem, " "))
	switch stem {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	if len(stem) >= 4 && (stem[:3] == "COM" || stem[:3] == "LPT") {
		switch stem[3:] {
		case "1", "2", "3", "4", "5", "6", "7", "8", "9", "\u00b9", "\u00b2", "\u00b3":
			return true
		}
	}
	return false
}

// placed remembers the files one restore has written, as the file system
// identifies them. Two names a Linux host keeps apart, a.cfg and A.cfg,
// are one file on Windows and on a default macOS volume. Asking the file
// system is the only test that is right for every volume: no table of
// case rules is.
type placed struct {
	infos []os.FileInfo
	paths []string
}

// clash returns an error when dst is a file this restore already wrote
// for another path. It is called before the write, so the earlier file
// keeps its bytes.
func (w *placed) clash(dst, path string) error {
	st, err := os.Lstat(dst)
	if err != nil {
		return nil
	}
	for i, in := range w.infos {
		if os.SameFile(in, st) {
			return fmt.Errorf("%s and %s are the same file on this file system (their names differ only by case); %s was not written. Restore on a case-sensitive file system", w.paths[i], path, path)
		}
	}
	return nil
}

func (w *placed) add(dst, path string) error {
	st, err := os.Lstat(dst)
	if err != nil {
		return err
	}
	w.infos, w.paths = append(w.infos, st), append(w.paths, path)
	return nil
}

// WriteTarget writes files under targetDir keeping their basenames. It
// refuses to overwrite unless force is set and never writes under /var/lib.
func (p *Plan) WriteTarget(targetDir string, force bool) ([]string, error) {
	abs, err := filepath.Abs(targetDir)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(abs, "/var/lib") {
		return nil, fmt.Errorf("refusing to write under /var/lib (%s); config belongs in /etc", abs)
	}
	var written []string
	seen := map[string]string{}
	for _, f := range p.Files {
		if err := checkPath(f.Path); err != nil {
			return nil, err
		}
		base := filepath.Base(filepath.Clean(f.Path))
		if first, dup := seen[base]; dup {
			return nil, fmt.Errorf("%s and %s would land on the same name %s in %s; restore them by hand from the dry-run directory", first, f.Path, base, abs)
		}
		seen[base] = f.Path
		if err := hostKeeps(base); err != nil {
			return nil, err
		}
		dst := filepath.Join(abs, base)
		st, err := os.Lstat(dst)
		if err != nil {
			continue
		}
		// A symlink is refused with or without --force: the write would
		// land on whatever it points at, outside the target directory.
		// backup refuses to read through one for the same reason.
		if st.Mode()&os.ModeSymlink != 0 {
			return written, fmt.Errorf("%s is a symlink; restore into the directory of the real file, or remove the link", dst)
		}
		if !st.Mode().IsRegular() {
			return written, fmt.Errorf("%s exists and is not a regular file", dst)
		}
		if !force {
			return written, fmt.Errorf("%s exists; pass --force to overwrite", dst)
		}
	}
	var done placed
	for _, f := range p.Files {
		dst := filepath.Join(abs, filepath.Base(f.Path))
		if err := done.clash(dst, f.Path); err != nil {
			return written, err
		}
		if err := writeFile(dst, f); err != nil {
			return written, err
		}
		if err := done.add(dst, f.Path); err != nil {
			return written, err
		}
		written = append(written, dst)
	}
	return written, nil
}

// safeRelative turns a stored absolute path into a relative one that
// cannot escape the temp dir. Manifests are authenticated, but a host key
// thief could author one, so paths are never trusted.
func safeRelative(p string) (string, error) {
	for _, part := range strings.Split(filepath.ToSlash(p), "/") {
		if part == ".." {
			return "", fmt.Errorf("refusing unsafe path %q in backup", p)
		}
	}
	// path, not filepath: the stored path is POSIX on every platform. On
	// Windows filepath.Clean turns the leading "//" this builds into the
	// start of a network path, and the result was absolute.
	clean := path.Clean("/" + filepath.ToSlash(p))
	rel := strings.TrimPrefix(clean, "/")
	// The test is on path components, not on a string prefix: a file
	// legitimately named "..0" or "..config" begins with two dots without
	// being a parent reference. checkPath accepts those, and WriteTarget
	// writes them, so refusing them here made the dry run fail where the
	// --write it is meant to precede would have succeeded. The component
	// loop below is what actually refuses a parent reference.
	if rel == "" || rel == "." {
		return "", fmt.Errorf("refusing unsafe path %q in backup", p)
	}
	for _, part := range strings.Split(rel, "/") {
		if part == ".." {
			return "", fmt.Errorf("refusing unsafe path %q in backup", p)
		}
	}
	return filepath.FromSlash(rel), nil
}

func writeFile(dst string, f File) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	// Permission bits only. No setuid, setgid, or sticky bits from a backup.
	mode := os.FileMode(f.Mode) & 0o777
	if mode == 0 {
		mode = 0o600
	}
	// Write beside the destination and rename over it. Writing in place
	// kept the mode of a file that was already there, whatever the backup
	// recorded, followed a symlink, and left a half-written config behind
	// if the write failed. The new file is private until it is whole, then
	// takes exactly the backed-up mode.
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".xrplbak-restore-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, err = tmp.Write(f.Data)
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(name, dst)
	}
	if err != nil {
		os.Remove(name)
		return err
	}
	return nil
}
