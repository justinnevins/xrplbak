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
	"sort"
	"strings"

	"github.com/justinnevins/xrplbak/internal/cfg"
	"github.com/justinnevins/xrplbak/internal/container"
	"github.com/justinnevins/xrplbak/internal/manifest"
	"github.com/justinnevins/xrplbak/internal/redact"
)

// File is one path the restore will produce.
type File struct {
	Path     string
	Mode     uint32
	Data     []byte
	Source   string // "onchain", "bundle", "onchain+bundle", "onchain (bundle missing)"
	Complete bool   // true when the SHA-256 matches the manifest's original
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
	byPath := map[string]*File{}
	bundleByPath := map[string]container.Entry{}
	for _, e := range bundle {
		bundleByPath[e.Path] = e
	}
	for _, e := range onchain {
		f := &File{Path: e.Path, Mode: e.Mode, Source: "onchain"}
		on := cfg.Parse(string(e.Data))
		if b, ok := bundleByPath[e.Path]; ok {
			f.Data = []byte(redact.Merge(on, cfg.Parse(string(b.Data))).Canonical())
			f.Source = "onchain+bundle"
			delete(bundleByPath, e.Path)
		} else {
			f.Data = []byte(redact.Merge(on, &cfg.File{}).Canonical())
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
		f.Complete = contentMatches(f.Data, mf.SHA256)
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
			p.Todo = append(p.Todo, fmt.Sprintf("Re-enter [%s]: %d line(s) were kept only in the off-chain bundle", r.Stanza, r.Lines))
		}
	}
	if m.Node.Role == "validator" {
		p.Todo = append(p.Todo, "Run only one validator with this token. Stop the old host before starting the new one")
	}
	return p, nil
}

// checkPath accepts only what backup itself writes: a clean absolute path
// with a real basename and no control bytes.
func checkPath(p string) error {
	bad := func() error { return fmt.Errorf("refused: unsafe path %q in backup", p) }
	if p == "" || strings.ContainsAny(p, "\x00") {
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

// contentMatches compares the produced bytes with the manifest hash, which
// backup computed over the canonical form of the original file.
func contentMatches(data []byte, wantHex string) bool {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) == wantHex
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
	dir, err := os.MkdirTemp("", "xrplbak-restore-")
	if err != nil {
		return "", err
	}
	for i, f := range p.Files {
		if err := writeFile(filepath.Join(dir, rels[i]), f); err != nil {
			return "", err
		}
	}
	return dir, nil
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
		dst := filepath.Join(abs, base)
		if _, err := os.Lstat(dst); err == nil && !force {
			return written, fmt.Errorf("%s exists; pass --force to overwrite", dst)
		}
	}
	for _, f := range p.Files {
		dst := filepath.Join(abs, filepath.Base(f.Path))
		if err := writeFile(dst, f); err != nil {
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
	clean := filepath.Clean("/" + filepath.ToSlash(p))
	rel := strings.TrimPrefix(clean, "/")
	if rel == "" || rel == "." || strings.HasPrefix(rel, "..") {
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
	return os.WriteFile(dst, f.Data, mode)
}
