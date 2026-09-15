// Package restore merges on-chain and bundle content into files and writes
// them either to a temp dir (dry run) or to the target (explicit --write).
package restore

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
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
func Build(m *manifest.Manifest, onchain, bundle []container.Entry) *Plan {
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
	return p
}

// contentMatches compares the produced bytes with the manifest hash, which
// backup computed over the canonical form of the original file.
func contentMatches(data []byte, wantHex string) bool {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) == wantHex
}

// WriteTemp writes the plan into a fresh temp dir mirroring absolute paths.
func (p *Plan) WriteTemp() (string, error) {
	dir, err := os.MkdirTemp("", "xrplbak-restore-")
	if err != nil {
		return "", err
	}
	for _, f := range p.Files {
		dst := filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(f.Path, "/")))
		if err := writeFile(dst, f); err != nil {
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
	for _, f := range p.Files {
		dst := filepath.Join(abs, filepath.Base(f.Path))
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

func writeFile(dst string, f File) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	mode := os.FileMode(f.Mode)
	if mode == 0 {
		mode = 0o600
	}
	return os.WriteFile(dst, f.Data, mode)
}
