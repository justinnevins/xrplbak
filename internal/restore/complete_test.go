package restore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/container"
	"github.com/justinnevins/xrplbak/internal/manifest"
)

// The second clause of the invariant: never report a backup as complete when
// it is not. These tests pin that "complete" is a statement about the bytes
// that get written, not a flag that can drift away from them.

const (
	cfgPath = "/etc/xrpld/xrpld.cfg"
	valPath = "/etc/xrpld/validators.txt"
)

var (
	cfgBytes = []byte("# node config\n[server]\nport_peer\n\n[port_peer]\nport = 51235\nprotocol = peer\n")
	valBytes = []byte("[validators]\nnHBexample\n")
)

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// completePlan builds a plan whose every file matches its manifest hash: the
// config from the on-chain side and validators.txt from the bundle.
func completePlan(t *testing.T, cfg, val []byte) *Plan {
	t.Helper()
	m := &manifest.Manifest{}
	m.Node.Role = "node"
	m.Files = []manifest.File{
		{Path: cfgPath, Mode: 0o600, SHA256: hexSum(cfgBytes), Where: "onchain"},
		{Path: valPath, Mode: 0o644, SHA256: hexSum(valBytes), Where: "bundle"},
	}
	p, err := Build(m,
		[]container.Entry{{Path: cfgPath, Mode: 0o600, Data: cfg}},
		[]container.Entry{{Path: valPath, Mode: 0o644, Data: val}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCompleteNeedsTheBytesItWasProvenOver pins the witness: a file is
// complete only while its bytes are the ones the hash comparison saw. Bytes
// changed after Build, by any later code path, must lose the status rather
// than carry a "complete" that no longer describes them.
func TestCompleteNeedsTheBytesItWasProvenOver(t *testing.T) {
	p := completePlan(t, cfgBytes, valBytes)
	if len(p.Files) != 2 {
		t.Fatalf("plan has %d files, want 2", len(p.Files))
	}
	for _, f := range p.Files {
		if !f.Complete() {
			t.Fatalf("%s: matching bytes not complete", f.Path)
		}
	}
	for i := range p.Files {
		for _, change := range []struct {
			name string
			edit func([]byte) []byte
		}{
			{"flip first byte", func(b []byte) []byte { b[0] ^= 1; return b }},
			{"flip last byte", func(b []byte) []byte { b[len(b)-1] ^= 0x80; return b }},
			{"append a byte", func(b []byte) []byte { return append(b, '\n') }},
			{"drop a byte", func(b []byte) []byte { return b[:len(b)-1] }},
		} {
			f := p.Files[i]
			f.Data = change.edit(append([]byte(nil), f.Data...))
			if f.Complete() {
				t.Errorf("%s, %s: still complete after its bytes changed", f.Path, change.name)
			}
		}
	}
}

// TestZeroFileIsNeverComplete pins that a File made outside Build, with no
// proof, never reads as complete, whatever bytes it carries.
func TestZeroFileIsNeverComplete(t *testing.T) {
	for _, f := range []File{{}, {Path: cfgPath, Data: cfgBytes}, {Path: cfgPath, Data: []byte{}}} {
		if f.Complete() {
			t.Errorf("a File with no proof reads as complete: %+v", f)
		}
	}
}

// TestOneByteOffIsNeverComplete drives every single-byte change of both
// files through Build. None may come out complete.
func TestOneByteOffIsNeverComplete(t *testing.T) {
	for _, target := range []string{cfgPath, valPath} {
		orig := cfgBytes
		if target == valPath {
			orig = valBytes
		}
		for pos := range orig {
			bad := append([]byte(nil), orig...)
			bad[pos] ^= 0x01
			cfg, val := cfgBytes, valBytes
			if target == cfgPath {
				cfg = bad
			} else {
				val = bad
			}
			p := completePlan(t, cfg, val)
			for _, f := range p.Files {
				if f.Path == target && f.Complete() {
					t.Fatalf("%s with byte %d flipped reads as complete", target, pos)
				}
				if f.Path != target && !f.Complete() {
					t.Fatalf("%s untouched but not complete", f.Path)
				}
			}
		}
	}
}

// TestWrittenBytesAreTheProvenBytes pins the write paths: a file that reads
// as complete lands on disk with exactly the bytes whose hash the manifest
// holds, and a file whose written bytes match the manifest reads as
// complete. Both directions, for the dry run and for --write.
func TestWrittenBytesAreTheProvenBytes(t *testing.T) {
	want := map[string]string{cfgPath: hexSum(cfgBytes), valPath: hexSum(valBytes)}
	for _, tc := range []struct {
		name     string
		cfg, val []byte
	}{
		{"all match", cfgBytes, valBytes},
		{"config differs", append(append([]byte(nil), cfgBytes...), '#'), valBytes},
		{"validators differ", cfgBytes, bytes.ToUpper(valBytes)},
	} {
		p := completePlan(t, tc.cfg, tc.val)

		dir, err := p.WriteTemp()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		target := t.TempDir()
		if _, err := p.WriteTarget(target, false); err != nil {
			t.Fatal(err)
		}
		for _, f := range p.Files {
			for _, on := range []string{
				filepath.Join(dir, strings.TrimPrefix(f.Path, "/")),
				filepath.Join(target, filepath.Base(f.Path)),
			} {
				got, err := os.ReadFile(on)
				if err != nil {
					t.Fatal(err)
				}
				matches := hexSum(got) == want[f.Path]
				if f.Complete() != matches {
					t.Errorf("%s, %s: complete=%v but written bytes match manifest=%v", tc.name, on, f.Complete(), matches)
				}
			}
		}
	}
}

// FuzzCompleteMeansHashMatches is the same property over arbitrary bytes:
// for any content, Build reports complete exactly when its SHA-256 is the
// manifest's.
func FuzzCompleteMeansHashMatches(f *testing.F) {
	f.Add(valBytes, valBytes)
	f.Add(valBytes, []byte("[validators]\nnHBexamplf\n"))
	f.Add([]byte{}, []byte{})
	f.Add([]byte("x"), []byte{})
	f.Fuzz(func(t *testing.T, orig, got []byte) {
		m := &manifest.Manifest{}
		m.Node.Role = "node"
		m.Files = []manifest.File{{Path: valPath, Mode: 0o644, SHA256: hexSum(orig), Where: "bundle"}}
		p, err := Build(m, nil, []container.Entry{{Path: valPath, Mode: 0o644, Data: got}})
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Files) != 1 {
			t.Fatalf("plan has %d files", len(p.Files))
		}
		if want := bytes.Equal(orig, got); p.Files[0].Complete() != want {
			t.Fatalf("complete=%v, bytes equal=%v", p.Files[0].Complete(), want)
		}
	})
}
