package restore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/justinnevins/xrplbak/internal/container"
	"github.com/justinnevins/xrplbak/internal/manifest"
)

// seedPaths are the hostile path shapes the adversarial corpus already
// drives through the command surface, plus the honest ones backup writes.
var seedPaths = []string{
	"/etc/xrpld.cfg",
	"/etc/xrpld/validators.txt",
	"",
	"/",
	".",
	"..",
	"relative.cfg",
	"/etc/../../etc/shadow",
	"/etc/./xrpld.cfg",
	"/etc//xrpld.cfg",
	"/etc/xrpld.cfg/",
	"/etc/\x00xrpld.cfg",
	"/etc/xrpld.cfg\nrestored /etc/shadow",
	"/etc/xrpld.cfg\r    complete",
	"/etc/\x1b[2Kxrpld.cfg",
	"/etc/\u202egfc.dlprx",
	"/etc/\u2066xrpld.cfg\u2069",
	"/etc/xrpld.cfg\x7f",
	"/etc/\xff\xfexrpld.cfg",
	"/etc/..\\..\\xrpld.cfg",
	"//etc/xrpld.cfg",
	"/..",
	"/a/../b",
	strings.Repeat("/a", 200) + "/x.cfg",
}

// FuzzCheckPathContract asserts the contract checkPath's own doc comment
// states: it accepts only a clean absolute path with a real basename and no
// control bytes. A restore prints these paths to the operator's terminal and
// then writes them, so a path that carries a newline or an escape sequence
// can forge a line of the completeness report.
func FuzzCheckPathContract(f *testing.F) {
	for _, p := range seedPaths {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if checkPath(p) != nil {
			return
		}
		for i := 0; i < len(p); i++ {
			if p[i] < 0x20 || p[i] == 0x7f {
				t.Fatalf("checkPath accepted %q, which carries control byte 0x%02x at %d", p, p[i], i)
			}
		}
		if !utf8.ValidString(p) {
			t.Fatalf("checkPath accepted %q, which is not valid UTF-8", p)
		}
		// The codepoints are listed here rather than read through
		// isBidiControl: an oracle that calls the function it is pinning
		// cannot notice that function being emptied.
		for _, r := range p {
			switch r {
			case 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
				0x2066, 0x2067, 0x2068, 0x2069:
				t.Fatalf("checkPath accepted %q, which carries bidi control U+%04X", p, r)
			}
		}
		if !strings.HasPrefix(p, "/") {
			t.Fatalf("checkPath accepted relative path %q", p)
		}
	})
}

// FuzzAcceptedPathStaysInsideRoot asserts that any path checkPath accepts is
// written strictly inside the directory the restore chose, by either route:
// safeRelative for the dry run and the basename for --write.
func FuzzAcceptedPathStaysInsideRoot(f *testing.F) {
	for _, p := range seedPaths {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, p string) {
		if checkPath(p) != nil {
			return
		}
		root := filepath.Clean("/tmp/xrplbak-root")
		rel, err := safeRelative(p)
		if err != nil {
			t.Fatalf("checkPath accepted %q but safeRelative refused it: %v", p, err)
		}
		if filepath.IsAbs(rel) {
			t.Fatalf("safeRelative(%q) returned absolute %q", p, rel)
		}
		dst := filepath.Clean(filepath.Join(root, rel))
		if dst == root || !strings.HasPrefix(dst, root+string(filepath.Separator)) {
			t.Fatalf("dry-run path %q escapes: %q", p, dst)
		}
		base := filepath.Base(filepath.Clean(p))
		if base == "" || base == "." || base == ".." || strings.ContainsRune(base, filepath.Separator) {
			t.Fatalf("checkPath accepted %q whose basename is %q", p, base)
		}
		wdst := filepath.Clean(filepath.Join(root, base))
		if wdst == root || !strings.HasPrefix(wdst, root+string(filepath.Separator)) {
			t.Fatalf("--write path %q escapes: %q", p, wdst)
		}
	})
}

// FuzzBuildNoPanic drives Build with hostile manifests and containers. A
// plan is never returned alongside an error, every file in a plan carries a
// path checkPath accepts, and no file appears that the manifest did not list.
func FuzzBuildNoPanic(f *testing.F) {
	f.Add("/etc/xrpld.cfg", "/etc/xrpld.cfg", "/etc/xrpld.cfg", []byte("[server]\n"), []byte(""), true)
	f.Add("/etc/a.cfg", "/etc/b.cfg", "", []byte("x"), []byte("y"), false)
	f.Add("", "..", "/", []byte{}, []byte{0}, true)
	f.Add("/etc/a.cfg\nforged", "/etc/a.cfg\nforged", "", []byte("x"), []byte(""), false)
	f.Fuzz(func(t *testing.T, mPath, onPath, bunPath string, onData, bunData []byte, withBundle bool) {
		m := &manifest.Manifest{}
		m.Files = append(m.Files, manifest.File{Path: mPath, Mode: 0o600, SHA256: "", Where: "onchain"})
		onchain := []container.Entry{{Path: onPath, Mode: 0o600, Data: onData}}
		var bundle []container.Entry
		if withBundle {
			bundle = []container.Entry{{Path: bunPath, Mode: 0o600, Data: bunData}}
		}
		p, err := Build(m, onchain, bundle)
		if err != nil {
			if p != nil {
				t.Fatalf("Build returned a plan alongside error %v", err)
			}
			return
		}
		listed := map[string]bool{mPath: true}
		for _, fl := range p.Files {
			if e := checkPath(fl.Path); e != nil {
				t.Fatalf("Build produced file %q that checkPath refuses: %v", fl.Path, e)
			}
			if !listed[fl.Path] {
				t.Fatalf("Build produced %q, which the manifest does not list", fl.Path)
			}
		}
	})
}

// FuzzWriteTempContainment writes a real plan and asserts every byte lands
// under the temp dir the call created.
func FuzzWriteTempContainment(f *testing.F) {
	f.Add("/etc/xrpld.cfg", "/etc/xrpld/validators.txt", uint32(0o600), []byte("x"))
	f.Add("/a", "/a/b", uint32(0o7777), []byte(""))
	f.Add("/etc/x", "/etc/x", uint32(0), []byte("y"))
	f.Fuzz(func(t *testing.T, p1, p2 string, mode uint32, data []byte) {
		// A Plan is not necessarily one Build produced, so WriteTemp carries
		// its own guard. Drive the refused shapes at it directly, or the
		// harness would only ever hand it paths already known to be safe.
		if checkPath(p1) != nil || checkPath(p2) != nil {
			bad := &Plan{Files: []File{{Path: p1, Mode: mode, Data: data}, {Path: p2, Mode: mode, Data: data}}}
			dir, err := bad.WriteTemp()
			if dir != "" {
				defer os.RemoveAll(dir)
			}
			if err == nil {
				t.Fatalf("WriteTemp accepted a plan holding %q / %q, which checkPath refuses", p1, p2)
			}
			return
		}
		pl := &Plan{Files: []File{
			{Path: p1, Mode: mode, Data: data},
			{Path: p2, Mode: mode, Data: data},
		}}
		dir, err := pl.WriteTemp()
		if dir != "" {
			defer os.RemoveAll(dir)
		}
		if err != nil {
			return
		}
		root := filepath.Clean(dir)
		for _, fl := range pl.Files {
			rel, rerr := safeRelative(fl.Path)
			if rerr != nil {
				t.Fatalf("WriteTemp succeeded but safeRelative refuses %q: %v", fl.Path, rerr)
			}
			dst := filepath.Clean(filepath.Join(root, rel))
			if !strings.HasPrefix(dst, root+string(filepath.Separator)) {
				t.Fatalf("WriteTemp placed %q at %q, outside %q", fl.Path, dst, root)
			}
		}
	})
}
