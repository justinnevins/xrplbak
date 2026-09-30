package restore

import (
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/container"
	"github.com/justinnevins/xrplbak/internal/manifest"
)

// TestManifestListingOnePathTwiceIsRefused pins the restore side of the
// same-file-twice defect. A manifest that lists one path twice, one entry
// on-chain and one in the bundle, used to merge the whole bundle copy into
// the on-chain split and write the file with its content doubled. backup
// no longer writes such a manifest, and restore must not trust one that
// someone else did.
func TestManifestListingOnePathTwiceIsRefused(t *testing.T) {
	const path = "/etc/xrpld/xrpld.cfg"
	body := []byte("[node_size]\nmedium\n")
	m := &manifest.Manifest{}
	m.Node.Role = "node"
	m.Files = []manifest.File{
		{Path: path, SHA256: "00", Where: "onchain"},
		{Path: path, SHA256: "00", Where: "bundle"},
	}
	on := []container.Entry{{Path: path, Mode: 0o600, Data: body}}
	bundle := []container.Entry{{Path: path, Mode: 0o600, Data: body}}
	p, err := Build(m, on, bundle)
	if err == nil {
		for _, f := range p.Files {
			t.Logf("%s: %d bytes from %s", f.Path, len(f.Data), f.Source)
		}
		t.Fatal("a manifest listing one path twice was accepted")
	}
	if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("error does not name the path or the problem: %v", err)
	}
}
