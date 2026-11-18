package restore

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/container"
	"github.com/justinnevins/xrplbak/internal/manifest"
	"github.com/justinnevins/xrplbak/internal/redact"
)

func sumHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func f107Plan(t *testing.T, want, on, bundle string) File {
	t.Helper()
	const path = "/etc/xrpld/xrpld.cfg"
	m := &manifest.Manifest{}
	m.Node.Role = "node"
	m.Files = []manifest.File{{Path: path, SHA256: sumHex(want), Where: "onchain+bundle"}}
	p, err := Build(m, []container.Entry{{Path: path, Mode: 0o600, Data: []byte(on)}}, []container.Entry{{Path: path, Mode: 0o600, Data: []byte(bundle)}})
	if err != nil {
		t.Fatal(err)
	}
	return p.Files[0]
}

// A v1.0 backup: one marker stands for every moved line of its stanza, and
// the manifest hash is over the canonical file (stanzas sorted). The
// line-by-line merge gives one bundle line per marker and gets it wrong.
func TestF107V1BackupRebuilds(t *testing.T) {
	on := "[ips_fixed]\n" + redact.MovedMarker + "\n\n[node_size]\nlarge\n\n[port_rpc]\nport = 5005\n" + redact.MovedMarker + "\nprotocol = http\n"
	bundle := "[ips_fixed]\n10.0.0.5 51235\n10.0.0.6 51235\n\n[port_rpc]\nadmin = 10.0.0.9\n\n[validator_token]\nAAAA\nBBBB\n"
	want := "[ips_fixed]\n10.0.0.5 51235\n10.0.0.6 51235\n\n[node_size]\nlarge\n\n[port_rpc]\nport = 5005\nadmin = 10.0.0.9\nprotocol = http\n\n[validator_token]\nAAAA\nBBBB\n"
	f := f107Plan(t, want, on, bundle)
	if !f.Complete() {
		t.Fatalf("a v1.0 backup is not complete; restore built:\n%s", f.Data)
	}
	if string(f.Data) != want {
		t.Errorf("restored:\n%s\nwant:\n%s", f.Data, want)
	}
	if !strings.Contains(f.Source, "v1.0 format") {
		t.Errorf("source %q does not name the v1.0 format", f.Source)
	}
}

// The v1.0 reading is taken only when its bytes match the manifest hash.
// When neither reading matches, the file is not complete and holds the
// current reading, as before: the old merge is not a second guess to show.
func TestF107V1ReadingNeedsTheHash(t *testing.T) {
	on := "[ips_fixed]\n" + redact.MovedMarker + "\n\n[node_size]\nlarge\n"
	bundle := "[ips_fixed]\n10.0.0.5 51235\n10.0.0.6 51235\n"
	f := f107Plan(t, "something else entirely\n", on, bundle)
	if f.Complete() {
		t.Fatal("complete without a matching hash")
	}
	if strings.Contains(f.Source, "v1.0") {
		t.Errorf("source %q claims the v1.0 format without proof", f.Source)
	}
	// The current reading of this input, written out: the marker takes the
	// bundle's first line, the rest follow at the end.
	if want := "[ips_fixed]\n[ips_fixed]\n\n[node_size]\nlarge\n10.0.0.5 51235\n10.0.0.6 51235\n"; string(f.Data) != want {
		t.Errorf("data changed for a backup that matches neither reading:\n%q\nwant\n%q", f.Data, want)
	}
}

// A current backup that happens to hold one marker per stanza is read the
// current way and stays byte-exact, comments and order included.
func TestF107CurrentBackupIsStillReadTheCurrentWay(t *testing.T) {
	on := "# top note\n[node_size]\nlarge\n\n[ips_fixed]\n" + redact.MovedMarker + "\n"
	bundle := "10.0.0.5 51235\n"
	want := "# top note\n[node_size]\nlarge\n\n[ips_fixed]\n10.0.0.5 51235\n"
	f := f107Plan(t, want, on, bundle)
	if !f.Complete() || string(f.Data) != want {
		t.Fatalf("complete=%v data:\n%s", f.Complete(), f.Data)
	}
	if strings.Contains(f.Source, "v1.0") {
		t.Errorf("source %q names the v1.0 format for a current backup", f.Source)
	}
}
