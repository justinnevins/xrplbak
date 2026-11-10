package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIncludeKeyFileNamesRefused pins every file name refuseSecrets turns
// away as an --include, one name per case, so that losing any single name
// from the list fails a test. The content is harmless on purpose: the name
// alone must be enough. Before this test only validator-keys.json was
// covered, and a mutation pass could break the wallet.db, .pem and .key
// checks with every test still passing.
func TestIncludeKeyFileNamesRefused(t *testing.T) {
	e := newEnv(t)
	harmless := []byte("# notes\nnothing secret here\n")
	build := func(t *testing.T, name string) error {
		t.Helper()
		dir := t.TempDir()
		inc := filepath.Join(dir, name)
		if err := os.WriteFile(inc, harmless, 0o600); err != nil {
			t.Fatal(err)
		}
		o := e.opts(t, 1)
		o.Includes = []string{inc}
		_, err := Build(o)
		return err
	}

	for _, name := range []string{
		"validator-keys.json",
		"Validator-Keys.JSON",
		"wallet.db",
		"WALLET.DB",
		"server.pem",
		"SERVER.PEM",
		"node.key",
		"NODE.KEY",
		".pem",
		".key",
	} {
		t.Run(name, func(t *testing.T) {
			err := build(t, name)
			if err == nil {
				t.Fatalf("include %q accepted; it must be refused by name", name)
			}
			if !strings.Contains(err.Error(), "refused") || !strings.Contains(err.Error(), "private key files") {
				t.Fatalf("include %q failed for another reason: %v", name, err)
			}
		})
	}

	// The same content under names that only resemble the refused ones is
	// accepted, so the cases above fail on the name and nothing else.
	for _, name := range []string{
		"notes.txt",
		"wallet.db.txt",
		"validator-keys.json.bak",
		"pem",
		"key",
		"keys.conf",
		"server.pem.md",
	} {
		t.Run("accepted/"+name, func(t *testing.T) {
			if err := build(t, name); err != nil {
				t.Fatalf("include %q refused: %v", name, err)
			}
		})
	}
}
