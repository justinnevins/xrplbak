package backup

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIncludeKeyMaterialRefusedInAnyCase pins that an --include file with
// a PEM header or secret_key is refused whatever its letter case.
func TestIncludeKeyMaterialRefusedInAnyCase(t *testing.T) {
	e := newEnv(t)
	for i, body := range []string{
		"-----begin rsa private key-----\nMIIBogIBAAJBALRiMLAH\n-----end rsa private key-----\n",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAH\n",
		"SECRET_KEY = abc\n",
	} {
		inc := filepath.Join(e.dir, "notes"+string(rune('a'+i))+".txt")
		if err := os.WriteFile(inc, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		o := e.opts(t, 1)
		o.Includes = []string{inc}
		if _, err := Build(o); err == nil {
			t.Errorf("%q: include accepted", body)
		}
	}
}
