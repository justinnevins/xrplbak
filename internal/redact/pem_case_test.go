package redact

import (
	"errors"
	"testing"

	"github.com/justinnevins/xrplbak/internal/cfg"
)

// TestPEMHeaderRefusedInAnyCase pins that the PEM check does not depend
// on letter case. It was a case-sensitive match on "-----BEGIN", so a
// lowercase header passed onto the ledger.
func TestPEMHeaderRefusedInAnyCase(t *testing.T) {
	for _, h := range []string{"-----BEGIN RSA PRIVATE KEY-----", "-----begin rsa private key-----", "-----Begin Private Key-----"} {
		_, err := Split(cfg.Parse("[node_size]\nmedium\n"+h+"\nMIIBogIBAAJBALRiMLAH\n"), Options{})
		var re *RefusedError
		if !errors.As(err, &re) {
			t.Errorf("%q: not refused (err = %v)", h, err)
		}
	}
}
