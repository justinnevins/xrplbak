package crypto

import (
	"strings"
	"testing"
)

// A wrapped key file says which wrap format it uses in its fifth byte.
// The byte was never read, so a file from a later format would have been
// opened as format 1 and failed as "wrong passphrase, or damaged".
func TestWrappedKeyFileVersionIsChecked(t *testing.T) {
	kf := &KeyFile{Epoch: 9}
	kf.Key = fixedRoot().DeriveEpochKey(9)
	w, err := kf.EncodeWrapped([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeKeyFile(w, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	for _, v := range []byte{0, 2, 99, 255} {
		bad := append([]byte{}, w...)
		bad[4] = v
		_, err := DecodeKeyFile(bad, []byte("pw"))
		if err == nil {
			t.Errorf("wrap version %d: opened as version 1", v)
			continue
		}
		if !strings.Contains(err.Error(), "version") || strings.Contains(err.Error(), "passphrase") {
			t.Errorf("wrap version %d: the error does not name the version: %v", v, err)
		}
	}
}
