package crypto

import (
	"strings"
	"testing"
)

// TestDamagedKeyFileDoesNotBlameThePassphrase pins a message that asserted
// something the code cannot know. A wrapped key file is opened with AEAD,
// and an Open failure means either a wrong passphrase or damaged bytes. The
// message named the passphrase, so an operator with the right passphrase and
// a corrupted file was sent to look in the wrong place, during a recovery.
func TestDamagedKeyFileDoesNotBlameThePassphrase(t *testing.T) {
	root, err := NewRootKey()
	if err != nil {
		t.Fatal(err)
	}
	kf := &KeyFile{Epoch: 0, Key: root.DeriveEpochKey(0)}
	enc, err := kf.EncodeWrapped([]byte("correct passphrase"))
	if err != nil {
		t.Fatal(err)
	}

	damaged := append([]byte{}, enc...)
	damaged[len(damaged)-1] ^= 0x01

	_, err = DecodeKeyFile(damaged, []byte("correct passphrase"))
	if err == nil {
		t.Fatal("a damaged key file decoded")
	}
	if !strings.Contains(err.Error(), "damaged") {
		t.Errorf("the message does not allow for damage: %q", err)
	}
	if !strings.Contains(err.Error(), "passphrase") {
		t.Errorf("the message no longer mentions the passphrase: %q", err)
	}
}
