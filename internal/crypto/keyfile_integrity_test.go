package crypto

import (
	"strings"
	"testing"
)

// TestPlainKeyFileEveryByteFlipIsRefused. A plain key file has no AEAD tag,
// so before the checksum a flipped bit in the epoch, key, account or seed
// decoded into a different key and the operator was told the ledger held
// no backup. Every single-bit change to the body must now be refused and
// named as damage, so the operator looks at the file and not at the ledger.
func TestPlainKeyFileEveryByteFlipIsRefused(t *testing.T) {
	kf := &KeyFile{Epoch: 3}
	kf.Key = fixedRoot().DeriveEpochKey(3)
	kf.AccountID[0] = 1
	kf.WriterSeed[15] = 2
	enc := kf.Encode()
	if _, err := DecodeKeyFile(enc, nil); err != nil {
		t.Fatal("clean file must decode:", err)
	}
	for i := range enc {
		for bit := 0; bit < 8; bit++ {
			bad := append([]byte{}, enc...)
			bad[i] ^= 1 << bit
			got, err := DecodeKeyFile(bad, nil)
			if err == nil {
				t.Fatalf("byte %d bit %d flipped: decoded to epoch %d with no error", i, bit, got.Epoch)
			}
			// The magic and version bytes have their own messages; the
			// body must be called damaged.
			if i >= 5 && !strings.Contains(err.Error(), "damaged") {
				t.Fatalf("byte %d bit %d flipped: %q does not say the file is damaged", i, bit, err)
			}
		}
	}
}

// TestWrappedKeyFileStillRoundTripsWithChecksum pins that the checksum
// rides inside the wrap and the wrapped path is unchanged for a clean file.
func TestWrappedKeyFileStillRoundTripsWithChecksum(t *testing.T) {
	kf := &KeyFile{Epoch: 9}
	kf.Key = fixedRoot().DeriveEpochKey(9)
	w, err := kf.EncodeWrapped([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeKeyFile(w, []byte("pw"))
	if err != nil || *back != *kf {
		t.Fatal("wrapped round trip", err)
	}
}

// TestVersion1KeyFileIsNamedNotSilentlyRefused. A pre-checksum file must
// not be reported as "not an xrplbak key file"; it is one, from an older
// build, and the message must say what to do.
func TestVersion1KeyFileIsNamedNotSilentlyRefused(t *testing.T) {
	kf := &KeyFile{Epoch: 1}
	enc := kf.Encode()
	v1 := append([]byte{}, enc[:77]...) // the v1 layout: no checksum
	v1[4] = 1
	_, err := DecodeKeyFile(v1, nil)
	if err == nil {
		t.Fatal("a version 1 file decoded")
	}
	if !strings.Contains(err.Error(), "version 1") || !strings.Contains(err.Error(), "rotate") {
		t.Fatalf("%q does not name version 1 and the way forward", err)
	}
}
