package anchor

import (
	"testing"

	"github.com/justinnevins/xrplbak/internal/crypto"
)

func testKey() crypto.EpochKey {
	var k crypto.EpochKey
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

// FuzzParseNoPanic asserts that hostile DID Data cannot panic and cannot
// return a record alongside an error. Anyone can write a DID object, so
// these bytes are fully attacker-controlled.
func FuzzParseNoPanic(f *testing.F) {
	f.Add(Encode(testKey(), &Record{Epoch: 1, Seq: 1}))
	f.Add([]byte{1})
	f.Add(make([]byte, Len))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := Parse(b)
		if err != nil && r != nil {
			t.Fatalf("Parse returned a record alongside error %v", err)
		}
		// Verify must tolerate any length and must never accept junk that
		// Parse rejected outright.
		if Verify(testKey(), b) && err != nil {
			t.Fatalf("Verify accepted %d bytes that Parse rejected: %v", len(b), err)
		}
	})
}

// FuzzForgedMACIsRejected asserts that no single-byte edit of a valid
// anchor still verifies. The MAC is what stops a writer-key thief from
// pointing the anchor at a manifest of their choosing.
func FuzzForgedMACIsRejected(f *testing.F) {
	f.Add(uint32(1), uint32(1), uint32(0), 0)
	f.Add(uint32(7), uint32(3), uint32(9000), 40)
	f.Fuzz(func(t *testing.T, epoch, seq, ledger uint32, pos int) {
		k := testKey()
		good := Encode(k, &Record{Epoch: epoch, Seq: seq, ManifestLedger: ledger})
		if !Verify(k, good) {
			t.Fatal("a freshly encoded anchor failed its own MAC")
		}
		if pos < 0 {
			pos = -pos
		}
		bad := append([]byte{}, good...)
		bad[pos%len(bad)] ^= 0x01
		if Verify(k, bad) {
			t.Fatalf("a one-bit edit at byte %d still verified", pos%len(bad))
		}
	})
}
