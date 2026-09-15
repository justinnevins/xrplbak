package crypto

import (
	"bytes"
	"testing"
)

func fuzzKey() [KeyLen]byte {
	var k [KeyLen]byte
	for i := range k {
		k[i] = byte(i * 7)
	}
	return k
}

// FuzzOpenBundleNoPanic asserts that a hostile bundle file cannot panic and
// cannot allocate without bound. The bundle is a file the operator may
// receive from anywhere, including a compromised backup host.
func FuzzOpenBundleNoPanic(f *testing.F) {
	id := bytes.Repeat([]byte{0xCD}, 16)
	f.Add(SealBundle(fuzzKey(), id, []byte("hello")))
	f.Add([]byte("XBK1"))
	f.Add(append([]byte("XBK1"), id...))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, stream []byte) {
		out, err := OpenBundle(fuzzKey(), bytes.Repeat([]byte{0xCD}, 16), stream)
		if err != nil && out != nil {
			t.Fatalf("OpenBundle returned %d bytes alongside error %v", len(out), err)
		}
	})
}

// FuzzBundleRoundTrip asserts that a sealed bundle opens back to the same
// bytes at any size, including across the frame boundary, and that one
// flipped byte always fails authentication.
func FuzzBundleRoundTrip(f *testing.F) {
	f.Add([]byte("hello"), 0)
	f.Add(bytes.Repeat([]byte("x"), FrameLen+1), 30)
	f.Add([]byte{}, 5)
	f.Fuzz(func(t *testing.T, plain []byte, pos int) {
		if len(plain) > 4*FrameLen {
			return
		}
		id := bytes.Repeat([]byte{0xCD}, 16)
		k := fuzzKey()
		sealed := SealBundle(k, id, plain)
		back, err := OpenBundle(k, id, sealed)
		if err != nil {
			t.Fatalf("open own bundle: %v", err)
		}
		if !bytes.Equal(back, plain) {
			t.Fatalf("round trip changed %d bytes into %d", len(plain), len(back))
		}
		if pos < 0 {
			pos = -pos
		}
		// Every byte of the stream is authenticated or length-checked.
		bad := append([]byte{}, sealed...)
		bad[pos%len(bad)] ^= 0x01
		if _, err := OpenBundle(k, id, bad); err == nil {
			t.Fatalf("a one-bit edit at byte %d of %d still opened", pos%len(bad), len(bad))
		}
	})
}

// FuzzChunkAuth asserts that a chunk opened under the wrong index or the
// wrong total always fails. The index and total are in the AAD, so a
// reordered chunk must not decrypt.
func FuzzChunkAuth(f *testing.F) {
	f.Add(uint16(0), uint16(4), []byte("block"))
	f.Fuzz(func(t *testing.T, idx, total uint16, plain []byte) {
		if total == 0 || idx >= total || len(plain) > BlockLenGuard {
			return
		}
		id := bytes.Repeat([]byte{0xEF}, 16)
		k := fuzzKey()
		ct := SealChunk(k, id, idx, total, plain)
		back, err := OpenChunk(k, id, idx, total, ct)
		if err != nil {
			t.Fatalf("open own chunk: %v", err)
		}
		if !bytes.Equal(back, plain) {
			t.Fatal("chunk round trip changed the plaintext")
		}
		if idx+1 < total {
			if _, err := OpenChunk(k, id, idx+1, total, ct); err == nil {
				t.Fatal("a chunk opened under the wrong index")
			}
		}
		if _, err := OpenChunk(k, id, idx, total+1, ct); err == nil {
			t.Fatal("a chunk opened under the wrong total")
		}
	})
}

// BlockLenGuard bounds fuzz plaintext so a run does not spend its time on
// allocation. It is not a protocol limit.
const BlockLenGuard = 8192
