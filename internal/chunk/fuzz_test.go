package chunk

import (
	"bytes"
	"testing"

	"github.com/justinnevins/xrplbak/internal/crypto"
	"github.com/justinnevins/xrplbak/internal/xrpl/codec"
)

// FuzzDecodeNoPanic asserts that an arbitrary memo cannot panic the
// decoder. Memos are public ledger data written by anyone, so junk memos
// on the writer account are the expected case, not the exception.
func FuzzDecodeNoPanic(f *testing.F) {
	f.Add(TypeChunk, []byte{})
	f.Add(TypeManifest, make([]byte, headerLen+crypto.ManifestNonceLen+crypto.TagLen))
	f.Add("other/type", []byte("junk"))
	f.Add(TypeChunk, []byte{1, 0, 0})
	f.Fuzz(func(t *testing.T, typ string, data []byte) {
		p, ok := Decode(codec.Memo{Type: []byte(typ), Data: data})
		if !ok {
			return
		}
		if p.Total == 0 || p.Index >= p.Total {
			t.Fatalf("accepted index %d of total %d", p.Index, p.Total)
		}
		if len(p.Ciphertext) < crypto.TagLen {
			t.Fatalf("accepted ciphertext shorter than the tag: %d bytes", len(p.Ciphertext))
		}
	})
}

// FuzzEncodeDecodeRoundTrip asserts that a chunk survives the memo layout
// and that the size guard holds: anything Encode accepts must fit a memo.
func FuzzEncodeDecodeRoundTrip(f *testing.F) {
	f.Add(uint16(0), uint16(1), make([]byte, 32))
	f.Add(uint16(3), uint16(8), make([]byte, 976))
	f.Fuzz(func(t *testing.T, idx, total uint16, ct []byte) {
		if total == 0 || idx >= total || len(ct) < crypto.TagLen {
			return
		}
		id := bytes.Repeat([]byte{0xAB}, 16)
		m, err := Encode(TypeChunk, id, idx, total, nil, ct)
		if err != nil {
			return // oversized payloads are refused by design
		}
		p, ok := Decode(m)
		if !ok {
			t.Fatalf("Encode produced a memo its own Decode rejects")
		}
		if p.Index != idx || p.Total != total || !bytes.Equal(p.Ciphertext, ct) {
			t.Fatalf("round trip changed the payload")
		}
	})
}
