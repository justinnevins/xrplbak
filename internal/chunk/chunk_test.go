package chunk

import (
	"bytes"
	"testing"

	"github.com/justinnevins/xrplbak/internal/container"
	"github.com/justinnevins/xrplbak/internal/crypto"
	"github.com/justinnevins/xrplbak/internal/xrpl/codec"
)

func TestMemoRoundTripAndCap(t *testing.T) {
	id := bytes.Repeat([]byte{0xAB}, 16)
	ct := make([]byte, container.BlockLen+crypto.TagLen)
	m, err := Encode(TypeChunk, id, 3, 8, ct)
	if err != nil {
		t.Fatal(err)
	}
	ser, _ := codec.SerializeMemos([]codec.Memo{m})
	if len(ser) != 1018 {
		t.Fatalf("serialized %d", len(ser))
	}
	p, ok := Decode(m)
	if !ok || p.Index != 3 || p.Total != 8 || p.BackupID != [16]byte(id) || !bytes.Equal(p.Ciphertext, ct) {
		t.Fatal("decode")
	}
	if _, err := Encode(TypeChunk, id, 0, 1, make([]byte, container.BlockLen+crypto.TagLen+7)); err == nil {
		t.Fatal("one block plus 7 bytes must exceed the 1 KB memo cap")
	}
	if _, ok := Decode(codec.Memo{Type: []byte("other"), Data: m.Data}); ok {
		t.Fatal("foreign memo type must be ignored")
	}
}

func TestSplit(t *testing.T) {
	parts, err := Split(make([]byte, container.BlockLen*3))
	if err != nil || len(parts) != 3 {
		t.Fatal(err)
	}
	if _, err := Split(make([]byte, 5)); err == nil {
		t.Fatal("unaligned must fail")
	}
}
