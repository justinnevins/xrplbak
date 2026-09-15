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
	m, err := Encode(TypeChunk, id, 3, 8, nil, ct)
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
	if _, err := Encode(TypeChunk, id, 0, 1, nil, make([]byte, container.BlockLen+crypto.TagLen+7)); err == nil {
		t.Fatal("one block plus 7 bytes must exceed the 1 KB memo cap")
	}
	nonce := make([]byte, crypto.ManifestNonceLen)
	mm, err := Encode(TypeManifest, id, 1, 2, nonce, make([]byte, ManifestPartLen+crypto.TagLen))
	if err != nil {
		t.Fatal("largest manifest part must fit:", err)
	}
	mp, ok := Decode(mm)
	if !ok || mp.Index != 1 || len(mp.Ciphertext) != ManifestPartLen+crypto.TagLen {
		t.Fatal("manifest decode")
	}
	if _, err := Encode(TypeManifest, id, 0, 1, nil, ct); err == nil {
		t.Fatal("manifest without nonce must fail")
	}
	if _, ok := Decode(codec.Memo{Type: []byte(TypeChunk), Data: m.Data[:20]}); ok {
		t.Fatal("short memo must be ignored")
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
