package codec

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Golden vectors from XRPLF/xrpl.js ripple-binary-codec codec-fixtures.json.
func TestGoldenDIDSet(t *testing.T) {
	tx := &Tx{
		Type:          TxDIDSet,
		Flags:         2147483648,
		Sequence:      3,
		FeeDrops:      10,
		SigningPubKey: mustHex(t, "ED9861C4CB029C0DA737B823D7D3459A70F227958D5C0C111CC7CF947FC5A93347"),
		TxnSignature:  mustHex(t, "AACD31A04CAE14670FC483A1382F393AA96B49C84479B58067F049FBD772999325667A6AA2520A63756EE84F3657298815019DD56A1AECE796B08535C4009C08"),
		Account:       mustHex(t, "01476926B590BA3245F63C829116A0A3AF7F382D"),
		URI:           []byte("did_example"),
		DIDDocument:   []byte("doc"),
		Data:          []byte("attest"),
	}
	want := "1200312280000000240000000368400000000000000A7321ED9861C4CB029C0DA737B823D7D3459A70F227958D5C0C111CC7CF947FC5A933477440AACD31A04CAE14670FC483A1382F393AA96B49C84479B58067F049FBD772999325667A6AA2520A63756EE84F3657298815019DD56A1AECE796B08535C4009C08750B6469645F6578616D706C65701A03646F63701B06617474657374811401476926B590BA3245F63C829116A0A3AF7F382D"
	got, err := Serialize(tx, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ToUpper(hex.EncodeToString(got)) != want {
		t.Fatalf("got %X", got)
	}
}

func TestGoldenDIDDelete(t *testing.T) {
	tx := &Tx{
		Type:          TxDIDDelete,
		Flags:         2147483648,
		Sequence:      4,
		FeeDrops:      10,
		SigningPubKey: mustHex(t, "ED9861C4CB029C0DA737B823D7D3459A70F227958D5C0C111CC7CF947FC5A93347"),
		TxnSignature:  mustHex(t, "71E28B12465A1B47162C22E121DF61089DCD9AAF5773704B76179E771666886C8AAD5A33A87E34CC381A7D924E3FE3645F0BF98D565DE42C81E1A7A7E7981802"),
		Account:       mustHex(t, "01476926B590BA3245F63C829116A0A3AF7F382D"),
	}
	want := "1200322280000000240000000468400000000000000A7321ED9861C4CB029C0DA737B823D7D3459A70F227958D5C0C111CC7CF947FC5A93347744071E28B12465A1B47162C22E121DF61089DCD9AAF5773704B76179E771666886C8AAD5A33A87E34CC381A7D924E3FE3645F0BF98D565DE42C81E1A7A7E7981802811401476926B590BA3245F63C829116A0A3AF7F382D"
	got, err := Serialize(tx, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ToUpper(hex.EncodeToString(got)) != want {
		t.Fatalf("got %X", got)
	}
}

// Hand-checked structure: F9 (Memos) EA (Memo) 7C len type 7D len data E1 F1.
func TestMemosStructure(t *testing.T) {
	got, err := SerializeMemos([]Memo{{Type: []byte("ab"), Data: []byte{1, 2, 3}}})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xF9, 0xEA, 0x7C, 0x02, 'a', 'b', 0x7D, 0x03, 1, 2, 3, 0xE1, 0xF1}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %X want %X", got, want)
	}
}

func TestMemosSizeCap(t *testing.T) {
	typ := []byte("xrplbak/v1/c")
	// 989 data bytes: 2 + 2 + 14 + 3 + 989 = 1010.
	got, err := SerializeMemos([]Memo{{Type: typ, Data: make([]byte, 989)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1010 {
		t.Fatalf("len %d", len(got))
	}
	if _, err := SerializeMemos([]Memo{{Type: typ, Data: make([]byte, 1004)}}); err == nil {
		t.Fatal("expected cap error")
	}
	if _, err := SerializeMemos([]Memo{{Type: typ, Data: make([]byte, 1003)}}); err != nil {
		t.Fatal("1003 bytes must fit exactly:", err)
	}
}

func TestVLTwoByteLength(t *testing.T) {
	b := appendVL(nil, make([]byte, 193))
	if b[0] != 193 || b[1] != 0 || len(b) != 195 {
		t.Fatalf("got %X", b[:2])
	}
	b = appendVL(nil, make([]byte, 989))
	// 989-193 = 796 = 0x031C -> first byte 193+3 = 196, second 0x1C
	if b[0] != 196 || b[1] != 0x1C {
		t.Fatalf("got %X", b[:2])
	}
}
