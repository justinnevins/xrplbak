package sign

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Vectors from XRPLF/xrpl.js ripple-keypairs test fixtures (api.json).
func TestEd25519Vector(t *testing.T) {
	k, err := KeyFromFamilySeed("sEdSKaCy2JT7JaM7v95H9SxkhP9wS2r")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.ToUpper(hex.EncodeToString(k.PublicKey())); got != "ED01FA53FA5A7E77798F882ECE20B1ABC00BB358A9E55A202D0D0676BD0CE37A63" {
		t.Fatalf("public key %s", got)
	}
	if k.Address() != "rLUEXYuLiQptky37CqLcm9USQpPiz5rkpD" {
		t.Fatalf("address %s", k.Address())
	}
	sig := k.Sign([]byte("test message"))
	want := "CB199E1BFD4E3DAA105E4832EEDFA36413E1F44205E4EFB9E27E826044C21E3E2E848BBC8195E8959BADF887599B7310AD1B7047EF11B682E0D068F73749750E"
	if got := strings.ToUpper(hex.EncodeToString(sig)); got != want {
		t.Fatalf("signature %s", got)
	}
	if !VerifyEd25519(k.PublicKey(), []byte("test message"), sig) {
		t.Fatal("verify failed")
	}
	if k.FamilySeed() != "sEdSKaCy2JT7JaM7v95H9SxkhP9wS2r" {
		t.Fatalf("seed round trip %s", k.FamilySeed())
	}
}

func TestAddressRoundTrip(t *testing.T) {
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	id, err := DecodeAddress(k.Address())
	if err != nil {
		t.Fatal(err)
	}
	if EncodeAddress(id) != k.Address() {
		t.Fatal("round trip")
	}
	if _, err := DecodeAddress("rFAKEnotanaddress"); err == nil {
		t.Fatal("expected error")
	}
}
