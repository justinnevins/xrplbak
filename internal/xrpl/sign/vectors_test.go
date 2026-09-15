package sign

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type vectorFile struct {
	Source  string `json:"source"`
	Vectors []struct {
		Seed        string `json:"seed"`
		Ed25519Seed string `json:"ed25519_seed"`
		PublicKey   string `json:"public_key"`
		Address     string `json:"address"`
	} `json:"vectors"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	b, err := os.ReadFile("../../../tests/fixtures/rippled-ed25519-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Vectors) < 50 {
		t.Fatalf("vector file looks truncated: %d entries", len(v.Vectors))
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRippledEd25519Vectors checks seed -> private key -> public key ->
// address against rippled's own unit-test vectors, copied verbatim from
// XRPLF/rippled src/test/protocol/SecretKey_test.cpp. If xrplbak ever
// derives a key differently from rippled, this fails.
func TestRippledEd25519Vectors(t *testing.T) {
	v := loadVectors(t)
	for i, tc := range v.Vectors {
		k, err := KeyFromSeed(mustHex(t, tc.Seed))
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		// rippled's secret key for ed25519 is SHA-512Half(seed).
		h := sha512.Sum512(mustHex(t, tc.Seed))
		if got := strings.ToUpper(hex.EncodeToString(h[:32])); got != tc.Ed25519Seed {
			t.Fatalf("vector %d: ed25519 seed %s want %s", i, got, tc.Ed25519Seed)
		}
		if got := strings.ToUpper(hex.EncodeToString(k.PublicKey())); got != tc.PublicKey {
			t.Fatalf("vector %d: public key %s want %s", i, got, tc.PublicKey)
		}
		if k.Address() != tc.Address {
			t.Fatalf("vector %d: address %s want %s", i, k.Address(), tc.Address)
		}
		id, err := DecodeAddress(tc.Address)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		if strings.ToUpper(hex.EncodeToString(id)) != strings.ToUpper(hex.EncodeToString(k.AccountID())) {
			t.Fatalf("vector %d: account id round trip", i)
		}
	}
}

// Attestation signing convention, confirmed against source on 2026-09-15:
//
//   - ripple/validator-keys-tool src/ValidatorKeys.cpp, ValidatorKeys::sign:
//     strHex(xrpl::sign(publicKey, secretKey, makeSlice(data))) -- the
//     argument to "validator-keys sign <data>" is signed as its raw bytes,
//     not hex-decoded first, and the output is hex.
//   - XRPLF/rippled src/libxrpl/protocol/SecretKey.cpp, sign(): the
//     KeyType::Ed25519 branch calls ed25519_sign over the message bytes
//     directly. No domain prefix and no pre-hash. Only the Secp256k1
//     branch takes SHA-512Half first.
//   - ValidatorKeysTool.cpp createKeyFile always builds master keys with
//     KeyType::Ed25519, so a key file from any current version verifies here.
//
// So xrplbak verifies an attestation as raw ed25519 over the ASCII attest
// string. The constants below are a deterministic regression pin using
// rippled's first ed25519 test vector.
const (
	attestVectorMsg = "xrplbak/v1/attest 000102030405060708090a0b0c0d0e0f " +
		"0000000000000000000000000000000000000000000000000000000000000000 " +
		"1111111111111111111111111111111111111111111111111111111111111111"
	attestVectorSeed = "AF41FF66F75EBD3A6B18FB7A1DF61C97"
	attestVectorPub  = "ED48CBBBE0EE7B8686A7DE9F0A0159734E65F9C369947F2E2696232B461E553213"
	attestVectorSig  = "5AA842D325C460323F25DB3900940FB33483692CB668D08AC302E88B2A679B16" +
		"42BEED1D8BB31D1ACAB5A476775E02398FF3CB438D806A6E91036AAF4D1FEF05"
	// The same message signed after SHA-512Half, i.e. the secp256k1
	// convention applied to an ed25519 key. It must not verify.
	attestVectorPrehashSig = "96A8D541F0663EE99CAC9CFFBA99A08951272E454D5774C87E64AA4B765A601E" +
		"561B5A9BB564B8C1F6E421D23D468132DFEF4BABDA1D5021C0994650C5CEEF0C"
)

func TestAttestationSignBytes(t *testing.T) {
	k, err := KeyFromSeed(mustHex(t, attestVectorSeed))
	if err != nil {
		t.Fatal(err)
	}
	pub := k.PublicKey()
	if got := strings.ToUpper(hex.EncodeToString(pub)); got != attestVectorPub {
		t.Fatalf("public key %s want %s", got, attestVectorPub)
	}
	sig := k.Sign([]byte(attestVectorMsg))
	if len(sig) != 64 {
		t.Fatalf("signature length %d", len(sig))
	}
	if got := strings.ToUpper(hex.EncodeToString(sig)); got != attestVectorSig {
		t.Fatalf("signature %s want %s", got, attestVectorSig)
	}
	if !VerifyEd25519(pub, []byte(attestVectorMsg), sig) {
		t.Fatal("raw-bytes signature must verify")
	}
	// A pre-hashed signature is the secp256k1 convention and must be
	// rejected, so a wrong-convention attestation reads as INVALID rather
	// than silently passing.
	if VerifyEd25519(pub, []byte(attestVectorMsg), mustHex(t, attestVectorPrehashSig)) {
		t.Fatal("pre-hashed signature must not verify")
	}
	// One flipped byte in the message must fail.
	bad := []byte(attestVectorMsg)
	bad[len(bad)-1] ^= 0x01
	if VerifyEd25519(pub, bad, sig) {
		t.Fatal("modified message must not verify")
	}
	// A 33-byte key that is not ed25519-prefixed must be refused, not
	// treated as a bare key.
	secp := append([]byte{0x02}, pub[1:]...)
	if VerifyEd25519(secp, []byte(attestVectorMsg), sig) {
		t.Fatal("non-ED key prefix must not verify")
	}
}
