package pubattest

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/xrpl/codec"
	"github.com/justinnevins/xrplbak/internal/xrpl/sign"
)

// a stand-in validator master key: sign.Key is ed25519, the same key type a
// current validator-keys-tool master key uses, and Sign signs raw bytes.
func testValidator(t *testing.T) *sign.Key {
	t.Helper()
	k, err := sign.KeyFromSeed([]byte("validator-master-seed-16b"[:16]))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestPublicAttestationRoundTripAndVerify(t *testing.T) {
	v := testValidator(t)
	vpk := sign.EncodeNodePublic(v.PublicKey())
	const account = "rMSzDMzeSWEXhCipw6fDN6cyoeey6TgcdE"
	const backupID = "24acbdc5cd7aab3eae7fa988e4b7b752"

	msg := SignString(vpk, account, 0, 1, backupID)
	sig := v.Sign([]byte(msg))

	m, err := Memo(vpk, 0, 1, backupID, hex.EncodeToString(sig))
	if err != nil {
		t.Fatal(err)
	}
	if string(m.Type) != MemoType {
		t.Fatalf("memo type %q", m.Type)
	}

	r, ok := Decode(m)
	if !ok {
		t.Fatal("decode failed on a memo we just built")
	}
	if r.NodePublic() != vpk || r.Epoch != 0 || r.Seq != 1 || r.BackupIDHex() != backupID {
		t.Fatalf("decoded fields wrong: %+v", r)
	}
	if !r.Verify(account) {
		t.Fatal("a correct attestation must verify")
	}

	// Replay under a different account must fail: the account is in the
	// signed string, not the memo.
	if r.Verify("rQ3fNyLjbvcDaPNS4EAJY8aT9zR3uGk9Bd") {
		t.Fatal("attestation verified for the wrong account")
	}
	// A flipped signature byte must fail.
	bad := r
	bad.Sig = append([]byte(nil), r.Sig...)
	bad.Sig[0] ^= 0x01
	if bad.Verify(account) {
		t.Fatal("a tampered signature verified")
	}
	// A different backup id changes the signed string and must fail.
	bad2 := r
	bad2.BackupID[0] ^= 0x01
	if bad2.Verify(account) {
		t.Fatal("attestation verified for a different backup id")
	}
}

func TestMemoRefusesSecp256k1Key(t *testing.T) {
	v := testValidator(t)
	// A 33-byte key with a non-ED prefix stands in for a secp256k1 key.
	secp := append([]byte{0x02}, v.PublicKey()[1:]...)
	vpk := sign.EncodeNodePublic(secp)
	_, err := Memo(vpk, 0, 1, "24acbdc5cd7aab3eae7fa988e4b7b752", strings.Repeat("00", 64))
	if err == nil {
		t.Fatal("a secp256k1 validator key must be refused in v1")
	}
}

func TestDecodeRejectsJunkOfOurType(t *testing.T) {
	// Right memo type, wrong length: must not decode.
	if _, ok := Decode(codecMemo(MemoType, []byte{1, 2, 3})); ok {
		t.Fatal("a short memo of our type decoded")
	}
	// Wrong type entirely.
	if _, ok := Decode(codecMemo("xrplbak/v1/c", make([]byte, memoLen))); ok {
		t.Fatal("a chunk memo decoded as an attestation")
	}
	// Right length, wrong version byte.
	bad := make([]byte, memoLen)
	bad[0] = 2
	if _, ok := Decode(codecMemo(MemoType, bad)); ok {
		t.Fatal("a wrong-version memo decoded")
	}
}

// codecMemo builds a raw memo for the decode tests.
func codecMemo(typ string, data []byte) codec.Memo {
	return codec.Memo{Type: []byte(typ), Data: data}
}
