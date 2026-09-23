package pubattest

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/xrpl"
	"github.com/justinnevins/xrplbak/internal/xrpl/codec"
	"github.com/justinnevins/xrplbak/internal/xrpl/sign"
)

const (
	acctA = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
	acctB = "rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe"
	bid   = "00112233445566778899aabbccddeeff"
)

type master struct {
	np   string
	priv ed25519.PrivateKey
}

func newMaster(t *testing.T) master {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return master{np: sign.EncodeNodePublic(append([]byte{0xED}, pub...)), priv: priv}
}

func newAttestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// delegation signs a delegation for account with m, the way the operator
// does offline.
func delegation(t *testing.T, m master, account string, pub ed25519.PublicKey, dseq uint32) codec.Memo {
	t.Helper()
	sig := ed25519.Sign(m.priv, []byte(DelegationString(m.np, account, pub, dseq)))
	memo, err := DelegationMemo(m.np, pub, dseq, hex.EncodeToString(sig))
	if err != nil {
		t.Fatal(err)
	}
	return memo
}

func attestation(t *testing.T, m master, account string, priv ed25519.PrivateKey, dseq, seq uint32) codec.Memo {
	t.Helper()
	memo, err := DelegatedMemo(m.np, account, priv, dseq, 0, seq, bid)
	if err != nil {
		t.Fatal(err)
	}
	return memo
}

func tx(account string, ledger uint32, memos ...codec.Memo) xrpl.TxRecord {
	return xrpl.TxRecord{Account: account, LedgerIndex: ledger, Result: "tesSUCCESS", Memos: memos}
}

func TestDelegatedAttestationChain(t *testing.T) {
	m := newMaster(t)
	pub1, priv1 := newAttestKey(t)
	pub2, priv2 := newAttestKey(t)
	_, stranger := newAttestKey(t)
	other := newMaster(t)

	cases := []struct {
		name   string
		txs    []xrpl.TxRecord
		want   Status
		reason string
	}{
		{"delegation then attestation", []xrpl.TxRecord{
			tx(acctA, 10, delegation(t, m, acctA, pub1, 1)),
			tx(acctA, 20, attestation(t, m, acctA, priv1, 1, 1)),
		}, Valid, ""},
		{"delegation and attestation in one transaction", []xrpl.TxRecord{
			tx(acctA, 10, delegation(t, m, acctA, pub1, 1), attestation(t, m, acctA, priv1, 1, 1)),
		}, Valid, ""},
		{"delegation published after the attestation", []xrpl.TxRecord{
			tx(acctA, 10, attestation(t, m, acctA, priv1, 1, 1)),
			tx(acctA, 20, delegation(t, m, acctA, pub1, 1)),
		}, Invalid, "no valid delegation"},
		{"delegation signed by another master key", []xrpl.TxRecord{
			tx(acctA, 10, forged(t, m, other, acctA, pub1, 1)),
			tx(acctA, 20, attestation(t, m, acctA, priv1, 1, 1)),
		}, Invalid, "no valid delegation"},
		{"delegation signed for another account", []xrpl.TxRecord{
			tx(acctA, 10, delegation(t, m, acctB, pub1, 1)),
			tx(acctA, 20, attestation(t, m, acctA, priv1, 1, 1)),
		}, Invalid, "no valid delegation"},
		{"attestation signed by a key that was never delegated", []xrpl.TxRecord{
			tx(acctA, 10, delegation(t, m, acctA, pub1, 1)),
			tx(acctA, 20, attestation(t, m, acctA, stranger, 1, 1)),
		}, Invalid, "delegated key signature does not verify"},
		{"old key used after a replacement delegation", []xrpl.TxRecord{
			tx(acctA, 10, delegation(t, m, acctA, pub1, 1)),
			tx(acctA, 20, delegation(t, m, acctA, pub2, 2)),
			tx(acctA, 30, attestation(t, m, acctA, priv1, 1, 2)),
		}, Invalid, "was replaced by key 2"},
		{"new key after a replacement delegation", []xrpl.TxRecord{
			tx(acctA, 10, delegation(t, m, acctA, pub1, 1)),
			tx(acctA, 20, attestation(t, m, acctA, priv1, 1, 1)),
			tx(acctA, 30, delegation(t, m, acctA, pub2, 2)),
			tx(acctA, 40, attestation(t, m, acctA, priv2, 2, 2)),
		}, Valid, ""},
		{"attestation made before the replacement stays valid", []xrpl.TxRecord{
			tx(acctA, 10, delegation(t, m, acctA, pub1, 1)),
			tx(acctA, 20, attestation(t, m, acctA, priv1, 1, 1)),
		}, Valid, ""},
		{"delegated attestation copied onto another account", []xrpl.TxRecord{
			tx(acctA, 10, delegation(t, m, acctA, pub1, 1)),
			tx(acctB, 20, attestation(t, m, acctA, priv1, 1, 1)),
		}, None, ""},
		{"no attestation", []xrpl.TxRecord{tx(acctA, 10, delegation(t, m, acctA, pub1, 1))}, None, ""},
		{"attestation names a validator whose delegation it does not have", []xrpl.TxRecord{
			tx(acctA, 10, delegation(t, other, acctA, pub1, 1)),
			tx(acctA, 20, attestation(t, m, acctA, priv1, 1, 1)),
		}, Invalid, "no valid delegation"},
		{"attestation names a dseq that was never delegated", []xrpl.TxRecord{
			tx(acctA, 10, delegation(t, m, acctA, pub1, 1)),
			tx(acctA, 20, attestation(t, m, acctA, priv1, 2, 1)),
		}, Invalid, "no valid delegation"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := Evaluate(c.txs, acctA)
			if f.Status != c.want {
				t.Fatalf("status %d, want %d (reason %q)", f.Status, c.want, f.Reason)
			}
			if c.reason != "" && !strings.Contains(f.Reason, c.reason) {
				t.Fatalf("reason %q, want it to contain %q", f.Reason, c.reason)
			}
			if c.want == Valid && !f.Delegated {
				t.Fatal("a valid version 2 attestation must be reported as delegated")
			}
		})
	}
}

// A delegated attestation moved to the account it names in its signature,
// but whose delegation lives on another account, must fail on the account
// it was posted to: each record is bound to the account that published it.
func TestDelegatedAttestationBoundToItsAccount(t *testing.T) {
	m := newMaster(t)
	pub, priv := newAttestKey(t)
	txs := []xrpl.TxRecord{
		tx(acctA, 10, delegation(t, m, acctA, pub, 1)),
		tx(acctB, 20, delegation(t, m, acctA, pub, 1), attestation(t, m, acctA, priv, 1, 1)),
	}
	if f := Evaluate(txs, acctB); f.Status != Invalid {
		t.Fatalf("records signed for %s must not verify on %s, got status %d", acctA, acctB, f.Status)
	}
}

// Version 1 (master-signed) attestations keep working, and a version 2
// record can never pass the version 1 check.
func TestVersionOneStillVerifies(t *testing.T) {
	m := newMaster(t)
	sig := ed25519.Sign(m.priv, []byte(SignString(m.np, acctA, 0, 1, bid)))
	v1, err := Memo(m.np, 0, 1, bid, hex.EncodeToString(sig))
	if err != nil {
		t.Fatal(err)
	}
	if f := Evaluate([]xrpl.TxRecord{tx(acctA, 10, v1)}, acctA); f.Status != Valid || f.Delegated {
		t.Fatalf("version 1 attestation: status %d delegated %v", f.Status, f.Delegated)
	}
	_, priv := newAttestKey(t)
	r, ok := Decode(attestation(t, m, acctA, priv, 1, 1))
	if !ok || r.Version != VersionDelegated || r.DSeq != 1 {
		t.Fatalf("version 2 decode: ok %v version %d dseq %d", ok, r.Version, r.DSeq)
	}
	if r.Verify(acctA) {
		t.Fatal("a version 2 record must not pass the master-key check")
	}
}

// forged builds a delegation that claims validator m but is signed by other.
func forged(t *testing.T, m, other master, account string, pub ed25519.PublicKey, dseq uint32) codec.Memo {
	t.Helper()
	sig := ed25519.Sign(other.priv, []byte(DelegationString(m.np, account, pub, dseq)))
	memo, err := DelegationMemo(m.np, pub, dseq, hex.EncodeToString(sig))
	if err != nil {
		t.Fatal(err)
	}
	return memo
}

// Only algorithm 1 (ed25519) is defined. A delegation carrying any other
// algorithm byte is not a delegation, even if its signature would verify.
func TestDelegationRejectsUnknownAlgorithm(t *testing.T) {
	m := newMaster(t)
	pub, _ := newAttestKey(t)
	memo := delegation(t, m, acctA, pub, 1)
	if _, ok := DecodeDelegation(memo); !ok {
		t.Fatal("a well-formed delegation must decode")
	}
	memo.Data[1+vpkLen] = 2
	if _, ok := DecodeDelegation(memo); ok {
		t.Fatal("a delegation with algorithm 2 must not decode")
	}
}
