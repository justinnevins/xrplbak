package pubattest

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/justinnevins/xrplbak/internal/xrpl"
	"github.com/justinnevins/xrplbak/internal/xrpl/codec"
)

func f082Direct(t *testing.T, m master, seq uint32) codec.Memo {
	t.Helper()
	sig := ed25519.Sign(m.priv, []byte(SignString(m.np, acctA, 0, seq, bid)))
	memo, err := Memo(m.np, 0, seq, bid, hex.EncodeToString(sig))
	if err != nil {
		t.Fatal(err)
	}
	return memo
}

func f082Damage(m codec.Memo) codec.Memo {
	out := m
	out.Data = append([]byte(nil), m.Data...)
	out.Data[len(out.Data)-1] ^= 1
	return out
}

// F-082: Evaluate judged only the newest attestation memo. Whoever holds
// the writer seed can post a memo of the right type with a signature that
// does not verify, and that one memo turned a validator's standing proof to
// INVALID. The newest attestation that verifies is the answer now; the
// newer ones that do not are counted and reported, not obeyed.
func TestF082ADamagedMemoDoesNotHideAValidAttestation(t *testing.T) {
	m := newMaster(t)
	good := f082Direct(t, m, 1)
	f := Evaluate([]xrpl.TxRecord{tx(acctA, 100, good), tx(acctA, 200, f082Damage(good)), tx(acctA, 300, f082Damage(good))}, acctA)
	if f.Status != Valid {
		t.Fatalf("status %d, want Valid: %s", f.Status, f.Reason)
	}
	if f.Ledger != 100 || f.Record.Seq != 1 {
		t.Fatalf("answer is the memo in ledger %d (seq %d); the valid one is in ledger 100", f.Ledger, f.Record.Seq)
	}
	if f.NewerInvalid != 2 || f.NewerLedger != 300 || f.NewerReason == "" {
		t.Fatalf("newer memos that do not verify: count %d, newest ledger %d, reason %q; want 2, 300 and a reason", f.NewerInvalid, f.NewerLedger, f.NewerReason)
	}
}

// A newer valid attestation still wins over an older one, with nothing to
// warn about, and damaged memos older than the answer are not counted.
func TestF082TheNewestValidAttestationIsTheAnswer(t *testing.T) {
	m := newMaster(t)
	one, two := f082Direct(t, m, 1), f082Direct(t, m, 2)
	f := Evaluate([]xrpl.TxRecord{tx(acctA, 100, one), tx(acctA, 150, f082Damage(one)), tx(acctA, 200, two)}, acctA)
	if f.Status != Valid || f.Record.Seq != 2 || f.Ledger != 200 {
		t.Fatalf("status %d seq %d ledger %d; want Valid, seq 2, ledger 200", f.Status, f.Record.Seq, f.Ledger)
	}
	if f.NewerInvalid != 0 || f.NewerReason != "" || f.NewerLedger != 0 {
		t.Fatalf("nothing is newer than the answer, yet NewerInvalid=%d reason=%q ledger=%d", f.NewerInvalid, f.NewerReason, f.NewerLedger)
	}
}

// When no attestation verifies, the verdict is still INVALID, about the
// newest one, as before.
func TestF082OnlyInvalidAttestationsStayInvalid(t *testing.T) {
	m := newMaster(t)
	good := f082Direct(t, m, 1)
	f := Evaluate([]xrpl.TxRecord{tx(acctA, 100, f082Damage(good)), tx(acctA, 200, f082Damage(good))}, acctA)
	if f.Status != Invalid || f.Ledger != 200 || f.Reason == "" {
		t.Fatalf("status %d ledger %d reason %q; want Invalid about ledger 200", f.Status, f.Ledger, f.Reason)
	}
	if f.NewerInvalid != 0 {
		t.Fatalf("NewerInvalid=%d on an Invalid finding", f.NewerInvalid)
	}
}

// The delegated path: an attestation signed by a retired key, posted after
// the key was replaced, does not hide the valid attestation before it.
func TestF082ARetiredKeyDoesNotHideTheValidDelegatedAttestation(t *testing.T) {
	m := newMaster(t)
	pubA, privA := newAttestKey(t)
	pubB, _ := newAttestKey(t)
	f := Evaluate([]xrpl.TxRecord{
		tx(acctA, 10, delegation(t, m, acctA, pubA, 1)),
		tx(acctA, 20, attestation(t, m, acctA, privA, 1, 5)),
		tx(acctA, 30, delegation(t, m, acctA, pubB, 2)),
		tx(acctA, 40, attestation(t, m, acctA, privA, 1, 6)), // the retired key signs again
	}, acctA)
	if f.Status != Valid || f.Ledger != 20 || f.Record.Seq != 5 || !f.Delegated {
		t.Fatalf("status %d ledger %d seq %d delegated %v; want the ledger 20 attestation", f.Status, f.Ledger, f.Record.Seq, f.Delegated)
	}
	if f.NewerInvalid != 1 || f.NewerLedger != 40 {
		t.Fatalf("NewerInvalid=%d NewerLedger=%d; want 1 and 40", f.NewerInvalid, f.NewerLedger)
	}
}

// Two attestations in one ledger: the later memo is the newer one.
func TestF082OrderInsideOneLedger(t *testing.T) {
	m := newMaster(t)
	one, two := f082Direct(t, m, 1), f082Direct(t, m, 2)
	f := Evaluate([]xrpl.TxRecord{tx(acctA, 100, one), tx(acctA, 100, two)}, acctA)
	if f.Status != Valid || f.Record.Seq != 2 {
		t.Fatalf("status %d seq %d; the later memo in the ledger is seq 2", f.Status, f.Record.Seq)
	}
	f = Evaluate([]xrpl.TxRecord{tx(acctA, 100, two), tx(acctA, 100, one)}, acctA)
	if f.Status != Valid || f.Record.Seq != 1 {
		t.Fatalf("status %d seq %d; the later memo in the ledger is seq 1", f.Status, f.Record.Seq)
	}
	f = EvaluateNewest([]xrpl.TxRecord{tx(acctA, 100, one), tx(acctA, 100, f082Damage(one))}, acctA)
	if f.Status != Invalid {
		t.Fatalf("EvaluateNewest: status %d; the newest memo does not verify and no older one may stand in", f.Status)
	}
}
