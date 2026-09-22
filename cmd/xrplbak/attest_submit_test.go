package main

// F-042. backup --submit took any 64-byte --attest-public-sig and published
// it. A signature that does not verify under --attest-public-key (a paste
// error, a signature over last week's string, the wrong key) went onto the
// ledger permanently, and the operator learned of it only when a third
// party ran attest-verify. The check is cheap and offline, so it happens
// before anything is submitted.

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/backup"
	"github.com/justinnevins/xrplbak/internal/pubattest"
	"github.com/justinnevins/xrplbak/internal/xrpl/fake"
	"github.com/justinnevins/xrplbak/internal/xrpl/sign"
)

// validatorKey is a throwaway ed25519 validator identity in nHB form.
func validatorKey(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return sign.EncodeNodePublic(append([]byte{0xED}, pub...)), priv
}

func attestSubmit(t *testing.T, w *world, vpk, sigHex string) (error, int) {
	t.Helper()
	ledger := fake.New()
	ledger.Batch = true // one Batch instead of four sequential waits
	ledger.Fund(w.writer.Address(), 5_000_000)
	o := backup.Options{ConfigPath: w.cfgPath, ValidatorsPath: w.valPath, Key: w.key, Seq: 1, AttestPublicVPK: vpk}
	err := doSubmit(o, ledger, "fake", w.writer, t.TempDir(), 0, false, true, "auto", vpk, sigHex, nil)
	txs, _, _ := ledger.AccountTx(w.writer.Address())
	return err, len(txs)
}

func TestSubmitRefusesAnAttestationThatDoesNotVerify(t *testing.T) {
	w := newWorld(t, 1)
	vpk, priv := validatorKey(t)
	p, err := backup.Build(backup.Options{ConfigPath: w.cfgPath, ValidatorsPath: w.valPath, Key: w.key, Seq: 1, AttestPublicVPK: vpk})
	if err != nil {
		t.Fatal(err)
	}
	good := ed25519.Sign(priv, []byte(p.AttestPublicText))

	bad := append([]byte(nil), good...)
	bad[0] ^= 0x01
	_, otherPriv := validatorKey(t)
	byOther := ed25519.Sign(otherPriv, []byte(p.AttestPublicText))
	stale := ed25519.Sign(priv, []byte(strings.Replace(p.AttestPublicText, " 0 1 ", " 0 2 ", 1)))

	for name, sig := range map[string][]byte{"flipped bit": bad, "another validator's key": byOther, "signature over a different seq": stale} {
		t.Run(name, func(t *testing.T) {
			err, n := attestSubmit(t, w, vpk, hex.EncodeToString(sig))
			if err == nil || exitCode(err) != exitUsage {
				t.Fatalf("err %v (exit %d), want a usage refusal", err, exitCode(err))
			}
			if !strings.Contains(err.Error(), "does not verify") || !strings.Contains(err.Error(), vpk) {
				t.Fatalf("refusal must say the signature does not verify under %s: %v", vpk, err)
			}
			if n != 0 {
				t.Fatalf("%d transaction(s) were submitted despite the refusal", n)
			}
		})
	}

	t.Run("a good signature is published", func(t *testing.T) {
		err, n := attestSubmit(t, w, vpk, hex.EncodeToString(good))
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatal("nothing was submitted")
		}
		if _, err := pubattest.Memo(vpk, 0, 1, p.Manifest.BackupID, hex.EncodeToString(good)); err != nil {
			t.Fatal(err)
		}
	})
}
