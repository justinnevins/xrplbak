package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/backup"
	"github.com/justinnevins/xrplbak/internal/pubattest"
)

// TestDelegatedAttestationEndToEnd pins the delegated attestation through
// the real submit path and attest-verify. The master key signs one
// delegation; later backups attest with the delegated key alone. Every
// attestation that would read as invalid is refused before anything is
// submitted: no delegation on the ledger, a delegation signature that does
// not verify, or a key already replaced by a higher dseq.
func TestDelegatedAttestationEndToEnd(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	w := newWorld(t, 3)
	w.ledger.Batch = true // one Batch per backup instead of sequential waits
	vpk, master := validatorKey(t)
	account := w.writer.Address()
	newKey := func(dseq uint32) *attestKey {
		_, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		return &attestKey{VPK: vpk, DSeq: dseq, Priv: priv}
	}
	delegate := func(k *attestKey) string {
		return hex.EncodeToString(ed25519.Sign(master, []byte(pubattest.DelegationString(vpk, account, k.pub(), k.DSeq))))
	}
	seq := uint32(1)
	submit := func(k *attestKey, sig string) (error, int) {
		t.Helper()
		before, _, _ := w.ledger.AccountTx(account)
		seq++
		o := backup.Options{ConfigPath: w.cfgPath, ValidatorsPath: w.valPath, Key: w.key, Seq: seq}
		err := doSubmit(o, w.ledger, "fake", w.writer, t.TempDir(), 0, false, true, "auto", "", "", nil, k, sig)
		after, _, _ := w.ledger.AccountTx(account)
		if err != nil {
			seq--
		}
		return err, len(after) - len(before)
	}
	verify := func() result {
		t.Helper()
		return w.run("", "attest-verify", "--dump", w.dumpFile("attest"), "--account", account, "--validator-key", vpk)
	}

	k1 := newKey(1)
	if err, n := submit(k1, ""); exitCode(err) != exitUsage || !strings.Contains(err.Error(), "no delegation for attestation key dseq 1") || n != 0 {
		t.Fatalf("attesting before any delegation must refuse with the string to sign and submit nothing: %v (exit %d), %d tx", err, exitCode(err), n)
	}
	bad := []byte(delegate(k1))
	bad[0] ^= 1
	if err, n := submit(k1, string(bad)); exitCode(err) != exitUsage || !strings.Contains(err.Error(), "does not verify") || n != 0 {
		t.Fatalf("a delegation signature that does not verify must refuse and submit nothing: %v, %d tx", err, n)
	}
	if err, _ := submit(k1, delegate(k1)); err != nil {
		t.Fatalf("publishing the delegation with the first attestation: %v", err)
	}
	if r := verify(); r.code != exitOK || !strings.Contains(r.out, "delegated attestation key 1") {
		t.Fatalf("attest-verify after the delegation: exit %d\n%s", r.code, r.out)
	}
	if err, _ := submit(k1, ""); err != nil {
		t.Fatalf("a later backup must attest with the delegated key alone: %v", err)
	}
	if r := verify(); r.code != exitOK || !strings.Contains(r.out, "delegated attestation key 1") {
		t.Fatalf("attest-verify after a key-only attestation: exit %d\n%s", r.code, r.out)
	}

	// The operator replaces a stolen key 1 with key 2.
	k2 := newKey(2)
	if err, _ := submit(k2, delegate(k2)); err != nil {
		t.Fatalf("publishing the replacement delegation: %v", err)
	}
	if err, n := submit(k1, ""); exitCode(err) != exitAuth || !strings.Contains(err.Error(), "replaced by key 2") || n != 0 {
		t.Fatalf("the replaced key must be refused and submit nothing: %v (exit %d), %d tx", err, exitCode(err), n)
	}
	if r := verify(); r.code != exitOK || !strings.Contains(r.out, "delegated attestation key 2") {
		t.Fatalf("attest-verify after the replacement: exit %d\n%s", r.code, r.out)
	}

	// A thief who kept key 1 posts an attestation with it directly, around
	// the submit-time check. attest-verify must call it invalid, and why.
	seq++
	p := w.build(seq, w.cfgPath, w.valPath)
	memo, err := pubattest.DelegatedMemo(vpk, account, k1.Priv, 1, p.Manifest.Epoch, p.Manifest.Seq, p.Manifest.BackupID)
	must(t, err)
	s := &backup.Submitter{Client: w.ledger, Writer: w.writer, Key: w.key, Sleep: func(time.Duration) {}, AttestMemo: &memo}
	must(t, s.Submit(p))
	if r := verify(); r.code != exitAuth || !strings.Contains(r.out, "INVALID") || !strings.Contains(r.out, "replaced by key 2") {
		t.Fatalf("attest-verify must reject the replaced key's attestation with the reason: exit %d\n%s", r.code, r.out)
	}
}

// TestAttestFlagsAndKeyFile pins the flag rules and the key file.
func TestAttestFlagsAndKeyFile(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	w := newWorld(t, 4)
	vpk, _ := validatorKey(t)

	if r := w.run("", "backup", "--config", w.cfgPath, "--key", w.keyFile, "--attest-delegation-sig", "00"); r.code != exitUsage || !strings.Contains(r.out, "needs --attest") {
		t.Fatalf("--attest-delegation-sig without --attest must be a usage error, got %d:\n%s", r.code, r.out)
	}
	if r := w.run("", "backup", "--config", w.cfgPath, "--key", w.keyFile, "--attest", "--attest-public-key", vpk); r.code != exitUsage || !strings.Contains(r.out, "choose one") {
		t.Fatalf("--attest with --attest-public-key must be a usage error, got %d:\n%s", r.code, r.out)
	}

	dir := t.TempDir()
	r := w.run("", "attest-key", "--validator-key", vpk, "--key", w.keyFile, "--out", dir)
	if r.code != exitOK || !strings.Contains(r.out, "validator-keys sign \"xrplbak/v1/delegate "+vpk+" "+w.writer.Address()+" ed25519 ") {
		t.Fatalf("attest-key must write the key and print the delegation string, got %d:\n%s", r.code, r.out)
	}
	path := filepath.Join(dir, attestKeyName)
	k, err := loadAttestKey(path)
	if err != nil || k.VPK != vpk || k.DSeq != 1 {
		t.Fatalf("key file round trip: %v %+v", err, k)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file must be 0600: %v %v", err, fi.Mode())
	}
	if r := w.run("", "attest-key", "--validator-key", vpk, "--key", w.keyFile, "--out", dir); r.code != exitWrite {
		t.Fatalf("attest-key must never overwrite a key file, got %d", r.code)
	}
	b, _ := os.ReadFile(path)
	b[40] ^= 1
	must(t, os.WriteFile(path, b, 0o600))
	if _, err := loadAttestKey(path); exitCode(err) != exitAuth || !strings.Contains(err.Error(), "damaged") {
		t.Fatalf("a damaged key file must be named damaged: %v", err)
	}
	if r := w.run("", "attest-key", "--validator-key", vpk, "--key", w.keyFile, "--out", t.TempDir(), "--dseq", "0"); r.code != exitUsage {
		t.Fatalf("--dseq 0 must be a usage error, got %d", r.code)
	}
}
