package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/backup"
	"github.com/justinnevins/xrplbak/internal/dump"
)

// --delete-anchor only acts with --tombstone. Alone it was ignored, exit 0.
func TestDeleteAnchorNeedsTombstone(t *testing.T) {
	w := newWorld(t, 91)
	r := w.run("", "backup", "--config", w.cfgPath, "--validators", w.valPath, "--key", w.keyFile, "--out", t.TempDir(), "--delete-anchor")
	if r.code != exitUsage || !strings.Contains(r.out, "--delete-anchor needs --tombstone") {
		t.Fatalf("--delete-anchor alone must be a usage error, got exit %d:\n%s", r.code, r.out)
	}
}

// A tombstone stores no data, so an --include file would be dropped
// without a word.
func TestTombstoneRefusesInclude(t *testing.T) {
	w := newWorld(t, 92)
	r := w.run("", "backup", "--tombstone", "--config", w.cfgPath, "--key", w.keyFile, "--out", t.TempDir(), "--include", filepath.Join(w.dir, "does-not-exist"))
	if r.code != exitUsage || !strings.Contains(r.out, "--tombstone stores no files") {
		t.Fatalf("--tombstone --include must be a usage error, got exit %d:\n%s", r.code, r.out)
	}
}

// An attestation says this validator backs up. Publishing one with a
// tombstone, which retires the backups, says the opposite of what it does.
func TestTombstoneRefusesAttestationFlags(t *testing.T) {
	w := newWorld(t, 93)
	vpk, _ := validatorKey(t)
	for _, extra := range [][]string{
		{"--attest"},
		{"--attest-public-key", vpk},
		{"--attestation", "00", "--attestation-key", vpk},
	} {
		args := append([]string{"backup", "--tombstone", "--config", w.cfgPath, "--key", w.keyFile, "--out", t.TempDir()}, extra...)
		r := w.run("", args...)
		if r.code != exitUsage || !strings.Contains(r.out, "a tombstone carries no attestation") {
			t.Fatalf("--tombstone %v must be a usage error, got exit %d:\n%s", extra, r.code, r.out)
		}
	}
}

// The same rule below the flag layer: doSubmit must not publish a public
// attestation next to a tombstone, even with a signature that verifies.
func TestTombstoneSubmitRefusesPublicAttestation(t *testing.T) {
	w := newWorld(t, 94)
	vpk, priv := validatorKey(t)
	o := backup.Options{ConfigPath: w.cfgPath, Key: w.key, Seq: 2, Tombstone: true, AttestPublicVPK: vpk}
	p, err := backup.Build(o)
	must(t, err)
	sig := ed25519Hex(priv, p.AttestPublicText)
	before := len(w.ledger.Txs)
	err = doSubmit(o, w.ledger, "fake", w.writer, t.TempDir(), 0, false, true, "off", vpk, sig, nil, nil, "", "", "")
	if err == nil || len(w.ledger.Txs) != before {
		t.Fatalf("a tombstone with a public attestation must be refused before anything is sent (err %v, %d new tx)", err, len(w.ledger.Txs)-before)
	}
}

// --tombstone --delete-anchor removes the DID from the ledger. The dump it
// writes is the offline restore source, so it must not keep the DID.
func TestDeleteAnchorUpdatesDump(t *testing.T) {
	w := newWorld(t, 95)
	out := t.TempDir()
	o := backup.Options{ConfigPath: w.cfgPath, ValidatorsPath: w.valPath, Key: w.key, Seq: 2, Supersedes: w.plan.Manifest.BackupID, Tombstone: true}
	must(t, doSubmit(o, w.ledger, "fake", w.writer, out, 0, true, true, "off", "", "", nil, nil, "", "", ""))
	if _, ok := w.ledger.DID[w.writer.Address()]; ok {
		t.Fatal("the ledger still has the DID")
	}
	files, _ := filepath.Glob(filepath.Join(out, "*.dump.json"))
	if len(files) != 1 {
		t.Fatalf("want one dump, got %v", files)
	}
	d, err := dump.Load(files[0])
	must(t, err)
	if d.DID != nil {
		t.Fatalf("the dump still carries a DID (%d hex chars) that the ledger deleted", len(d.DID.Data))
	}
	r := w.run("", "restore", "--dump", files[0], "--words-file", w.words, "--account", w.writer.Address())
	if !strings.Contains(r.out, "anchor:   none") {
		t.Fatalf("restore from that dump must report no anchor:\n%s", r.out)
	}
}

func ed25519Hex(priv ed25519.PrivateKey, msg string) string {
	return hex.EncodeToString(ed25519.Sign(priv, []byte(msg)))
}
