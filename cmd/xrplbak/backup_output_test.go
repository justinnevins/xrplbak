package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/backup"
	"github.com/justinnevins/xrplbak/internal/pubattest"
)

// TestDryRunShowsTeamAttestationOnlyWhenAsked pins that the plan does not
// print the team attestation string to every operator. It once appeared in
// every dry run, beside the public attestation an operator had asked for,
// and read as a step they had to take. --attestation-key on a dry run
// still prints the string to sign.
func TestDryRunShowsTeamAttestationOnlyWhenAsked(t *testing.T) {
	w := newWorld(t, 7)
	vpk, _ := validatorKey(t)
	plain := w.run("", "backup", "--config", w.cfgPath, "--key", w.keyFile, "--out", t.TempDir())
	if plain.code != exitOK {
		t.Fatalf("dry run: exit %d", plain.code)
	}
	if strings.Contains(plain.out, "team setups") || strings.Contains(plain.out, "xrplbak/v1/attest ") {
		t.Errorf("a plain dry run prints the team attestation:\n%s", plain.out)
	}
	asked := w.run("", "backup", "--config", w.cfgPath, "--key", w.keyFile, "--out", t.TempDir(), "--attestation-key", vpk)
	if asked.code != exitOK || !strings.Contains(asked.out, "xrplbak/v1/attest ") {
		t.Errorf("a dry run with --attestation-key must print the string to sign: exit %d\n%s", asked.code, asked.out)
	}
}

// TestSubmitSaysWhatItPublished pins that a submit with --attest names
// the attestation it published, and that the closing verify hint is a
// command that works as printed: the network as the operator gave it, the
// key file, and the bundle.
func TestSubmitSaysWhatItPublished(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	w := newWorld(t, 8)
	w.ledger.Batch = true
	vpk, master := validatorKey(t)
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	k := &attestKey{VPK: vpk, DSeq: 1, Priv: priv}
	sig := hex.EncodeToString(ed25519.Sign(master, []byte(pubattest.DelegationString(vpk, w.writer.Address(), k.pub(), 1))))
	var buf bytes.Buffer
	old := stdout
	stdout = io.Writer(&buf)
	defer func() { stdout = old }()
	o := backup.Options{ConfigPath: w.cfgPath, ValidatorsPath: w.valPath, Key: w.key, Seq: 2}
	out := t.TempDir()
	if err := doSubmit(o, w.ledger, "https://example.test:51234", w.writer, out, 0, false, true, "auto", "", "", nil, k, sig, "testnet", w.keyFile); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{
		"delegation:     published for attestation key 1",
		"attestation:    published, signed by delegated attestation key 1",
		"verify anytime: xrplbak verify --rpc testnet --key " + w.keyFile + " --bundle " + out + "/",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
}
