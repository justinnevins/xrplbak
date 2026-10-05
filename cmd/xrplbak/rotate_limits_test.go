package main

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/backup"
	"github.com/justinnevins/xrplbak/internal/crypto"
)

// A passphrase-wrapped key file asks for its passphrase on rotate. The new
// key file holds the same writer seed, so it must stay wrapped. It used to
// be written in plaintext unless --key-passphrase was given again.
func TestRotateKeepsKeyFileWrapped(t *testing.T) {
	w := newWorld(t, 81)
	d := t.TempDir()
	b, err := w.keyAt(0).EncodeWrapped([]byte("hunter2"))
	must(t, err)
	must(t, os.WriteFile(filepath.Join(d, "xrplbak.key"), b, 0o600))
	r := w.run("hunter2\n", "init", "--rotate", "--out", d, "--words-file", w.words)
	nb, _ := os.ReadFile(filepath.Join(d, "xrplbak.key"))
	if r.code != exitOK || !crypto.IsWrapped(nb) {
		t.Fatalf("rotate of a wrapped key file must keep it wrapped, got exit %d, wrapped %v:\n%s", r.code, crypto.IsWrapped(nb), r.out)
	}
	kf, err := crypto.DecodeKeyFile(nb, []byte("hunter2"))
	if err != nil || kf.Epoch != 1 || kf.Key != w.root.DeriveEpochKey(1) {
		t.Fatalf("the new key file must open with the same passphrase at epoch 1: %v", err)
	}
	if !strings.Contains(r.out, "same passphrase") {
		t.Fatalf("rotate must say the key file keeps its passphrase:\n%s", r.out)
	}
}

// Control: a plaintext key file rotated without --key-passphrase stays
// plaintext, as before.
func TestRotatePlainKeyFileStaysPlain(t *testing.T) {
	w := newWorld(t, 82)
	d := t.TempDir()
	must(t, os.WriteFile(filepath.Join(d, "xrplbak.key"), w.keyAt(0).Encode(), 0o600))
	r := w.run("", "init", "--rotate", "--out", d, "--words-file", w.words)
	nb, _ := os.ReadFile(filepath.Join(d, "xrplbak.key"))
	if r.code != exitOK || crypto.IsWrapped(nb) {
		t.Fatalf("plaintext rotate: exit %d, wrapped %v:\n%s", r.code, crypto.IsWrapped(nb), r.out)
	}
}

// The epoch is a uint32. Rotating past the last one wrapped to epoch 0,
// the first epoch key, which an old key file may still hold.
func TestRotateRefusesAtMaxEpoch(t *testing.T) {
	w := newWorld(t, 83)
	d := t.TempDir()
	path := filepath.Join(d, "xrplbak.key")
	before := w.keyAt(math.MaxUint32).Encode()
	must(t, os.WriteFile(path, before, 0o600))
	r := w.run("", "init", "--rotate", "--out", d, "--words-file", w.words)
	after, _ := os.ReadFile(path)
	if r.code != exitRefused || string(after) != string(before) {
		t.Fatalf("rotate at epoch %d must refuse with exit %d and leave the key file alone, got exit %d:\n%s", uint32(math.MaxUint32), exitRefused, r.code, r.out)
	}
	if _, err := os.Stat(path + ".epoch4294967295"); err == nil {
		t.Fatal("the key file was moved aside despite the refusal")
	}
}

// The seq is a uint32. A backup after seq 4294967295 got seq 0 and sorted
// below every older backup.
func TestNextSeqRefusesAtMaxSeq(t *testing.T) {
	w := newWorld(t, 84)
	w.postAt(w.key, math.MaxUint32, false)
	seq, _, _, err := backup.NextSeq(w.ledger, w.key, w.writer.Address())
	if err == nil {
		t.Fatalf("NextSeq after seq %d must refuse, got seq %d", uint32(math.MaxUint32), seq)
	}
	if !strings.Contains(err.Error(), "init --rotate") {
		t.Fatalf("the refusal must say how to go on (rotate to a new epoch): %v", err)
	}
	// The plan carries the same message, and the error stays an ErrLastSeq
	// so backup --submit refuses it even with --force-seq.
	o := backup.Options{ConfigPath: w.cfgPath, ValidatorsPath: w.valPath, Key: w.key}
	warns, err := bindPlan(&o, w.ledger, w.key, w.writer.Address())
	if !errors.Is(err, backup.ErrLastSeq) || len(warns) != 1 || !strings.Contains(warns[0], "init --rotate") || strings.Contains(warns[0], "assumes seq 1") {
		t.Fatalf("bindPlan must return ErrLastSeq with the rotate message, got err %v, warns %q", err, warns)
	}
}

// Rotate moves the old key file aside as xrplbak.key.epochN. If a file
// with that name was already there (a hand-saved copy, or a second rotate
// from a restored key file), it was replaced without a word. Rotate must
// never overwrite a file: it picks a free name and says which.
func TestRotateDoesNotOverwriteOldCopy(t *testing.T) {
	w := newWorld(t, 85)
	d := t.TempDir()
	path := filepath.Join(d, "xrplbak.key")
	oldKey := w.keyAt(0).Encode()
	must(t, os.WriteFile(path, oldKey, 0o600))
	saved := path + ".epoch0"
	must(t, os.WriteFile(saved, []byte("operator's own copy"), 0o600))
	r := w.run("", "init", "--rotate", "--out", d, "--words-file", w.words)
	if r.code != exitOK {
		t.Fatalf("rotate must still succeed, got exit %d:\n%s", r.code, r.out)
	}
	if got, _ := os.ReadFile(saved); string(got) != "operator's own copy" {
		t.Fatalf("%s was overwritten", saved)
	}
	moved := path + ".epoch0.2"
	if got, err := os.ReadFile(moved); err != nil || string(got) != string(oldKey) {
		t.Fatalf("the old key file must move to %s (err %v)", moved, err)
	}
	if !strings.Contains(r.out, "moved to "+moved) {
		t.Fatalf("rotate must name where the old key went:\n%s", r.out)
	}
	nb, _ := os.ReadFile(path)
	if kf, err := crypto.DecodeKeyFile(nb, nil); err != nil || kf.Epoch != 1 {
		t.Fatalf("the new key file must be epoch 1: %v", err)
	}
}
