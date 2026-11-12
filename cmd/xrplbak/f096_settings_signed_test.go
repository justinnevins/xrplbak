package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F-096. xrplbak.settings could turn comments or fixed peers on-chain with
// no typed phrase: anyone who could write the key file's directory could
// write the file, without reading the key. A setting from a file that
// xrplbak did not sign with this key file now asks for the phrase again.
// Stdin is empty, so a run that asks fails with the not-confirmed error.
func TestF096HandEditedOnchainAsksAgain(t *testing.T) {
	for _, tc := range []struct{ line, phrase, flag string }{
		{"comments=onchain\n", "Type " + ackPhrase, "--comments=onchain was not confirmed"},
		{"peers=onchain\n", "Type " + peersAckPhrase, "--peers=onchain was not confirmed"},
	} {
		w := newWorld(t, 70)
		sp := filepath.Join(filepath.Dir(w.keyFile), settingsName)
		must(t, os.WriteFile(sp, []byte(tc.line), 0o600))
		r := w.run("", "backup", "--config", w.cfgPath, "--key", w.keyFile, "--out", t.TempDir())
		if r.code != exitUsage || !strings.Contains(r.out, tc.phrase) || !strings.Contains(r.out, tc.flag) {
			t.Errorf("%q from a hand-written file: exit %d, want %d after asking for the phrase\n%s", strings.TrimSpace(tc.line), r.code, exitUsage, r.out)
		}
	}
}

// F-096. A file this tool signed is trusted only as written: changing any
// setting after signing breaks the sig, and the phrase is asked again. A
// sig made with another key file does not verify either.
func TestF096EditedOrForeignSignedFileAsksAgain(t *testing.T) {
	w := newWorld(t, 71)
	sp := filepath.Join(filepath.Dir(w.keyFile), settingsName)
	other := newWorld(t, 72)
	for name, write := range map[string]func(){
		"edited after signing": func() {
			must(t, saveSettings(sp, settings{Comments: "bundle", Peers: "onchain"}, w.key.WriterSeed[:]))
			raw, err := os.ReadFile(sp)
			must(t, err)
			must(t, os.WriteFile(sp, []byte(strings.Replace(string(raw), "comments=bundle", "comments=onchain", 1)), 0o600))
		},
		"signed by another key file": func() {
			must(t, saveSettings(sp, settings{Comments: "onchain"}, other.key.WriterSeed[:]))
		},
	} {
		write()
		r := w.run("", "backup", "--config", w.cfgPath, "--key", w.keyFile, "--out", t.TempDir())
		if r.code != exitUsage || !strings.Contains(r.out, "Type "+ackPhrase) || !strings.Contains(r.out, "is not signed by this key file") {
			t.Errorf("%s: exit %d, want %d after asking for the phrase\n%s", name, r.code, exitUsage, r.out)
		}
	}
}

// F-096. --save writes the sig, and a parse of the saved file still reads
// back the same settings.
func TestF096SaveSigns(t *testing.T) {
	w := newWorld(t, 73)
	sp := filepath.Join(t.TempDir(), settingsName)
	want := settings{RPC: "testnet", MaxFee: 100, Comments: "onchain", Peers: "bundle"}
	must(t, saveSettings(sp, want, w.key.WriterSeed[:]))
	raw, err := os.ReadFile(sp)
	must(t, err)
	got, err := parseSettings(string(raw))
	if err != nil || *got != want {
		t.Fatalf("read back %+v (%v), want %+v", got, err, want)
	}
	if !settingsSigned(string(raw), *got, w.key.WriterSeed[:]) {
		t.Fatalf("the saved file does not verify:\n%s", raw)
	}
}
