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
