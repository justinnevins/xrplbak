package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/backup"
	"github.com/justinnevins/xrplbak/internal/chunk"
	"github.com/justinnevins/xrplbak/internal/xrpl"
	"github.com/justinnevins/xrplbak/internal/xrpl/codec"
)

// A manifest above the discovery cap must never reach the ledger: discovery
// would ignore it, and every later command would report the previous backup
// as the newest, exit 0. Before the fix Build accepted this plan.
func TestBackupRefusesManifestOverPartLimit(t *testing.T) {
	w := newWorld(t, 11)
	var incs []string
	for i := 0; i < 150; i++ {
		p := filepath.Join(w.dir, fmt.Sprintf("extra-file-with-a-fairly-long-descriptive-name-%04d.conf", i))
		must(t, os.WriteFile(p, []byte(fmt.Sprintf("v=%d\n", i)), 0o600))
		incs = append(incs, p)
	}
	_, err := backup.Build(backup.Options{ConfigPath: w.cfgPath, ValidatorsPath: w.valPath, Includes: incs, Key: w.key, Seq: 2})
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("the limit is %d", chunk.MaxManifestParts)) {
		t.Fatalf("Build accepted a manifest above %d parts: err=%v", chunk.MaxManifestParts, err)
	}

	args := []string{"backup", "--config", w.cfgPath, "--validators", w.valPath, "--key", w.keyFile}
	for _, inc := range incs {
		args = append(args, "--include", inc)
	}
	before := len(w.ledger.Txs)
	r := w.run("", args...)
	if r.code != exitUsage || !strings.Contains(r.out, "--include") {
		t.Fatalf("CLI backup exit=%d, want %d with advice on --include", r.code, exitUsage)
	}
	if len(w.ledger.Txs) != before || strings.Contains(r.out, "Done") {
		t.Fatalf("nothing may be published on a refusal")
	}
}

// Just under the cap still builds, so the refusal is the cap and not an
// earlier limit.
func TestBackupAcceptsManifestAtPartLimit(t *testing.T) {
	w := newWorld(t, 12)
	var incs []string
	for i := 0; i < 60; i++ {
		p := filepath.Join(w.dir, fmt.Sprintf("f%02d.conf", i))
		must(t, os.WriteFile(p, []byte("v=1\n"), 0o600))
		incs = append(incs, p)
	}
	p, err := backup.Build(backup.Options{ConfigPath: w.cfgPath, ValidatorsPath: w.valPath, Includes: incs, Key: w.key, Seq: 2})
	must(t, err)
	w.plan = p
	w.submit(p)
	r := w.run("", "verify", "--dump", w.dumpFile("v"), "--words-file", w.words, "--account", w.writer.Address())
	if r.code != exitOK || !strings.Contains(r.out, "* epoch 0 seq 2") {
		t.Fatalf("verify exit=%d, want 0 selecting seq 2", r.code)
	}
}

// A manifest part on the ledger with a Total above the cap is counted as
// rejected and named in a warning, not dropped in silence. Before the fix
// verify printed "0 rejected" and no warning.
func TestDiscoverWarnsOnOversizedManifest(t *testing.T) {
	w := newWorld(t, 13)
	var id [16]byte
	for i := range id {
		id[i] = byte(0x40 + i)
	}
	nonce := []byte("0123456789")
	memo, err := chunk.Encode(chunk.TypeManifest, id[:], 0, chunk.MaxManifestParts+1, nonce, []byte("junk ciphertext that never opens"))
	must(t, err)
	w.ledger.Seq++
	w.ledger.Txs = append(w.ledger.Txs, xrpl.TxRecord{
		Hash:        strings.Repeat("AB", 32),
		LedgerIndex: w.ledger.Seq,
		Validated:   true,
		Result:      "tesSUCCESS",
		Account:     w.writer.Address(),
		TxType:      "AccountSet",
		Sequence:    99,
		Memos:       []codec.Memo{memo},
	})
	r := w.run("", "verify", "--dump", w.dumpFile("v"), "--words-file", w.words, "--account", w.writer.Address())
	if r.code != exitOK || !strings.Contains(r.out, "* epoch 0 seq 1") {
		t.Fatalf("verify exit=%d, want 0 still selecting seq 1", r.code)
	}
	if !strings.Contains(r.out, "1 authenticated, 1 rejected") {
		t.Fatalf("oversized manifest not counted as rejected")
	}
	if !strings.Contains(r.out, fmt.Sprintf("%d parts, above the limit of %d", chunk.MaxManifestParts+1, chunk.MaxManifestParts)) {
		t.Fatalf("no warning names the oversized manifest")
	}
}
