package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/chunk"
	"github.com/justinnevins/xrplbak/internal/xrpl"
	"github.com/justinnevins/xrplbak/internal/xrpl/codec"
)

// A junk memo that copies a real manifest's id and nonce with another
// part count hid the real manifest when the server listed the junk first.
// The order a server or a dump lists transactions in must not decide.
func TestJunkPartCountCannotHideAManifest(t *testing.T) {
	var outs []result
	for _, first := range []bool{false, true} {
		w := newWorld(t, 73)
		var real *xrpl.TxRecord
		var pl chunk.Payload
		for i := range w.ledger.Txs {
			for _, m := range w.ledger.Txs[i].Memos {
				if p, ok := chunk.Decode(m); ok && p.Type == chunk.TypeManifest {
					real, pl = &w.ledger.Txs[i], p
				}
			}
		}
		if real == nil {
			t.Fatal("no manifest transaction")
		}
		junkMemo, err := chunk.Encode(chunk.TypeManifest, pl.BackupID[:], 0, pl.Total+1, pl.Nonce[:], make([]byte, 40))
		must(t, err)
		junk := *real
		junk.Hash = "DEADBEEF00000000000000000000000000000000000000000000000000000001"
		junk.Memos = []codec.Memo{junkMemo}
		if first {
			w.ledger.Txs = append([]xrpl.TxRecord{junk}, w.ledger.Txs...)
		} else {
			w.ledger.Txs = append(w.ledger.Txs, junk)
		}
		w.dropAnchor()
		outs = append(outs, w.restoreWords())
	}
	if outs[0].code != exitOK {
		t.Fatalf("junk listed last: exit %d\n%s", outs[0].code, outs[0].out)
	}
	if outs[1].code != exitOK {
		t.Errorf("junk listed first hid the backup: exit %d\n%s", outs[1].code, outs[1].out)
	}
}

// A damaged dump file for this backup was ignored without a word, and
// the run started over and overwrote it.
func TestResumeRefusesADamagedDump(t *testing.T) {
	dir := t.TempDir()
	id := strings.Repeat("ab", 16)
	p := filepath.Join(dir, id+".dump.json")
	if d, err := loadResume(p, id); d != nil || err != nil {
		t.Fatalf("no file: %v %v", d, err)
	}
	for name, body := range map[string]string{
		"cut off":           `{"v":1,"backup_id":"` + id + `","txs":[{"hash":"AA","tx_js`,
		"empty":             ``,
		"another backup id": `{"v":1,"backup_id":"` + strings.Repeat("cd", 16) + `","txs":[]}`,
	} {
		must(t, os.WriteFile(p, []byte(body), 0o600))
		d, err := loadResume(p, id)
		if err == nil {
			t.Errorf("%s: no error (dump %v)", name, d != nil)
			continue
		}
		if !strings.Contains(err.Error(), p) {
			t.Errorf("%s: the error does not name the file: %v", name, err)
		}
	}
}

// The settings file can turn on-chain publishing on without the typed
// phrase. It is honoured only when nobody but its owner can write it.
func TestSettingsFileOthersCanWriteIsRefused(t *testing.T) {
	w := newWorld(t, 41)
	sp := filepath.Join(filepath.Dir(w.keyFile), settingsName)
	must(t, os.WriteFile(sp, []byte("comments=onchain\n"), 0o600))
	for _, mode := range []os.FileMode{0o620, 0o602, 0o666} {
		must(t, os.Chmod(sp, mode))
		r := w.run("", "backup", "--config", w.cfgPath, "--key", w.keyFile, "--out", t.TempDir())
		if r.code == exitOK || strings.Contains(r.out, "comments: on-chain") {
			t.Errorf("mode %o: the settings file was used (exit %d)", mode, r.code)
		}
		if !strings.Contains(r.out, sp) {
			t.Errorf("mode %o: the message does not name the file:\n%s", mode, r.out)
		}
	}
	must(t, os.Chmod(sp, 0o600))
	if r := w.run("", "backup", "--config", w.cfgPath, "--key", w.keyFile, "--out", t.TempDir()); r.code != exitOK {
		t.Errorf("mode 600: exit %d\n%s", r.code, r.out)
	}
}
