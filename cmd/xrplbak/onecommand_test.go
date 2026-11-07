package main

// v1.1.7: one-command backup. A routine backup on the 2026-11-07 Mainnet run
// took twelve operator steps: the same four flags and two typed phrases on
// every run, a fee spike that ended the run, then verify, restore, a hash
// compare and a cleanup to prove the bytes read back. These tests pin the
// three changes that fold that into one command: saved settings, the
// read-back check after submit, and the copy hint.

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/backup"
	"github.com/justinnevins/xrplbak/internal/xrpl"
	"github.com/justinnevins/xrplbak/internal/xrpl/fake"
)

// captureStdout runs f with stdout sent to a buffer.
func captureStdout(t *testing.T, f func() error) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	old := stdout
	stdout = io.Writer(&buf)
	defer func() { stdout = old }()
	err := f()
	return buf.String(), err
}

// noSleep makes the read-back poll instant for the test.
func noSleep(t *testing.T) {
	t.Helper()
	old := submitSleep
	submitSleep = func(time.Duration) {}
	t.Cleanup(func() { submitSleep = old })
}

func TestSettingsParseRoundTrip(t *testing.T) {
	in := settings{RPC: "mainnet", MaxFee: 100, Comments: "onchain", Peers: "onchain"}
	got, err := parseSettings(in.render())
	if err != nil {
		t.Fatal(err)
	}
	if *got != in {
		t.Fatalf("round trip: got %+v want %+v", *got, in)
	}
	got, err = parseSettings("# a comment\n\nrpc = testnet\n")
	if err != nil || got.RPC != "testnet" || got.MaxFee != 0 || got.Comments != "" {
		t.Fatalf("partial file: %+v %v", got, err)
	}
}

// TestSettingsRefuseWhatTheyDoNotKnow pins fail closed: a key or value the
// tool does not know is refused, never skipped. A typo in "comments" must
// not quietly fall back to a different choice than the operator wrote.
func TestSettingsRefuseWhatTheyDoNotKnow(t *testing.T) {
	for _, bad := range []string{
		"coments=onchain\n",
		"comments=yes\n",
		"peers=public\n",
		"max-fee=lots\n",
		"max-fee=0\n",
		"rpc=ftp://example.test\n",
		"rpc\n",
		"rpc=mainnet\nrpc=testnet\n",
	} {
		if _, err := parseSettings(bad); err == nil {
			t.Errorf("%q: accepted, want refused", bad)
		}
	}
}

// TestSavedOnchainNeedsNoPhrase pins that a saved on-chain choice is used
// without the typed phrase, and says so on its own line. Stdin is empty: if
// the tool asked, the run would fail.
func TestSavedOnchainNeedsNoPhrase(t *testing.T) {
	w := newWorld(t, 41)
	sp := filepath.Join(filepath.Dir(w.keyFile), settingsName)
	must(t, os.WriteFile(sp, []byte("comments=onchain\npeers=onchain\n"), 0o600))
	r := w.run("", "backup", "--config", w.cfgPath, "--key", w.keyFile, "--out", t.TempDir())
	if r.code != exitOK {
		t.Fatalf("dry run with saved settings: exit %d", r.code)
	}
	for _, want := range []string{"comments: on-chain (saved in " + sp + ")", "peers: on-chain (saved in " + sp + ")"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if strings.Contains(r.out, "Type PUBLISH") {
		t.Error("a saved choice must not ask for the phrase again")
	}
}

// TestFlagBeatsSettings pins that a flag on the command line wins, and that
// --no-settings ignores the file.
func TestFlagBeatsSettings(t *testing.T) {
	w := newWorld(t, 42)
	sp := filepath.Join(filepath.Dir(w.keyFile), settingsName)
	must(t, os.WriteFile(sp, []byte("comments=onchain\n"), 0o600))
	for _, extra := range [][]string{{"--comments", "bundle"}, {"--no-settings"}} {
		args := append([]string{"backup", "--config", w.cfgPath, "--key", w.keyFile, "--out", t.TempDir()}, extra...)
		r := w.run("", args...)
		if r.code != exitOK {
			t.Fatalf("%v: exit %d", extra, r.code)
		}
		if strings.Contains(r.out, "comments: on-chain") {
			t.Errorf("%v: the saved choice was used", extra)
		}
	}
}

// TestBadSettingsFileRefuses pins that a broken settings file stops the run
// with its path named, rather than being skipped.
func TestBadSettingsFileRefuses(t *testing.T) {
	w := newWorld(t, 43)
	sp := filepath.Join(filepath.Dir(w.keyFile), settingsName)
	must(t, os.WriteFile(sp, []byte("comments=maybe\n"), 0o600))
	r := w.run("", "backup", "--config", w.cfgPath, "--key", w.keyFile, "--out", t.TempDir())
	if r.code != exitUsage || !strings.Contains(r.out, sp) {
		t.Fatalf("want exit %d naming %s, got exit %d", exitUsage, sp, r.code)
	}
}

func TestSaveNeedsSubmit(t *testing.T) {
	w := newWorld(t, 44)
	r := w.run("", "backup", "--config", w.cfgPath, "--key", w.keyFile, "--out", t.TempDir(), "--save")
	if r.code != exitUsage || !strings.Contains(r.out, "--save needs --submit") {
		t.Fatalf("--save on a dry run: exit %d, want %d and the reason", r.code, exitUsage)
	}
}

func TestFeeWaitFlagRefusesNegative(t *testing.T) {
	w := newWorld(t, 45)
	r := w.run("", "backup", "--config", w.cfgPath, "--key", w.keyFile, "--out", t.TempDir(), "--fee-wait", "-1m")
	if r.code != exitUsage || !strings.Contains(r.out, "--fee-wait must be zero or more") {
		t.Fatalf("--fee-wait -1m: exit %d, want %d and the reason", r.code, exitUsage)
	}
}

// TestSubmitSavesSettings pins that --save writes the choices beside the key
// file, owner-only, after the backup landed.
func TestSubmitSavesSettings(t *testing.T) {
	noSleep(t)
	w := newWorld(t, 46)
	w.ledger.Batch = true
	sp := filepath.Join(t.TempDir(), settingsName)
	want := settings{RPC: "testnet", MaxFee: 100, Comments: "onchain", Peers: "bundle"}
	o := backup.Options{ConfigPath: w.cfgPath, ValidatorsPath: w.valPath, Key: w.key, Seq: 2}
	out, err := captureStdout(t, func() error {
		return doSubmit(o, w.ledger, "fake", w.writer, t.TempDir(), 0, false, true, "auto", "", "", nil, nil, "", "testnet", w.keyFile,
			submitExtras{Save: true, SettingsPath: sp, Settings: want})
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(sp)
	if err != nil {
		t.Fatalf("settings not written: %v\n%s", err, out)
	}
	got, err := parseSettings(string(raw))
	if err != nil || *got != want {
		t.Fatalf("saved %+v (%v), want %+v", got, err, want)
	}
	if fi, _ := os.Stat(sp); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", fi.Mode().Perm())
	}
	if !strings.Contains(out, "settings saved: "+sp) {
		t.Errorf("output does not name the saved file:\n%s", out)
	}
}

// TestSaveHintOnlyWhenUseful pins that the hint to add --save appears when a
// run used non-default choices that are not saved, and not otherwise.
func TestSaveHintOnlyWhenUseful(t *testing.T) {
	noSleep(t)
	for _, tc := range []struct {
		name string
		x    submitExtras
		want bool
	}{
		{"custom, unsaved", submitExtras{Settings: settings{RPC: "testnet", MaxFee: 100}}, true},
		{"all defaults", submitExtras{Settings: settings{RPC: "testnet"}}, false},
		{"already saved", submitExtras{SettingsExist: true, Settings: settings{RPC: "testnet", MaxFee: 100}}, false},
	} {
		w := newWorld(t, 47)
		o := backup.Options{ConfigPath: w.cfgPath, ValidatorsPath: w.valPath, Key: w.key, Seq: 2}
		out, err := captureStdout(t, func() error {
			return doSubmit(o, w.ledger, "fake", w.writer, t.TempDir(), 0, false, true, "off", "", "", nil, nil, "", "testnet", w.keyFile, tc.x)
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(out, "add --save"); got != tc.want {
			t.Errorf("%s: hint shown = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestReadBackPasses pins the read-back after submit: the backup is found on
// the ledger, every file rebuilds to the backed-up bytes, and the run says
// PASS, for both submit paths.
func TestReadBackPasses(t *testing.T) {
	noSleep(t)
	for _, batch := range []string{"auto", "off"} {
		w := newWorld(t, 48)
		w.ledger.Batch = true
		o := backup.Options{ConfigPath: w.cfgPath, ValidatorsPath: w.valPath, Key: w.key, Seq: 2}
		out, err := captureStdout(t, func() error {
			return doSubmit(o, w.ledger, "fake", w.writer, t.TempDir(), 0, false, true, batch, "", "", nil, nil, "", "testnet", w.keyFile, submitExtras{ReadBack: true})
		})
		if err != nil {
			t.Fatalf("batch=%s: %v\n%s", batch, err, out)
		}
		if !strings.Contains(out, "read-back: PASS, 2 file(s) byte-identical") {
			t.Errorf("batch=%s: no PASS line:\n%s", batch, out)
		}
	}
}

// laggyLedger answers account_tx from before the submit for the first lag
// calls, the way a server behind the one that took the transaction does.
type laggyLedger struct {
	*fake.Ledger
	before, lag int
}

func (l *laggyLedger) AccountTx(account string) ([]xrpl.TxRecord, xrpl.Range, error) {
	if l.lag > 0 {
		l.lag--
		saved := l.Ledger.Txs
		l.Ledger.Txs = saved[:l.before]
		defer func() { l.Ledger.Txs = saved }()
	}
	return l.Ledger.AccountTx(account)
}

func TestReadBackWaitsForALaggingServer(t *testing.T) {
	noSleep(t)
	w := newWorld(t, 49)
	w.ledger.Batch = true
	lag := &laggyLedger{Ledger: w.ledger, before: len(w.ledger.Txs), lag: 3}
	o := backup.Options{ConfigPath: w.cfgPath, ValidatorsPath: w.valPath, Key: w.key, Seq: 2}
	out, err := captureStdout(t, func() error {
		return doSubmit(o, lag, "fake", w.writer, t.TempDir(), 0, false, true, "auto", "", "", nil, nil, "", "testnet", w.keyFile, submitExtras{ReadBack: true})
	})
	if err != nil || !strings.Contains(out, "read-back: PASS") {
		t.Fatalf("a lagging server must be waited for: %v\n%s", err, out)
	}
}

// TestReadBackNeverFindsIt pins "did not finish": a server that never shows
// the new backup ends with exit 2 and no PASS line.
func TestReadBackNeverFindsIt(t *testing.T) {
	noSleep(t)
	w := newWorld(t, 50)
	w.ledger.Batch = true
	lag := &laggyLedger{Ledger: w.ledger, before: len(w.ledger.Txs), lag: 1 << 30}
	o := backup.Options{ConfigPath: w.cfgPath, ValidatorsPath: w.valPath, Key: w.key, Seq: 2}
	out, err := captureStdout(t, func() error {
		return doSubmit(o, lag, "fake", w.writer, t.TempDir(), 0, false, true, "auto", "", "", nil, nil, "", "testnet", w.keyFile, submitExtras{ReadBack: true})
	})
	if exitCode(err) != exitNetwork || strings.Contains(out, "PASS") {
		t.Fatalf("want exit %d and no PASS, got exit %d (%v)\n%s", exitNetwork, exitCode(err), err, out)
	}
	if !strings.Contains(err.Error(), "xrplbak verify") {
		t.Errorf("the error must name the command to finish the check: %v", err)
	}
}

// holeyLedger hides one transaction of the new backup from every read once
// the read-back starts (the first account_tx call), as if a chunk had never
// landed. Submit itself never reads account_tx.
type holeyLedger struct {
	*fake.Ledger
	before int
	hidden string
}

func (l *holeyLedger) pick() {
	if l.hidden != "" {
		return
	}
	for _, t := range l.Ledger.Txs[l.before:] {
		if t.TxType == "AccountSet" {
			l.hidden = t.Hash
			return
		}
	}
}

func (l *holeyLedger) AccountTx(account string) ([]xrpl.TxRecord, xrpl.Range, error) {
	l.pick()
	txs, rng, err := l.Ledger.AccountTx(account)
	var out []xrpl.TxRecord
	for _, t := range txs {
		if t.Hash != l.hidden {
			out = append(out, t)
		}
	}
	return out, rng, err
}

func (l *holeyLedger) Tx(hash string) (*xrpl.TxRecord, error) {
	if l.hidden != "" && strings.EqualFold(hash, l.hidden) {
		return nil, xrpl.ErrNotFound
	}
	return l.Ledger.Tx(hash)
}

// TestReadBackCatchesAMissingChunk pins the fail outcome: when the ledger
// does not hold every piece, the run must not say PASS. A missing chunk is
// exit 5; a missing manifest part leaves the backup unfound, exit 2.
func TestReadBackCatchesAMissingChunk(t *testing.T) {
	noSleep(t)
	w := newWorld(t, 51)
	w.ledger.Batch = true
	holey := &holeyLedger{Ledger: w.ledger, before: len(w.ledger.Txs)}
	o := backup.Options{ConfigPath: w.cfgPath, ValidatorsPath: w.valPath, Key: w.key, Seq: 2}
	out, err := captureStdout(t, func() error {
		return doSubmit(o, holey, "fake", w.writer, t.TempDir(), 0, false, true, "auto", "", "", nil, nil, "", "testnet", w.keyFile, submitExtras{ReadBack: true})
	})
	if err == nil || strings.Contains(out, "PASS") {
		t.Fatalf("a hole in the backup must fail the read-back:\n%s", out)
	}
	if c := exitCode(err); c != exitIncomplete {
		t.Errorf("exit %d (%v), want %d", c, err, exitIncomplete)
	}
}

// TestDoneNamesTheFilesToCopy pins the copy hint: absolute paths and the
// sha256 of the bundle and the dump, so the operator can check the copies.
func TestDoneNamesTheFilesToCopy(t *testing.T) {
	noSleep(t)
	w := newWorld(t, 52)
	w.ledger.Batch = true
	dir := t.TempDir()
	o := backup.Options{ConfigPath: w.cfgPath, ValidatorsPath: w.valPath, Key: w.key, Seq: 2}
	out, err := captureStdout(t, func() error {
		return doSubmit(o, w.ledger, "fake", w.writer, dir, 0, false, true, "auto", "", "", nil, nil, "", "testnet", w.keyFile, submitExtras{})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "copy both files off this host now") {
		t.Errorf("no copy line:\n%s", out)
	}
	for _, ext := range []string{".bundle", ".dump.json"} {
		matches, _ := filepath.Glob(filepath.Join(dir, "*"+ext))
		if len(matches) != 1 {
			t.Fatalf("%s: %d files", ext, len(matches))
		}
		raw, _ := os.ReadFile(matches[0])
		if !strings.Contains(out, sha256hex(raw)+"  "+matches[0]) {
			t.Errorf("no sha256 line for %s:\n%s", matches[0], out)
		}
	}
}
