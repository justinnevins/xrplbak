package main

import (
	"os"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/backup"
	"github.com/justinnevins/xrplbak/internal/testsupport/fake"
)

// editingLedger changes a file on disk at the first submit, the way an
// operator editing the config during a backup would.
type editingLedger struct {
	*fake.Ledger
	path string
	done bool
}

func (l *editingLedger) Submit(blob []byte) (string, error) {
	if !l.done {
		l.done = true
		f, err := os.OpenFile(l.path, os.O_APPEND|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = f.WriteString("\n# edited during the backup\n")
			_ = f.Close()
		}
	}
	return l.Ledger.Submit(blob)
}

// TestReadBackWarnsWhenAFileChangedOnDisk pins the warning after a passing
// read-back: the backup holds the file as it was read, and the operator
// is told the file on disk has moved on.
func TestReadBackWarnsWhenAFileChangedOnDisk(t *testing.T) {
	noSleep(t)
	w := newWorld(t, 54)
	w.ledger.Batch = true
	o := backup.Options{ConfigPath: w.cfgPath, ValidatorsPath: w.valPath, Key: w.key, Seq: 2}
	out, err := captureStdout(t, func() error {
		return doSubmit(o, &editingLedger{Ledger: w.ledger, path: w.cfgPath}, "fake", w.writer, t.TempDir(), 0, false, true, "auto", "", "", nil, nil, "", "testnet", w.keyFile, submitExtras{ReadBack: true})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "read-back: PASS") || !strings.Contains(out, "WARNING: "+w.cfgPath+" changed on disk after the backup read it") {
		t.Fatalf("no changed-file warning after the read-back:\n%s", out)
	}
}
