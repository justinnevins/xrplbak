package backup

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/crypto"
)

// Backup reads a validator host's files and stores their POSIX paths. On
// Windows it cannot. It must refuse, and say so in those words: the old
// message blamed the file's name and told the operator to rename it.
func TestBackupOnWindowsSaysWhereItRuns(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	cfgPath := filepath.Join(t.TempDir(), "xrpld.cfg")
	if err := os.WriteFile(cfgPath, []byte("[server]\nport_rpc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var root crypto.RootKey
	kf := &crypto.KeyFile{Epoch: 0, Key: root.DeriveEpochKey(0)}
	_, err := Build(Options{ConfigPath: cfgPath, Key: kf, Seq: 1, Now: time.Unix(1, 0)})
	if err == nil {
		t.Fatal("Build accepted a Windows path")
	}
	if !strings.Contains(err.Error(), "does not run on Windows") || strings.Contains(err.Error(), "Rename the file") {
		t.Errorf("the refusal does not say backup runs on the validator host only: %v", err)
	}
}
