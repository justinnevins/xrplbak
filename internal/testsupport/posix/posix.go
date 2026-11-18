// Package posix is test support. Nothing in the xrplbak binary imports it.
package posix

import (
	"runtime"
	"testing"
)

// Need skips a test that builds a backup from files on this machine. A
// backup stores each file's absolute path and accepts only the POSIX form
// (/etc/xrpld/xrpld.cfg), because that is what a validator host has and
// what restore checks. A Windows path is refused, so on Windows these
// tests have nothing to run. The Windows build restores and verifies;
// tests of that read a recorded backup instead.
func Need(t testing.TB) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("builds a backup from local files; backup takes POSIX paths only and does not run on Windows")
	}
}

// NeedModes skips a test that asserts Unix permission bits on a written
// file. Windows keeps a read-only flag and nothing else.
func NeedModes(t testing.TB) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("asserts Unix file modes; Windows does not keep them")
	}
}
