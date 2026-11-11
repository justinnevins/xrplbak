package main

import (
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/container"
	"github.com/justinnevins/xrplbak/internal/testsupport/fake"
)

// F-080: verify fetched and authenticated the chunks and printed "on-chain
// data: complete", but never built the restore. A backup that restore
// refuses (an unsafe path in the manifest, a file the manifest does not
// list, one path twice) verified with exit 0. verify now runs the same
// build restore runs, and fails the way restore fails.
func TestF080VerifyRefusesWhatRestoreRefuses(t *testing.T) {
	for _, path := range []string{"../../../etc/xrplbak-escape.cfg", "/etc/xrpld/x\x1by.cfg", "relative.cfg"} {
		w := newWorld(t, 7)
		w.hostilePaths(path)
		dump := w.dumpFile("v")
		for name, extra := range map[string][]string{"with the bundle": {"--bundle", w.bundle}, "without the bundle": nil} {
			args := append([]string{"--dump", dump, "--words-file", w.words, "--account", w.writer.Address()}, extra...)
			rs := w.run("", append([]string{"restore"}, args...)...)
			rv := w.run("", append([]string{"verify"}, args...)...)
			if rs.code != exitRefused {
				t.Fatalf("setup, %q %s: restore exit %d, want %d", path, name, rs.code, exitRefused)
			}
			if rv.code != rs.code {
				t.Errorf("%q %s: verify exit %d, restore exit %d\n%s", path, name, rv.code, rs.code, rv.out)
			}
		}
	}
}

// A good backup still verifies, and verify says what the restore check
// covered: every byte with the bundle, acceptance only without it.
func TestF080VerifyReportsTheRestoreCheck(t *testing.T) {
	w := newWorld(t, 7)
	dump := w.dumpFile("v")
	base := []string{"verify", "--dump", dump, "--words-file", w.words, "--account", w.writer.Address()}
	with := w.run("", append(base, "--bundle", w.bundle)...)
	if with.code != 0 || !strings.Contains(with.out, "restore check: every file rebuilds to its backed-up bytes") {
		t.Fatalf("with the bundle: exit %d\n%s", with.code, with.out)
	}
	without := w.run("", base...)
	if without.code != 0 || !strings.Contains(without.out, "restore check: restore accepts this backup") {
		t.Fatalf("without the bundle: exit %d\n%s", without.code, without.out)
	}
	if strings.Contains(without.out, "every file rebuilds") {
		t.Fatalf("without the bundle verify claimed a byte check:\n%s", without.out)
	}
}

// A file the manifest stores wholly on-chain must rebuild to the hash the
// manifest names, bundle or no bundle. A backup where it does not is
// incomplete, and verify says so.
func TestF080VerifyFailsWhenAnOnChainFileDoesNotRebuild(t *testing.T) {
	w := newWorld(t, 7)
	w.ledger = fake.New()
	w.ledger.Fund(w.writer.Address(), 5_000_000)
	p := w.resealOnChain([]container.Entry{{Path: "/etc/xrpld/extra.cfg", Mode: 0o600, Data: []byte("[server]\nport_rpc\n")}})
	p.Manifest.Files[0].SHA256 = strings.Repeat("0", 64)
	w.plan = p
	w.submit(p)
	rv := w.run("", "verify", "--dump", w.dumpFile("v"), "--words-file", w.words, "--account", w.writer.Address())
	if rv.code != exitIncomplete || !strings.Contains(rv.out, "does not rebuild to the backed-up bytes") {
		t.Fatalf("verify exit %d, want %d\n%s", rv.code, exitIncomplete, rv.out)
	}
}
