package main

import (
	"os"
	"strings"
	"testing"
)

// The third cold-read evaluation was the first with a two-file backup
// (xrpld.cfg plus validators.txt) at a real path. Three things it tripped
// over are pinned here.

// todoLines returns the "Before starting the server" items of a report.
func todoLines(out string) []string {
	var lines []string
	in := false
	for _, l := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(l, "== Before starting"):
			in = true
		case strings.HasPrefix(l, "== "):
			in = false
		case in && strings.TrimSpace(l) != "":
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	return lines
}

// TestTodoNamesTheFileWhenTheBackupHasTwo pins F-034. With two files the
// todo list was one flat list: "Re-enter the lines before the first stanza"
// appeared twice, and "[validator_list_keys]" sat among xrpld.cfg stanzas
// with nothing to say it belongs to validators.txt. The evaluator mapped
// every item back by hand from the marker positions.
func TestTodoNamesTheFileWhenTheBackupHasTwo(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	w := newWorld(t, 0)
	r := w.run("yes\n", "restore", "--dump", w.dumpFile("case"),
		"--words-file", w.words, "--account", w.writer.Address())
	if r.code != exitOK {
		t.Fatalf("exit %d, want %d:\n%s", r.code, exitOK, r.out)
	}
	seen := map[string]bool{}
	valHeader := false
	for _, l := range todoLines(r.out) {
		if !strings.Contains(l, "kept only in") {
			continue
		}
		if !strings.Contains(l, "xrpld.cfg") && !strings.Contains(l, "validators.txt") {
			t.Errorf("a re-enter item names no file: %s", l)
		}
		if seen[l] {
			t.Errorf("two items read the same, so one of them cannot be followed: %s", l)
		}
		seen[l] = true
		// And the right file, not merely a file.
		if strings.Contains(l, "[ips_fixed]") && !strings.Contains(l, "xrpld.cfg") {
			t.Errorf("[ips_fixed] lives in xrpld.cfg, item says otherwise: %s", l)
		}
		if strings.Contains(l, "before the first stanza") && strings.Contains(l, "validators.txt") {
			valHeader = true
		}
	}
	if !valHeader {
		t.Errorf("validators.txt's leading comment is not attributed to validators.txt:\n%s", r.out)
	}
}

// TestCommentOnlyRedactionIsNotAMissingSetting pins F-035. A comment inside
// [ledger_history] moved to the bundle, so the todo said "Re-enter
// [ledger_history]: 1 line(s) were kept only in the off-chain bundle" while
// the setting itself, 512, was in the restored file. The evaluator concluded
// a retention value had been lost. The todo must say when only a comment is
// missing, and it must not tell the operator to re-enter what is there.
func TestCommentOnlyRedactionIsNotAMissingSetting(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	w := newWorld(t, 0)
	raw, err := os.ReadFile(w.cfgPath)
	must(t, err)
	raw = append(raw, []byte("\n[ledger_history]\n512\n# retention reviewed after the March load test\n")...)
	must(t, os.WriteFile(w.cfgPath, raw, 0o600))
	w.plan = w.build(2, w.cfgPath, w.valPath)
	w.submit(w.plan)

	r := w.run("yes\n", "restore", "--dump", w.dumpFile("case"),
		"--words-file", w.words, "--account", w.writer.Address())
	if r.code != exitOK {
		t.Fatalf("exit %d, want %d:\n%s", r.code, exitOK, r.out)
	}
	if !strings.Contains(r.out, "[ledger_history]") {
		t.Fatalf("the comment move is not reported at all:\n%s", r.out)
	}
	for _, l := range todoLines(r.out) {
		if !strings.Contains(l, "[ledger_history]") {
			continue
		}
		if strings.HasPrefix(l, "Re-enter") || strings.Contains(l, ". Re-enter") {
			t.Errorf("told to re-enter a stanza whose settings are all present: %s", l)
		}
		if !strings.Contains(l, "comment") {
			t.Errorf("does not say that only a comment is missing: %s", l)
		}
	}
}

// TestAccountHelpDoesNotPointAtTheKeyFile pins F-036, the second cold-read
// evaluator's remark that the --account default "from the key file" is the
// wrong default for the one situation restore exists for, and the third
// evaluator's identical remark a day later. A recovery has no key file.
func TestAccountHelpDoesNotPointAtTheKeyFile(t *testing.T) {
	w := newWorld(t, 0)
	for _, sub := range []string{"restore", "verify"} {
		r := w.run("", sub, "-h")
		if strings.Contains(r.out, "from the key file") {
			t.Errorf("%s -h still presents the key file as the source of --account:\n%s", sub, r.out)
		}
		if !strings.Contains(r.out, "paper") {
			t.Errorf("%s -h does not say where a recovery gets the address:\n%s", sub, r.out)
		}
	}
}

// TestUsageListsVersion: the tool has a version command and the usage text
// did not mention it, so the evaluator could not tell what it was running.
func TestUsageListsVersion(t *testing.T) {
	w := newWorld(t, 0)
	r := w.run("", "help")
	if !strings.Contains(r.out, "version") {
		t.Errorf("usage does not list the version command:\n%s", r.out)
	}
}
