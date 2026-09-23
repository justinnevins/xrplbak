package main

// A [validators_file] stanza that names a file which does not exist
// must refuse, not fall through to validators.txt beside the config and not
// proceed as if the config named nothing. rippled itself refuses to start in
// that state (Config.cpp: "The file specified in [validators_file] does not
// exist"), so a backup that shipped anyway would describe a node that cannot
// run, and a stray validators.txt beside the config is not the file the
// operator named.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const namedMissingCfg = "[server]\nport_rpc\n\n[port_rpc]\nport = 5005\nip = 127.0.0.1\nprotocol = http\n\n[validators_file]\ndoes_not_exist.txt\n"

// namedMissingWorld writes a config whose [validators_file] names a path
// that is not there. With stray set, an unrelated validators.txt sits
// beside the config as well.
func namedMissingWorld(t *testing.T, stray bool) (*world, string) {
	t.Helper()
	w := newWorld(t, 1)
	dir := filepath.Join(w.dir, "named")
	must(t, os.MkdirAll(dir, 0o700))
	cfgPath := filepath.Join(dir, "xrpld.cfg")
	must(t, os.WriteFile(cfgPath, []byte(namedMissingCfg), 0o600))
	if stray {
		must(t, os.WriteFile(filepath.Join(dir, "validators.txt"), []byte("[validators]\nnHUeeJCSY2dM71oxM8Cgjouf5ekTuev2mwDpc374V6dvPGENz1yk\n"), 0o644))
	}
	return w, cfgPath
}

func assertNamedMissingRefused(t *testing.T, r result, cfgPath, outDir string) {
	t.Helper()
	if r.code != exitUsage {
		t.Fatalf("exit %d, want %d (usage)", r.code, exitUsage)
	}
	want := filepath.Join(filepath.Dir(cfgPath), "does_not_exist.txt")
	if !strings.Contains(r.out, "[validators_file]") || !strings.Contains(r.out, want) {
		t.Fatalf("output must name the stanza and the missing path %q:\n%s", want, r.out)
	}
	if strings.Contains(r.out, "validators.txt") {
		t.Fatalf("output must not mention the stray validators.txt:\n%s", r.out)
	}
	if outDir != "" {
		if _, err := os.Stat(outDir); err == nil {
			t.Fatalf("out dir %s was written despite the refusal", outDir)
		}
	}
}

func TestNamedButMissingValidatorsFileIsRefused(t *testing.T) {
	for _, stray := range []bool{false, true} {
		name := "nothing-beside"
		if stray {
			name = "stray-validators-txt-beside"
		}
		t.Run("backup/"+name, func(t *testing.T) {
			w, cfgPath := namedMissingWorld(t, stray)
			outDir := filepath.Join(w.dir, "out")
			r := w.run("", "backup", "--config", cfgPath, "--key", w.keyFile, "--out", outDir)
			assertNamedMissingRefused(t, r, cfgPath, outDir)
		})
		t.Run("redact/"+name, func(t *testing.T) {
			w, cfgPath := namedMissingWorld(t, stray)
			r := w.run("", "redact", "--config", cfgPath)
			assertNamedMissingRefused(t, r, cfgPath, "")
		})
	}
}

// --validators still wins over the stanza, so an operator whose config is
// stale on a fresh host has a way through without editing it.
func TestExplicitValidatorsOverridesNamedMissing(t *testing.T) {
	w, cfgPath := namedMissingWorld(t, false)
	r := w.run("", "redact", "--config", cfgPath, "--validators", w.valPath)
	if r.code != exitOK {
		t.Fatalf("exit %d, want 0:\n%s", r.code, r.out)
	}
	if !strings.Contains(r.out, w.valPath) {
		t.Fatalf("redact must list the explicit validators file:\n%s", r.out)
	}
}

// No stanza and no validators.txt beside the config is still fine: rippled
// does not complain in that state either.
func TestNoValidatorsFileAtAllIsAllowed(t *testing.T) {
	w := newWorld(t, 1)
	dir := filepath.Join(w.dir, "alone")
	must(t, os.MkdirAll(dir, 0o700))
	cfgPath := filepath.Join(dir, "xrpld.cfg")
	must(t, os.WriteFile(cfgPath, []byte(strings.SplitN(namedMissingCfg, "[validators_file]", 2)[0]), 0o600))
	r := w.run("", "redact", "--config", cfgPath)
	if r.code != exitOK {
		t.Fatalf("exit %d, want 0:\n%s", r.code, r.out)
	}
}
