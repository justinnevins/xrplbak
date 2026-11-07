package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// settingsName is the file, beside xrplbak.key, that holds the choices an
// operator makes on every run: the server, the fee cap, and where comments
// and fixed peers go. It is written only by backup --submit --save, after a
// backup landed, and only with the choices that run used. An on-chain choice
// can only reach it from a run in which the operator typed the phrase, or
// from the file itself. The file sits beside the key file with the same
// mode, so whoever can edit it can already read the key.
const settingsName = "xrplbak.settings"

// settings are the saved choices. An empty field is not set.
type settings struct {
	RPC      string
	MaxFee   uint64
	Comments string
	Peers    string
}

// render writes the settings in the file's format, set fields only.
func (s settings) render() string {
	var b strings.Builder
	b.WriteString("# xrplbak settings, written by backup --submit --save.\n")
	b.WriteString("# A flag on the command line wins. --no-settings ignores this file.\n")
	if s.RPC != "" {
		fmt.Fprintf(&b, "rpc=%s\n", s.RPC)
	}
	if s.MaxFee != 0 {
		fmt.Fprintf(&b, "max-fee=%d\n", s.MaxFee)
	}
	if s.Comments != "" {
		fmt.Fprintf(&b, "comments=%s\n", s.Comments)
	}
	if s.Peers != "" {
		fmt.Fprintf(&b, "peers=%s\n", s.Peers)
	}
	return b.String()
}

// parseSettings reads key=value lines. Blank lines and lines starting with #
// are skipped. Anything else it does not know is refused: a typo must never
// fall back to a choice the operator did not write.
func parseSettings(text string) (*settings, error) {
	s := &settings{}
	seen := map[string]bool{}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || v == "" {
			return nil, fmt.Errorf("line %d: want key=value", i+1)
		}
		if seen[k] {
			return nil, fmt.Errorf("line %d: %s is set twice", i+1, k)
		}
		seen[k] = true
		switch k {
		case "rpc":
			if _, alias := rpcAliases[strings.ToLower(v)]; !alias && !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
				return nil, fmt.Errorf("line %d: rpc must be mainnet, testnet, devnet or an http(s) URL, not %q", i+1, v)
			}
			s.RPC = v
		case "max-fee":
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil || n == 0 {
				return nil, fmt.Errorf("line %d: max-fee must be a whole number of drops above zero, not %q", i+1, v)
			}
			s.MaxFee = n
		case "comments", "peers":
			if v != "bundle" && v != "onchain" {
				return nil, fmt.Errorf("line %d: %s must be bundle or onchain, not %q", i+1, k, v)
			}
			if k == "comments" {
				s.Comments = v
			} else {
				s.Peers = v
			}
		default:
			return nil, fmt.Errorf("line %d: unknown setting %q (known: rpc, max-fee, comments, peers)", i+1, k)
		}
	}
	return s, nil
}

// loadSettings reads the file at path. A missing file is no settings, not
// an error. Any other problem is an error.
func loadSettings(path string) (*settings, bool, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return &settings{}, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	s, err := parseSettings(string(raw))
	return s, true, err
}

// saveSettings writes the file owner-only, through a temp file and a rename
// so a crash never leaves half a file for the next run to refuse.
func saveSettings(path string, s settings) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".xrplbak.settings-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(s.render()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// customized reports whether a run used any choice worth saving.
func (s settings) customized() bool {
	return s.RPC != "" || (s.MaxFee != 0 && s.MaxFee != defaultMaxFee) || s.Comments == "onchain" || s.Peers == "onchain"
}

// defaultMaxFee is backup's --max-fee default, in drops per transaction.
const defaultMaxFee = 5000

// submitSleep is how backup --submit waits. Tests replace it.
var submitSleep = time.Sleep

// submitExtras are the v1.1.7 one-command options. The zero value is the
// behavior before them: no fee wait, no read-back, nothing saved.
type submitExtras struct {
	FeeWait       time.Duration
	ReadBack      bool
	Save          bool
	SettingsPath  string
	SettingsExist bool
	Settings      settings // the choices this run used
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
