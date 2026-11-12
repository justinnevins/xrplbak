package main

import (
	"crypto/hmac"
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
// can only reach it from a run in which the operator typed the phrase. The
// file carries a sig line, an HMAC keyed by the writer seed in the key
// file: an on-chain choice is taken as already confirmed only from a file
// that verifies (F-096). Someone who can write the directory but not read
// the key can still edit the file, and then the phrase is asked again. The
// file is written with mode 0600 and is refused when group or others can
// write it.
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
		case "sig":
			if b, err := hex.DecodeString(v); err != nil || len(b) != sha256.Size {
				return nil, fmt.Errorf("line %d: sig must be %d bytes of hex", i+1, sha256.Size)
			}
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
			return nil, fmt.Errorf("line %d: unknown setting %q (known: rpc, max-fee, comments, peers, sig)", i+1, k)
		}
	}
	return s, nil
}

// settingsMAC signs the settings with a key derived from the writer seed,
// which only a holder of the key file has.
func settingsMAC(s settings, writerSeed []byte) string {
	k := sha256.Sum256(append([]byte("xrplbak/v1/settings"), writerSeed...))
	m := hmac.New(sha256.New, k[:])
	m.Write([]byte(s.render()))
	return hex.EncodeToString(m.Sum(nil))
}

// settingsSigned reports whether the file text carries a sig line that
// verifies for its settings under this writer seed.
func settingsSigned(text string, s settings, writerSeed []byte) bool {
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(k) == "sig" {
			want := settingsMAC(s, writerSeed)
			return hmac.Equal([]byte(strings.ToLower(strings.TrimSpace(v))), []byte(want))
		}
	}
	return false
}

// loadSettings reads the file at path. A missing file is no settings, not
// an error. Any other problem is an error.
func loadSettings(path string) (*settings, string, bool, error) {
	st, err := os.Stat(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return &settings{}, "", false, nil
	}
	if err != nil {
		return nil, "", false, err
	}
	// The file can turn on-chain publishing on without the typed phrase,
	// so it counts only when its owner alone can write it.
	if st.Mode().Perm()&0o022 != 0 {
		return nil, "", false, fmt.Errorf("file mode %o lets others write it; run \"chmod 600\" on it after you check its content", st.Mode().Perm())
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, "", false, err
	}
	s, err := parseSettings(string(raw))
	return s, string(raw), true, err
}

// saveSettings writes the file owner-only, through a temp file and a rename
// so a crash never leaves half a file for the next run to refuse. With a
// writer seed it adds the sig line that lets a later run trust its
// on-chain choices.
func saveSettings(path string, s settings, writerSeed []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".xrplbak.settings-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	text := s.render()
	if writerSeed != nil {
		text += "sig=" + settingsMAC(s, writerSeed) + "\n"
	}
	if _, err := tmp.WriteString(text); err != nil {
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
	WriterSeed    []byte   // signs the saved file
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
