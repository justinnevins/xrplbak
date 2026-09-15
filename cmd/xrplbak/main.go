// Command xrplbak backs up and restores xrpld/rippled configuration with the
// XRP Ledger as the integrity anchor. Run with no arguments for usage.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/justinnevins/xrplbak/internal/backup"
	"github.com/justinnevins/xrplbak/internal/cfg"
	"github.com/justinnevins/xrplbak/internal/crypto"
	"github.com/justinnevins/xrplbak/internal/discover"
	"github.com/justinnevins/xrplbak/internal/dump"
	"github.com/justinnevins/xrplbak/internal/redact"
	"github.com/justinnevins/xrplbak/internal/xrpl"
	"github.com/justinnevins/xrplbak/internal/xrpl/rpc"
)

// Exit codes. Scripts can branch on them; humans get the message.
const (
	exitOK         = 0
	exitUsage      = 1
	exitNetwork    = 2
	exitRefused    = 3
	exitAuth       = 4
	exitIncomplete = 5
	exitWrite      = 6
)

// version is set by the Makefile with -ldflags "-X main.version=...".
var version = "dev"

const usage = `xrplbak: back up and restore xrpld/rippled config with the XRP Ledger as the anchor.

Commands
  init      Create the recovery key, the host key file, and the writer account.
  redact    Show what goes on-chain, what goes in the bundle, and what is refused.
  backup    Plan a backup (dry run). Add --submit to write it to the ledger.
  verify    Check backups on the ledger (--rpc) or in a dump file (--dump).
  restore   Recover files to a temp dir (dry run). Add --write --target DIR to place them.

Run "xrplbak <command> -h" for the flags of one command.

Nothing leaves this machine except the XRPL requests you ask for with --rpc.
Validator master keys, node seeds, wallet.db, and TLS keys are refused on sight.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(exitUsage)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "redact":
		err = cmdRedact(os.Args[2:])
	case "backup":
		err = cmdBackup(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "restore":
		err = cmdRestore(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("xrplbak", version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(exitUsage)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(exitCode(err))
	}
}

// exitError carries a specific exit code.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func fail(code int, format string, a ...any) error {
	return &exitError{code: code, err: fmt.Errorf(format, a...)}
}

func exitCode(err error) int {
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	var re *redact.RefusedError
	if errors.As(err, &re) {
		return exitRefused
	}
	if errors.Is(err, crypto.ErrAuth) {
		return exitAuth
	}
	return exitUsage
}

// newFlags builds a flag set that prints its own usage on error.
func newFlags(name, summary string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "xrplbak %s: %s\n\nFlags:\n", name, summary)
		fs.PrintDefaults()
	}
	return fs
}

// Known config locations, newest layout first.
var configCandidates = []string{
	"/etc/xrpld/xrpld.cfg",
	"/etc/opt/ripple/rippled.cfg",
	"/opt/ripple/etc/rippled.cfg",
	"xrpld.cfg",
	"rippled.cfg",
}

func findConfig(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	for _, c := range configCandidates {
		if st, err := os.Stat(c); err == nil && st.Mode().IsRegular() {
			return c, nil
		}
	}
	return "", fail(exitUsage, "no config found in the usual places; pass --config PATH")
}

// findValidators resolves [validators_file] relative to the config, else
// validators.txt beside it. Returns "" when none exists.
func findValidators(explicit, configPath string) string {
	if explicit != "" {
		return explicit
	}
	dir := filepath.Dir(configPath)
	if raw, err := os.ReadFile(configPath); err == nil {
		if s := cfg.Parse(string(raw)).Get("validators_file"); s != nil && len(s.Lines) > 0 {
			p := s.Lines[0]
			if !filepath.IsAbs(p) {
				p = filepath.Join(dir, p)
			}
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	p := filepath.Join(dir, "validators.txt")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// findKeyFile looks next to the config, then in the working directory.
func findKeyFile(explicit, configPath string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	candidates := []string{"xrplbak.key"}
	if configPath != "" {
		candidates = append([]string{filepath.Join(filepath.Dir(configPath), "xrplbak.key")}, candidates...)
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fail(exitUsage, "no xrplbak.key found next to the config or here; run \"xrplbak init\" first or pass --key PATH")
}

func loadKeyFile(path string, passphrase bool) (*crypto.KeyFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pw []byte
	if crypto.IsWrapped(b) || passphrase {
		pw = []byte(prompt("Key file passphrase: "))
	}
	kf, err := crypto.DecodeKeyFile(b, pw)
	if err != nil {
		return nil, fail(exitAuth, "%s: %v", path, err)
	}
	return kf, nil
}

// Public endpoints the operator can name by alias. They are used only when
// asked for on the command line.
var rpcAliases = map[string]string{
	"mainnet": "https://xrplcluster.com",
	"testnet": "https://s.altnet.rippletest.net:51234",
	"devnet":  "https://s.devnet.rippletest.net:51234",
}

func openClient(rpcURL, dumpPath string) (xrpl.Client, string, error) {
	switch {
	case rpcURL != "" && dumpPath != "":
		return nil, "", fail(exitUsage, "pass either --rpc or --dump, not both")
	case dumpPath != "":
		d, err := dump.Load(dumpPath)
		if err != nil {
			return nil, "", err
		}
		return &dump.Client{D: d}, "dump file " + dumpPath, nil
	case rpcURL != "":
		if u, ok := rpcAliases[strings.ToLower(rpcURL)]; ok {
			rpcURL = u
		}
		if !strings.HasPrefix(rpcURL, "http://") && !strings.HasPrefix(rpcURL, "https://") {
			return nil, "", fail(exitUsage, "--rpc must be an http(s) URL or one of: mainnet, testnet, devnet")
		}
		return rpc.New(rpcURL), rpcURL, nil
	}
	return nil, "", fail(exitUsage, "pass --rpc URL (or mainnet/testnet) for a live server, or --dump FILE for offline")
}

// recoveryKeys asks for words or shares and returns a root-key provider.
func recoveryKeys(wordsFile, sharesFile string) (discover.Keys, crypto.RootKey, error) {
	var root crypto.RootKey
	var err error
	switch {
	case wordsFile != "":
		b, rerr := os.ReadFile(wordsFile)
		if rerr != nil {
			return nil, root, rerr
		}
		root, err = crypto.FromWords(crypto.ParseWords(string(b)))
	case sharesFile != "":
		b, rerr := os.ReadFile(sharesFile)
		if rerr != nil {
			return nil, root, rerr
		}
		root, err = crypto.Combine(nonEmptyLines(string(b)))
	default:
		fmt.Println("Enter the 24 recovery words on one line, or paste recovery shares one per line and finish with an empty line.")
		var lines []string
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if l == "" {
				break
			}
			lines = append(lines, l)
			if len(lines) == 1 && len(crypto.ParseWords(l)) == crypto.WordCount {
				break
			}
		}
		if len(lines) == 0 {
			return nil, root, fail(exitUsage, "no recovery key entered")
		}
		if len(lines) == 1 && len(crypto.ParseWords(lines[0])) == crypto.WordCount {
			root, err = crypto.FromWords(crypto.ParseWords(lines[0]))
		} else {
			root, err = crypto.Combine(lines)
		}
	}
	if err != nil {
		return nil, root, fail(exitAuth, "recovery key: %v", err)
	}
	return discover.RootKeys{Root: root}, root, nil
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func prompt(msg string) string {
	fmt.Print(msg)
	sc := bufio.NewScanner(os.Stdin)
	sc.Scan()
	return strings.TrimSpace(sc.Text())
}

func confirm(msg string) bool {
	return strings.EqualFold(prompt(msg+" [yes/no]: "), "yes")
}

func hr(title string) {
	fmt.Printf("\n== %s ==\n", title)
}

// summarizeMoves prints the redaction report in operator language.
func summarizeMoves(moves []redact.Move) {
	if len(moves) == 0 {
		fmt.Println("  nothing moved: every stanza is allowed on-chain")
		return
	}
	for _, m := range moves {
		fmt.Printf("  [%s]: %d line(s) -> bundle (%s)\n", m.Stanza, m.Lines, m.Reason)
	}
}

// reportRun prints discovery output shared by verify and restore.
func reportRun(res *discover.Result, source string) {
	hr("Discovery")
	fmt.Printf("  source:   %s\n", source)
	fmt.Printf("  account:  %s\n", res.Account)
	fmt.Printf("  searched: ledgers %d to %d\n", res.Range.Min, res.Range.Max)
	switch {
	case res.Anchor == nil:
		fmt.Println("  anchor:   none (DID entry absent)")
	case res.AnchorOK:
		fmt.Printf("  anchor:   ok, epoch %d seq %d\n", res.Anchor.Epoch, res.Anchor.Seq)
	default:
		fmt.Println("  anchor:   present but NOT verified")
	}
	fmt.Printf("  backups:  %d authenticated, %d rejected\n", len(res.Candidates), res.Rejected)
	for _, c := range res.Candidates {
		mark := " "
		if c == res.Latest {
			mark = "*"
		}
		kind := "backup"
		if c.Manifest.Tombstone {
			kind = "tombstone"
		}
		fmt.Printf("  %s epoch %d seq %-4d %s  %s  id %s\n", mark, c.Epoch, c.Manifest.Seq, c.Manifest.Created, kind, c.Manifest.BackupID[:16])
	}
	for _, w := range res.Warnings {
		fmt.Println("  WARNING:", w)
	}
}

// bindPlan applies discovery to a backup plan's sequencing. The error is
// returned so --submit can refuse to guess a sequence number.
func bindPlan(o *backup.Options, c xrpl.Client, kf *crypto.KeyFile, account string) ([]string, error) {
	seq, sup, warns, err := backup.NextSeq(c, kf, account)
	if err != nil {
		return []string{"could not read existing backups (" + err.Error() + "); this plan assumes seq 1"}, err
	}
	o.Seq, o.Supersedes = seq, sup
	return warns, nil
}
