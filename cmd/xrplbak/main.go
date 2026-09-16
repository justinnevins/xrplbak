// Command xrplbak backs up and restores xrpld/rippled configuration with the
// XRP Ledger as the integrity anchor. Run with no arguments for usage.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
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
  version   Print the version this binary was built as. Compare it to the release tag.

Run "xrplbak <command> -h" for the flags of one command.

Nothing leaves this machine except the XRPL requests you ask for with --rpc.
Validator master keys, node seeds, wallet.db, and TLS keys are refused on sight.
`

// Streams are package variables so tests can drive run in-process.
var (
	stdin  io.Reader = os.Stdin
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr
)

// stdinLines is the one buffered reader every prompt shares. Giving each
// prompt its own bufio.Scanner looks harmless and is not: a Scanner reads
// ahead into its own buffer, so the first question swallows the answers to
// all the later ones. A terminal hides it, because each read returns a
// single line. A pipe or a file does not.
var stdinLines *bufio.Reader

// setStdin points the prompts at r and discards anything buffered from a
// previous reader.
func setStdin(r io.Reader) {
	stdin = r
	stdinLines = bufio.NewReader(r)
}

// readLine returns the next line of input without its terminator, and
// whether there was one.
func readLine() (string, bool) {
	if stdinLines == nil {
		setStdin(stdin)
	}
	line, err := stdinLines.ReadString('\n')
	if line == "" && err != nil {
		return "", false
	}
	return strings.TrimRight(line, "\r\n"), true
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run executes one command and returns its exit code. It never calls
// os.Exit, so the adversarial corpus can assert codes directly.
func run(args []string, in io.Reader, out, errOut io.Writer) int {
	setStdin(in)
	stdout, stderr = out, errOut
	if len(args) < 1 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	var err error
	switch args[0] {
	case "init":
		err = cmdInit(args[1:])
	case "redact":
		err = cmdRedact(args[1:])
	case "backup":
		err = cmdBackup(args[1:])
	case "verify":
		err = cmdVerify(args[1:])
	case "restore":
		err = cmdRestore(args[1:])
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "xrplbak", version)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitCode(err)
	}
	return exitOK
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
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "xrplbak %s: %s\n\nFlags:\n", name, summary)
		fs.PrintDefaults()
	}
	return fs
}

// parseError maps a flag parse result to an exit. -h is not an error.
func parseError(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return fail(exitUsage, "%v", err)
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
	if wordsFile != "" && sharesFile != "" {
		// Taking the words and never opening the shares lets a stale or
		// wrong words file quietly beat the correct shares. --rpc and
		// --dump already refuse each other for the same reason.
		return nil, root, fail(exitUsage, "pass either --words-file or --shares-file, not both")
	}
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
		fmt.Fprintln(stdout, "Enter the 24 recovery words on one line, or paste recovery shares one per line and finish with an empty line.")
		var lines []string
		for {
			raw, ok := readLine()
			if !ok {
				break
			}
			l := strings.TrimSpace(raw)
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
	fmt.Fprint(stdout, msg)
	line, _ := readLine()
	return strings.TrimSpace(line)
}

func confirm(msg string) bool {
	return strings.EqualFold(prompt(msg+" [yes/no]: "), "yes")
}

func hr(title string) {
	fmt.Fprintf(stdout, "\n== %s ==\n", title)
}

// summarizeMoves prints the redaction report in operator language.
func summarizeMoves(moves []redact.Move) {
	if len(moves) == 0 {
		fmt.Fprintln(stdout, "  nothing moved: every stanza is allowed on-chain")
		return
	}
	// With more than one file, say which file each move is in. The
	// redact command has no path on its moves, and one file needs no
	// heading.
	files := map[string]bool{}
	for _, m := range moves {
		if m.File != "" {
			files[m.File] = true
		}
	}
	last := ""
	for _, m := range moves {
		if len(files) > 1 && m.File != last {
			fmt.Fprintf(stdout, "  %s\n", m.File)
			last = m.File
		}
		fmt.Fprintf(stdout, "  [%s]: %d line(s) -> bundle (%s)\n", m.Stanza, m.Lines, m.Reason)
	}
}

// reportRun prints discovery output shared by verify and restore.
func reportRun(res *discover.Result, source string) {
	hr("Discovery")
	fmt.Fprintf(stdout, "  source:   %s\n", source)
	fmt.Fprintf(stdout, "  account:  %s\n", res.Account)
	fmt.Fprintf(stdout, "  searched: ledgers %d to %d\n", res.Range.Min, res.Range.Max)
	switch {
	case res.Anchor == nil:
		fmt.Fprintln(stdout, "  anchor:   none (DID entry absent)")
	case res.AnchorOK:
		fmt.Fprintf(stdout, "  anchor:   ok, epoch %d seq %d\n", res.Anchor.Epoch, res.Anchor.Seq)
	default:
		fmt.Fprintln(stdout, "  anchor:   present but NOT verified")
	}
	fmt.Fprintf(stdout, "  backups:  %d authenticated, %d rejected\n", len(res.Candidates), res.Rejected)
	for _, c := range res.Candidates {
		mark := " "
		if c == res.Latest {
			mark = "*"
		}
		kind := "backup"
		if c.Manifest.Tombstone {
			kind = "tombstone"
		}
		fmt.Fprintf(stdout, "  %s epoch %d seq %-4d %s  %s  id %s\n", mark, c.Epoch, c.Manifest.Seq, c.Manifest.Created, kind, c.Manifest.BackupID[:16])
	}
	for _, w := range res.Warnings {
		fmt.Fprintln(stdout, "  WARNING:", w)
	}
	if res.Conflict != "" {
		fmt.Fprintln(stdout, "  CONFLICT:", res.Conflict)
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
