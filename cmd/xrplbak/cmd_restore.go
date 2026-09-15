package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/justinnevins/xrplbak/internal/chunk"
	"github.com/justinnevins/xrplbak/internal/container"
	"github.com/justinnevins/xrplbak/internal/discover"
	"github.com/justinnevins/xrplbak/internal/manifest"
	"github.com/justinnevins/xrplbak/internal/restore"
	"github.com/justinnevins/xrplbak/internal/xrpl"
	"github.com/justinnevins/xrplbak/internal/xrpl/sign"
)

// sourceFlags are shared by verify and restore.
type sourceFlags struct {
	rpcURL, dumpPath, account, key, wordsFile, sharesFile *string
	keyPass                                               *bool
	epoch                                                 *int
	backupID                                              *string
}

func addSourceFlags(fs *flag.FlagSet) *sourceFlags {
	return &sourceFlags{
		rpcURL:     fs.String("rpc", "", "XRPL JSON-RPC URL, or mainnet / testnet / devnet"),
		dumpPath:   fs.String("dump", "", "offline dump file written by backup (instead of --rpc)"),
		account:    fs.String("account", "", "writer account address (default: from the key file)"),
		key:        fs.String("key", "", "xrplbak.key path; when present no recovery words are needed"),
		keyPass:    fs.Bool("key-passphrase", false, "prompt for the key file passphrase"),
		wordsFile:  fs.String("words-file", "", "file with the 24 recovery words (default: prompt)"),
		sharesFile: fs.String("shares-file", "", "file with recovery shares, one per line (default: prompt)"),
		epoch:      fs.Int("epoch", -1, "epoch to start probing from (default: key file epoch or 0)"),
		backupID:   fs.String("backup-id", "", "use this backup (hex id or unique prefix) instead of the newest"),
	}
}

// choose picks the backup to work with: the newest, or the one named by
// --backup-id. A conflict at the newest seq is refused unless named.
func (sf *sourceFlags) choose(res *discover.Result, account string) (*discover.Candidate, error) {
	if want := strings.ToLower(*sf.backupID); want != "" {
		var hit *discover.Candidate
		for _, c := range res.Candidates {
			if strings.HasPrefix(c.Manifest.BackupID, want) {
				if hit != nil {
					return nil, fail(exitUsage, "--backup-id %s matches more than one backup; give more characters", want)
				}
				hit = c
			}
		}
		if hit == nil {
			return nil, fail(exitAuth, "no authenticated backup has id %s", want)
		}
		return hit, nil
	}
	if res.Conflict != "" {
		return nil, fail(exitAuth, "%s", res.Conflict)
	}
	if res.Latest == nil {
		return nil, fail(exitAuth, "no backup authenticates for %s with this key in the searched range. Check the account address, the recovery key, and the epoch", account)
	}
	return res.Latest, nil
}

type source struct {
	client  xrpl.Client
	name    string
	account string
	keys    discover.Keys
	hint    uint32
}

// resolve turns flags into a client, an account, and keys. A key file is
// used when one is found or named; otherwise the recovery key is asked for.
func (sf *sourceFlags) resolve() (*source, error) {
	c, name, err := openClient(*sf.rpcURL, *sf.dumpPath)
	if err != nil {
		return nil, err
	}
	s := &source{client: c, name: name, account: *sf.account}
	if *sf.wordsFile == "" && *sf.sharesFile == "" {
		kp, kerr := findKeyFile(*sf.key, "")
		if kerr == nil {
			kf, lerr := loadKeyFile(kp, *sf.keyPass)
			if lerr != nil {
				return nil, lerr
			}
			s.keys = discover.FileKeys{E: kf.Epoch, Key: kf.Key}
			s.hint = kf.Epoch
			if s.account == "" {
				s.account = sign.EncodeAddress(kf.AccountID[:])
			}
			fmt.Fprintf(stdout, "using key file %s (epoch %d)\n", kp, kf.Epoch)
		} else if *sf.key != "" {
			return nil, kerr
		}
	}
	if s.keys == nil {
		k, _, rerr := recoveryKeys(*sf.wordsFile, *sf.sharesFile)
		if rerr != nil {
			return nil, rerr
		}
		s.keys = k
	}
	if s.account == "" {
		s.account = prompt("Writer account address (r...): ")
	}
	if _, derr := sign.DecodeAddress(s.account); derr != nil {
		return nil, fail(exitUsage, "%v", derr)
	}
	if *sf.epoch >= 0 {
		s.hint = uint32(*sf.epoch)
	}
	return s, nil
}

func cmdVerify(args []string) error {
	fs := newFlags("verify", "find and authenticate backups from a server or a dump")
	sf := addSourceFlags(fs)
	bundlePath := fs.String("bundle", "", "also check this bundle file against the latest manifest")
	asJSON := fs.Bool("json", false, "print the latest manifest as JSON")
	if err := fs.Parse(args); err != nil {
		return parseError(err)
	}

	s, err := sf.resolve()
	if err != nil {
		return err
	}
	res, err := discover.Run(s.client, s.keys, s.account, s.hint)
	if err != nil {
		return fail(exitNetwork, "%v", err)
	}
	reportRun(res, s.name)
	latest, err := sf.choose(res, s.account)
	if err != nil {
		return err
	}
	hr("Selected backup")
	entries, err := discover.Fetch(s.client, s.keys, res, latest)
	switch {
	case latest.Manifest.Tombstone:
		fmt.Fprintln(stdout, "  tombstone: earlier backups are retired")
	case err != nil:
		var me *chunk.MissingError
		if errors.As(err, &me) {
			return fail(exitIncomplete, "%v", err)
		}
		return fail(exitAuth, "%v", err)
	default:
		fmt.Fprintf(stdout, "  on-chain data: complete, %d chunk(s), %d file(s)\n", len(latest.Manifest.OnChain.Chunks), len(entries))
	}
	reportAttestation(latest.Manifest)
	if *bundlePath != "" {
		b, err := os.ReadFile(*bundlePath)
		if err != nil {
			return err
		}
		if _, err := discover.OpenBundle(s.keys, latest, b); err != nil {
			return fail(exitAuth, "bundle: %v", err)
		}
		fmt.Fprintln(stdout, "  bundle:        matches the manifest and decrypts")
	} else {
		fmt.Fprintf(stdout, "  bundle:        not checked (pass --bundle FILE); expected sha256 %s\n", latest.Manifest.Bundle.CipherSHA256[:16])
	}
	if *asJSON {
		fmt.Fprintln(stdout, string(latest.Plain))
	}
	return nil
}

func reportAttestation(m *manifest.Manifest) {
	if m.Attestation == nil {
		return
	}
	a := m.Attestation
	pub, err := sign.DecodeNodePublic(a.VPK)
	if err != nil {
		fmt.Fprintln(stdout, "  attestation:   present but the key is malformed")
		return
	}
	if pub[0] != 0xED {
		fmt.Fprintln(stdout, "  attestation:   present, unverifiable in v1 (secp256k1 validator key)")
		return
	}
	sig, _ := decodeHex(a.Sig)
	msg := manifest.AttestString(m.BackupID, m.OnChain.PlainSHA256, m.Bundle.PlainSHA256)
	if sign.VerifyEd25519(pub, []byte(msg), sig) {
		fmt.Fprintf(stdout, "  attestation:   valid ed25519 signature by %s\n", a.VPK)
	} else {
		fmt.Fprintf(stdout, "  attestation:   INVALID signature for %s\n", a.VPK)
	}
}

func cmdRestore(args []string) error {
	fs := newFlags("restore", "rebuild config files; dry run unless --write")
	sf := addSourceFlags(fs)
	bundlePath := fs.String("bundle", "", "bundle file for this backup (optional; without it some content stays missing)")
	write := fs.Bool("write", false, "write files into --target instead of a temp dir")
	target := fs.String("target", "", "directory for --write, e.g. /etc/xrpld")
	force := fs.Bool("force", false, "with --write: overwrite existing files")
	allowTomb := fs.Bool("allow-tombstoned", false, "restore the newest non-tombstone backup even if a tombstone is newer")
	asJSON := fs.Bool("json", false, "print the file report as JSON")
	if err := fs.Parse(args); err != nil {
		return parseError(err)
	}

	if *write && *target == "" {
		return fail(exitUsage, "--write needs --target DIR")
	}
	s, err := sf.resolve()
	if err != nil {
		return err
	}
	res, err := discover.Run(s.client, s.keys, s.account, s.hint)
	if err != nil {
		return fail(exitNetwork, "%v", err)
	}
	reportRun(res, s.name)
	cand, err := sf.choose(res, s.account)
	if err != nil {
		return err
	}
	if cand.Manifest.Tombstone {
		if !*allowTomb {
			return fail(exitIncomplete, "the newest backup is a tombstone: the operator retired these backups. Pass --allow-tombstoned to restore the newest real backup anyway")
		}
		cand = nil
		for _, c := range res.Candidates {
			if !c.Manifest.Tombstone {
				cand = c
				break
			}
		}
		if cand == nil {
			return fail(exitIncomplete, "only tombstones were found")
		}
	}
	entries, err := discover.Fetch(s.client, s.keys, res, cand)
	if err != nil {
		var me *chunk.MissingError
		if errors.As(err, &me) {
			return fail(exitIncomplete, "%v", err)
		}
		return fail(exitAuth, "%v", err)
	}
	var bundle []container.Entry
	if *bundlePath != "" {
		b, err := os.ReadFile(*bundlePath)
		if err != nil {
			return err
		}
		bundle, err = discover.OpenBundle(s.keys, cand, b)
		if err != nil {
			return fail(exitAuth, "bundle: %v", err)
		}
	}
	plan, err := restore.Build(cand.Manifest, entries, bundle)
	if err != nil {
		return fail(exitRefused, "%v", err)
	}
	hr("Files")
	for _, f := range plan.Files {
		state := "complete"
		if !f.Complete {
			state = "INCOMPLETE"
		}
		fmt.Fprintf(stdout, "  %-40s %s  (%s, mode %04o)\n", f.Path, state, f.Source, f.Mode)
	}
	if len(plan.Todo) > 0 {
		hr("Before starting the server")
		for i, t := range plan.Todo {
			fmt.Fprintf(stdout, "  %d. %s\n", i+1, t)
		}
	}
	if *asJSON {
		type row struct {
			Path, Source string
			Complete     bool
		}
		var rows []row
		for _, f := range plan.Files {
			rows = append(rows, row{f.Path, f.Source, f.Complete})
		}
		b, _ := json.MarshalIndent(map[string]any{"files": rows, "todo": plan.Todo}, "", " ")
		fmt.Fprintln(stdout, string(b))
	}
	if !*write {
		dir, err := plan.WriteTemp()
		if err != nil {
			return fail(exitWrite, "%v", err)
		}
		hr("Dry run")
		fmt.Fprintf(stdout, "  files written under %s\n", dir)
		fmt.Fprintln(stdout, "  Inspect them. Then re-run with --write --target /etc/xrpld to place them.")
		return nil
	}
	if !confirm(fmt.Sprintf("  Write %d file(s) into %s?", len(plan.Files), *target)) {
		return fail(exitUsage, "cancelled; nothing was written")
	}
	written, err := plan.WriteTarget(*target, *force)
	if err != nil {
		return fail(exitWrite, "%v", err)
	}
	hr("Written")
	fmt.Fprintln(stdout, "  "+strings.Join(written, "\n  "))
	return nil
}

func decodeHex(s string) ([]byte, error) { return hex.DecodeString(s) }
