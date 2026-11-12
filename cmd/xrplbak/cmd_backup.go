package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/justinnevins/xrplbak/internal/backup"
	"github.com/justinnevins/xrplbak/internal/cfg"
	"github.com/justinnevins/xrplbak/internal/crypto"
	"github.com/justinnevins/xrplbak/internal/dump"
	"github.com/justinnevins/xrplbak/internal/pubattest"
	"github.com/justinnevins/xrplbak/internal/redact"
	"github.com/justinnevins/xrplbak/internal/xrpl"
	"github.com/justinnevins/xrplbak/internal/xrpl/codec"
	"github.com/justinnevins/xrplbak/internal/xrpl/sign"
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func cmdRedact(args []string) error {
	fs := newFlags("redact", "show the on-chain / bundle split for a config without encrypting anything")
	config := fs.String("config", "", "path to xrpld.cfg or rippled.cfg (default: auto-detect)")
	validators := fs.String("validators", "", "path to validators.txt (default: from [validators_file] or beside the config)")
	out := fs.String("out", "", "also write onchain/ and bundle/ copies into this directory")
	comments := fs.String("comments", "bundle", commentsFlagHelp)
	peers := fs.String("peers", "bundle", peersFlagHelp)
	if err := fs.Parse(args); err != nil {
		return parseError(err)
	}

	mode, err := commentsMode(*comments, false)
	if err != nil {
		return err
	}
	peersOn, err := peersMode(*peers, false)
	if err != nil {
		return err
	}
	cfgPath, err := findConfig(*config)
	if err != nil {
		return err
	}
	paths := []string{cfgPath}
	valPath, err := findValidators(*validators, cfgPath)
	if err != nil {
		return err
	}
	if valPath != "" {
		paths = append(paths, valPath)
	}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		res, err := redact.Split(cfg.Parse(string(raw)), redact.Options{Comments: mode, PeersOnChain: peersOn})
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		hr(p)
		fmt.Fprintf(stdout, "  role: %s\n", res.Role)
		summarizeMoves(res.Moves)
		if *out != "" {
			for sub, f := range map[string]string{"onchain": res.OnChain.Render(), "bundle": res.Bundle.Render()} {
				dst := filepath.Join(*out, sub, filepath.Base(p))
				if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
					return err
				}
				if err := os.WriteFile(dst, []byte(f), 0o600); err != nil {
					return err
				}
				fmt.Fprintf(stdout, "  wrote %s\n", dst)
			}
		}
	}
	return nil
}

// backupFlags holds the parsed command line of xrplbak backup. set names the
// flags given on the command line, so saved settings fill in only the rest.
type backupFlags struct {
	config, validators, key, out, rpcURL    string
	includes                                multiFlag
	keyPass, submit, yes, save, noSettings  bool
	noReadBack, tombstone, deleteAnchor     bool
	forceSeq, attestDelegated               bool
	maxFee                                  uint64
	feeWait                                 time.Duration
	vpk, attest, attestVPK, comments, peers string
	batch, attestPubKey, attestPubSig       string
	attestKeyPath, delegSig                 string
	set                                     map[string]bool
}

func cmdBackup(args []string) error {
	f, err := parseBackupFlags(args)
	if f == nil {
		// Parsing stopped: a usage error, or nil after -h printed the help.
		return err
	}
	if err := checkBackupFlags(f); err != nil {
		return err
	}
	cfgPath, err := findConfig(f.config)
	if err != nil {
		return err
	}
	keyPath, err := findKeyFile(f.key, cfgPath)
	if err != nil {
		return err
	}
	settingsPath := filepath.Join(filepath.Dir(keyPath), settingsName)
	settingsExist, savedOnchain, err := applySettings(f, settingsPath)
	if err != nil {
		return err
	}
	mode, peersOn, err := backupModes(f, savedOnchain, settingsPath)
	if err != nil {
		return err
	}
	kf, writer, err := loadWriter(keyPath, f.keyPass)
	if err != nil {
		return err
	}
	o, att, err := backupOptions(f, cfgPath, keyPath, kf, mode, peersOn)
	if err != nil {
		return err
	}
	return runBackup(f, o, att, kf, writer, keyPath, settingsPath, settingsExist)
}

// parseBackupFlags defines and parses the backup flags. It returns nil flags
// when parsing stops, with the error cmdBackup returns (nil after -h).
func parseBackupFlags(args []string) (*backupFlags, error) {
	fs := newFlags("backup", "plan a backup; --submit writes it to the ledger")
	f := &backupFlags{}
	fs.StringVar(&f.config, "config", "", "path to xrpld.cfg or rippled.cfg (default: auto-detect)")
	fs.StringVar(&f.validators, "validators", "", "path to validators.txt (default: from [validators_file] or beside the config)")
	fs.Var(&f.includes, "include", "extra file for the off-chain bundle (repeatable). Key material is refused")
	fs.StringVar(&f.key, "key", "", "path to xrplbak.key (default: next to the config, then ./xrplbak.key)")
	fs.BoolVar(&f.keyPass, "key-passphrase", false, "prompt for the key file passphrase")
	fs.StringVar(&f.out, "out", "xrplbak-out", "directory for the bundle, dump, and report")
	fs.StringVar(&f.rpcURL, "rpc", "", "XRPL JSON-RPC URL, or mainnet / testnet / devnet")
	fs.BoolVar(&f.submit, "submit", false, "actually submit transactions (default is a dry run). Asks before submitting; pass --yes to answer up front")
	fs.BoolVar(&f.yes, "yes", false, "answer the submit confirmation with yes, for scripts")
	fs.Uint64Var(&f.maxFee, "max-fee", defaultMaxFee, "abort if the network fee per transaction exceeds this many drops")
	fs.DurationVar(&f.feeWait, "fee-wait", 10*time.Minute, "with --submit: while the network fee is above --max-fee, wait this long for it to fall before giving up (0 gives up at once)")
	fs.BoolVar(&f.save, "save", false, "with --submit: after the backup lands, save --rpc, --max-fee, --comments and --peers to "+settingsName+" beside the key file, so the next run needs only --submit")
	fs.BoolVar(&f.noSettings, "no-settings", false, "ignore "+settingsName)
	fs.BoolVar(&f.noReadBack, "no-readback", false, "with --submit: skip reading the new backup back from the ledger")
	fs.BoolVar(&f.tombstone, "tombstone", false, "publish a tombstone that marks earlier backups as retired")
	fs.BoolVar(&f.deleteAnchor, "delete-anchor", false, "with --tombstone only: also delete the DID entry (frees 0.2 XRP)")
	fs.BoolVar(&f.forceSeq, "force-seq", false, "submit even when existing backups could not be read (risks a duplicate seq)")
	fs.StringVar(&f.vpk, "validator-key", "", "validator public key (nHB...) to label this backup with; stored only as a hash inside the ciphertext, for your records, and not checked by verify or restore")
	fs.StringVar(&f.attest, "attestation", "", "removed in v1.1.6; use --attest")
	fs.StringVar(&f.attestVPK, "attestation-key", "", "removed in v1.1.6; use --attest")
	fs.StringVar(&f.comments, "comments", "bundle", commentsFlagHelp)
	fs.StringVar(&f.peers, "peers", "bundle", peersFlagHelp)
	fs.StringVar(&f.batch, "batch", "auto", batchFlagHelp)
	fs.StringVar(&f.attestPubKey, "attest-public-key", "", "advanced: sign each public attestation with the validator master key itself (nHB..., ed25519). Most operators want --attest, which keeps the master key offline")
	fs.StringVar(&f.attestPubSig, "attest-public-sig", "", "hex signature over the public attest string, made offline with validator-keys sign")
	fs.BoolVar(&f.attestDelegated, "attest", false, "publish a public attestation that this validator backs up, signed by the delegated attestation key (see xrplbak attest-key); the master key stays offline")
	fs.StringVar(&f.attestKeyPath, "attest-key", "", "attestation key file (default: "+attestKeyName+" beside xrplbak.key)")
	fs.StringVar(&f.delegSig, "attest-delegation-sig", "", "with --attest: the master key's hex signature over the delegation string, to publish the delegation with this backup")
	if err := fs.Parse(args); err != nil {
		return nil, parseError(err)
	}
	f.set = map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { f.set[fl.Name] = true })
	return f, nil
}

// checkBackupFlags refuses flag values and combinations that cannot work,
// before any file is read.
func checkBackupFlags(f *backupFlags) error {
	if f.feeWait < 0 {
		return fail(exitUsage, "--fee-wait must be zero or more, not %s", f.feeWait)
	}
	if f.save && !f.submit {
		return fail(exitUsage, "--save needs --submit: settings are saved only after a backup lands")
	}
	if f.save && f.noSettings {
		return fail(exitUsage, "choose one: --save or --no-settings")
	}
	for name, v := range map[string]string{"comments": f.comments, "peers": f.peers} {
		if v != "bundle" && v != "onchain" {
			return fail(exitUsage, "--%s must be bundle or onchain, not %q", name, v)
		}
	}
	switch f.batch {
	case "auto", "on", "off":
	default:
		return fail(exitUsage, "--batch must be auto, on or off, not %q", f.batch)
	}
	if f.deleteAnchor && !f.tombstone {
		return fail(exitUsage, "--delete-anchor needs --tombstone")
	}
	if f.tombstone && len(f.includes) > 0 {
		return fail(exitUsage, "--tombstone stores no files; drop --include")
	}
	if f.tombstone && (f.attestDelegated || f.attestPubKey != "" || f.attestPubSig != "" || f.attest != "" || f.attestVPK != "" || f.delegSig != "") {
		return fail(exitUsage, "a tombstone carries no attestation; drop --attest, --attest-public-key and --attestation")
	}
	return checkAttestFlags(f)
}

// checkAttestFlags refuses attestation flag combinations that cannot work.
func checkAttestFlags(f *backupFlags) error {
	if f.delegSig != "" && !f.attestDelegated {
		return fail(exitUsage, "--attest-delegation-sig needs --attest")
	}
	if f.attestDelegated && f.attestPubKey != "" {
		return fail(exitUsage, "choose one: --attest (delegated key, the default) or --attest-public-key (sign each backup with the master key)")
	}
	if (f.attestPubSig != "") && (f.attestPubKey == "") {
		return fail(exitUsage, "--attest-public-sig needs --attest-public-key")
	}
	if f.attestPubKey != "" {
		pub, err := sign.DecodeNodePublic(f.attestPubKey)
		if err != nil {
			return err
		}
		if len(pub) != 33 || pub[0] != 0xED {
			return fail(exitUsage, "--attest-public-key must be an ed25519 validator key (nHB...); secp256k1 keys are not supported in v1")
		}
		if f.attestPubSig != "" {
			if b, err := hex.DecodeString(f.attestPubSig); err != nil || len(b) != 64 {
				return fail(exitUsage, "--attest-public-sig must be 64 bytes of hex")
			}
		}
	}
	return nil
}

// applySettings fills in, from the saved settings file, what the command
// line left out. savedOnchain names each on-chain choice that came from the
// file.
func applySettings(f *backupFlags, settingsPath string) (exist bool, savedOnchain map[string]bool, err error) {
	saved := &settings{}
	if !f.noSettings {
		if saved, exist, err = loadSettings(settingsPath); err != nil {
			return false, nil, fail(exitUsage, "%s: %v. Fix the file, or pass --no-settings to ignore it", settingsPath, err)
		}
	}
	if !f.set["rpc"] && saved.RPC != "" {
		f.rpcURL = saved.RPC
	}
	if !f.set["max-fee"] && saved.MaxFee != 0 {
		f.maxFee = saved.MaxFee
	}
	savedOnchain = map[string]bool{}
	if !f.set["comments"] && saved.Comments != "" {
		f.comments = saved.Comments
		savedOnchain["comments"] = saved.Comments == "onchain"
	}
	if !f.set["peers"] && saved.Peers != "" {
		f.peers = saved.Peers
		savedOnchain["peers"] = saved.Peers == "onchain"
	}
	return exist, savedOnchain, nil
}

// backupModes resolves --comments and --peers, asking for the typed
// confirmation an on-chain choice needs.
func backupModes(f *backupFlags, savedOnchain map[string]bool, settingsPath string) (redact.Mode, bool, error) {
	// An on-chain choice read from the file was typed and acknowledged in
	// the run that saved it, so it is not asked again. It is named instead.
	mode, err := commentsMode(f.comments, !savedOnchain["comments"])
	if err != nil {
		return mode, false, err
	}
	if savedOnchain["comments"] {
		fmt.Fprintf(stdout, "  comments: on-chain (saved in %s)\n", settingsPath)
	}
	peersOn, err := peersMode(f.peers, !savedOnchain["peers"])
	if err != nil {
		return mode, false, err
	}
	if savedOnchain["peers"] {
		fmt.Fprintf(stdout, "  peers: on-chain (saved in %s)\n", settingsPath)
	}
	return mode, peersOn, nil
}

// loadWriter opens the key file and checks that its writer seed matches the
// stored account.
func loadWriter(keyPath string, keyPass bool) (*crypto.KeyFile, *sign.Key, error) {
	kf, err := loadKeyFile(keyPath, keyPass)
	if err != nil {
		return nil, nil, err
	}
	writer, err := sign.KeyFromSeed(kf.WriterSeed[:])
	if err != nil {
		return nil, nil, err
	}
	if writer.AccountID() == nil || sign.EncodeAddress(kf.AccountID[:]) != writer.Address() {
		return nil, nil, fail(exitAuth, "key file is inconsistent: writer seed does not match the stored account")
	}
	return kf, writer, nil
}

// backupOptions builds the backup plan options and loads the delegated
// attestation key when --attest is given.
func backupOptions(f *backupFlags, cfgPath, keyPath string, kf *crypto.KeyFile, mode redact.Mode, peersOn bool) (backup.Options, *attestKey, error) {
	valPath, err := findValidators(f.validators, cfgPath)
	if err != nil {
		return backup.Options{}, nil, err
	}
	var att *attestKey
	if f.attestDelegated {
		p := f.attestKeyPath
		if p == "" {
			p = filepath.Join(filepath.Dir(keyPath), attestKeyName)
		}
		if att, err = loadAttestKey(p); err != nil {
			return backup.Options{}, nil, err
		}
	}
	o := backup.Options{ConfigPath: cfgPath, ValidatorsPath: valPath, Includes: f.includes, Key: kf, Tombstone: f.tombstone, Seq: 1, Comments: mode, PeersOnChain: peersOn, AttestPublicVPK: f.attestPubKey}
	if f.vpk != "" {
		pub, err := sign.DecodeNodePublic(f.vpk)
		if err != nil {
			return backup.Options{}, nil, err
		}
		sum := sha256.Sum256(pub)
		o.VPKSHA256 = hex.EncodeToString(sum[:])
	}
	if f.attest != "" || f.attestVPK != "" {
		// The team attestation sat inside the encrypted manifest, so only a
		// holder of the recovery words could check it, and it was published
		// without being checked (F-064). The public attestation does the job.
		return backup.Options{}, nil, fail(exitUsage, "--attestation and --attestation-key were removed in v1.1.6. Use --attest for a public attestation (see xrplbak attest-key). Backups made with them still verify")
	}
	return o, att, nil
}

// runBackup binds the plan to the ledger when an RPC server is named, then
// submits with --submit or prints the dry run.
func runBackup(f *backupFlags, o backup.Options, att *attestKey, kf *crypto.KeyFile, writer *sign.Key, keyPath, settingsPath string, settingsExist bool) error {
	var warns []string
	if f.submit || f.rpcURL != "" {
		client, source, err := openClient(f.rpcURL, "")
		if err != nil {
			return err
		}
		var seqErr error
		warns, seqErr = bindPlan(&o, client, kf, writer.Address())
		if f.submit {
			if errors.Is(seqErr, backup.ErrLastSeq) {
				// --force-seq would submit seq 1 in the same epoch, which
				// sorts below every backup already there.
				return fail(exitRefused, "%v", seqErr)
			}
			if seqErr != nil && !f.forceSeq {
				return fail(exitNetwork, "could not read existing backups (%v). Fix the server or pass --force-seq to submit as seq 1 anyway", seqErr)
			}
			x := submitExtras{FeeWait: f.feeWait, ReadBack: !f.noReadBack, Save: f.save, SettingsPath: settingsPath, SettingsExist: settingsExist,
				Settings: settings{RPC: f.rpcURL, MaxFee: f.maxFee, Comments: f.comments, Peers: f.peers}}
			return doSubmit(o, client, source, writer, f.out, f.maxFee, f.deleteAnchor, f.yes, f.batch, f.attestPubKey, f.attestPubSig, warns, att, f.delegSig, f.rpcURL, keyPath, x)
		}
	}
	if att != nil {
		hr("Delegated attestation")
		fmt.Fprintf(stdout, "  key:        dseq %d for validator %s\n", att.DSeq, att.VPK)
		if f.delegSig == "" {
			fmt.Fprintln(stdout, "  The delegation must already be on the ledger, or pass --attest-delegation-sig to publish it with this backup.")
		}
	}
	return doDryRun(o, warns, f.out)
}

func planReport(p *backup.Plan, o backup.Options) {
	m := p.Manifest
	hr("Plan")
	fmt.Fprintf(stdout, "  backup id:   %s\n", m.BackupID)
	fmt.Fprintf(stdout, "  epoch/seq:   %d / %d", m.Epoch, m.Seq)
	if m.Supersedes != "" {
		fmt.Fprintf(stdout, "  (supersedes %s)", m.Supersedes[:16])
	}
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "  role:        %s\n", p.Role)
	for _, f := range m.Files {
		fmt.Fprintf(stdout, "  file:        %s  (%s)\n", f.Path, f.Where)
	}
	if m.Tombstone {
		fmt.Fprintln(stdout, "  tombstone:   yes. No data will be stored.")
		return
	}
	hr("Redactions (kept only in the off-chain bundle)")
	summarizeMoves(p.Moves)
	hr("On-chain")
	// One transaction per chunk, per manifest part and for the DID anchor.
	// The part count is a projection the sealed manifest may undercut by
	// one, so the figure is a ceiling. Batches (XLS-56) cost (inner + 2)
	// base fees each; backup.BaseFees knows the layout Submit uses.
	c, k := len(p.Chunks), p.ManifestParts
	fmt.Fprintf(stdout, "  %d chunk transaction(s) + %d manifest part(s) + DID anchor: %d transactions, up to %d drops in fees at the base rate (%d drops with --batch)\n", c, k, c+k+1, backup.BaseFees(c, k, false)*10, backup.BaseFees(c, k, true)*10)
	for i, c := range p.Chunks {
		sum := sha256.Sum256(c)
		fmt.Fprintf(stdout, "  chunk %d: %d bytes ciphertext, sha256 %s\n", i+1, len(c), hex.EncodeToString(sum[:8]))
	}
	hr("Off-chain bundle")
	fmt.Fprintf(stdout, "  %d bytes encrypted. Keep it in two places. Its hash is in the manifest.\n", len(p.Bundle))
	if p.AttestPublicText != "" {
		hr("Public attestation (optional, on-chain, cleartext)")
		fmt.Fprintln(stdout, "  This publishes, in the clear and permanently, that your validator")
		fmt.Fprintln(stdout, "  key vouches for this account's backups. The key is already public;")
		fmt.Fprintln(stdout, "  the link between it and this account is what becomes public.")
		fmt.Fprintln(stdout, "  Sign this exact string offline with validator-keys sign, then pass")
		fmt.Fprintln(stdout, "  --attest-public-sig:")
		fmt.Fprintln(stdout, "  "+p.AttestPublicText)
	}
}

func doDryRun(o backup.Options, warns []string, out string) error {
	p, err := backup.Build(o)
	if err != nil {
		return err
	}
	planReport(p, o)
	for _, w := range warns {
		fmt.Fprintln(stdout, "  NOTE:", w)
	}
	if err := writeBundle(p, out); err != nil {
		return err
	}
	hr("Dry run")
	fmt.Fprintln(stdout, "  Nothing was submitted. Re-run with --submit --rpc <mainnet|URL> to write this backup to the ledger.")
	return nil
}

func writeBundle(p *backup.Plan, out string) error {
	if p.Manifest.Tombstone {
		return nil
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}
	path := filepath.Join(out, p.Manifest.BackupID+".bundle")
	if err := os.WriteFile(path, p.Bundle, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "  bundle written: %s\n", path)
	return nil
}

func doSubmit(o backup.Options, client xrpl.Client, source string, writer *sign.Key, out string, maxFee uint64, deleteAnchor, yes bool, batch, attestPubKey, attestPubSig string, warns []string, att *attestKey, delegSig, rpcArg, keyPath string, x submitExtras) error {
	if o.Tombstone && (attestPubKey != "" || attestPubSig != "" || att != nil || o.AttestPublicVPK != "") {
		return fail(exitUsage, "a tombstone carries no attestation; drop --attest and --attest-public-key")
	}
	if deleteAnchor && !o.Tombstone {
		return fail(exitUsage, "--delete-anchor needs --tombstone")
	}
	p, err := backup.Build(o)
	if err != nil {
		return err
	}
	planReport(p, o)
	attestMemo, delegMemo, err := attestationMemos(client, writer, p, att, delegSig, attestPubKey, attestPubSig)
	if err != nil {
		return err
	}
	useBatch, err := confirmSubmit(client, source, writer, batch, warns, yes)
	if err != nil {
		return err
	}
	dumpPath, err := runSubmit(o, p, client, writer, out, maxFee, deleteAnchor, useBatch, attestMemo, delegMemo, x)
	if err != nil {
		return err
	}
	tip, err := printDone(p, out, dumpPath, source, rpcArg, keyPath, writer, att, attestMemo, delegMemo)
	if err != nil {
		return err
	}
	if x.ReadBack && !p.Manifest.Tombstone {
		if err := finishReadBack(client, o, writer, p, tip); err != nil {
			return err
		}
	}
	return saveOrHint(x)
}

// attestationMemos builds the delegation and attestation memos the run
// publishes, if any. A public attestation signed by the master key is
// checked before it is published: it is permanent.
func attestationMemos(client xrpl.Client, writer *sign.Key, p *backup.Plan, att *attestKey, delegSig, attestPubKey, attestPubSig string) (attestMemo, delegMemo *codec.Memo, err error) {
	if att != nil {
		dm, am, err := delegatedMemos(client, writer.Address(), att, delegSig, p)
		if err != nil {
			return nil, nil, err
		}
		delegMemo, attestMemo = dm, am
	}
	if attestPubSig != "" {
		m, err := pubattest.Memo(attestPubKey, p.Manifest.Epoch, p.Manifest.Seq, p.Manifest.BackupID, attestPubSig)
		if err != nil {
			return nil, nil, fail(exitUsage, "%v", err)
		}
		// An attestation is permanent. Refuse one that would read as INVALID
		// to every third party. The string changes with the backup
		// id, so a signature from an earlier dry run goes stale as soon as
		// another backup lands in between.
		if !pubattest.Check(attestPubKey, writer.Address(), p.Manifest.Epoch, p.Manifest.Seq, p.Manifest.BackupID, attestPubSig) {
			return nil, nil, fail(exitUsage, "--attest-public-sig does not verify under %s for this backup; sign this exact string offline and pass the result:\n  %s", attestPubKey, p.AttestPublicText)
		}
		attestMemo = &m
	} else if attestPubKey != "" {
		fmt.Fprintln(stdout, "  NOTE: no --attest-public-sig given, so no public attestation is published this run")
	}
	return attestMemo, delegMemo, nil
}

// confirmSubmit prints the warnings and the submit summary, decides
// whether to batch, and asks before anything is sent unless --yes.
func confirmSubmit(client xrpl.Client, source string, writer *sign.Key, batch string, warns []string, yes bool) (bool, error) {
	for _, w := range warns {
		fmt.Fprintln(stdout, "  WARNING:", w)
	}
	useBatch, batchNote, err := decideBatch(client, batch)
	if err != nil {
		return false, fail(exitNetwork, "%v", err)
	}
	hr("Submit")
	fmt.Fprintf(stdout, "  server:  %s\n", source)
	fmt.Fprintf(stdout, "  account: %s\n", writer.Address())
	fmt.Fprintf(stdout, "  batch:   %s\n", batchNote)
	if !yes && !confirm("  Submit these transactions?") {
		return false, fail(exitUsage, "cancelled; nothing was submitted. In a script, pass --yes to answer this up front")
	}
	return useBatch, nil
}

// runSubmit sends the backup, resuming from a dump of the same backup
// when one is there, deletes the anchor when asked, and writes the
// bundle. It returns the dump path.
func runSubmit(o backup.Options, p *backup.Plan, client xrpl.Client, writer *sign.Key, out string, maxFee uint64, deleteAnchor, useBatch bool, attestMemo, delegMemo *codec.Memo, x submitExtras) (string, error) {
	if err := os.MkdirAll(out, 0o700); err != nil {
		return "", err
	}
	dumpPath := filepath.Join(out, p.Manifest.BackupID+".dump.json")
	s := &backup.Submitter{Client: client, Writer: writer, Key: o.Key, MaxFee: maxFee, FeeWait: x.FeeWait, Sleep: submitSleep, DumpOut: dumpPath, Batch: useBatch, AttestMemo: attestMemo, DelegationMemo: delegMemo, Log: func(f string, a ...any) { fmt.Fprintf(stdout, "  "+f+"\n", a...) }}
	prev, err := loadResume(dumpPath, p.Manifest.BackupID)
	if err != nil {
		return "", fail(exitRefused, "%v", err)
	}
	if prev != nil {
		s.Dump = prev
		fmt.Fprintf(stdout, "  resuming from %s (%d transaction(s) already validated)\n", dumpPath, len(prev.Txs))
	}
	if err := s.Submit(p); err != nil {
		if s.Dump != nil && len(s.Dump.Txs) > 0 {
			fmt.Fprintf(stdout, "  partial progress saved in %s; re-run the same command to resume\n", dumpPath)
		}
		return "", fail(exitNetwork, "%v", err)
	}
	if o.Tombstone && deleteAnchor {
		fmt.Fprintln(stdout, "  deleting DID anchor")
		if err := s.DeleteAnchor(); err != nil {
			return "", fail(exitNetwork, "%v", err)
		}
	}
	if err := writeBundle(p, out); err != nil {
		return "", err
	}
	return dumpPath, nil
}

// printDone prints what landed, how to verify it, and the copy hint. It
// returns the verify command, which the read-back names if it cannot
// finish.
func printDone(p *backup.Plan, out, dumpPath, source, rpcArg, keyPath string, writer *sign.Key, att *attestKey, attestMemo, delegMemo *codec.Memo) (string, error) {
	hr("Done")
	fmt.Fprintf(stdout, "  dump written:   %s (offline restore source; contains ciphertext only)\n", dumpPath)
	fmt.Fprintln(stdout, "  keep safe:      the bundle file, the dump file, your recovery words or shares, and the account address")
	if delegMemo != nil {
		fmt.Fprintf(stdout, "  delegation:     published for attestation key %d\n", att.DSeq)
	}
	switch {
	case attestMemo != nil && att != nil:
		fmt.Fprintf(stdout, "  attestation:    published, signed by delegated attestation key %d. Check it: xrplbak attest-verify --rpc %s --account %s\n", att.DSeq, verifyRPC(rpcArg, source), writer.Address())
	case attestMemo != nil:
		fmt.Fprintf(stdout, "  attestation:    published, signed by the validator master key. Check it: xrplbak attest-verify --rpc %s --account %s\n", verifyRPC(rpcArg, source), writer.Address())
	}
	tip := "xrplbak verify --rpc " + verifyRPC(rpcArg, source)
	if keyPath != "" {
		tip += " --key " + keyPath
	}
	if !p.Manifest.Tombstone {
		tip += " --bundle " + filepath.Join(out, p.Manifest.BackupID+".bundle")
	}
	fmt.Fprintln(stdout, "  verify anytime: "+tip)
	if p.Manifest.Tombstone {
		return tip, nil
	}
	// The bundle is the only copy of what stays off the ledger, the
	// validator token among it. A host that dies with it takes it along.
	fmt.Fprintln(stdout, "  copy both files off this host now, then check each copy's sha256:")
	for _, f := range []string{filepath.Join(out, p.Manifest.BackupID+".bundle"), dumpPath} {
		abs, err := filepath.Abs(f)
		if err != nil {
			return "", err
		}
		raw, err := os.ReadFile(filepath.Clean(abs))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(stdout, "    %s  %s\n", sha256hex(raw), abs)
	}
	return tip, nil
}

// finishReadBack reads the new backup back from the ledger. A network
// failure there is not a failed backup: the error names the command that
// finishes the check.
func finishReadBack(client xrpl.Client, o backup.Options, writer *sign.Key, p *backup.Plan, tip string) error {
	hr("Read-back")
	n, err := readBack(client, o.Key, writer.Address(), p)
	if err != nil {
		var ee *exitError
		if errors.As(err, &ee) && ee.code == exitNetwork {
			return fail(exitNetwork, "the backup was submitted, but the read-back could not finish: %v. Finish the check with: %s", err, tip)
		}
		return err
	}
	fmt.Fprintf(stdout, "  read-back: PASS, %d file(s) byte-identical to what was backed up\n", n)
	warnChangedFiles(p)
	return nil
}

// saveOrHint saves the settings with --save, or says --save exists when
// the run used settings worth saving.
func saveOrHint(x submitExtras) error {
	switch {
	case x.Save:
		if err := saveSettings(x.SettingsPath, x.Settings); err != nil {
			return fail(exitWrite, "the backup landed, but %s could not be saved: %v", x.SettingsPath, err)
		}
		fmt.Fprintf(stdout, "  settings saved: %s. Next time, run: xrplbak backup --submit\n", x.SettingsPath)
	case !x.SettingsExist && x.Settings.customized():
		fmt.Fprintln(stdout, "  next time:      add --save to remember --rpc, --max-fee, --comments and --peers")
	}
	return nil
}

// verifyRPC is the --rpc value to print in a hint: the operator's own
// word (mainnet, testnet) when they gave one, else the server URL.
func verifyRPC(rpcArg, source string) string {
	if rpcArg != "" {
		return rpcArg
	}
	return strings.Fields(source)[0]
}

// batchFlagHelp: the atomic path is the default wherever the ledger offers
// it. "off" is for a server whose feature RPC lies, or for testing the
// one-transaction path; "on" refuses to run without it.
const batchFlagHelp = "wrap the transactions in an all-or-nothing Batch (XLS-56): auto (when the server has the amendment, the default), on (refuse otherwise), off"

// decideBatch turns the --batch flag and the server's amendment list into a
// yes or no, with the sentence the operator sees. Unknown reads as no: an
// answer the tool cannot get is not a reason to guess.
func decideBatch(client xrpl.Client, flag string) (bool, string, error) {
	if flag == "off" {
		return false, "no (--batch=off); one transaction at a time", nil
	}
	enabled, err := client.AmendmentEnabled(xrpl.AmendmentBatchV1_1)
	switch {
	case err != nil && flag == "on":
		return false, "", fmt.Errorf("--batch=on but the server's amendment list could not be read: %v", err)
	case err != nil:
		return false, fmt.Sprintf("no; the server's amendment list could not be read (%v); one transaction at a time", err), nil
	case !enabled && flag == "on":
		return false, "", errors.New("--batch=on but this server does not have the Batch amendment (BatchV1_1) enabled")
	case !enabled:
		return false, "no; this server does not have the Batch amendment enabled; one transaction at a time", nil
	}
	return true, "yes; all-or-nothing, the manifest and the anchor land together or not at all", nil
}

// commentsFlagHelp documents the one choice the operator has about their own
// prose. Comments are kept either way; this says where.
const commentsFlagHelp = "where the operator's comments go: bundle (off-chain, the default) or onchain"

// ackPhrase is what the operator types to put comments on a public ledger.
const ackPhrase = "PUBLISH COMMENTS"

// commentsMode reads the --comments flag. Choosing onchain means the
// comments go into the on-chain ciphertext, which is public, permanent, and
// readable by anyone who ever gets the key, so it is confirmed by hand. The
// confirmation is skipped for redact, which encrypts and publishes nothing.
func commentsMode(v string, confirm bool) (redact.Mode, error) {
	switch v {
	case "bundle":
		return redact.CommentsToBundle, nil
	case "onchain":
		if !confirm {
			return redact.CommentsOnChain, nil
		}
		fmt.Fprintf(stdout, "--comments=onchain puts every comment in your config into the on-chain\nciphertext. That is a public ledger: the bytes are permanent, and anyone\nwho ever obtains the backup key can read them. Comments are kept either\nway; the default keeps them in the off-chain bundle instead.\n\n")
		if got := prompt("Type " + ackPhrase + " to continue: "); got != ackPhrase {
			return 0, fail(exitUsage, "--comments=onchain was not confirmed; nothing was submitted")
		}
		fmt.Fprintf(stdout, "  acknowledged: comments will be written on-chain\n")
		return redact.CommentsOnChain, nil
	}
	return 0, fail(exitUsage, "--comments must be bundle or onchain, not %q", v)
}

// peersFlagHelp documents where [ips_fixed] goes.
const peersFlagHelp = "where [ips_fixed] goes: bundle (off-chain, the default) or onchain; private addresses and internal names move to the bundle either way"

// peersAckPhrase is what the operator types to put fixed peers on a public ledger.
const peersAckPhrase = "PUBLISH PEERS"

// peersMode reads the --peers flag. Choosing onchain puts the public lines
// of [ips_fixed] into the on-chain ciphertext, which is permanent and
// readable by anyone who ever gets the key, so it is confirmed by hand. The
// confirmation is skipped for redact, which encrypts and publishes nothing.
func peersMode(v string, confirm bool) (bool, error) {
	switch v {
	case "bundle":
		return false, nil
	case "onchain":
		if !confirm {
			return true, nil
		}
		fmt.Fprintf(stdout, "--peers=onchain puts the public lines of [ips_fixed] into the on-chain\nciphertext. That is a public ledger: the bytes are permanent, and anyone\nwho ever obtains the backup key can read which peers this server pins.\nPrivate addresses and internal names still go to the off-chain bundle.\n\n")
		if got := prompt("Type " + peersAckPhrase + " to continue: "); got != peersAckPhrase {
			return false, fail(exitUsage, "--peers=onchain was not confirmed; nothing was submitted")
		}
		fmt.Fprintf(stdout, "  acknowledged: public fixed peers will be written on-chain\n")
		return true, nil
	}
	return false, fail(exitUsage, "--peers must be bundle or onchain, not %q", v)
}

// delegatedMemos builds the memos for a delegated attestation and refuses to
// publish one that a third party would read as invalid. It judges the
// result with the same rules attest-verify uses: the account's history plus
// the anchor transaction about to be sent must yield a valid attestation.
// A missing delegation, a signature that does not verify, or a key already
// replaced by a higher dseq all stop the run before anything is submitted.
func delegatedMemos(client xrpl.Client, account string, att *attestKey, delegSig string, p *backup.Plan) (*codec.Memo, *codec.Memo, error) {
	var memos []codec.Memo
	var deleg *codec.Memo
	delegString := pubattest.DelegationString(att.VPK, account, att.pub(), att.DSeq)
	if delegSig != "" {
		if !pubattest.CheckDelegation(att.VPK, account, att.pub(), att.DSeq, delegSig) {
			return nil, nil, fail(exitUsage, "--attest-delegation-sig does not verify under %s; sign this exact string offline and pass the result:\n  %s", att.VPK, delegString)
		}
		m, err := pubattest.DelegationMemo(att.VPK, att.pub(), att.DSeq, delegSig)
		if err != nil {
			return nil, nil, fail(exitUsage, "%v", err)
		}
		deleg = &m
		memos = append(memos, m)
	}
	am, err := pubattest.DelegatedMemo(att.VPK, account, att.Priv, att.DSeq, p.Manifest.Epoch, p.Manifest.Seq, p.Manifest.BackupID)
	if err != nil {
		return nil, nil, fail(exitUsage, "%v", err)
	}
	memos = append(memos, am)
	txs, _, err := client.AccountTx(account)
	if err != nil {
		return nil, nil, fail(exitNetwork, "account_tx for %s: %v", account, err)
	}
	var top uint32
	for _, t := range txs {
		if t.LedgerIndex > top {
			top = t.LedgerIndex
		}
	}
	next := append(append([]xrpl.TxRecord(nil), txs...), xrpl.TxRecord{Account: account, LedgerIndex: top + 1, Result: "tesSUCCESS", Memos: memos})
	if f := pubattest.EvaluateNewest(next, account); f.Status != pubattest.Valid {
		if deleg == nil && strings.Contains(f.Reason, "no valid delegation") {
			return nil, nil, fail(exitUsage, "no delegation for attestation key dseq %d is on the ledger yet. Sign this exact string offline with validator-keys sign and pass --attest-delegation-sig <hex>:\n  %s", att.DSeq, delegString)
		}
		return nil, nil, fail(exitAuth, "this attestation would not verify (%s); nothing was submitted", f.Reason)
	}
	return deleg, &am, nil
}

// loadResume reads the progress file of an earlier run of this backup. No
// file means a first run. A file that cannot be read, or that belongs to
// another backup, is refused: starting over would overwrite it and send
// again what the ledger may already hold.
func loadResume(path, backupID string) (*dump.Dump, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	prev, err := dump.Load(path)
	if err != nil {
		return nil, fmt.Errorf("%s is the progress file of an earlier run of this backup and cannot be read (%v). Nothing was sent. Move the file aside to start this backup over; transactions the earlier run sent stay on the ledger", path, err)
	}
	if prev.BackupID != backupID {
		return nil, fmt.Errorf("%s holds backup %s, not this one. Nothing was sent. Move the file aside and retry", path, prev.BackupID)
	}
	return prev, nil
}
