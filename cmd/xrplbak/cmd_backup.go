package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/justinnevins/xrplbak/internal/backup"
	"github.com/justinnevins/xrplbak/internal/cfg"
	"github.com/justinnevins/xrplbak/internal/dump"
	"github.com/justinnevins/xrplbak/internal/manifest"
	"github.com/justinnevins/xrplbak/internal/redact"
	"github.com/justinnevins/xrplbak/internal/xrpl"
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
	if err := fs.Parse(args); err != nil {
		return parseError(err)
	}

	mode, err := commentsMode(*comments, false)
	if err != nil {
		return err
	}
	cfgPath, err := findConfig(*config)
	if err != nil {
		return err
	}
	paths := []string{cfgPath}
	if v := findValidators(*validators, cfgPath); v != "" {
		paths = append(paths, v)
	}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		res, err := redact.Split(cfg.Parse(string(raw)), redact.Options{Comments: mode})
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

func cmdBackup(args []string) error {
	fs := newFlags("backup", "plan a backup; --submit writes it to the ledger")
	config := fs.String("config", "", "path to xrpld.cfg or rippled.cfg (default: auto-detect)")
	validators := fs.String("validators", "", "path to validators.txt (default: from [validators_file] or beside the config)")
	var includes multiFlag
	fs.Var(&includes, "include", "extra file for the off-chain bundle (repeatable). Key material is refused")
	key := fs.String("key", "", "path to xrplbak.key (default: next to the config, then ./xrplbak.key)")
	keyPass := fs.Bool("key-passphrase", false, "prompt for the key file passphrase")
	out := fs.String("out", "xrplbak-out", "directory for the bundle, dump, and report")
	rpcURL := fs.String("rpc", "", "XRPL JSON-RPC URL, or mainnet / testnet / devnet")
	submit := fs.Bool("submit", false, "actually submit transactions (default is a dry run). Asks before submitting; pass --yes to answer up front")
	yes := fs.Bool("yes", false, "answer the submit confirmation with yes, for scripts")
	maxFee := fs.Uint64("max-fee", 5000, "abort if the network fee per transaction exceeds this many drops")
	tombstone := fs.Bool("tombstone", false, "publish a tombstone that marks earlier backups as retired")
	deleteAnchor := fs.Bool("delete-anchor", false, "with --tombstone: also delete the DID entry (frees 0.2 XRP)")
	forceSeq := fs.Bool("force-seq", false, "submit even when existing backups could not be read (risks a duplicate seq)")
	vpk := fs.String("validator-key", "", "validator public key (nHB...) to bind, stored only as a hash inside the ciphertext")
	attest := fs.String("attestation", "", "hex signature over the attest string, made offline with validator-keys sign")
	attestVPK := fs.String("attestation-key", "", "validator public key (nHB...) that made the attestation")
	comments := fs.String("comments", "bundle", commentsFlagHelp)
	batch := fs.String("batch", "auto", batchFlagHelp)
	if err := fs.Parse(args); err != nil {
		return parseError(err)
	}

	mode, err := commentsMode(*comments, true)
	if err != nil {
		return err
	}
	switch *batch {
	case "auto", "on", "off":
	default:
		return fail(exitUsage, "--batch must be auto, on or off, not %q", *batch)
	}
	cfgPath, err := findConfig(*config)
	if err != nil {
		return err
	}
	keyPath, err := findKeyFile(*key, cfgPath)
	if err != nil {
		return err
	}
	kf, err := loadKeyFile(keyPath, *keyPass)
	if err != nil {
		return err
	}
	writer, err := sign.KeyFromSeed(kf.WriterSeed[:])
	if err != nil {
		return err
	}
	if writer.AccountID() == nil || sign.EncodeAddress(kf.AccountID[:]) != writer.Address() {
		return fail(exitAuth, "key file is inconsistent: writer seed does not match the stored account")
	}
	o := backup.Options{ConfigPath: cfgPath, ValidatorsPath: findValidators(*validators, cfgPath), Includes: includes, Key: kf, Tombstone: *tombstone, Seq: 1, Comments: mode}
	if *vpk != "" {
		pub, err := sign.DecodeNodePublic(*vpk)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(pub)
		o.VPKSHA256 = hex.EncodeToString(sum[:])
	}
	if (*attest == "") != (*attestVPK == "") {
		return fail(exitUsage, "--attestation and --attestation-key go together")
	}
	if *attest != "" {
		if _, err := sign.DecodeNodePublic(*attestVPK); err != nil {
			return err
		}
		if _, err := hex.DecodeString(*attest); err != nil {
			return fail(exitUsage, "--attestation must be hex")
		}
		o.Attestation = &manifest.Attestation{Scheme: "ed25519", VPK: *attestVPK, Sig: strings.ToUpper(*attest)}
	}

	var warns []string
	if *submit || *rpcURL != "" {
		client, source, err := openClient(*rpcURL, "")
		if err != nil {
			return err
		}
		var seqErr error
		warns, seqErr = bindPlan(&o, client, kf, writer.Address())
		if *submit {
			if seqErr != nil && !*forceSeq {
				return fail(exitNetwork, "could not read existing backups (%v). Fix the server or pass --force-seq to submit as seq 1 anyway", seqErr)
			}
			return doSubmit(o, client, source, writer, *out, *maxFee, *deleteAnchor, *yes, *batch, warns)
		}
	}
	return doDryRun(o, warns, *out)
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
	fmt.Fprintf(stdout, "  %d chunk transaction(s) + manifest + DID anchor, about %d drops in fees at the base rate\n", len(p.Chunks), (len(p.Chunks)+2)*10)
	for i, c := range p.Chunks {
		sum := sha256.Sum256(c)
		fmt.Fprintf(stdout, "  chunk %d: %d bytes ciphertext, sha256 %s\n", i+1, len(c), hex.EncodeToString(sum[:8]))
	}
	hr("Off-chain bundle")
	fmt.Fprintf(stdout, "  %d bytes encrypted. Keep it in two places. Its hash is in the manifest.\n", len(p.Bundle))
	hr("Attestation (optional, team setups)")
	fmt.Fprintln(stdout, "  sign this exact string offline with validator-keys sign, then pass --attestation:")
	fmt.Fprintln(stdout, "  "+p.AttestText)
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

func doSubmit(o backup.Options, client xrpl.Client, source string, writer *sign.Key, out string, maxFee uint64, deleteAnchor, yes bool, batch string, warns []string) error {
	p, err := backup.Build(o)
	if err != nil {
		return err
	}
	planReport(p, o)
	for _, w := range warns {
		fmt.Fprintln(stdout, "  WARNING:", w)
	}
	useBatch, batchNote, err := decideBatch(client, batch)
	if err != nil {
		return fail(exitNetwork, "%v", err)
	}
	hr("Submit")
	fmt.Fprintf(stdout, "  server:  %s\n", source)
	fmt.Fprintf(stdout, "  account: %s\n", writer.Address())
	fmt.Fprintf(stdout, "  batch:   %s\n", batchNote)
	if !yes && !confirm("  Submit these transactions?") {
		return fail(exitUsage, "cancelled; nothing was submitted. In a script, pass --yes to answer this up front")
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}
	dumpPath := filepath.Join(out, p.Manifest.BackupID+".dump.json")
	s := &backup.Submitter{Client: client, Writer: writer, Key: o.Key, MaxFee: maxFee, DumpOut: dumpPath, Batch: useBatch, Log: func(f string, a ...any) { fmt.Fprintf(stdout, "  "+f+"\n", a...) }}
	if prev, err := dump.Load(dumpPath); err == nil && prev.BackupID == p.Manifest.BackupID {
		s.Dump = prev
		fmt.Fprintf(stdout, "  resuming from %s (%d transaction(s) already validated)\n", dumpPath, len(prev.Txs))
	}
	if err := s.Submit(p); err != nil {
		if s.Dump != nil && len(s.Dump.Txs) > 0 {
			fmt.Fprintf(stdout, "  partial progress saved in %s; re-run the same command to resume\n", dumpPath)
		}
		return fail(exitNetwork, "%v", err)
	}
	if o.Tombstone && deleteAnchor {
		fmt.Fprintln(stdout, "  deleting DID anchor")
		if err := s.DeleteAnchor(); err != nil {
			return fail(exitNetwork, "%v", err)
		}
	}
	if err := writeBundle(p, out); err != nil {
		return err
	}
	hr("Done")
	fmt.Fprintf(stdout, "  dump written:   %s (offline restore source; contains ciphertext only)\n", dumpPath)
	fmt.Fprintln(stdout, "  keep safe:      the bundle file, the dump file, your recovery words or shares, and the account address")
	fmt.Fprintln(stdout, "  verify anytime: xrplbak verify --rpc", strings.Fields(source)[0])
	return nil
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
