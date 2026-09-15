package main

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/justinnevins/xrplbak/internal/crypto"
	"github.com/justinnevins/xrplbak/internal/xrpl/sign"
)

func cmdInit(args []string) error {
	fs := newFlags("init", "create the recovery key, the host key file, and the writer account")
	out := fs.String("out", ".", "directory for xrplbak.key")
	shares := fs.Int("shares", 0, "split the recovery key into N shares (0 = 24 words instead)")
	threshold := fs.Int("threshold", 0, "shares needed to recover (default 2 when --shares is set)")
	passphrase := fs.Bool("key-passphrase", false, "protect xrplbak.key with a passphrase")
	yes := fs.Bool("yes", false, "skip the re-entry check (scripts only; not recommended)")
	rotate := fs.Bool("rotate", false, "advance the epoch of an existing key file (asks for the recovery words or shares)")
	wordsFile := fs.String("words-file", "", "with --rotate: file with the recovery words")
	sharesFile := fs.String("shares-file", "", "with --rotate: file with recovery shares, one per line")
	if err := fs.Parse(args); err != nil {
		return parseError(err)
	}

	keyPath := filepath.Join(*out, "xrplbak.key")
	if *rotate {
		return doRotate(keyPath, *wordsFile, *sharesFile, *passphrase)
	}
	if _, err := os.Stat(keyPath); err == nil {
		return fail(exitWrite, "%s already exists. Move it away first; init never overwrites a key file", keyPath)
	}
	if *shares > 0 && *threshold == 0 {
		*threshold = 2
	}

	root, err := crypto.NewRootKey()
	if err != nil {
		return err
	}
	writer, err := sign.NewKey()
	if err != nil {
		return err
	}

	hr("Recovery key")
	fmt.Fprintln(stdout, "Write this down on paper. It is the ONLY way to recover if this machine is lost.")
	fmt.Fprintln(stdout, "Do not store it on this host, in a screenshot, or in a password manager you would lose with the host.")
	fmt.Fprintln(stdout)
	var lines []string
	if *shares > 0 {
		lines, err = root.Split(*shares, *threshold)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%d shares, any %d recover the key. Give each share to a different person or place.\n\n", *shares, *threshold)
		for i, s := range lines {
			fmt.Fprintf(stdout, "  share %d of %d:  %s\n", i+1, *shares, s)
		}
	} else {
		words := root.ToWords()
		lines = words
		for i := 0; i < len(words); i += 6 {
			fmt.Fprintf(stdout, "  %2d. %-10s %2d. %-10s %2d. %-10s %2d. %-10s %2d. %-10s %2d. %-10s\n",
				i+1, words[i], i+2, words[i+1], i+3, words[i+2], i+4, words[i+3], i+5, words[i+4], i+6, words[i+5])
		}
	}
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "  writer account:  %s\n", writer.Address())
	fmt.Fprintln(stdout, "  epoch:           0")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Write the account address on the same paper. Restore needs the key AND the address.")

	if !*yes {
		if !checkReentry(lines, *shares > 0) {
			return fail(exitUsage, "re-entry check failed. Nothing was written. Run init again and copy carefully")
		}
	}

	kf := &crypto.KeyFile{Epoch: 0, Key: root.DeriveEpochKey(0)}
	copy(kf.AccountID[:], writer.AccountID())
	copy(kf.WriterSeed[:], writer.Seed())
	var b []byte
	if *passphrase {
		pw := prompt("Choose a passphrase for xrplbak.key: ")
		if pw != prompt("Repeat it: ") {
			return fail(exitUsage, "passphrases differ")
		}
		b, err = kf.EncodeWrapped([]byte(pw))
		if err != nil {
			return err
		}
	} else {
		b = kf.Encode()
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, b, 0o600); err != nil {
		return err
	}
	crypto.Zero(root[:])

	hr("Done")
	fmt.Fprintf(stdout, "  key file:  %s (mode 0600). It holds the epoch key and the writer seed, never the recovery key.\n", keyPath)
	fmt.Fprintf(stdout, "  next:      fund %s with at least 1.5 XRP from a fresh path (1 XRP base reserve + 0.2 XRP DID reserve + fees).\n", writer.Address())
	fmt.Fprintln(stdout, "  then:      xrplbak backup            (dry run, safe)")
	fmt.Fprintln(stdout, "             xrplbak backup --submit --rpc mainnet")
	return nil
}

// doRotate derives the next epoch key from the recovery key and rewrites
// the key file. The writer account stays the same. Use it after a host
// compromise: the thief keeps the old epoch, not the new one.
func doRotate(keyPath, wordsFile, sharesFile string, passphrase bool) error {
	b, err := os.ReadFile(keyPath)
	if err != nil {
		return fail(exitUsage, "no key file at %s to rotate", keyPath)
	}
	var pw []byte
	if crypto.IsWrapped(b) {
		pw = []byte(prompt("Current key file passphrase: "))
	}
	kf, err := crypto.DecodeKeyFile(b, pw)
	if err != nil {
		return fail(exitAuth, "%v", err)
	}
	_, root, err := recoveryKeys(wordsFile, sharesFile)
	if err != nil {
		return err
	}
	if root.DeriveEpochKey(kf.Epoch) != kf.Key {
		return fail(exitAuth, "the recovery key does not match this key file (epoch %d). Wrong words, or wrong key file", kf.Epoch)
	}
	next := &crypto.KeyFile{Epoch: kf.Epoch + 1, Key: root.DeriveEpochKey(kf.Epoch + 1), AccountID: kf.AccountID, WriterSeed: kf.WriterSeed}
	crypto.Zero(root[:])
	var out []byte
	if passphrase {
		p := prompt("Choose a passphrase for xrplbak.key: ")
		if p != prompt("Repeat it: ") {
			return fail(exitUsage, "passphrases differ")
		}
		out, err = next.EncodeWrapped([]byte(p))
		if err != nil {
			return err
		}
	} else {
		out = next.Encode()
	}
	old := keyPath + ".epoch" + strconv.FormatUint(uint64(kf.Epoch), 10)
	if err := os.Rename(keyPath, old); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, out, 0o600); err != nil {
		return err
	}
	hr("Rotated")
	fmt.Fprintf(stdout, "  key file:  %s is now epoch %d\n", keyPath, next.Epoch)
	fmt.Fprintf(stdout, "  old key:   moved to %s; delete it once the new epoch has a backup\n", old)
	fmt.Fprintln(stdout, "  next:      xrplbak backup --submit --rpc mainnet   (first backup of the new epoch is seq 1)")
	fmt.Fprintln(stdout, "  note:      restores with the recovery words find every epoch; the key file finds only its own")
	return nil
}

// checkReentry asks for three random words (or one full share) so a
// transcription error is caught before anything depends on it.
func checkReentry(lines []string, isShares bool) bool {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	fmt.Fprintln(stdout)
	if isShares {
		i := r.Intn(len(lines))
		got := prompt(fmt.Sprintf("Re-enter share %d of %d: ", i+1, len(lines)))
		norm := func(s string) string { return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(s)) }
		return norm(got) == norm(lines[i])
	}
	picks := r.Perm(len(lines))[:3]
	for _, i := range picks {
		got := prompt(fmt.Sprintf("Re-enter word %d: ", i+1))
		if !strings.EqualFold(strings.TrimSpace(got), lines[i]) {
			fmt.Fprintf(stdout, "  word %d does not match.\n", i+1)
			return false
		}
	}
	return true
}
