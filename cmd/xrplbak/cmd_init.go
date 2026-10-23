package main

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
	if *threshold != 0 && *shares == 0 {
		return fail(exitUsage, "--threshold only means something with --shares. Pass --shares N, or drop --threshold")
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

	release := func() {}
	if !*yes {
		// From here until the key file is written, a Ctrl-C would void
		// words the operator has already copied. The guard asks for a
		// second one before giving up.
		ch, stop := interrupts()
		done := make(chan struct{})
		go interruptGuard(ch, done)
		var once sync.Once
		release = func() { once.Do(func() { close(done); stop() }) }
		defer release()
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
	// The words are saved now. Ctrl-C goes back to stopping the process.
	release()

	if !*yes {
		what := "the 24 words"
		if *shares > 0 {
			what = "the shares"
		}
		if confirm(fmt.Sprintf("\nClear %s from this screen now? Do it once they are on paper.", what)) {
			// Home, erase the screen, erase the scrollback.
			fmt.Fprint(stdout, "\x1b[H\x1b[2J\x1b[3J")
		}
		fmt.Fprintf(stdout, "  note:      a terminal or SSH client may keep %s in its scrollback anyway. Close this window when you are done.\n", what)
	}

	hr("Done")
	fmt.Fprintf(stdout, "  key file:  %s (mode 0600). It holds the epoch key and the writer seed, never the recovery key.\n", keyPath)
	fmt.Fprintf(stdout, "  next:      fund %s with at least 1.5 XRP (1 XRP base reserve + 0.2 XRP DID reserve + fees).\n", writer.Address())
	fmt.Fprintln(stdout, "             The payment is public: anyone can see which account funded this one. Send it from an account you are content to link to this backup.")
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
	if kf.Epoch == math.MaxUint32 {
		// The next epoch would wrap to 0, a key an old key file may hold.
		return fail(exitRefused, "the key file is at the last epoch (%d) and cannot rotate. Run init for a new writer account and recovery key", kf.Epoch)
	}
	next := &crypto.KeyFile{Epoch: kf.Epoch + 1, Key: root.DeriveEpochKey(kf.Epoch + 1), AccountID: kf.AccountID, WriterSeed: kf.WriterSeed}
	crypto.Zero(root[:])
	var out []byte
	kept := false
	if passphrase {
		p := prompt("Choose a passphrase for xrplbak.key: ")
		if p != prompt("Repeat it: ") {
			return fail(exitUsage, "passphrases differ")
		}
		out, err = next.EncodeWrapped([]byte(p))
		if err != nil {
			return err
		}
	} else if pw != nil {
		// The key file was wrapped and the operator just typed its
		// passphrase. The new file holds the same writer seed, so it
		// keeps the same protection.
		out, err = next.EncodeWrapped(pw)
		if err != nil {
			return err
		}
		kept = true
	} else {
		out = next.Encode()
	}
	old, err := moveAside(keyPath, keyPath+".epoch"+strconv.FormatUint(uint64(kf.Epoch), 10))
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, out, 0o600); err != nil {
		return err
	}
	hr("Rotated")
	fmt.Fprintf(stdout, "  key file:  %s is now epoch %d\n", keyPath, next.Epoch)
	if kept {
		fmt.Fprintln(stdout, "  passphrase: the new key file uses the same passphrase. Pass --key-passphrase to choose a new one")
	}
	fmt.Fprintf(stdout, "  old key:   moved to %s; delete it once the new epoch has a backup\n", old)
	fmt.Fprintln(stdout, "  next:      xrplbak backup --submit --rpc mainnet   (first backup of the new epoch is seq 1)")
	fmt.Fprintln(stdout, "  note:      restores with the recovery words open every epoch; the key file opens only its own")
	return nil
}

// moveAside moves path to base, or to base.2, base.3 and so on when that
// name is taken. A hard link fails when the target exists, so no file is
// ever replaced, unlike a rename. It returns the name used.
func moveAside(path, base string) (string, error) {
	for i := 1; i <= 100; i++ {
		dst := base
		if i > 1 {
			dst = base + "." + strconv.Itoa(i)
		}
		err := os.Link(path, dst)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		return dst, os.Remove(path)
	}
	return "", fail(exitRefused, "%s and 99 numbered copies already exist; move some aside and rotate again", base)
}

// reentryAttempts is how many tries each word or share gets. Nothing is
// saved until the check passes, so a typo costs a retry, not the words
// already on paper.
const reentryAttempts = 3

// reentryPicks returns the order in which line indexes are asked for. A
// variable so tests can know which words the check will ask.
var reentryPicks = func(n int) []int {
	return rand.New(rand.NewSource(time.Now().UnixNano())).Perm(n)
}

// checkReentry asks for three random words (or one full share) so a
// transcription error is caught before anything depends on it.
func checkReentry(lines []string, isShares bool) bool {
	fmt.Fprintln(stdout)
	picks := reentryPicks(len(lines))
	if isShares {
		picks = picks[:1]
	} else {
		picks = picks[:3]
	}
	for _, i := range picks {
		label := fmt.Sprintf("Re-enter word %d: ", i+1)
		name := fmt.Sprintf("word %d", i+1)
		match := func(got string) bool { return strings.EqualFold(strings.TrimSpace(got), lines[i]) }
		if isShares {
			label = fmt.Sprintf("Re-enter share %d of %d: ", i+1, len(lines))
			name = fmt.Sprintf("share %d", i+1)
			match = func(got string) bool { return sameShare(got, lines[i]) }
		}
		for try := 1; ; try++ {
			fmt.Fprint(stdout, label)
			got, ok := readLine()
			if !ok {
				fmt.Fprintln(stdout, "\n  no input.")
				return false
			}
			if match(got) {
				break
			}
			if try == reentryAttempts {
				fmt.Fprintf(stdout, "  %s does not match, %d times.\n", name, reentryAttempts)
				return false
			}
			fmt.Fprintf(stdout, "  %s does not match. Nothing is saved yet, and the words on your paper are still the right ones.\n", name)
			fmt.Fprintf(stdout, "  Check the paper against the screen above, fix it if it differs, and try again (%d left).\n", reentryAttempts-try)
		}
	}
	return true
}

// interrupts delivers Ctrl-C to init's guard. A variable so tests can send
// one without signalling the test process.
var interrupts = func() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	return ch, func() { signal.Stop(ch) }
}

// exitNow ends the process. A variable so tests can observe the exit.
var exitNow = os.Exit

// interruptGuard runs while init holds recovery words that are printed but
// not yet saved. A Ctrl-C there used to kill the process and void words the
// operator had already written down; a terminal user can press it by habit,
// or to copy. The first Ctrl-C only explains. The second stops, and says
// plainly that nothing was saved.
func interruptGuard(ch <-chan os.Signal, done <-chan struct{}) {
	select {
	case <-ch:
	case <-done:
		return
	}
	fmt.Fprintln(stdout, "\n  Ctrl-C does not stop init here, so the words on your paper stay valid.")
	fmt.Fprintln(stdout, "  Keep going with the question above. Press Ctrl-C again to quit without saving.")
	select {
	case <-ch:
	case <-done:
		return
	}
	fmt.Fprintln(stdout, "\n  Stopped. Nothing was saved. Cross out the words above: they will never be used.")
	exitNow(exitUsage)
}

// sameShare compares a re-entered share with the one that was printed, using
// the decoder's own rules. A share is copied off paper by hand, so
// crypto.NormalizeShare folds the characters people confuse. Keeping a
// second, stricter comparator here meant the check could reject a re-entry
// the decoder would have accepted.
func sameShare(got, want string) bool {
	return crypto.NormalizeShare(got) == crypto.NormalizeShare(want)
}
