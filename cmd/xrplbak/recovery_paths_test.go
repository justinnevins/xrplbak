package main

// Twenty-one recovery-path cases: the ways an operator can go wrong while
// recovering, under pressure, after losing a host. Each case is proven by
// mutation, breaking the guard it exists for and confirming the case goes
// red, rather than by a captured failing run.
//
// These paths are walked once, under pressure. They are cheap to keep and
// expensive to rediscover.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/crypto"
)

// ---------------------------------------------------------------------
// Recovery words
// ---------------------------------------------------------------------

// wordsWorld returns a world plus its correct 24 words.
func wordsWorld(t *testing.T) (*world, []string) {
	t.Helper()
	w := newWorld(t, 0)
	return w, w.root.ToWords()
}

// writeWords puts text at a fresh path inside the world and returns it.
func writeWords(t *testing.T, w *world, name, text string) string {
	t.Helper()
	p := filepath.Join(w.dir, name)
	must(t, os.WriteFile(p, []byte(text), 0o600))
	return p
}

// restoreWithWords runs a dry-run restore reading the recovery key from a
// words file. It is the whole recovery path, not just the parser.
func restoreWithWords(w *world, wordsPath string) result {
	return w.run("", "restore", "--dump", w.dumpFile("case"),
		"--words-file", wordsPath, "--account", w.writer.Address(), "--bundle", w.bundle)
}

// TestTwentyFiveWordsAreRefused. A miscount is the likeliest transcription
// error there is, and 25 words must not be truncated to 24 and used.
func TestTwentyFiveWordsAreRefused(t *testing.T) {
	w, words := wordsWorld(t)
	p := writeWords(t, w, "w25.txt", strings.Join(append(words, words[0]), " ")+"\n")
	r := restoreWithWords(w, p)
	if r.code != exitAuth {
		t.Fatalf("exit %d, want %d (25 words must be refused):\n%s", r.code, exitAuth, r.out)
	}
	if !strings.Contains(r.out, "expected 24 words") {
		t.Fatalf("the message does not say how many words were expected:\n%s", r.out)
	}
}

// TestShuffledWordsFailTheChecksum. Every word is in the list and the count
// is right; only the order is wrong. The BIP39 checksum is the only thing
// standing between that and a silently different key.
func TestShuffledWordsFailTheChecksum(t *testing.T) {
	w, words := wordsWorld(t)
	sw := append([]string(nil), words...)
	i := swapIndex(t, sw)
	sw[0], sw[i] = sw[i], sw[0]
	p := writeWords(t, w, "wshuffle.txt", strings.Join(sw, " ")+"\n")
	r := restoreWithWords(w, p)
	if r.code != exitAuth {
		t.Fatalf("exit %d, want %d (a shuffled mnemonic must not authenticate):\n%s", r.code, exitAuth, r.out)
	}
	if !strings.Contains(r.out, "checksum mismatch") {
		t.Fatalf("the message does not name the checksum:\n%s", r.out)
	}
}

// swapIndex finds a word that differs from the first one.
func swapIndex(t *testing.T, words []string) int {
	t.Helper()
	for i := 1; i < len(words); i++ {
		if words[i] != words[0] {
			return i
		}
	}
	t.Fatal("this mnemonic is 24 copies of one word")
	return 0
}

// TestCyrillicLookalikeIsNamed. A word pasted from a rendered page can
// carry a Cyrillic a. It is not the same word and it must be rejected by
// position and by name, not with a checksum failure that sends the
// operator looking at the wrong thing.
func TestCyrillicLookalikeIsNamed(t *testing.T) {
	w, words := wordsWorld(t)
	idx := -1
	for i, x := range words {
		if strings.Contains(x, "a") {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Skip("no word in this mnemonic contains the letter a")
	}
	bad := append([]string(nil), words...)
	bad[idx] = strings.Replace(bad[idx], "a", "\u0430", 1)
	p := writeWords(t, w, "wcyrillic.txt", strings.Join(bad, " ")+"\n")
	r := restoreWithWords(w, p)
	if r.code != exitAuth {
		t.Fatalf("exit %d, want %d:\n%s", r.code, exitAuth, r.out)
	}
	if !strings.Contains(r.out, "is not in the BIP39 list") {
		t.Fatalf("a look-alike must be named, not folded into a checksum failure:\n%s", r.out)
	}
}

// TestCRLFWordsFileIsAccepted. The words get typed on the machine the
// operator still has, which may be Windows. One word per line with CRLF
// terminators must recover.
func TestCRLFWordsFileIsAccepted(t *testing.T) {
	w, words := wordsWorld(t)
	p := writeWords(t, w, "wcrlf.txt", strings.Join(words, "\r\n")+"\r\n")
	if r := restoreWithWords(w, p); r.code != exitOK {
		t.Fatalf("exit %d, want %d (a CRLF words file must recover):\n%s", r.code, exitOK, r.out)
	}
}

// TestWordsFileWithoutTrailingNewlineIsAccepted. Editors that do not add a
// final newline are common, and the last word must not be lost or merged.
func TestWordsFileWithoutTrailingNewlineIsAccepted(t *testing.T) {
	w, words := wordsWorld(t)
	p := writeWords(t, w, "wnonl.txt", strings.Join(words, " "))
	if r := restoreWithWords(w, p); r.code != exitOK {
		t.Fatalf("exit %d, want %d (no trailing newline must still recover):\n%s", r.code, exitOK, r.out)
	}
}

// TestMixedCaseWordsAreAccepted. Paper is transcribed with whatever case
// the operator writes in, and BIP39 words are case-insensitive.
func TestMixedCaseWordsAreAccepted(t *testing.T) {
	w, words := wordsWorld(t)
	mixed := make([]string, len(words))
	for i, x := range words {
		if i%2 == 0 {
			mixed[i] = strings.ToUpper(x)
		} else {
			mixed[i] = strings.Title(x) //nolint:staticcheck // ASCII words only
		}
	}
	p := writeWords(t, w, "wcase.txt", strings.Join(mixed, " ")+"\n")
	if r := restoreWithWords(w, p); r.code != exitOK {
		t.Fatalf("exit %d, want %d (mixed case must recover):\n%s", r.code, exitOK, r.out)
	}
}

// ---------------------------------------------------------------------
// Share bounds
// ---------------------------------------------------------------------

// initShares runs init with the given split and reports the result plus
// whether a key file survived. A refused split must write nothing.
func initShares(t *testing.T, args ...string) (int, string, bool) {
	t.Helper()
	dir := t.TempDir()
	var out strings.Builder
	code := run(append([]string{"init", "--out", dir, "--yes"}, args...),
		strings.NewReader(""), &out, &out)
	_, err := os.Stat(filepath.Join(dir, "xrplbak.key"))
	return code, out.String(), err == nil
}

// TestThresholdBelowTwoIsRefused. A threshold of one is not a split: every
// single share would be the whole key, while the operator believes the key
// is divided.
func TestThresholdBelowTwoIsRefused(t *testing.T) {
	code, out, wrote := initShares(t, "--shares", "3", "--threshold", "1")
	if code != exitUsage {
		t.Fatalf("exit %d, want %d:\n%s", code, exitUsage, out)
	}
	if wrote {
		t.Fatal("a refused split wrote a key file")
	}
}

// TestThresholdAboveShareCountIsRefused. Three shares that need four to
// recover are a key nobody can ever recover.
func TestThresholdAboveShareCountIsRefused(t *testing.T) {
	code, out, wrote := initShares(t, "--shares", "3", "--threshold", "4")
	if code != exitUsage {
		t.Fatalf("exit %d, want %d:\n%s", code, exitUsage, out)
	}
	if wrote {
		t.Fatal("a refused split wrote a key file")
	}
}

// TestShareCountAboveMaxIsRefused. MaxShares bounds the paper ceremony.
func TestShareCountAboveMaxIsRefused(t *testing.T) {
	code, out, wrote := initShares(t, "--shares", "17", "--threshold", "2")
	if code != exitUsage {
		t.Fatalf("exit %d, want %d (%d is above MaxShares=%d):\n%s", code, exitUsage, 17, crypto.MaxShares, out)
	}
	if wrote {
		t.Fatal("a refused split wrote a key file")
	}
}

// TestShareCountBelowTwoIsRefused. One share is not a split either, and the
// default threshold of two makes it unrecoverable rather than merely
// pointless.
func TestShareCountBelowTwoIsRefused(t *testing.T) {
	code, out, wrote := initShares(t, "--shares", "1")
	if code != exitUsage {
		t.Fatalf("exit %d, want %d:\n%s", code, exitUsage, out)
	}
	if wrote {
		t.Fatal("a refused split wrote a key file")
	}
}

// TestDuplicateSharesAreDetected. Two copies of one share look like two
// shares to a tired operator. Combining them must refuse rather than
// return a key that is not the key.
func TestDuplicateSharesAreDetected(t *testing.T) {
	root, err := crypto.NewRootKey()
	must(t, err)
	lines, err := root.Split(3, 2)
	must(t, err)
	if _, err := crypto.Combine([]string{lines[0], lines[0]}); err == nil {
		t.Fatal("two copies of one share combined into a key")
	}
}

// TestSharesBelowThresholdAreRefused. Shamir over GF(2^8) returns a
// plausible 32-byte answer from too few shares. The encoded threshold is
// what turns that into a refusal.
func TestSharesBelowThresholdAreRefused(t *testing.T) {
	root, err := crypto.NewRootKey()
	must(t, err)
	lines, err := root.Split(4, 3)
	must(t, err)
	got, err := crypto.Combine(lines[:2])
	if err == nil {
		t.Fatal("two of three shares combined without complaint")
	}
	if got != (crypto.RootKey{}) {
		t.Fatal("a refused combine returned key material")
	}
	if !strings.Contains(err.Error(), "need 3") {
		t.Fatalf("the message does not say how many shares are needed: %v", err)
	}
}

// ---------------------------------------------------------------------
// Rotation
// ---------------------------------------------------------------------

// rotateWorld writes a plain key file at epoch 0 for a known root, plus a
// correct and an incorrect words file. It returns the directory.
func rotateWorld(t *testing.T) (dir string, root crypto.RootKey, keyPath, good, bad string) {
	t.Helper()
	dir = t.TempDir()
	for i := range root {
		root[i] = byte(i) * 7
	}
	var other crypto.RootKey
	for i := range other {
		other[i] = byte(i)*7 + 1
	}
	kf := &crypto.KeyFile{Epoch: 0, Key: root.DeriveEpochKey(0)}
	keyPath = filepath.Join(dir, "xrplbak.key")
	must(t, os.WriteFile(keyPath, kf.Encode(), 0o600))
	good = filepath.Join(dir, "good.txt")
	must(t, os.WriteFile(good, []byte(strings.Join(root.ToWords(), " ")+"\n"), 0o600))
	bad = filepath.Join(dir, "bad.txt")
	must(t, os.WriteFile(bad, []byte(strings.Join(other.ToWords(), " ")+"\n"), 0o600))
	return dir, root, keyPath, good, bad
}

// TestRotateWithWrongWordsIsRefused. A valid mnemonic for a different key
// must not advance the epoch: doing so would destroy the only key that can
// read the existing backups.
func TestRotateWithWrongWordsIsRefused(t *testing.T) {
	dir, _, _, _, bad := rotateWorld(t)
	var out strings.Builder
	code := run([]string{"init", "--rotate", "--out", dir, "--words-file", bad},
		strings.NewReader(""), &out, &out)
	if code != exitAuth {
		t.Fatalf("exit %d, want %d:\n%s", code, exitAuth, out.String())
	}
	if !strings.Contains(out.String(), "does not match this key file") {
		t.Fatalf("the message does not say the recovery key is the mismatch:\n%s", out.String())
	}
}

// TestRotateRefusedLeavesTheKeyFileByteIdentical. The refusal above is only
// worth anything if nothing was written or renamed on the way to it.
func TestRotateRefusedLeavesTheKeyFileByteIdentical(t *testing.T) {
	dir, _, keyPath, _, bad := rotateWorld(t)
	before, err := os.ReadFile(keyPath)
	must(t, err)
	var out strings.Builder
	run([]string{"init", "--rotate", "--out", dir, "--words-file", bad},
		strings.NewReader(""), &out, &out)
	after, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("the key file is gone after a refused rotate: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("a refused rotate changed the key file")
	}
	if ents, _ := filepath.Glob(filepath.Join(dir, "xrplbak.key.epoch*")); len(ents) != 0 {
		t.Fatalf("a refused rotate left a rotated-away copy: %v", ents)
	}
}

// TestRotateTwiceDerivesTheEpochTwoKey. Rotation is the one operation that
// changes what the key file can read. Two rotations must land on
// HKDF(root, epoch 2), not on a chain of re-derivations from epoch 1.
func TestRotateTwiceDerivesTheEpochTwoKey(t *testing.T) {
	dir, root, keyPath, good, _ := rotateWorld(t)
	for i := 0; i < 2; i++ {
		var out strings.Builder
		if code := run([]string{"init", "--rotate", "--out", dir, "--words-file", good},
			strings.NewReader(""), &out, &out); code != exitOK {
			t.Fatalf("rotate %d: exit %d:\n%s", i+1, code, out.String())
		}
	}
	b, err := os.ReadFile(keyPath)
	must(t, err)
	kf, err := crypto.DecodeKeyFile(b, nil)
	must(t, err)
	if kf.Epoch != 2 {
		t.Fatalf("epoch %d after two rotations, want 2", kf.Epoch)
	}
	if kf.Key != root.DeriveEpochKey(2) {
		t.Fatal("the key file holds a key that is not HKDF(root, epoch 2)")
	}
}

// ---------------------------------------------------------------------
// Damaged key files
// ---------------------------------------------------------------------

// TestTruncatedPlainKeyFileIsRefused. A short read or a half-written file
// must not be parsed into a shorter-than-expected key.
func TestTruncatedPlainKeyFileIsRefused(t *testing.T) {
	w := newWorld(t, 0)
	b, err := os.ReadFile(w.keyFile)
	must(t, err)
	p := filepath.Join(w.dir, "short.key")
	must(t, os.WriteFile(p, b[:len(b)-1], 0o600))
	r := w.run("", "verify", "--dump", w.dumpFile("case"), "--key", p)
	if r.code != exitAuth {
		t.Fatalf("exit %d, want %d:\n%s", r.code, exitAuth, r.out)
	}
	if !strings.Contains(r.out, "not an xrplbak key file") {
		t.Fatalf("the message does not say the file is not a key file:\n%s", r.out)
	}
}

// TestTruncatedWrappedKeyFileIsRefused. A wrapped file that is too short to
// hold a salt and a tag must be named as truncated, not as a wrong
// passphrase: those send the operator to different places.
func TestTruncatedWrappedKeyFileIsRefused(t *testing.T) {
	w := newWorld(t, 0)
	wrapped, err := w.key.EncodeWrapped([]byte("pw"))
	must(t, err)
	p := filepath.Join(w.dir, "shortwrapped.key")
	must(t, os.WriteFile(p, wrapped[:20], 0o600))
	r := w.run("pw\n", "verify", "--dump", w.dumpFile("case"), "--key", p)
	if r.code != exitAuth {
		t.Fatalf("exit %d, want %d:\n%s", r.code, exitAuth, r.out)
	}
	if !strings.Contains(r.out, "truncated") {
		t.Fatalf("the message does not say the file is truncated:\n%s", r.out)
	}
}

// ---------------------------------------------------------------------
// Epoch probing
// ---------------------------------------------------------------------

// TestFarFutureEpochFindsNothing. --epoch is a starting point for a bounded
// downward probe, not a hint the scan may ignore. Starting far above the
// real epoch must end in a refusal that names the epoch as a thing to
// check, never in a quiet success from epoch 0.
func TestFarFutureEpochFindsNothing(t *testing.T) {
	w := newWorld(t, 0)
	r := w.run("", "restore", "--dump", w.dumpFile("case"), "--words-file", w.words,
		"--account", w.writer.Address(), "--epoch", "1000")
	if r.code != exitAuth {
		t.Fatalf("exit %d, want %d (epoch 1000 is far outside the probe window):\n%s", r.code, exitAuth, r.out)
	}
	if !strings.Contains(r.out, "epoch") {
		t.Fatalf("the refusal does not mention the epoch:\n%s", r.out)
	}
}

// TestKeyFileEpochDisagreeingWithTheLedgerIsRefused. A key file knows one
// epoch. Against a ledger holding only another epoch's backups it must
// refuse, because a key file that silently read a neighbouring epoch would
// be claiming an authentication it never performed.
func TestKeyFileEpochDisagreeingWithTheLedgerIsRefused(t *testing.T) {
	w := newWorld(t, 0)
	kf := &crypto.KeyFile{Epoch: 7, Key: w.root.DeriveEpochKey(7), AccountID: w.key.AccountID, WriterSeed: w.key.WriterSeed}
	p := filepath.Join(w.dir, "epoch7.key")
	must(t, os.WriteFile(p, kf.Encode(), 0o600))
	r := w.run("", "verify", "--dump", w.dumpFile("case"), "--key", p)
	if r.code != exitAuth {
		t.Fatalf("exit %d, want %d (an epoch-7 key file must not read an epoch-0 backup):\n%s", r.code, exitAuth, r.out)
	}
	if !strings.Contains(r.out, "no backup authenticates") {
		t.Fatalf("the message does not say nothing authenticated:\n%s", r.out)
	}
}

// ---------------------------------------------------------------------
// Interactive entry
// ---------------------------------------------------------------------

// TestInteractiveWordsEntryWorks. No --words-file: the operator types the
// mnemonic at the prompt. One line of 24 words ends entry on its own.
func TestInteractiveWordsEntryWorks(t *testing.T) {
	w := newWorld(t, 0)
	in := strings.Join(w.root.ToWords(), " ") + "\n"
	r := w.run(in, "restore", "--dump", w.dumpFile("case"),
		"--account", w.writer.Address(), "--bundle", w.bundle)
	if r.code != exitOK {
		t.Fatalf("exit %d, want %d:\n%s", r.code, exitOK, r.out)
	}
}

// TestInteractiveSharesEntryWorks. The same prompt takes shares one per
// line, ended by a blank line, and must tell them apart from a mnemonic
// without being told which is coming.
func TestInteractiveSharesEntryWorks(t *testing.T) {
	w := newWorld(t, 0)
	lines, err := w.root.Split(3, 2)
	must(t, err)
	in := lines[0] + "\n" + lines[2] + "\n\n"
	r := w.run(in, "restore", "--dump", w.dumpFile("case"),
		"--account", w.writer.Address(), "--bundle", w.bundle)
	if r.code != exitOK {
		t.Fatalf("exit %d, want %d:\n%s", r.code, exitOK, r.out)
	}
}
