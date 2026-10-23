package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests pin init's handling of the recovery words between printing
// them and saving the key file, after the first Mainnet run (2026-10-20):
// one Ctrl-C at the re-entry check voided 24 words the operator had already
// copied, and one typo did the same.

// scripted is a stdin that answers each prompt from what init printed so far.
// run is synchronous, so by the time a prompt reads, its question is in out.
type scripted struct {
	out     *bytes.Buffer
	answer  func(out string) (string, bool)
	pending []byte
}

func (s *scripted) Read(p []byte) (int, error) {
	if len(s.pending) == 0 {
		line, ok := s.answer(s.out.String())
		if !ok {
			return 0, io.EOF
		}
		s.pending = []byte(line + "\n")
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}

var gridWord = regexp.MustCompile(`(\d{1,2})\. ([a-z]+)`)

// printedWords reads the 24-word grid from init's output.
func printedWords(t *testing.T, out string) map[int]string {
	t.Helper()
	end := strings.Index(out, "writer account:")
	if end < 0 {
		t.Fatalf("no writer account line yet:\n%s", out)
	}
	words := map[int]string{}
	for _, m := range gridWord.FindAllStringSubmatch(out[:end], -1) {
		n, _ := strconv.Atoi(m[1])
		words[n] = m[2]
	}
	if len(words) != 24 {
		t.Fatalf("read %d words from the grid, want 24:\n%s", len(words), out)
	}
	return words
}

var askedWord = regexp.MustCompile(`Re-enter word (\d+): $`)

// fixPicks makes the check ask for words 1, 2 and 3, in that order.
func fixPicks(t *testing.T) {
	old := reentryPicks
	reentryPicks = func(n int) []int {
		p := make([]int, n)
		for i := range p {
			p[i] = i
		}
		return p
	}
	t.Cleanup(func() { reentryPicks = old })
}

// fakeInterrupts replaces the Ctrl-C source for one test and records when
// the guard is released.
func fakeInterrupts(t *testing.T) (ch chan os.Signal, released *bool, exited chan int) {
	t.Helper()
	ch = make(chan os.Signal)
	released = new(bool)
	exited = make(chan int, 1)
	oldI, oldE := interrupts, exitNow
	interrupts = func() (<-chan os.Signal, func()) { return ch, func() { *released = true } }
	exitNow = func(code int) {
		select {
		case exited <- code:
		default:
		}
	}
	t.Cleanup(func() { interrupts, exitNow = oldI, oldE })
	return ch, released, exited
}

// runInit drives init with an answer function and returns code and output.
func runInit(t *testing.T, dir string, answer func(t *testing.T, out string) (string, bool), extra ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	in := &scripted{out: &out, answer: func(o string) (string, bool) { return answer(t, o) }}
	code := run(append([]string{"init", "--out", dir}, extra...), in, &out, &out)
	t.Logf("$ xrplbak init\n%s(exit %d)", out.String(), code)
	return code, out.String()
}

// answerWords answers word N with wrong[N] the given number of times, then
// with the right word. The clear-screen question gets clear.
func answerWords(wrong map[int]int, clear string) func(t *testing.T, out string) (string, bool) {
	return func(t *testing.T, out string) (string, bool) {
		if m := askedWord.FindStringSubmatch(out); m != nil {
			n, _ := strconv.Atoi(m[1])
			if wrong[n] > 0 {
				wrong[n]--
				return "notaword", true
			}
			return printedWords(t, out)[n], true
		}
		if strings.HasSuffix(out, "[yes/no]: ") {
			return clear, true
		}
		t.Fatalf("unexpected question:\n%s", out)
		return "", false
	}
}

func keyFileExists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "xrplbak.key"))
	return err == nil
}

// TestReentryTypoKeepsTheWords pins that a mismatched word is asked again,
// against the same words, and says that nothing is lost.
func TestReentryTypoKeepsTheWords(t *testing.T) {
	fixPicks(t)
	fakeInterrupts(t)
	dir := t.TempDir()
	code, out := runInit(t, dir, answerWords(map[int]int{1: 1, 3: 2}, "no"))
	if code != exitOK {
		t.Fatalf("exit %d after two typos within the limit, want %d", code, exitOK)
	}
	if !keyFileExists(dir) {
		t.Fatal("no key file after the check passed on retry")
	}
	if !strings.Contains(out, "Nothing is saved yet, and the words on your paper are still the right ones") {
		t.Errorf("a typo does not say the words are still good:\n%s", out)
	}
	if n := strings.Count(out, "Re-enter word 1: "); n != 2 {
		t.Errorf("word 1 asked %d times, want 2", n)
	}
	if n := strings.Count(out, "Re-enter word 3: "); n != 3 {
		t.Errorf("word 3 asked %d times, want 3", n)
	}
}

// TestReentryGivesUpAfterThreeMisses pins the limit: three misses on one
// word stop init with nothing written.
func TestReentryGivesUpAfterThreeMisses(t *testing.T) {
	fixPicks(t)
	fakeInterrupts(t)
	dir := t.TempDir()
	code, out := runInit(t, dir, answerWords(map[int]int{2: 3}, "no"))
	if code != exitUsage {
		t.Fatalf("exit %d, want %d", code, exitUsage)
	}
	if keyFileExists(dir) {
		t.Fatal("a key file was written after the check failed")
	}
	if !strings.Contains(out, "word 2 does not match, 3 times") || !strings.Contains(out, "Nothing was written") {
		t.Errorf("the failure does not say what happened:\n%s", out)
	}
}

// TestReentryEndOfInputStops pins that closed stdin ends the check at once
// instead of counting as three wrong answers.
func TestReentryEndOfInputStops(t *testing.T) {
	fixPicks(t)
	fakeInterrupts(t)
	dir := t.TempDir()
	code, out := runInit(t, dir, func(*testing.T, string) (string, bool) { return "", false })
	if code != exitUsage || keyFileExists(dir) {
		t.Fatalf("exit %d, key file %v; want %d and none", code, keyFileExists(dir), exitUsage)
	}
	if strings.Contains(out, "try again") {
		t.Errorf("end of input was treated as a wrong word:\n%s", out)
	}
}

// TestInterruptGuardNeedsTwoCtrlC pins the guard itself: one Ctrl-C explains
// and keeps going, a second one stops with exit 1 and says nothing was saved.
func TestInterruptGuardNeedsTwoCtrlC(t *testing.T) {
	ch, _, exited := fakeInterrupts(t)
	var out bytes.Buffer
	defer swapStreams(strings.NewReader(""), &out)()

	done := make(chan struct{})
	finished := make(chan struct{})
	go func() { interruptGuard(ch, done); close(finished) }()
	ch <- os.Interrupt
	ch <- os.Interrupt
	select {
	case code := <-exited:
		if code != exitUsage {
			t.Errorf("exit %d, want %d", code, exitUsage)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("two Ctrl-C did not stop init")
	}
	close(done)
	<-finished
	got := out.String()
	if !strings.Contains(got, "the words on your paper stay valid") {
		t.Errorf("first Ctrl-C does not explain:\n%s", got)
	}
	if !strings.Contains(got, "Stopped. Nothing was saved") {
		t.Errorf("second Ctrl-C does not say nothing was saved:\n%s", got)
	}
}

// TestInterruptGuardOneCtrlCDoesNotStop pins that a single Ctrl-C followed
// by the end of the guarded stretch never exits.
func TestInterruptGuardOneCtrlCDoesNotStop(t *testing.T) {
	ch, _, exited := fakeInterrupts(t)
	var out bytes.Buffer
	defer swapStreams(strings.NewReader(""), &out)()

	done := make(chan struct{})
	finished := make(chan struct{})
	go func() { interruptGuard(ch, done); close(finished) }()
	ch <- os.Interrupt
	close(done)
	<-finished
	select {
	case code := <-exited:
		t.Fatalf("one Ctrl-C exited with %d", code)
	default:
	}
}

// TestInitGuardsTheCheckAndReleasesAfterSaving pins the wiring: init listens
// for Ctrl-C while the words are unsaved, and gives Ctrl-C back before it
// asks anything once the key file exists.
func TestInitGuardsTheCheckAndReleasesAfterSaving(t *testing.T) {
	fixPicks(t)
	ch, released, exited := fakeInterrupts(t)
	dir := t.TempDir()
	interrupted := false
	answer := answerWords(map[int]int{}, "no")
	code, out := runInit(t, dir, func(t *testing.T, out string) (string, bool) {
		if !interrupted && strings.HasSuffix(out, "Re-enter word 1: ") {
			interrupted = true
			for i := 0; i < 2; i++ {
				select {
				case ch <- os.Interrupt:
				case <-time.After(5 * time.Second):
					t.Fatal("init does not listen for Ctrl-C during the check")
				}
			}
			select {
			case <-exited:
			case <-time.After(5 * time.Second):
				t.Fatal("two Ctrl-C during the check did not stop init")
			}
		}
		if strings.HasSuffix(out, "[yes/no]: ") && !*released {
			t.Error("Ctrl-C is still held after the key file was written")
		}
		return answer(t, out)
	})
	if !interrupted {
		t.Fatal("the check never asked for word 1")
	}
	if code != exitOK {
		t.Fatalf("exit %d, want %d (the fake exit lets init finish)", code, exitOK)
	}
	if !strings.Contains(out, "Stopped. Nothing was saved") {
		t.Errorf("the guard's message is missing:\n%s", out)
	}
}

// TestInitOffersToClearTheWords pins the scrollback question: "yes" sends
// the clear-screen and clear-scrollback sequences, anything else does not,
// and both say a terminal may keep a copy.
func TestInitOffersToClearTheWords(t *testing.T) {
	fixPicks(t)
	for _, tc := range []struct {
		answer string
		clears bool
	}{{"yes", true}, {"no", false}, {"", false}} {
		fakeInterrupts(t)
		dir := t.TempDir()
		code, out := runInit(t, dir, answerWords(map[int]int{}, tc.answer))
		if code != exitOK {
			t.Fatalf("answer %q: exit %d", tc.answer, code)
		}
		if got := strings.Contains(out, "\x1b[3J"); got != tc.clears {
			t.Errorf("answer %q: cleared=%v, want %v", tc.answer, got, tc.clears)
		}
		if !strings.Contains(out, "may keep the 24 words in its scrollback") {
			t.Errorf("answer %q: no scrollback note:\n%s", tc.answer, out)
		}
		clearAt := strings.Index(out, "Clear the 24 words")
		if clearAt < 0 || clearAt > strings.Index(out, "== Done ==") {
			t.Errorf("answer %q: the question must come before the Done block:\n%s", tc.answer, out)
		}
	}
}

// TestInitYesAsksNothing pins that --yes, for scripts, adds no question.
func TestInitYesAsksNothing(t *testing.T) {
	fakeInterrupts(t)
	dir := t.TempDir()
	code, _ := runInit(t, dir, func(t *testing.T, out string) (string, bool) {
		t.Fatalf("--yes asked a question:\n%s", out)
		return "", false
	}, "--yes")
	if code != exitOK || !keyFileExists(dir) {
		t.Fatalf("exit %d, key file %v", code, keyFileExists(dir))
	}
}

// TestInitExplainsTheFundingLink pins the funding hint. "From a fresh path"
// was explained nowhere. The fact behind it is that the funding payment is
// public and links the two accounts.
func TestInitExplainsTheFundingLink(t *testing.T) {
	fakeInterrupts(t)
	code, out := runInit(t, t.TempDir(), func(*testing.T, string) (string, bool) { return "", false }, "--yes")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if strings.Contains(out, "fresh path") {
		t.Errorf("init still says \"fresh path\":\n%s", out)
	}
	if !strings.Contains(out, "anyone can see which account funded this one") {
		t.Errorf("init does not say the funding payment is public:\n%s", out)
	}
}
