package crypto

import "testing"

// F-108: a share is copied off paper by hand, often in lower case. The
// look-alike letters must fold in either case: o and O to zero, i, I, l and
// L to one. Before the fix the fold ran before the upper-casing, so the
// lower-case letters reached the decoder and the share was refused.
func TestShareLookalikesFoldInEitherCase(t *testing.T) {
	var root RootKey
	for i := range root {
		root[i] = byte(i*7 + 3)
	}
	swaps := []struct{ from, to byte }{{'0', 'O'}, {'0', 'o'}, {'1', 'I'}, {'1', 'i'}, {'1', 'L'}, {'1', 'l'}}
	tested := map[byte]bool{}
	// Split draws fresh randomness, so one split may hold no 1 at all.
	// Split again until every form was tried.
	var shares []string
	for try := 0; try < 50 && len(tested) < len(swaps); try++ {
		var err error
		if shares, err = root.Split(3, 2); err != nil {
			t.Fatal(err)
		}
		tryLookalikes(t, root, shares, swaps, tested)
	}
	for _, sw := range swaps {
		if !tested[sw.to] {
			t.Errorf("no share held a %q in 50 splits, so the %q form was never tried", sw.from, sw.to)
		}
	}
}

func tryLookalikes(t *testing.T, root RootKey, shares []string, swaps []struct{ from, to byte }, tested map[byte]bool) {
	t.Helper()
	for si, s := range shares {
		other := shares[(si+1)%len(shares)]
		for _, sw := range swaps {
			alt := []byte(s)
			changed := false
			for i := range alt {
				if alt[i] == sw.from {
					alt[i] = sw.to
					changed = true
				}
			}
			if !changed {
				continue
			}
			tested[sw.to] = true
			if got, want := NormalizeShare(string(alt)), NormalizeShare(s); got != want {
				t.Errorf("share %d with %q typed as %q: normalized to %q, want %q", si+1, sw.from, sw.to, got, want)
			}
			got, err := Combine([]string{string(alt), other})
			if err != nil {
				t.Errorf("share %d with %q typed as %q: refused: %v", si+1, sw.from, sw.to, err)
				continue
			}
			if got != root {
				t.Errorf("share %d with %q typed as %q: recovered a different key", si+1, sw.from, sw.to)
			}
		}
	}
}
