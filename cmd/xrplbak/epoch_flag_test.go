package main

import (
	"strings"
	"testing"
)

// TestEpochAboveUint32IsAUsageError pins that --epoch refuses a value that
// does not fit an epoch. Epochs are uint32. Without the check a larger
// value wraps silently (4294967296 becomes 0), so a mistyped flag probes an
// epoch the operator never asked for and is never told about.
func TestEpochAboveUint32IsAUsageError(t *testing.T) {
	w := newWorld(t, 0)
	for _, v := range []string{"4294967296", "4294967297", "9223372036854775807"} {
		r := w.restore("--epoch", v)
		if r.code != exitUsage || !strings.Contains(r.out, "--epoch") {
			t.Fatalf("--epoch %s must be a usage error naming the flag, got exit %d:\n%s", v, r.code, r.out)
		}
	}
	// The largest epoch is a valid value. It finds no backup here, which is
	// an auth outcome, not a usage error.
	if r := w.restore("--epoch", "4294967295"); r.code == exitUsage {
		t.Fatalf("--epoch 4294967295 is a valid epoch, got a usage error:\n%s", r.out)
	}
}
