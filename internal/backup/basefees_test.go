package backup

import (
	"testing"

	"github.com/justinnevins/xrplbak/internal/xrpl/codec"
)

// BaseFees must follow the layout submitBatched uses (F-066). The cases
// pin the three shapes: everything in one Batch, a lone chunk sent plain
// ahead of batched parts, and parts split across Batches with the anchor
// in the last one. Batched numbers are worked by hand from splitBatches:
// groups as even as possible, at most MaxBatchInner each, (g + 2) fees
// per Batch, a lone transaction plain.
func TestBaseFeesFollowsBatchLayout(t *testing.T) {
	if codec.MaxBatchInner != 8 {
		t.Fatalf("MaxBatchInner is %d; the cases below assume 8", codec.MaxBatchInner)
	}
	cases := []struct {
		c, k       int
		seq, batch int
		reason     string
	}{
		{1, 1, 3, 5, "3 inner in one Batch: 3+2"},
		{3, 4, 8, 10, "8 inner in one Batch: 8+2"},
		{1, 8, 10, 14, "lone chunk plain (1), parts+anchor 9 -> [4,5]: 6+7"},
		{3, 8, 12, 18, "chunks Batch (5), parts+anchor 9 -> [4,5]: 6+7"},
		{8, 16, 25, 33, "chunks Batch (10), parts+anchor 17 -> [5,6,6]: 7+8+8"},
	}
	for _, c := range cases {
		if got := BaseFees(c.c, c.k, false); got != c.seq {
			t.Errorf("BaseFees(%d,%d,sequential)=%d want %d", c.c, c.k, got, c.seq)
		}
		if got := BaseFees(c.c, c.k, true); got != c.batch {
			t.Errorf("BaseFees(%d,%d,batch)=%d want %d (%s)", c.c, c.k, got, c.batch, c.reason)
		}
	}
}
