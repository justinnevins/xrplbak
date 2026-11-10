package chunk

import (
	"testing"

	"github.com/justinnevins/xrplbak/internal/container"
	"github.com/justinnevins/xrplbak/internal/crypto"
	"github.com/justinnevins/xrplbak/internal/xrpl/codec"
)

func f073Memo(typ string, ctLen int) codec.Memo {
	n := headerLen + ctLen
	if typ == TypeManifest {
		n += crypto.ManifestNonceLen
	}
	data := make([]byte, n)
	data[0] = Version
	data[20] = 1 // total 1, index 0
	return codec.Memo{Type: []byte(typ), Data: data}
}

// F-073: Decode had a lower bound on a memo and no upper bound. The tool
// never writes a chunk ciphertext over 976 bytes or a manifest part over
// 960, yet Decode accepted a memo of any size from a server or a dump
// file, and discovery kept every one.
func TestF073DecodeRefusesAMemoLargerThanTheToolWrites(t *testing.T) {
	maxChunk := container.BlockLen + crypto.TagLen
	maxPart := ManifestPartLen + crypto.TagLen
	if maxChunk != 976 || maxPart != 960 {
		t.Fatalf("format maxima moved: chunk %d, manifest part %d; docs/wire-format.md says 976 and 960", maxChunk, maxPart)
	}
	for _, c := range []struct {
		typ  string
		ct   int
		want bool
	}{
		{TypeChunk, maxChunk, true},
		{TypeChunk, maxChunk + 1, false},
		{TypeChunk, 1 << 20, false},
		{TypeManifest, maxPart, true},
		{TypeManifest, maxPart + 1, false},
		{TypeManifest, 1 << 20, false},
	} {
		p, ok := Decode(f073Memo(c.typ, c.ct))
		if ok != c.want {
			t.Errorf("%s with %d ciphertext bytes: Decode ok=%v, want %v", c.typ, c.ct, ok, c.want)
		}
		if ok && len(p.Ciphertext) != c.ct {
			t.Errorf("%s: ciphertext %d bytes, want %d", c.typ, len(p.Ciphertext), c.ct)
		}
	}
}
