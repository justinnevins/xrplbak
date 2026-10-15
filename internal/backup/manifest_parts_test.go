package backup

import (
	"fmt"
	"strings"
	"testing"

	"github.com/justinnevins/xrplbak/internal/chunk"
	"github.com/justinnevins/xrplbak/internal/crypto"
	"github.com/justinnevins/xrplbak/internal/manifest"
)

// ManifestMemos is the last gate before the ledger. It refuses a manifest
// above the discovery cap even if a caller skipped Build's check.
func TestManifestMemosRefusesOverPartLimit(t *testing.T) {
	var root crypto.RootKey
	key := root.DeriveEpochKey(0)
	id := make([]byte, 16)
	m := &manifest.Manifest{Epoch: 0, Seq: 1}
	for i := 0; i < 400; i++ {
		m.Files = append(m.Files, manifest.File{Path: fmt.Sprintf("/etc/xrpld/extra-file-with-a-long-name-%04d.conf", i), SHA256: strings.Repeat("a", 64), Where: "bundle"})
	}
	_, _, err := ManifestMemos(key, id, m)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("the limit is %d", chunk.MaxManifestParts)) {
		t.Fatalf("sealed a manifest above the cap: err=%v", err)
	}
	m.Files = m.Files[:4]
	memos, _, err := ManifestMemos(key, id, m)
	if err != nil || len(memos) == 0 || len(memos) > chunk.MaxManifestParts {
		t.Fatalf("small manifest: memos=%d err=%v", len(memos), err)
	}
}

// Build's projection fills the chunk tx fields Submit adds later, so a
// manifest that fits at plan time still fits on the ledger.
func TestProjectedManifestCountsSubmitGrowth(t *testing.T) {
	m := &manifest.Manifest{Epoch: 0, Seq: 1}
	for i := 0; i < chunk.MaxChunks; i++ {
		m.OnChain.Chunks = append(m.OnChain.Chunks, manifest.Chunk{Index: i, SHA256: strings.Repeat("b", 64)})
	}
	full := *m
	full.OnChain.Chunks = append([]manifest.Chunk(nil), m.OnChain.Chunks...)
	for i := range full.OnChain.Chunks {
		full.OnChain.Chunks[i].TxHash = strings.Repeat("0", 64)
		full.OnChain.Chunks[i].Ledger = 4294967295
	}
	want, err := manifest.Marshal(&full)
	if err != nil {
		t.Fatal(err)
	}
	got, err := projectedManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("projection is %d bytes, want %d with every tx hash and ledger at full length", len(got), len(want))
	}
	if len(m.OnChain.Chunks[0].TxHash) != 0 || m.OnChain.Chunks[0].Ledger != 0 {
		t.Fatalf("projection mutated the caller's manifest")
	}
	n, err := projectedManifestParts(m)
	if err != nil {
		t.Fatal(err)
	}
	if wantN := (len(want) + chunk.ManifestPartLen - 1) / chunk.ManifestPartLen; n != wantN {
		t.Fatalf("projected parts %d, want %d", n, wantN)
	}
}
