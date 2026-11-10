package discover

import (
	"errors"
	"testing"

	"github.com/justinnevins/xrplbak/internal/chunk"
	"github.com/justinnevins/xrplbak/internal/crypto"
	"github.com/justinnevins/xrplbak/internal/manifest"
	"github.com/justinnevins/xrplbak/internal/xrpl"
)

// f072Client answers tx with "not found" and then fails the account scan,
// the way a server does when it drops the connection between two calls.
type f072Client struct {
	xrpl.Client
	scanErr error
}

func (f072Client) Tx(string) (*xrpl.TxRecord, error) { return nil, xrpl.ErrNotFound }
func (c f072Client) AccountTx(string) ([]xrpl.TxRecord, xrpl.Range, error) {
	return nil, xrpl.Range{Min: -1, Max: -1}, c.scanErr
}

// F-072: Fetch read a chunk by hash, got "not found", fell back to the
// account scan and dropped the scan's error. A network failure then read
// as a missing chunk (exit 5, "use a server with more history") instead
// of a network error (exit 2).
func TestF072FetchFallbackKeepsTheScanError(t *testing.T) {
	m := &manifest.Manifest{}
	m.OnChain.Chunks = []manifest.Chunk{{Index: 0, TxHash: "AB"}}
	res := &Result{Account: "rExample", Range: xrpl.Range{Min: 1, Max: 9}}
	cand := &Candidate{Manifest: m}
	keys := RootKeys{Root: crypto.RootKey{}}

	scanErr := errors.New("HTTP 500")
	_, err := Fetch(f072Client{scanErr: scanErr}, keys, res, cand)
	var me *chunk.MissingError
	if errors.As(err, &me) {
		t.Fatalf("a failed account scan was reported as a missing chunk: %v", err)
	}
	var ne *NetworkError
	if !errors.As(err, &ne) {
		t.Fatalf("want *NetworkError, got %T: %v", err, err)
	}
	if !errors.Is(err, scanErr) {
		t.Fatalf("the network error lost its cause: %v", err)
	}

	// The scan worked and the chunk is not in it: that is still "missing".
	_, err = Fetch(f072Client{}, keys, res, cand)
	if !errors.As(err, &me) {
		t.Fatalf("a clean scan without the chunk must stay a MissingError, got %T: %v", err, err)
	}
}
