package backup

import (
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/pubattest"
	"github.com/justinnevins/xrplbak/internal/xrpl/codec"
	"github.com/justinnevins/xrplbak/internal/xrpl/sign"
)

// buildPublicAttestation makes the memo a real validator would publish: its
// master key signs the exact SignString for this backup, offline.
func buildPublicAttestation(t *testing.T, e *env, p *Plan) (vpk string, memo codec.Memo) {
	t.Helper()
	v, err := sign.KeyFromSeed([]byte("validator-master0"[:16]))
	if err != nil {
		t.Fatal(err)
	}
	vpk = sign.EncodeNodePublic(v.PublicKey())
	msg := pubattest.SignString(vpk, e.writer.Address(), p.Manifest.Epoch, p.Manifest.Seq, p.Manifest.BackupID)
	sig := v.Sign([]byte(msg))
	m, err := pubattest.Memo(vpk, p.Manifest.Epoch, p.Manifest.Seq, p.Manifest.BackupID, hex.EncodeToString(sig))
	if err != nil {
		t.Fatal(err)
	}
	return vpk, m
}

// findAttestation scans the account's transactions for a public attestation
// memo and decodes it.
func findAttestation(t *testing.T, e *env) (pubattest.Record, bool) {
	t.Helper()
	txs, _, _ := e.ledger.AccountTx(e.writer.Address())
	for i := len(txs) - 1; i >= 0; i-- {
		for _, m := range txs[i].Memos {
			if r, ok := pubattest.Decode(m); ok {
				return r, true
			}
		}
	}
	return pubattest.Record{}, false
}

// TestPublicAttestationRidesTheAnchor proves the cleartext attestation lands
// on the DID anchor transaction and verifies from the ledger with only the
// account, in both the batched and the sequential path.
func TestPublicAttestationRidesTheAnchor(t *testing.T) {
	for _, tc := range []struct {
		name  string
		batch bool
	}{{"sequential", false}, {"batched", true}} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.ledger.Batch = tc.batch
			p, err := Build(e.opts(t, 1))
			if err != nil {
				t.Fatal(err)
			}
			vpk, memo := buildPublicAttestation(t, e, p)
			s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Batch: tc.batch, Sleep: func(time.Duration) {}, DumpOut: filepath.Join(e.dir, "a.dump.json")}
			s.AttestMemo = &memo
			if err := s.Submit(p); err != nil {
				t.Fatal(err)
			}
			r, ok := findAttestation(t, e)
			if !ok {
				t.Fatal("no public attestation memo landed on the ledger")
			}
			if !r.Verify(e.writer.Address()) {
				t.Fatal("the published attestation does not verify from the ledger")
			}
			if r.NodePublic() != vpk {
				t.Fatalf("attestation names %s, want %s", r.NodePublic(), vpk)
			}
			// Verified against the wrong account must fail: the binding is real.
			if r.Verify("rQ3fNyLjbvcDaPNS4EAJY8aT9zR3uGk9Bd") {
				t.Fatal("attestation verified for the wrong account")
			}
		})
	}
}
