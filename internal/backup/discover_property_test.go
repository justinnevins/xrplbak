package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/crypto"
	"github.com/justinnevins/xrplbak/internal/discover"
	"github.com/justinnevins/xrplbak/internal/redact"
	"github.com/justinnevins/xrplbak/internal/restore"
	"github.com/justinnevins/xrplbak/internal/xrpl/fake"
	"github.com/justinnevins/xrplbak/internal/xrpl/sign"
)

// FuzzEveryBuiltPlanIsDiscovered pins the seam between backup and discovery:
// every plan Build accepts, once submitted, is the backup discovery finds,
// and it restores complete. Build and discover each enforce size limits of
// their own. F-057 lived in the gap between two of them: Build accepted a
// manifest that discovery then ignored, and the operator was told the
// backup succeeded. This target drives plan sizes across those limits
// (chunk count, manifest parts, file count) in both comment modes, with and
// without Batch, and with either kind of key.
//
// The property is checked only for plans Build accepts. A refusal is a
// correct outcome; an accepted plan that cannot be found is not.
func FuzzEveryBuiltPlanIsDiscovered(f *testing.F) {
	// extra config, sntp lines, includes, include name length, flags, seq.
	// flags: 0x01 comments on-chain, 0x02 peers on-chain, 0x04 Batch,
	// 0x08 discover with the key file instead of the recovery key.
	// The seeds sit on both sides of each limit Build enforces, measured
	// 2026-10-23 at v1.1.4: 363 sntp lines is the last that fits in 8
	// chunks; 80 includes with 8-character names, 61 with 60, and 48 with
	// 119 are the last that fit in 16 manifest parts.
	f.Add([]byte(""), uint16(0), uint16(0), uint8(0), uint8(0), uint16(0))
	f.Add([]byte("# a comment\n[ips]\nr.ripple.com 51235\n"), uint16(40), uint16(3), uint8(10), uint8(0x07), uint16(7))
	f.Add([]byte(""), uint16(363), uint16(0), uint8(0), uint8(0x04), uint16(1))
	f.Add([]byte(""), uint16(364), uint16(0), uint8(0), uint8(0x0c), uint16(2))
	f.Add([]byte(""), uint16(0), uint16(80), uint8(0), uint8(0x00), uint16(3))
	f.Add([]byte(""), uint16(0), uint16(81), uint8(0), uint8(0x04), uint16(3))
	f.Add([]byte(""), uint16(0), uint16(61), uint8(52), uint8(0x0b), uint16(5))
	f.Add([]byte(""), uint16(0), uint16(48), uint8(111), uint8(0x04), uint16(4))
	f.Add([]byte(""), uint16(350), uint16(73), uint8(0), uint8(0x0f), uint16(4999))
	f.Fuzz(func(t *testing.T, extra []byte, sntp, includes uint16, nameLen, flags uint8, seq uint16) {
		p, e, keys := fuzzPlan(t, extra, int(sntp)%420, int(includes)%110, 8+int(nameLen)%120, flags, uint32(seq)%5000+1)
		if p == nil {
			return // Build refused: a correct outcome, outside the property
		}
		s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Sleep: func(time.Duration) {}, Batch: flags&0x04 != 0}
		if err := s.Submit(p); err != nil {
			t.Fatalf("Build accepted a plan Submit could not send (%d chunks, %d files): %v", len(p.Chunks), len(p.Manifest.Files), err)
		}

		res, err := discover.Run(e.ledger, keys, e.writer.Address(), 0)
		if err != nil {
			t.Fatalf("discovery failed on a backup Build accepted: %v", err)
		}
		if res.Latest == nil {
			t.Fatalf("discovery found no backup (%d chunks, %d files, %d rejected, warnings %q)", len(p.Chunks), len(p.Manifest.Files), res.Rejected, res.Warnings)
		}
		if !bytes.Equal(res.Latest.BackupID[:], p.BackupID) {
			t.Fatalf("discovery found %x, want %x", res.Latest.BackupID, p.BackupID)
		}
		if res.Rejected != 0 || res.Conflict != "" || res.AnchorMissing != "" || !res.AnchorOK {
			t.Fatalf("discovery of an honest backup: rejected %d, conflict %q, anchor missing %q, anchor ok %v, warnings %q",
				res.Rejected, res.Conflict, res.AnchorMissing, res.AnchorOK, res.Warnings)
		}

		entries, err := discover.Fetch(e.ledger, keys, res, res.Latest)
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		bundle, err := discover.OpenBundle(keys, res.Latest, p.Bundle)
		if err != nil {
			t.Fatalf("bundle: %v", err)
		}
		plan, err := restore.Build(res.Latest.Manifest, entries, bundle)
		if err != nil {
			t.Fatalf("restore refused an honest backup: %v", err)
		}
		if len(plan.Files) != len(p.Manifest.Files) {
			t.Fatalf("restore produced %d files, the manifest lists %d", len(plan.Files), len(p.Manifest.Files))
		}
		for _, f := range plan.Files {
			if !f.Complete() {
				t.Fatalf("%s restored incomplete with the bundle present", f.Path)
			}
		}
	})
}

// fuzzPlan writes one host's files and builds a plan over them. It returns
// nil when Build refuses.
func fuzzPlan(t *testing.T, extra []byte, sntp, includes, nameLen int, flags uint8, seq uint32) (*Plan, *env, discover.Keys) {
	t.Helper()
	e := &env{ledger: fake.New()}
	for i := range e.root {
		e.root[i] = byte(i) * 7
	}
	e.key = &crypto.KeyFile{Epoch: 0, Key: e.root.DeriveEpochKey(0)}
	e.writer, _ = sign.KeyFromSeed(bytes.Repeat([]byte{9}, 16))
	copy(e.key.AccountID[:], e.writer.AccountID())
	copy(e.key.WriterSeed[:], e.writer.Seed())
	e.ledger.Fund(e.writer.Address(), 1_000_000_000)
	e.ledger.Batch = flags&0x04 != 0

	dir := t.TempDir()
	raw, err := os.ReadFile(fixtures + "validator-full.cfg")
	if err != nil {
		t.Fatal(err)
	}
	var cfg bytes.Buffer
	cfg.Write(raw)
	cfg.WriteString("\n")
	cfg.Write(extra)
	if sntp > 0 {
		cfg.WriteString("\n[sntp_servers]\n")
		for i := 0; i < sntp; i++ {
			// Incompressible, so the packed container grows with sntp.
			sum := sha256.Sum256([]byte(fmt.Sprintf("%d", i)))
			fmt.Fprintf(&cfg, "%s.example.com\n", hex.EncodeToString(sum[:16]))
		}
	}
	cfgPath := filepath.Join(dir, "xrpld.cfg")
	valPath := filepath.Join(dir, "validators.txt")
	val, err := os.ReadFile(fixtures + "validators.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, cfg.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(valPath, val, 0o644); err != nil {
		t.Fatal(err)
	}
	var incs []string
	for i := 0; i < includes; i++ {
		name := fmt.Sprintf("%04d-%s.conf", i, strings.Repeat("n", nameLen))
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(fmt.Sprintf("setting = %d\n", i)), 0o600); err != nil {
			t.Fatal(err)
		}
		incs = append(incs, p)
	}

	o := Options{ConfigPath: cfgPath, ValidatorsPath: valPath, Includes: incs, Key: e.key, Now: time.Unix(1_800_000_000, 0), Seq: seq}
	if flags&0x01 != 0 {
		o.Comments = redact.CommentsOnChain
	}
	o.PeersOnChain = flags&0x02 != 0
	p, err := Build(o)
	if err != nil {
		return nil, nil, nil
	}
	var keys discover.Keys = discover.RootKeys{Root: e.root}
	if flags&0x08 != 0 {
		keys = discover.FileKeys{E: 0, Key: e.key.Key}
	}
	return p, e, keys
}
