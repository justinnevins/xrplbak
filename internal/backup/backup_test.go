package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/anchor"
	"github.com/justinnevins/xrplbak/internal/cfg"
	"github.com/justinnevins/xrplbak/internal/chunk"
	"github.com/justinnevins/xrplbak/internal/crypto"
	"github.com/justinnevins/xrplbak/internal/discover"
	"github.com/justinnevins/xrplbak/internal/dump"
	"github.com/justinnevins/xrplbak/internal/restore"
	"github.com/justinnevins/xrplbak/internal/xrpl/fake"
	"github.com/justinnevins/xrplbak/internal/xrpl/sign"
)

const fixtures = "../../tests/fixtures/"

type env struct {
	root   crypto.RootKey
	key    *crypto.KeyFile
	writer *sign.Key
	ledger *fake.Ledger
	dir    string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	var root crypto.RootKey
	for i := range root {
		root[i] = byte(i * 3)
	}
	writer, _ := sign.KeyFromSeed(bytes.Repeat([]byte{5}, 16))
	kf := &crypto.KeyFile{Epoch: 0, Key: root.DeriveEpochKey(0)}
	copy(kf.AccountID[:], writer.AccountID())
	copy(kf.WriterSeed[:], writer.Seed())
	l := fake.New()
	l.Fund(writer.Address(), 5_000_000)
	return &env{root: root, key: kf, writer: writer, ledger: l, dir: t.TempDir()}
}

func (e *env) opts(t *testing.T, seq uint32) Options {
	return Options{ConfigPath: fixtures + "validator-full.cfg", ValidatorsPath: fixtures + "validators.txt", Key: e.key, Now: time.Unix(1_800_000_000, 0), Seq: seq}
}

func (e *env) submit(t *testing.T, p *Plan) *Submitter {
	t.Helper()
	s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Sleep: func(time.Duration) {}, DumpOut: filepath.Join(e.dir, p.Manifest.BackupID+".dump.json")}
	if err := s.Submit(p); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBuildDeterministic(t *testing.T) {
	e := newEnv(t)
	a, err := Build(e.opts(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Build(e.opts(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.BackupID, b.BackupID) || len(a.Chunks) != len(b.Chunks) {
		t.Fatal("backup id must be stable")
	}
	for i := range a.Chunks {
		if !bytes.Equal(a.Chunks[i], b.Chunks[i]) {
			t.Fatalf("chunk %d differs", i)
		}
	}
	if !bytes.Equal(a.Bundle, b.Bundle) {
		t.Fatal("bundle must be stable")
	}
	if a.Role != "validator" || len(a.Chunks) == 0 || len(a.Chunks) > chunk.MaxChunks {
		t.Fatalf("role %s chunks %d", a.Role, len(a.Chunks))
	}
	// The plan must not contain the token or private IPs anywhere in on-chain text.
	for _, txt := range a.OnChainTxt {
		if strings.Contains(txt, "eyJ2YWxp") || strings.Contains(txt, "10.20.30.40") {
			t.Fatal("secret leaked into on-chain text")
		}
	}
	if !strings.HasPrefix(a.AttestText, "xrplbak/v1/attest "+a.Manifest.BackupID) {
		t.Fatal(a.AttestText)
	}
}

func TestRefusesSeedConfig(t *testing.T) {
	e := newEnv(t)
	o := e.opts(t, 1)
	o.ConfigPath = fixtures + "node-with-seed.cfg"
	if _, err := Build(o); err == nil || !strings.Contains(err.Error(), "node_seed") {
		t.Fatalf("want node_seed refusal, got %v", err)
	}
	o = e.opts(t, 1)
	inc := filepath.Join(t.TempDir(), "validator-keys.json")
	os.WriteFile(inc, []byte(`{"secret_key":"x"}`), 0o600)
	o.Includes = []string{inc}
	if _, err := Build(o); err == nil {
		t.Fatal("validator-keys.json must be refused as an include")
	}
}

func TestOversizedConfig(t *testing.T) {
	e := newEnv(t)
	big := filepath.Join(t.TempDir(), "big.cfg")
	var sb strings.Builder
	sb.WriteString("[sntp_servers]\n")
	for i := 0; i < 1200; i++ {
		sum := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		sb.WriteString(hex.EncodeToString(sum[:16]) + ".example.com\n")
	}
	os.WriteFile(big, []byte(sb.String()), 0o600)
	o := e.opts(t, 1)
	o.ConfigPath, o.ValidatorsPath = big, ""
	if _, err := Build(o); err == nil || !strings.Contains(err.Error(), "chunks") {
		t.Fatalf("want chunk limit error, got %v", err)
	}
}

func TestEndToEnd(t *testing.T) {
	e := newEnv(t)
	p, err := Build(e.opts(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	s := e.submit(t, p)
	if e.ledger.Submitted != len(p.Chunks)+1+1 && e.ledger.Submitted != len(p.Chunks)+2+1 {
		t.Fatalf("submitted %d txs for %d chunks", e.ledger.Submitted, len(p.Chunks))
	}
	keys := discover.RootKeys{Root: e.root}
	res, err := discover.Run(e.ledger, keys, e.writer.Address(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !res.AnchorOK || res.Latest == nil || !res.Latest.FromAnchor || len(res.Warnings) != 0 {
		t.Fatalf("discovery: anchorOK=%v latest=%v warnings=%v", res.AnchorOK, res.Latest, res.Warnings)
	}
	entries, err := discover.Fetch(e.ledger, keys, res, res.Latest)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := discover.OpenBundle(keys, res.Latest, p.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	plan := restore.Build(res.Latest.Manifest, entries, bundle)
	if len(plan.Files) != 2 {
		t.Fatalf("files %d", len(plan.Files))
	}
	for _, f := range plan.Files {
		if !f.Complete {
			t.Fatalf("%s incomplete (%s):\n%s", f.Path, f.Source, f.Data)
		}
	}
	orig, _ := os.ReadFile(fixtures + "validator-full.cfg")
	if string(plan.Files[0].Data) != cfg.Parse(string(orig)).Canonical() {
		t.Fatal("restored config differs from canonical original")
	}
	dir, err := plan.WriteTemp()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, fixtures+"validator-full.cfg")); err != nil {
		t.Fatal("temp write", err)
	}

	// Without the bundle: files are incomplete and the TODO list leads with the token.
	partial := restore.Build(res.Latest.Manifest, entries, nil)
	if partial.Files[0].Complete || !strings.Contains(partial.Todo[0], "validator token") {
		t.Fatalf("bundle-less restore: %+v", partial.Todo)
	}

	// Offline: the dump alone must reproduce the same result.
	d, err := dump.Load(s.DumpOut)
	if err != nil {
		t.Fatal(err)
	}
	off := &dump.Client{D: d}
	res2, err := discover.Run(off, keys, e.writer.Address(), 0)
	if err != nil || res2.Latest == nil || !res2.AnchorOK {
		t.Fatalf("dump discovery: %v %+v", err, res2)
	}
	entries2, err := discover.Fetch(off, keys, res2, res2.Latest)
	if err != nil || len(entries2) != len(entries) {
		t.Fatal("dump fetch", err)
	}

	// Key file (single epoch) works too.
	fk := discover.FileKeys{E: 0, Key: e.key.Key}
	res3, err := discover.Run(e.ledger, fk, e.writer.Address(), 0)
	if err != nil || res3.Latest == nil {
		t.Fatal("file key discovery", err)
	}

	// Wrong root key: nothing authenticates, anchor rejected.
	var wrong crypto.RootKey
	wrong[0] = 1
	res4, err := discover.Run(e.ledger, discover.RootKeys{Root: wrong}, e.writer.Address(), 0)
	if err != nil || res4.Latest != nil || res4.AnchorOK || res4.Rejected == 0 {
		t.Fatalf("wrong key must find nothing: %+v", res4)
	}
}

func TestSupersedeRollbackAndTombstone(t *testing.T) {
	e := newEnv(t)
	keys := discover.RootKeys{Root: e.root}
	p1, _ := Build(e.opts(t, 1))
	e.submit(t, p1)
	seq, sup, _, err := NextSeq(e.ledger, e.key, e.writer.Address())
	if err != nil || seq != 2 || sup != p1.Manifest.BackupID {
		t.Fatalf("next seq %d %s %v", seq, sup, err)
	}
	o := e.opts(t, 2)
	o.Supersedes = sup
	o.Now = time.Unix(1_800_000_100, 0)
	p2, _ := Build(o)
	e.submit(t, p2)
	res, _ := discover.Run(e.ledger, keys, e.writer.Address(), 0)
	if res.Latest.Manifest.Seq != 2 || res.Latest.Manifest.Supersedes != p1.Manifest.BackupID {
		t.Fatal("latest must be seq 2")
	}

	// Rollback: a writer-key thief re-points the anchor at backup 1.
	old := &anchor.Record{Epoch: 0, Seq: 1}
	copy(old.BackupID[:], p1.BackupID)
	e.ledger.DID[e.writer.Address()] = anchor.Encode(e.key.Key, old)
	res, _ = discover.Run(e.ledger, keys, e.writer.Address(), 0)
	if res.Latest.Manifest.Seq != 2 || len(res.Warnings) == 0 || !strings.Contains(res.Warnings[0], "rollback") {
		t.Fatalf("rollback must be detected: %+v", res.Warnings)
	}

	// Forged anchor (no key): ignored with a warning, scan still wins.
	e.ledger.DID[e.writer.Address()] = bytes.Repeat([]byte{1}, anchor.Len)
	res, _ = discover.Run(e.ledger, keys, e.writer.Address(), 0)
	if res.AnchorOK || res.Latest.Manifest.Seq != 2 {
		t.Fatal("forged anchor must be ignored")
	}

	// Tombstone.
	o = e.opts(t, 3)
	o.Tombstone = true
	p3, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	e.submit(t, p3)
	res, _ = discover.Run(e.ledger, keys, e.writer.Address(), 0)
	if !res.Latest.Manifest.Tombstone {
		t.Fatal("tombstone must be latest")
	}
	if _, err := discover.Fetch(e.ledger, keys, res, res.Latest); err == nil {
		t.Fatal("fetching a tombstone must fail")
	}
}

func TestTruncatedHistory(t *testing.T) {
	e := newEnv(t)
	keys := discover.RootKeys{Root: e.root}
	p, _ := Build(e.opts(t, 1))
	e.submit(t, p)
	// Prune everything up to the last chunk: chunks are gone, manifest stays.
	last := p.Manifest.OnChain.Chunks[len(p.Manifest.OnChain.Chunks)-1].Ledger
	e.ledger.Prune = last + 1
	res, err := discover.Run(e.ledger, keys, e.writer.Address(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Latest == nil {
		t.Fatalf("manifest should still be found: %+v", res.Warnings)
	}
	_, err = discover.Fetch(e.ledger, keys, res, res.Latest)
	var me *chunk.MissingError
	if !errors.As(err, &me) || me.Index != 0 || me.Account != e.writer.Address() {
		t.Fatalf("want MissingError for chunk 1, got %v", err)
	}
	if !strings.Contains(err.Error(), "chunk 1 of") || !strings.Contains(err.Error(), "searched ledgers") {
		t.Fatal(err.Error())
	}
}

func TestResumeAfterInterruption(t *testing.T) {
	e := newEnv(t)
	p, _ := Build(e.opts(t, 1))
	dumpPath := filepath.Join(e.dir, "partial.json")
	s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Sleep: func(time.Duration) {}, DumpOut: dumpPath}
	// First chunk lands, then the network "fails".
	e.ledger.FailSubmit = ""
	first := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Sleep: func(time.Duration) {}, DumpOut: dumpPath}
	_, _, err := first.send(chunkTx(p, 0))
	if err != nil {
		t.Fatal(err)
	}
	before := e.ledger.Submitted
	d, _ := dump.Load(dumpPath)
	s.Dump = d
	if err := s.Submit(p); err != nil {
		t.Fatal(err)
	}
	if e.ledger.Submitted-before != len(p.Chunks)-1+1+1 && e.ledger.Submitted-before != len(p.Chunks)-1+2+1 {
		t.Fatalf("resume must skip the recorded chunk: %d new submits", e.ledger.Submitted-before)
	}
	sum := sha256.Sum256(p.Chunks[0])
	if p.Manifest.OnChain.Chunks[0].SHA256 != hex.EncodeToString(sum[:]) || p.Manifest.OnChain.Chunks[0].TxHash == "" {
		t.Fatal("resumed chunk must keep its tx hash")
	}
}

func TestSubmitFailures(t *testing.T) {
	e := newEnv(t)
	p, _ := Build(e.opts(t, 1))
	e.ledger.Fee = 9000
	s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Sleep: func(time.Duration) {}}
	if err := s.Submit(p); err == nil || !strings.Contains(err.Error(), "fee") {
		t.Fatalf("fee cap: %v", err)
	}
	e.ledger.Fee = 10
	e.ledger.FailSubmit = "tecINSUFFICIENT_RESERVE"
	if err := s.Submit(p); err == nil || !strings.Contains(err.Error(), "tecINSUFFICIENT_RESERVE") {
		t.Fatalf("engine error must surface: %v", err)
	}
	unfunded, _ := sign.NewKey()
	s.Writer = unfunded
	if err := s.Submit(p); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("unfunded account: %v", err)
	}
}
