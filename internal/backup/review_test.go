package backup

// Regression tests for the findings of the 2026-09-15 security review.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/cfg"
	"github.com/justinnevins/xrplbak/internal/chunk"
	"github.com/justinnevins/xrplbak/internal/container"
	"github.com/justinnevins/xrplbak/internal/discover"
	"github.com/justinnevins/xrplbak/internal/dump"
	"github.com/justinnevins/xrplbak/internal/manifest"
	"github.com/justinnevins/xrplbak/internal/redact"
	"github.com/justinnevins/xrplbak/internal/restore"
	"github.com/justinnevins/xrplbak/internal/xrpl/codec"
)

// Finding 1: a resumed run must not re-seal the manifest under a used nonce.
func TestResumeNeverReencryptsManifest(t *testing.T) {
	e := newEnv(t)
	p, _ := Build(e.opts(t, 1))
	dumpPath := filepath.Join(e.dir, "d.json")
	s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Sleep: func(time.Duration) {}, DumpOut: dumpPath}
	if err := s.Submit(p); err != nil {
		t.Fatal(err)
	}
	before := e.ledger.Submitted
	// Second run with the same plan and the dump: only the anchor may be resent.
	d, _ := dump.Load(dumpPath)
	p2, _ := Build(e.opts(t, 1))
	p2.Manifest.Created = "2030-01-01T00:00:00Z" // a different manifest plaintext
	s2 := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Sleep: func(time.Duration) {}, DumpOut: dumpPath, Dump: d}
	if err := s2.Submit(p2); err != nil {
		t.Fatal(err)
	}
	if e.ledger.Submitted-before != 1 {
		t.Fatalf("resume resent %d transactions; only the anchor is allowed", e.ledger.Submitted-before)
	}
	// Every manifest memo on the ledger for this id carries a distinct (nonce, index).
	seen := map[string]bool{}
	for _, tx := range e.ledger.Txs {
		for _, m := range tx.Memos {
			pl, ok := chunk.Decode(m)
			if ok && pl.Type == chunk.TypeManifest {
				k := string(pl.Nonce[:]) + string(rune(pl.Index))
				if seen[k] {
					t.Fatal("nonce reuse on manifest part")
				}
				seen[k] = true
			}
		}
	}
	// Two separate sealings of the same manifest must differ.
	a, _, _ := ManifestMemos(e.key.Key, p.BackupID, p.Manifest)
	b, _, _ := ManifestMemos(e.key.Key, p.BackupID, p.Manifest)
	if bytes.Equal(a[0].Data, b[0].Data) {
		t.Fatal("manifest sealing must use a fresh nonce each run")
	}
}

// Finding 2: junk memos with the real backup id must not shadow real parts.
func TestJunkPartCannotShadowRealManifest(t *testing.T) {
	e := newEnv(t)
	keys := discover.RootKeys{Root: e.root}
	p1, _ := Build(e.opts(t, 1))
	e.submit(t, p1)
	o := e.opts(t, 2)
	o.Now = time.Unix(1_800_000_100, 0)
	p2, _ := Build(o)
	e.submit(t, p2)
	res, _ := discover.Run(e.ledger, keys, e.writer.Address(), 0)
	real := res.Latest
	if real.Manifest.Seq != 2 {
		t.Fatal("setup")
	}
	// Thief posts junk for (id, nonce, index 0) of the real latest backup.
	var nonce [10]byte
	for _, tx := range e.ledger.Txs {
		for _, m := range tx.Memos {
			if pl, ok := chunk.Decode(m); ok && pl.Type == chunk.TypeManifest && pl.BackupID == real.BackupID {
				nonce = pl.Nonce
			}
		}
	}
	total := uint16((len(real.Plain) + chunk.ManifestPartLen - 1) / chunk.ManifestPartLen)
	junk, err := chunk.Encode(chunk.TypeManifest, real.BackupID[:], 0, total, nonce[:], bytes.Repeat([]byte{0x42}, 100))
	if err != nil {
		t.Fatal(err)
	}
	s := &Submitter{Client: e.ledger, Writer: e.writer, Key: e.key, Sleep: func(time.Duration) {}}
	if _, _, err := s.send(&codec.Tx{Type: codec.TxAccountSet, Memos: []codec.Memo{junk}}); err != nil {
		t.Fatal(err)
	}
	e.ledger.DropDID = true
	res, _ = discover.Run(e.ledger, keys, e.writer.Address(), 0)
	if res.Latest == nil || res.Latest.Manifest.Seq != 2 {
		t.Fatalf("junk shadowed the real backup: latest=%v warnings=%v", res.Latest, res.Warnings)
	}
}

// Finding 3 and 4: port credentials and seeds in key stanzas.
func TestRedactPortCredentialsAndSeedInValidators(t *testing.T) {
	f := cfg.Parse("[port_rpc_admin_local]\nport = 5005\nip = 127.0.0.1\nadmin_password = hunter2\npassword = p\nssl_key = /etc/k.pem\nprotocol = http\n")
	res, err := redact.Split(f)
	if err != nil {
		t.Fatal(err)
	}
	on := res.OnChain.Canonical()
	for _, bad := range []string{"hunter2", "password = p", "/etc/k.pem"} {
		if strings.Contains(on, bad) {
			t.Fatalf("%q leaked on-chain:\n%s", bad, on)
		}
	}
	_, err = redact.Split(cfg.Parse("[validators]\nsnFAKEwhBBnsTS3hSm8Kq6a9JhnBdxa\n"))
	if err == nil {
		t.Fatal("seed in [validators] must be refused")
	}
	_, err = redact.Split(cfg.Parse("[node_size]\n" + redact.MovedMarker + "\n"))
	if err == nil {
		t.Fatal("restore marker in input must be refused")
	}
}

// Finding 7: hostile paths and modes in an authenticated container.
func TestRestoreRefusesTraversalAndSetuid(t *testing.T) {
	m := manifestFor("../../etc/cron.d/x", 0o4755)
	plan := restore.Build(m, []container.Entry{{Path: "../../etc/cron.d/x", Mode: 0o4755, Data: []byte("[a]\nb\n")}}, nil)
	if _, err := plan.WriteTemp(); err == nil {
		t.Fatal("traversal must be refused")
	}
	plan = restore.Build(m, []container.Entry{{Path: "/etc/xrpld/x.cfg", Mode: 0o4755, Data: []byte("[a]\nb\n")}}, nil)
	dir, err := plan.WriteTemp()
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(filepath.Join(dir, "etc", "xrpld", "x.cfg"))
	if st.Mode()&os.ModeSetuid != 0 {
		t.Fatal("setuid bit must be dropped")
	}
}

// Finding 12: duplicate stanza names survive split and merge.
func TestDuplicateStanzasMerge(t *testing.T) {
	f := cfg.Parse("[ips_fixed]\n10.0.0.1 2459\n[node_size]\nhuge\n[ips_fixed]\n10.0.0.2 2459\n")
	res, err := redact.Split(f)
	if err != nil {
		t.Fatal(err)
	}
	merged := redact.Merge(cfg.Parse(res.OnChain.Canonical()), cfg.Parse(res.Bundle.Canonical()))
	if merged.Canonical() != f.Canonical() || !strings.Contains(merged.Canonical(), "10.0.0.2") {
		t.Fatalf("merge lost lines:\n%s", merged.Canonical())
	}
}

func manifestFor(path string, mode uint32) *manifest.Manifest {
	m := &manifest.Manifest{}
	m.Files = append(m.Files, manifest.File{Path: path, Mode: mode, Where: "onchain"})
	m.Node.Role = "node"
	return m
}
