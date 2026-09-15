package main

// The Tier 1 adversarial corpus. Every row is one hostile or malformed input
// driven through the real command surface, and every row asserts a named
// exit code plus a message fragment, not merely "an error". The rows that
// expect exitOK are the cases where the tool must refuse one object (a
// forged anchor) and still recover from the authentic remainder; those rows
// also assert that the tampered object was reported as rejected.
//
// Rules from the assurance loop apply: a row that passed on first write was
// made to fail first (see xrplbak-assurance for the failing commits), and
// rows are never weakened or deleted.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/justinnevins/xrplbak/internal/anchor"
	"github.com/justinnevins/xrplbak/internal/backup"
	"github.com/justinnevins/xrplbak/internal/chunk"
	"github.com/justinnevins/xrplbak/internal/container"
	"github.com/justinnevins/xrplbak/internal/crypto"
	"github.com/justinnevins/xrplbak/internal/dump"
	"github.com/justinnevins/xrplbak/internal/manifest"
	"github.com/justinnevins/xrplbak/internal/xrpl"
	"github.com/justinnevins/xrplbak/internal/xrpl/fake"
	"github.com/justinnevins/xrplbak/internal/xrpl/sign"
)

const fixtures = "../../tests/fixtures/"

// world is one honest backup on a fake ledger, ready to be damaged.
type world struct {
	t       *testing.T
	dir     string
	root    crypto.RootKey
	key     *crypto.KeyFile
	writer  *sign.Key
	ledger  *fake.Ledger
	plan    *backup.Plan
	cfgPath string
	valPath string
	words   string // path to the 24-word file
	bundle  string // path to the bundle file
	keyFile string // path to xrplbak.key
}

// newWorld builds and submits a three-chunk validator backup at seq 1.
// rootByte makes two worlds differ in every key.
func newWorld(t *testing.T, rootByte byte) *world {
	t.Helper()
	w := &world{t: t, dir: t.TempDir()}
	for i := range w.root {
		w.root[i] = byte(i)*3 + rootByte
	}
	w.writer, _ = sign.KeyFromSeed(bytes.Repeat([]byte{rootByte + 5}, 16))
	w.key = &crypto.KeyFile{Epoch: 0, Key: w.root.DeriveEpochKey(0)}
	copy(w.key.AccountID[:], w.writer.AccountID())
	copy(w.key.WriterSeed[:], w.writer.Seed())
	w.ledger = fake.New()
	w.ledger.Fund(w.writer.Address(), 5_000_000)

	// Config with enough public on-chain text for several chunks.
	raw, err := os.ReadFile(fixtures + "validator-full.cfg")
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	sb.Write(raw)
	sb.WriteString("\n[sntp_servers]\n")
	for i := 0; i < 100; i++ {
		// Incompressible names, so the packed container spans chunks.
		sum := sha256.Sum256([]byte{byte(i), rootByte})
		fmt.Fprintf(&sb, "%s.example.com\n", hex.EncodeToString(sum[:16]))
	}
	w.cfgPath = filepath.Join(w.dir, "xrpld.cfg")
	w.valPath = filepath.Join(w.dir, "validators.txt")
	val, _ := os.ReadFile(fixtures + "validators.txt")
	must(t, os.WriteFile(w.cfgPath, []byte(sb.String()), 0o600))
	must(t, os.WriteFile(w.valPath, val, 0o644))

	w.plan = w.build(1, w.cfgPath, w.valPath)
	if len(w.plan.Chunks) < 3 {
		t.Fatalf("fixture must span several chunks, got %d", len(w.plan.Chunks))
	}
	w.submit(w.plan)

	w.words = filepath.Join(w.dir, "words.txt")
	must(t, os.WriteFile(w.words, []byte(strings.Join(w.root.ToWords(), " ")+"\n"), 0o600))
	w.bundle = filepath.Join(w.dir, "bundle.bin")
	must(t, os.WriteFile(w.bundle, w.plan.Bundle, 0o600))
	w.keyFile = filepath.Join(w.dir, "xrplbak.key")
	must(t, os.WriteFile(w.keyFile, w.key.Encode(), 0o600))
	return w
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (w *world) build(seq uint32, cfgPath, valPath string) *backup.Plan {
	w.t.Helper()
	p, err := backup.Build(backup.Options{ConfigPath: cfgPath, ValidatorsPath: valPath, Key: w.key, Now: time.Unix(1_800_000_000+int64(seq), 0), Seq: seq})
	must(w.t, err)
	return p
}

func (w *world) submit(p *backup.Plan) {
	w.t.Helper()
	s := &backup.Submitter{Client: w.ledger, Writer: w.writer, Key: w.key, Sleep: func(time.Duration) {}}
	must(w.t, s.Submit(p))
}

// dumpFile renders the fake ledger's current state as a dump file, so the
// CLI reads exactly what the test placed on the ledger.
func (w *world) dumpFile(name string) string {
	w.t.Helper()
	d := &dump.Dump{Account: w.writer.Address(), BackupID: w.plan.Manifest.BackupID}
	for _, rec := range w.ledger.Txs {
		if rec.LedgerIndex < w.ledger.Prune {
			continue
		}
		raw := map[string]any{"Account": rec.Account, "TransactionType": rec.TxType, "Sequence": rec.Sequence, "hash": rec.Hash, "ledger_index": rec.LedgerIndex, "validated": true}
		if len(rec.Memos) > 0 {
			raw["Memos"] = xrpl.MemosToJSON(rec.Memos)
		}
		b, _ := json.Marshal(raw)
		d.Txs = append(d.Txs, dump.Tx{Hash: rec.Hash, LedgerIndex: rec.LedgerIndex, Result: rec.Result, TxJSON: b})
	}
	if data, ok := w.ledger.DID[w.writer.Address()]; ok {
		d.DID = &dump.DID{LedgerIndex: w.ledger.Seq, Data: strings.ToUpper(hex.EncodeToString(data))}
	}
	path := filepath.Join(w.dir, name+".dump.json")
	must(w.t, d.Save(path))
	return path
}

// chunkTx returns the ledger record carrying chunk idx of the world's plan.
func (w *world) chunkTx(idx int) *xrpl.TxRecord {
	w.t.Helper()
	for i := range w.ledger.Txs {
		for _, m := range w.ledger.Txs[i].Memos {
			if p, ok := chunk.Decode(m); ok && p.Type == chunk.TypeChunk && int(p.Index) == idx && p.BackupID == [16]byte(w.plan.BackupID) {
				return &w.ledger.Txs[i]
			}
		}
	}
	w.t.Fatalf("no tx carries chunk %d", idx)
	return nil
}

// manifestTx returns the ledger record carrying manifest part idx.
func (w *world) manifestTx(idx int) *xrpl.TxRecord {
	w.t.Helper()
	for i := range w.ledger.Txs {
		for _, m := range w.ledger.Txs[i].Memos {
			if p, ok := chunk.Decode(m); ok && p.Type == chunk.TypeManifest && int(p.Index) == idx && p.BackupID == [16]byte(w.plan.BackupID) {
				return &w.ledger.Txs[i]
			}
		}
	}
	w.t.Fatalf("no tx carries manifest part %d", idx)
	return nil
}

// dropTx removes one record from the ledger history.
func (w *world) dropTx(rec *xrpl.TxRecord) {
	for i := range w.ledger.Txs {
		if w.ledger.Txs[i].Hash == rec.Hash {
			w.ledger.Txs = append(w.ledger.Txs[:i], w.ledger.Txs[i+1:]...)
			return
		}
	}
}

// flipLastByte flips the final memo byte (inside the AEAD tag).
func flipLastByte(rec *xrpl.TxRecord) {
	d := rec.Memos[0].Data
	d[len(d)-1] ^= 0x01
}

// resealOnChain replaces the plan's on-chain content with entries of the
// test's choosing and re-signs the manifest to match. It models a host-key
// holder authoring a hostile but fully authenticated backup.
func (w *world) resealOnChain(entries []container.Entry) *backup.Plan {
	w.t.Helper()
	onRaw, err := container.Encode(entries)
	must(w.t, err)
	packed, err := container.Pack(onRaw)
	must(w.t, err)
	pieces, err := chunk.Split(packed)
	must(w.t, err)
	p := w.build(1, w.cfgPath, w.valPath)
	m := p.Manifest
	sum := sha256.Sum256(onRaw)
	m.OnChain.PlainSHA256 = hex.EncodeToString(sum[:])
	m.OnChain.PlainLen = len(onRaw)
	m.OnChain.Chunks = nil
	m.Files = m.Files[:0]
	for _, e := range entries {
		s := sha256.Sum256(e.Data)
		m.Files = append(m.Files, manifest.File{Path: e.Path, Mode: e.Mode, SHA256: hex.EncodeToString(s[:]), Where: "onchain"})
	}
	kb := w.key.Key.BackupKey(p.BackupID)
	p.Chunks, p.ChunkMemos = nil, nil
	total := uint16(len(pieces))
	for i, piece := range pieces {
		ct := crypto.SealChunk(kb, p.BackupID, uint16(i), total, piece)
		memo, err := chunk.Encode(chunk.TypeChunk, p.BackupID, uint16(i), total, nil, ct)
		must(w.t, err)
		s := sha256.Sum256(ct)
		m.OnChain.Chunks = append(m.OnChain.Chunks, manifest.Chunk{Index: i, SHA256: hex.EncodeToString(s[:])})
		p.Chunks = append(p.Chunks, ct)
		p.ChunkMemos = append(p.ChunkMemos, memo)
	}
	return p
}

// result of one CLI run.
type result struct {
	code int
	out  string
}

func (w *world) run(stdinText string, args ...string) result {
	w.t.Helper()
	var buf bytes.Buffer
	code := run(args, strings.NewReader(stdinText), &buf, &buf)
	w.t.Logf("$ xrplbak %s\n%s(exit %d)", strings.Join(args, " "), buf.String(), code)
	return result{code: code, out: buf.String()}
}

// restore runs a dry-run restore from a dump written from the ledger now.
func (w *world) restore(extra ...string) result {
	w.t.Helper()
	args := []string{"restore", "--dump", w.dumpFile("case"), "--words-file", w.words, "--account", w.writer.Address(), "--bundle", w.bundle}
	return w.run("yes\n", append(args, extra...)...)
}

// corpusCase is one row.
type corpusCase struct {
	name string
	// setup damages the world and returns the arguments to run. A nil return
	// means "restore with defaults".
	setup func(w *world) []string
	code  int
	// msg must appear in the combined output.
	msg string
	// after runs extra checks once the command returned.
	after func(t *testing.T, w *world, r result)
}

func TestAdversarialCorpus(t *testing.T) {
	cases := []corpusCase{
		// ---- one flipped ciphertext byte, per layer -------------------------
		{
			name:  "chunk ciphertext flipped",
			setup: func(w *world) []string { flipLastByte(w.chunkTx(1)); return nil },
			code:  exitAuth, msg: "chunk 1 ciphertext hash does not match",
		},
		{
			name:  "manifest part flipped",
			setup: func(w *world) []string { flipLastByte(w.manifestTx(0)); return nil },
			code:  exitAuth, msg: "no backup authenticates",
		},
		{
			name: "bundle byte flipped",
			setup: func(w *world) []string {
				b, _ := os.ReadFile(w.bundle)
				b[len(b)-1] ^= 0x01
				must(w.t, os.WriteFile(w.bundle, b, 0o600))
				return nil
			},
			code: exitAuth, msg: "bundle file hash does not match",
		},
		{
			name: "bundle truncated",
			setup: func(w *world) []string {
				b, _ := os.ReadFile(w.bundle)
				must(w.t, os.WriteFile(w.bundle, b[:len(b)-40], 0o600))
				return nil
			},
			code: exitAuth, msg: "bundle file hash does not match",
		},
		{
			name: "bundle from another backup",
			setup: func(w *world) []string {
				other := newWorld(w.t, 40)
				return []string{"--bundle", other.bundle}
			},
			code: exitAuth, msg: "bundle belongs to backup",
		},

		// ---- chunk assembly --------------------------------------------------
		{
			name:  "chunk missing from history",
			setup: func(w *world) []string { w.dropTx(w.chunkTx(1)); return nil },
			code:  exitIncomplete, msg: "chunk 2 of 3 missing",
		},
		{
			name: "chunk transactions swapped",
			setup: func(w *world) []string {
				a, b := w.chunkTx(0), w.chunkTx(1)
				a.Memos, b.Memos = b.Memos, a.Memos
				return nil
			},
			code: exitAuth, msg: "does not carry chunk 0",
		},
		{
			name: "chunk index header rewritten",
			setup: func(w *world) []string {
				// Chunk 1's bytes relabelled as chunk 0 and placed in chunk 0's tx.
				a, b := w.chunkTx(0), w.chunkTx(1)
				d := append([]byte{}, b.Memos[0].Data...)
				d[17], d[18] = 0, 0
				a.Memos[0].Data = d
				return nil
			},
			code: exitAuth, msg: "chunk 0 ciphertext hash does not match",
		},
		{
			name: "chunk from another backup",
			setup: func(w *world) []string {
				other := newWorld(w.t, 40)
				w.chunkTx(0).Memos = other.chunkTx(0).Memos
				return nil
			},
			code: exitAuth, msg: "does not carry chunk 0",
		},
		{
			name: "duplicate seq with different content",
			setup: func(w *world) []string {
				// A second, different backup lands at the same (epoch, seq).
				must(w.t, os.WriteFile(w.cfgPath, []byte("[server]\nport_peer\n\n[port_peer]\nport = 51235\nprotocol = peer\n"), 0o600))
				p2 := w.build(1, w.cfgPath, "")
				w.submit(p2)
				// The later backup's bundle, so only the conflict can stop the restore.
				must(w.t, os.WriteFile(w.bundle, p2.Bundle, 0o600))
				return nil
			},
			code: exitAuth, msg: "share epoch 0 seq 1",
			after: func(t *testing.T, w *world, r result) {
				if strings.Contains(r.out, "== Files ==") {
					t.Fatal("restore must not pick one of two conflicting backups")
				}
			},
		},

		// ---- anchor ------------------------------------------------------------
		{
			name: "anchor MAC forged, history intact",
			setup: func(w *world) []string {
				d := w.ledger.DID[w.writer.Address()]
				d[len(d)-1] ^= 0x01
				return nil
			},
			code: exitOK, msg: "anchor:   present but NOT verified",
		},
		{
			name: "anchor MAC valid but from the wrong epoch",
			setup: func(w *world) []string {
				// Signed with the epoch 1 key and labelled epoch 1, but it names
				// the epoch 0 backup. The anchor must not be trusted.
				rec := &anchor.Record{Epoch: 1, Seq: 1}
				copy(rec.BackupID[:], w.plan.BackupID)
				w.ledger.DID[w.writer.Address()] = anchor.Encode(w.root.DeriveEpochKey(1), rec)
				return nil
			},
			code: exitOK, msg: "anchor:   present but NOT verified",
		},
		{
			name: "anchor rolled back to an older backup",
			setup: func(w *world) []string {
				p2 := w.build(2, w.cfgPath, w.valPath)
				p2.Manifest.Supersedes = w.plan.Manifest.BackupID
				w.submit(p2)
				old := &anchor.Record{Epoch: 0, Seq: 1}
				copy(old.BackupID[:], w.plan.BackupID)
				w.ledger.DID[w.writer.Address()] = anchor.Encode(w.key.Key, old)
				must(w.t, os.WriteFile(w.bundle, p2.Bundle, 0o600))
				return nil
			},
			code: exitOK, msg: "possible rollback",
			after: func(t *testing.T, w *world, r result) {
				if !strings.Contains(r.out, "* epoch 0 seq 2") {
					t.Fatal("newest authenticated backup must win over the anchor")
				}
			},
		},
		{
			name: "anchor names a manifest that is not in history",
			setup: func(w *world) []string {
				for i := 0; ; i++ {
					if i >= 8 {
						w.t.Fatal("manifest parts not found")
					}
					if mt := w.manifestTxOrNil(i); mt != nil {
						w.dropTx(mt)
					} else {
						break
					}
				}
				return nil
			},
			code: exitAuth, msg: "not in the searched range",
		},

		// ---- tombstone -----------------------------------------------------------
		{
			name: "tombstone newer than the newest backup",
			setup: func(w *world) []string {
				p, err := backup.Build(backup.Options{Key: w.key, Now: time.Unix(1_800_000_009, 0), Seq: 2, Tombstone: true, Supersedes: w.plan.Manifest.BackupID})
				must(w.t, err)
				w.submit(p)
				return nil
			},
			code: exitIncomplete, msg: "the newest backup is a tombstone",
			after: func(t *testing.T, w *world, r result) {
				if strings.Contains(r.out, "== Files ==") {
					t.Fatal("no file plan may be printed for a tombstoned backup")
				}
			},
		},

		// ---- restore --write ----------------------------------------------------
		{
			name: "write into a target that already holds the file",
			setup: func(w *world) []string {
				target := filepath.Join(w.dir, "target")
				must(w.t, os.MkdirAll(target, 0o700))
				must(w.t, os.WriteFile(filepath.Join(target, "xrpld.cfg"), []byte("live config, do not touch\n"), 0o600))
				return []string{"--write", "--target", target}
			},
			code: exitWrite, msg: "exists; pass --force",
			after: func(t *testing.T, w *world, r result) {
				target := filepath.Join(w.dir, "target")
				b, _ := os.ReadFile(filepath.Join(target, "xrpld.cfg"))
				if string(b) != "live config, do not touch\n" {
					t.Fatal("existing file was altered")
				}
				if _, err := os.Stat(filepath.Join(target, "validators.txt")); err == nil {
					t.Fatal("a sibling file was written before the refusal")
				}
			},
		},
		{
			name: "write when two backup files share a basename",
			setup: func(w *world) []string {
				// validators.txt content stored under a second path named xrpld.cfg.
				sub := filepath.Join(w.dir, "sub")
				must(w.t, os.MkdirAll(sub, 0o700))
				alt := filepath.Join(sub, "xrpld.cfg")
				val, _ := os.ReadFile(w.valPath)
				must(w.t, os.WriteFile(alt, val, 0o644))
				p := w.build(2, w.cfgPath, alt)
				w.submit(p)
				must(w.t, os.WriteFile(w.bundle, p.Bundle, 0o600))
				target := filepath.Join(w.dir, "target")
				must(w.t, os.MkdirAll(target, 0o700))
				return []string{"--write", "--target", target}
			},
			code: exitWrite, msg: "same name",
			after: func(t *testing.T, w *world, r result) {
				ents, _ := os.ReadDir(filepath.Join(w.dir, "target"))
				if len(ents) != 0 {
					t.Fatalf("target must stay empty, has %d entries", len(ents))
				}
			},
		},
		{
			name: "write under /var/lib",
			setup: func(w *world) []string {
				return []string{"--write", "--target", "/var/lib/xrplbak-corpus-never-created"}
			},
			code: exitWrite, msg: "refusing to write under /var/lib",
			after: func(t *testing.T, w *world, r result) {
				if _, err := os.Stat("/var/lib/xrplbak-corpus-never-created"); err == nil {
					t.Fatal("target directory was created")
				}
			},
		},
		{
			name: "write cancelled at the prompt",
			setup: func(w *world) []string {
				target := filepath.Join(w.dir, "target")
				must(w.t, os.MkdirAll(target, 0o700))
				return []string{"--write", "--target", target, "--stdin", "no"}
			},
			code: exitUsage, msg: "cancelled; nothing was written",
			after: func(t *testing.T, w *world, r result) {
				ents, _ := os.ReadDir(filepath.Join(w.dir, "target"))
				if len(ents) != 0 {
					t.Fatal("files written after a cancelled prompt")
				}
			},
		},
		{
			name:  "write without a target",
			setup: func(w *world) []string { return []string{"--write"} },
			code:  exitUsage, msg: "--write needs --target",
		},

		// ---- hostile paths in an authenticated manifest ------------------------
		{
			name: "path traversal in manifest files[].path",
			setup: func(w *world) []string {
				return w.hostilePaths("../../../etc/xrplbak-corpus-escape.cfg")
			},
			code: exitRefused, msg: "unsafe path",
		},
		{
			name:  "root path in manifest files[].path",
			setup: func(w *world) []string { return w.hostilePaths("/") },
			code:  exitRefused, msg: "unsafe path",
		},
		{
			name: "container carries a file the manifest does not list",
			setup: func(w *world) []string {
				raw, _ := os.ReadFile(w.cfgPath)
				w.hostilePaths(w.cfgPath)
				// Re-point the manifest at a different name; the container entry stays.
				w.ledger = fake.New()
				w.ledger.Fund(w.writer.Address(), 5_000_000)
				p := w.resealOnChain([]container.Entry{{Path: w.cfgPath, Mode: 0o600, Data: raw}})
				p.Manifest.Files[0].Path = filepath.Join(w.dir, "other.cfg")
				w.plan = p
				w.submit(p)
				must(w.t, os.WriteFile(w.bundle, p.Bundle, 0o600))
				return nil
			},
			code: exitRefused, msg: "not listed in the manifest",
		},
		{
			name:  "dot path in manifest files[].path",
			setup: func(w *world) []string { return w.hostilePaths("/etc/xrpld/.") },
			code:  exitRefused, msg: "unsafe path",
		},
		{
			// A path carrying a newline forges a second line in the dry-run
			// completeness listing, so a file that was never recovered can be
			// made to read as complete.
			name: "newline in manifest files[].path",
			setup: func(w *world) []string {
				return w.hostileSealedPath("/etc/xrpld.cfg\n  /etc/shadow                              complete")
			},
			code: exitRefused, msg: "unsafe path",
		},
		{
			// A cursor-control escape rewrites the line already printed.
			name: "terminal escape in manifest files[].path",
			setup: func(w *world) []string {
				return w.hostileSealedPath("/etc/\x1b[2K\x1b[Gxrpld.cfg")
			},
			code: exitRefused, msg: "unsafe path",
		},

		// ---- dump file -------------------------------------------------------------
		{
			name: "dump truncated",
			setup: func(w *world) []string {
				p := w.dumpFile("real")
				b, _ := os.ReadFile(p)
				must(w.t, os.WriteFile(p, b[:len(b)/2], 0o600))
				return []string{"--dump", p}
			},
			code: exitUsage, msg: "not an xrplbak dump file",
		},
		{
			name: "dump with trailing garbage",
			setup: func(w *world) []string {
				p := w.dumpFile("real")
				b, _ := os.ReadFile(p)
				must(w.t, os.WriteFile(p, append(b, []byte("\n{\"txs\":[]}\n")...), 0o600))
				return []string{"--dump", p}
			},
			code: exitUsage, msg: "not an xrplbak dump file",
		},
		{
			name: "dump from a future format version",
			setup: func(w *world) []string {
				p := w.dumpFile("real")
				b, _ := os.ReadFile(p)
				b = bytes.Replace(b, []byte(`"v": 1`), []byte(`"v": 2`), 1)
				must(w.t, os.WriteFile(p, b, 0o600))
				return []string{"--dump", p}
			},
			code: exitUsage, msg: "unsupported dump version",
		},
		{
			name: "dump entry whose tx_json is not a transaction",
			setup: func(w *world) []string {
				p := w.dumpFile("real")
				b, _ := os.ReadFile(p)
				var d dump.Dump
				must(w.t, json.Unmarshal(b, &d))
				d.Txs[1].TxJSON = json.RawMessage(`"not an object"`)
				must(w.t, d.Save(p))
				return []string{"--dump", p}
			},
			code: exitUsage, msg: "not an xrplbak dump file",
		},

		// ---- recovery key ---------------------------------------------------------
		{
			name: "words with a bad checksum",
			setup: func(w *world) []string {
				words := w.root.ToWords()
				words[23] = "zoo"
				if words[23] == w.root.ToWords()[23] {
					words[23] = "abandon"
				}
				return w.wordsArgs(strings.Join(words, " "))
			},
			code: exitAuth, msg: "checksum mismatch",
		},
		{
			name: "word not in the list",
			setup: func(w *world) []string {
				words := w.root.ToWords()
				words[3] = "xrpl"
				return w.wordsArgs(strings.Join(words, " "))
			},
			code: exitAuth, msg: "not in the BIP39 list",
		},
		{
			name:  "23 words",
			setup: func(w *world) []string { return w.wordsArgs(strings.Join(w.root.ToWords()[:23], " ")) },
			code:  exitAuth, msg: "expected 24 words",
		},
		{
			name: "valid words for a different key",
			setup: func(w *world) []string {
				other := newWorld(w.t, 40)
				return w.wordsArgs(strings.Join(other.root.ToWords(), " "))
			},
			code: exitAuth, msg: "no backup authenticates",
		},
		{
			name: "2 of 3 shares, one with a wrong character",
			setup: func(w *world) []string {
				s := w.shares(3, 2)
				s[1] = mutateShare(s[1])
				return w.sharesArgs(s[0], s[1])
			},
			code: exitAuth, msg: "checksum failed",
		},
		{
			name: "2 of 3 shares, one from a different split with a forged checksum",
			setup: func(w *world) []string {
				a := w.shares(3, 2)
				b := newWorld(w.t, 40).shares(3, 2)
				return w.sharesArgs(a[0], regraftShare(b[1], a[0]))
			},
			code: exitAuth, msg: "no backup authenticates",
		},
		{
			name:  "one share only",
			setup: func(w *world) []string { s := w.shares(3, 2); return w.sharesArgs(s[0]) },
			code:  exitAuth, msg: "need at least 2 shares",
		},
		{
			name: "shares from two different splits",
			setup: func(w *world) []string {
				a, b := w.shares(3, 2), w.shares(3, 2)
				return w.sharesArgs(a[0], b[1])
			},
			code: exitAuth, msg: "different split",
		},

		// ---- config that is already a partial restore ------------------------------
		{
			name: "backup of a config carrying an xrplbak restore marker",
			setup: func(w *world) []string {
				b, _ := os.ReadFile(w.cfgPath)
				b = append(b, []byte("\n[ips_fixed]\n# xrplbak: content moved to the off-chain bundle\n")...)
				must(w.t, os.WriteFile(w.cfgPath, b, 0o600))
				return []string{"backup", "--config", w.cfgPath, "--key", w.keyFile, "--out", filepath.Join(w.dir, "out")}
			},
			code: exitRefused, msg: "restore marker",
		},
		{
			name: "redact of a config carrying an xrplbak restore marker",
			setup: func(w *world) []string {
				b, _ := os.ReadFile(w.cfgPath)
				b = append(b, []byte("\n[ips_fixed]\n# xrplbak: content moved to the off-chain bundle\n")...)
				must(w.t, os.WriteFile(w.cfgPath, b, 0o600))
				return []string{"redact", "--config", w.cfgPath}
			},
			code: exitRefused, msg: "restore marker",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())
			w := newWorld(t, 0)
			extra := c.setup(w)
			var r result
			switch {
			case len(extra) > 0 && (extra[0] == "backup" || extra[0] == "redact"):
				r = w.run("", extra...)
			default:
				stdinText := "yes\n"
				if i := indexOf(extra, "--stdin"); i >= 0 {
					stdinText = extra[i+1] + "\n"
					extra = append(extra[:i], extra[i+2:]...)
				}
				args := []string{"restore", "--dump", w.dumpFile("case"), "--words-file", w.words, "--account", w.writer.Address(), "--bundle", w.bundle}
				r = w.run(stdinText, append(args, extra...)...)
			}
			if r.code != c.code {
				t.Fatalf("exit %d, want %d (%s)", r.code, c.code, exitName(c.code))
			}
			if !strings.Contains(r.out, c.msg) {
				t.Fatalf("output lacks %q", c.msg)
			}
			if c.code != exitOK {
				// Nothing may have been written to the temp dir on a refusal.
				if ents, _ := os.ReadDir(os.Getenv("TMPDIR")); len(ents) != 0 {
					t.Fatalf("refused run left %d entries in TMPDIR", len(ents))
				}
			}
			if c.after != nil {
				c.after(t, w, r)
			}
		})
	}
}

// ---- helpers used by rows --------------------------------------------------

func (w *world) manifestTxOrNil(idx int) *xrpl.TxRecord {
	for i := range w.ledger.Txs {
		for _, m := range w.ledger.Txs[i].Memos {
			if p, ok := chunk.Decode(m); ok && p.Type == chunk.TypeManifest && int(p.Index) == idx && p.BackupID == [16]byte(w.plan.BackupID) {
				return &w.ledger.Txs[i]
			}
		}
	}
	return nil
}

// hostilePaths reseals the on-chain container with one entry at path and
// resubmits the backup. The manifest authenticates: only the path is bad.
func (w *world) hostilePaths(path string) []string {
	w.t.Helper()
	w.ledger = fake.New()
	w.ledger.Fund(w.writer.Address(), 5_000_000)
	raw, _ := os.ReadFile(w.cfgPath)
	p := w.resealOnChain([]container.Entry{{Path: path, Mode: 0o600, Data: raw}})
	w.plan = p
	w.submit(p)
	must(w.t, os.WriteFile(w.bundle, p.Bundle, 0o600))
	return nil
}

// hostileSealedPath reseals both the on-chain container and the bundle at
// the same hostile path and rewrites the manifest to list only it, so the
// only guard left standing is checkPath. hostilePaths leaves the bundle at
// the honest path, which the unlisted-entry check catches first.
func (w *world) hostileSealedPath(path string) []string {
	w.t.Helper()
	w.ledger = fake.New()
	w.ledger.Fund(w.writer.Address(), 5_000_000)
	raw, _ := os.ReadFile(w.cfgPath)
	p := w.resealOnChain([]container.Entry{{Path: path, Mode: 0o600, Data: raw}})

	bRaw, err := container.Encode([]container.Entry{{Path: path, Mode: 0o600, Data: []byte("[validator_token]\nAAAA\n")}})
	must(w.t, err)
	bPacked, err := container.Pack(bRaw)
	must(w.t, err)
	p.Bundle = crypto.SealBundle(w.key.Key.BundleKey(p.BackupID), p.BackupID, bPacked)
	bSum := sha256.Sum256(bRaw)
	cSum := sha256.Sum256(p.Bundle)
	p.Manifest.Bundle.PlainSHA256 = hex.EncodeToString(bSum[:])
	p.Manifest.Bundle.CipherSHA256 = hex.EncodeToString(cSum[:])
	p.Manifest.Bundle.Len = len(p.Bundle)

	w.plan = p
	w.submit(p)
	must(w.t, os.WriteFile(w.bundle, p.Bundle, 0o600))
	return nil
}

func (w *world) wordsArgs(text string) []string {
	p := filepath.Join(w.dir, "alt-words.txt")
	must(w.t, os.WriteFile(p, []byte(text+"\n"), 0o600))
	return []string{"--words-file", p}
}

func (w *world) shares(n, t int) []string {
	s, err := w.root.Split(n, t)
	must(w.t, err)
	return s
}

func (w *world) sharesArgs(shares ...string) []string {
	p := filepath.Join(w.dir, "shares.txt")
	must(w.t, os.WriteFile(p, []byte(strings.Join(shares, "\n")+"\n"), 0o600))
	return []string{"--words-file", "", "--shares-file", p}
}

var crockford = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// mutateShare changes one character in the share body.
func mutateShare(s string) string {
	b := []byte(s)
	i := len(b) / 2
	for b[i] == '-' {
		i++
	}
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

// regraftShare takes a share from another split and rewrites its split id
// to match ref, recomputing the checksum so it decodes cleanly.
func regraftShare(foreign, ref string) string {
	dec := func(s string) []byte {
		b, err := crockford.DecodeString(strings.ReplaceAll(s, "-", ""))
		if err != nil {
			panic(err)
		}
		return b
	}
	f, r := dec(foreign), dec(ref)
	body := append([]byte{}, f[:len(f)-2]...)
	body[1], body[2] = r[1], r[2]
	sum := sha256.Sum256(body)
	enc := crockford.EncodeToString(append(body, sum[0], sum[1]))
	var groups []string
	for len(enc) > 7 {
		groups = append(groups, enc[:7])
		enc = enc[7:]
	}
	return strings.Join(append(groups, enc), "-")
}

func indexOf(list []string, s string) int {
	for i, v := range list {
		if v == s {
			return i
		}
	}
	return -1
}

func exitName(code int) string {
	switch code {
	case exitOK:
		return "exitOK"
	case exitUsage:
		return "exitUsage"
	case exitNetwork:
		return "exitNetwork"
	case exitRefused:
		return "exitRefused"
	case exitAuth:
		return "exitAuth"
	case exitIncomplete:
		return "exitIncomplete"
	case exitWrite:
		return "exitWrite"
	}
	return fmt.Sprint(code)
}

// TestBackupIDSelectsThroughConflict pins the escape hatch for the
// duplicate-seq refusal: naming the backup restores it.
func TestBackupIDSelectsThroughConflict(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	w := newWorld(t, 0)
	must(t, os.WriteFile(w.cfgPath, []byte("[server]\nport_peer\n\n[port_peer]\nport = 51235\nprotocol = peer\n"), 0o600))
	p2 := w.build(1, w.cfgPath, "")
	w.submit(p2)
	must(t, os.WriteFile(w.bundle, p2.Bundle, 0o600))
	if r := w.restore(); r.code != exitAuth {
		t.Fatalf("conflict must refuse, got exit %d", r.code)
	}
	r := w.restore("--backup-id", p2.Manifest.BackupID[:12])
	if r.code != exitOK || !strings.Contains(r.out, "== Files ==") {
		t.Fatalf("--backup-id must select through the conflict, got exit %d", r.code)
	}
	if r := w.restore("--backup-id", "ffff"); r.code != exitAuth {
		t.Fatalf("unknown --backup-id must refuse, got exit %d", r.code)
	}
	// An ambiguous prefix (one shared by both ids) is a usage error.
	a, b := w.plan.Manifest.BackupID, p2.Manifest.BackupID
	n := 0
	for n < len(a) && a[n] == b[n] {
		n++
	}
	if n > 0 {
		if r := w.restore("--backup-id", a[:n]); r.code != exitUsage {
			t.Fatalf("ambiguous --backup-id must be a usage error, got exit %d", r.code)
		}
	}
}
