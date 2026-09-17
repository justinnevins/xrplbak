// Package backup turns config files into a plan (dry run) and, on request,
// submits the plan to the ledger. Plan is pure; Submit is the only place
// that signs and sends.
package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/justinnevins/xrplbak/internal/anchor"
	"github.com/justinnevins/xrplbak/internal/cfg"
	"github.com/justinnevins/xrplbak/internal/chunk"
	"github.com/justinnevins/xrplbak/internal/container"
	"github.com/justinnevins/xrplbak/internal/crypto"
	"github.com/justinnevins/xrplbak/internal/discover"
	"github.com/justinnevins/xrplbak/internal/dump"
	"github.com/justinnevins/xrplbak/internal/manifest"
	"github.com/justinnevins/xrplbak/internal/redact"
	"github.com/justinnevins/xrplbak/internal/xrpl"
	"github.com/justinnevins/xrplbak/internal/xrpl/codec"
	"github.com/justinnevins/xrplbak/internal/xrpl/sign"
)

// ToolVersion is stamped into manifests. Set from the Makefile via ldflags.
var ToolVersion = "xrplbak/dev"

// Options for one run.
type Options struct {
	ConfigPath     string
	ValidatorsPath string // optional
	Includes       []string
	Key            *crypto.KeyFile
	Now            time.Time
	Tombstone      bool
	Attestation    *manifest.Attestation
	// Comments says where the operator's comments go. The zero value keeps
	// them in the off-chain bundle.
	Comments redact.Mode
	// Seq and Supersedes come from discovery when a client is available.
	Seq        uint32
	Supersedes string
	// VPKSHA256 binds the backup to a validator identity without naming it.
	VPKSHA256 string
}

// Plan is everything computable without the network.
type Plan struct {
	BackupID   []byte
	Manifest   *manifest.Manifest
	Chunks     [][]byte // ciphertext per on-chain chunk
	ChunkMemos []codec.Memo
	Bundle     []byte // encrypted bundle stream
	Moves      []redact.Move
	Role       string
	OnChainTxt map[string]string // path -> canonical on-chain text, for the report
	AttestText string
}

// Build reads, redacts, encodes, and encrypts. It never touches the network.
func Build(o Options) (*Plan, error) {
	if o.Key == nil {
		return nil, errors.New("key file is required")
	}
	if o.Now.IsZero() {
		o.Now = time.Now().UTC()
	}
	var onEntries, bundleEntries []container.Entry
	var files []manifest.File
	var moves []redact.Move
	role := "node"
	onTxt := map[string]string{}

	addSplit := func(path string) error {
		raw, mode, path, err := readFile(path)
		if err != nil {
			return err
		}
		res, err := redact.Split(cfg.Parse(string(raw)), redact.Options{Comments: o.Comments})
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if res.Role == "validator" {
			role = "validator"
		}
		for _, mv := range res.Moves {
			mv.File = path
			moves = append(moves, mv)
		}
		on := res.OnChain.Render()
		onTxt[path] = on
		onEntries = append(onEntries, container.Entry{Path: path, Mode: mode, Data: []byte(on)})
		where := "onchain"
		if len(res.Bundle.Lines) > 0 {
			bundleEntries = append(bundleEntries, container.Entry{Path: path, Mode: mode, Data: []byte(res.Bundle.Render())})
			where = "onchain+bundle"
		}
		// Hash the operator's own bytes. That is what a correct restore
		// reproduces, and what "complete" has to mean.
		sum := sha256.Sum256(raw)
		files = append(files, manifest.File{Path: path, Mode: mode, SHA256: hex.EncodeToString(sum[:]), Where: where})
		return nil
	}
	if !o.Tombstone {
		if err := addSplit(o.ConfigPath); err != nil {
			return nil, err
		}
		if o.ValidatorsPath != "" {
			if err := addSplit(o.ValidatorsPath); err != nil {
				return nil, err
			}
		}
		for _, inc := range o.Includes {
			raw, mode, inc, err := readFile(inc)
			if err != nil {
				return nil, err
			}
			if err := refuseSecrets(inc, raw); err != nil {
				return nil, err
			}
			bundleEntries = append(bundleEntries, container.Entry{Path: inc, Mode: mode, Data: raw})
			sum := sha256.Sum256(raw)
			files = append(files, manifest.File{Path: inc, Mode: mode, SHA256: hex.EncodeToString(sum[:]), Where: "bundle"})
		}
	}

	onRaw, err := container.Encode(onEntries)
	if err != nil {
		return nil, err
	}
	bundleRaw, err := container.Encode(bundleEntries)
	if err != nil {
		return nil, err
	}
	onPacked, err := container.Pack(onRaw)
	if err != nil {
		return nil, err
	}
	bundlePacked, err := container.Pack(bundleRaw)
	if err != nil {
		return nil, err
	}
	pieces, err := chunk.Split(onPacked)
	if err != nil {
		return nil, err
	}
	if len(pieces) > chunk.MaxChunks {
		return nil, fmt.Errorf("on-chain config needs %d chunks; the limit is %d (%d bytes). Move large stanzas to the bundle with --bundle-stanza, or shorten the config", len(pieces), chunk.MaxChunks, chunk.MaxChunks*container.BlockLen)
	}

	id := o.Key.Key.BackupID(append(append([]byte{}, onPacked...), bundlePacked...), o.Key.Epoch, o.Seq)
	kb := o.Key.Key.BackupKey(id)
	kbundle := o.Key.Key.BundleKey(id)

	m := &manifest.Manifest{Epoch: o.Key.Epoch, Seq: o.Seq, BackupID: hex.EncodeToString(id), Created: o.Now.UTC().Format(time.RFC3339), Tool: ToolVersion}
	m.Node.Role = role
	m.Node.VPKSHA256 = o.VPKSHA256
	onSum := sha256.Sum256(onRaw)
	m.OnChain.PlainSHA256 = hex.EncodeToString(onSum[:])
	m.OnChain.PlainLen = len(onRaw)
	bSum := sha256.Sum256(bundleRaw)
	m.Bundle.PlainSHA256 = hex.EncodeToString(bSum[:])
	m.Files = files
	for _, mv := range moves {
		idx := 0
		for i, f := range files {
			if f.Path == mv.File {
				idx = i + 1
				break
			}
		}
		m.Redactions = append(m.Redactions, manifest.Redaction{FileIndex: idx, Stanza: mv.Stanza, Lines: mv.Lines, Comments: mv.Comments, To: "bundle"})
	}
	m.Supersedes = o.Supersedes
	m.Tombstone = o.Tombstone
	m.Attestation = o.Attestation

	p := &Plan{BackupID: id, Manifest: m, Moves: moves, Role: role, OnChainTxt: onTxt}
	if !o.Tombstone {
		total := uint16(len(pieces))
		for i, piece := range pieces {
			ct := crypto.SealChunk(kb, id, uint16(i), total, piece)
			memo, err := chunk.Encode(chunk.TypeChunk, id, uint16(i), total, nil, ct)
			if err != nil {
				return nil, err
			}
			sum := sha256.Sum256(ct)
			m.OnChain.Chunks = append(m.OnChain.Chunks, manifest.Chunk{Index: i, SHA256: hex.EncodeToString(sum[:])})
			p.Chunks = append(p.Chunks, ct)
			p.ChunkMemos = append(p.ChunkMemos, memo)
		}
		p.Bundle = crypto.SealBundle(kbundle, id, bundlePacked)
		cSum := sha256.Sum256(p.Bundle)
		m.Bundle.CipherSHA256 = hex.EncodeToString(cSum[:])
		m.Bundle.Len = len(p.Bundle)
	}
	p.AttestText = manifest.AttestString(m.BackupID, m.OnChain.PlainSHA256, m.Bundle.PlainSHA256)
	return p, nil
}

// readFile reads a regular file and returns its content, permission bits,
// and absolute path. Paths are stored absolute so restore can never see
// a ".." component.
func readFile(path string) ([]byte, uint32, string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, 0, "", err
	}
	path = abs
	st, err := os.Lstat(path)
	if err != nil {
		return nil, 0, "", err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil, 0, "", fmt.Errorf("%s is a symlink; point at the real file", path)
	}
	if !st.Mode().IsRegular() {
		return nil, 0, "", fmt.Errorf("%s is not a regular file", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, "", err
	}
	return b, uint32(st.Mode().Perm()), path, nil
}

// refuseSecrets applies the C0 scanners to an --include file. Includes go
// to the bundle, but master keys still never enter the tool.
func refuseSecrets(path string, raw []byte) error {
	base := strings.ToLower(filepath.Base(path))
	if base == "validator-keys.json" || base == "wallet.db" || strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key") {
		return fmt.Errorf("%s: refused. xrplbak never handles validator master keys, wallet.db, or private key files", path)
	}
	if strings.Contains(string(raw), "secret_key") || strings.Contains(string(raw), "-----BEGIN") {
		return fmt.Errorf("%s: refused. File contains key material (secret_key or PEM)", path)
	}
	return nil
}

// ManifestMemos encrypts the finished manifest into memo parts under a
// fresh random nonce prefix. Call it once per sealing run; never re-seal a
// manifest that already landed (Submit reuses recorded parts instead).
func ManifestMemos(key crypto.EpochKey, id []byte, m *manifest.Manifest) ([]codec.Memo, []byte, error) {
	plain, err := manifest.Marshal(m)
	if err != nil {
		return nil, nil, err
	}
	prefix, err := crypto.NewManifestNonce()
	if err != nil {
		return nil, nil, err
	}
	kb := key.BackupKey(id)
	n := (len(plain) + chunk.ManifestPartLen - 1) / chunk.ManifestPartLen
	var memos []codec.Memo
	for i := 0; i < n; i++ {
		lo, hi := i*chunk.ManifestPartLen, (i+1)*chunk.ManifestPartLen
		if hi > len(plain) {
			hi = len(plain)
		}
		ct := crypto.SealManifest(kb, id, prefix, uint16(i), uint16(n), plain[lo:hi])
		memo, err := chunk.Encode(chunk.TypeManifest, id, uint16(i), uint16(n), prefix, ct)
		if err != nil {
			return nil, nil, err
		}
		memos = append(memos, memo)
	}
	return memos, plain, nil
}

// landed is a manifest part already on the ledger, found in the dump.
type landed struct {
	tx    dump.Tx
	total uint16
}

// Submitter carries what Submit needs beyond the plan.
type Submitter struct {
	Client  xrpl.Client
	Writer  *sign.Key
	Key     *crypto.KeyFile
	Log     func(string, ...any)
	Sleep   func(time.Duration)
	MaxFee  uint64
	Dump    *dump.Dump // filled in as transactions validate
	DumpOut string     // path to write the dump after every step
	// Batch wraps the transactions in XLS-56 Batch transactions
	// (tfAllOrNothing). The caller sets it only when the server reports the
	// BatchV1_1 amendment enabled. See submitBatched.
	Batch bool
}

// Submit sends chunks, then the manifest, then the anchor. Each step waits
// for validation. The dump is rewritten after every validated transaction
// so an interrupted run can be resumed.
func (s *Submitter) Submit(p *Plan) error {
	s.defaults()
	if s.Dump.BackupID == "" {
		s.Dump.BackupID = p.Manifest.BackupID
	}
	// Resume: match chunk ciphertext hashes to already-recorded transactions,
	// and collect manifest parts already on the ledger, grouped by nonce.
	recorded := map[string]dump.Tx{}
	manifestParts := map[[crypto.ManifestNonceLen]byte]map[uint16]landed{}
	for _, t := range s.Dump.Txs {
		rec, err := xrpl.ParseTxJSON(t.TxJSON, nil)
		if err != nil {
			continue
		}
		for _, m := range rec.Memos {
			pl, ok := chunk.Decode(m)
			if !ok || pl.BackupID != [16]byte(p.BackupID) {
				continue
			}
			if pl.Type == chunk.TypeChunk {
				sum := sha256.Sum256(pl.Ciphertext)
				recorded[hex.EncodeToString(sum[:])] = t
			} else {
				if manifestParts[pl.Nonce] == nil {
					manifestParts[pl.Nonce] = map[uint16]landed{}
				}
				manifestParts[pl.Nonce][pl.Index] = landed{tx: t, total: pl.Total}
			}
		}
	}

	m := p.Manifest
	if s.Batch {
		return s.submitBatched(p, recorded, manifestParts)
	}
	for i, memo := range p.ChunkMemos {
		if t, ok := recorded[m.OnChain.Chunks[i].SHA256]; ok {
			m.OnChain.Chunks[i].TxHash, m.OnChain.Chunks[i].Ledger = t.Hash, t.LedgerIndex
			s.Log("chunk %d of %d already on ledger (tx %s)", i+1, len(p.ChunkMemos), t.Hash)
			continue
		}
		s.Log("submitting chunk %d of %d", i+1, len(p.ChunkMemos))
		hash, ledger, err := s.send(&codec.Tx{Type: codec.TxAccountSet, Memos: []codec.Memo{memo}})
		if err != nil {
			return fmt.Errorf("chunk %d: %w", i, err)
		}
		m.OnChain.Chunks[i].TxHash, m.OnChain.Chunks[i].Ledger = hash, ledger
	}

	var manifestHash string
	var manifestLedger uint32
	// A complete manifest already on the ledger is reused as is. A partial
	// one is abandoned: re-sealing it would reuse its nonce.
	for _, parts := range manifestParts {
		if first, ok := parts[0]; ok && int(first.total) == len(parts) {
			manifestHash, manifestLedger = first.tx.Hash, first.tx.LedgerIndex
			s.Log("manifest already on ledger (tx %s)", manifestHash)
			break
		}
	}
	if manifestHash == "" {
		memos, _, err := ManifestMemos(s.Key.Key, p.BackupID, m)
		if err != nil {
			return err
		}
		for i, memo := range memos {
			s.Log("submitting manifest part %d of %d", i+1, len(memos))
			hash, ledger, err := s.send(&codec.Tx{Type: codec.TxAccountSet, Memos: []codec.Memo{memo}})
			if err != nil {
				return fmt.Errorf("manifest part %d: %w", i, err)
			}
			if i == 0 {
				manifestHash, manifestLedger = hash, ledger
			}
		}
	}

	rec := &anchor.Record{ManifestLedger: manifestLedger, Epoch: m.Epoch, Seq: m.Seq}
	copy(rec.BackupID[:], p.BackupID)
	hb, _ := hex.DecodeString(manifestHash)
	copy(rec.ManifestTxHash[:], hb)
	data := anchor.Encode(s.Key.Key, rec)
	s.Log("submitting DID anchor")
	_, ledger, err := s.send(&codec.Tx{Type: codec.TxDIDSet, Data: data})
	if err != nil {
		return fmt.Errorf("anchor: %w", err)
	}
	s.Dump.DID = &dump.DID{LedgerIndex: ledger, Data: strings.ToUpper(hex.EncodeToString(data))}
	return s.saveDump()
}

func (s *Submitter) defaults() {
	if s.MaxFee == 0 {
		s.MaxFee = 5000
	}
	if s.Sleep == nil {
		s.Sleep = time.Sleep
	}
	if s.Log == nil {
		s.Log = func(string, ...any) {}
	}
	if s.Dump == nil {
		s.Dump = &dump.Dump{Account: s.Writer.Address()}
	}
}

// DeleteAnchor sends DIDDelete. Used with --tombstone --delete-anchor.
func (s *Submitter) DeleteAnchor() error {
	_, _, err := s.send(&codec.Tx{Type: codec.TxDIDDelete})
	return err
}

func (s *Submitter) saveDump() error {
	if s.DumpOut == "" {
		return nil
	}
	return s.Dump.Save(s.DumpOut)
}

// send signs, submits, waits for validation, and records the result.
func (s *Submitter) send(tx *codec.Tx) (hash string, ledger uint32, err error) {
	s.defaults()
	for attempt := 0; attempt < 3; attempt++ {
		st, err := s.Client.ServerInfo()
		if err != nil {
			return "", 0, err
		}
		acct, err := s.Client.AccountInfo(s.Writer.Address())
		if errors.Is(err, xrpl.ErrNotFound) {
			return "", 0, fmt.Errorf("account %s does not exist on this network yet. Fund it with at least 1.5 XRP and retry", s.Writer.Address())
		} else if err != nil {
			return "", 0, err
		}
		fee := st.OpenLedgerFee
		if fee < st.BaseFeeDrops {
			fee = st.BaseFeeDrops
		}
		if fee > s.MaxFee {
			return "", 0, fmt.Errorf("network fee is %d drops, above the %d drop cap. Retry later or raise --max-fee", fee, s.MaxFee)
		}
		if acct.BalanceDrops < 1_200_000+fee {
			return "", 0, fmt.Errorf("account %s holds %d drops; it needs the 1.2 XRP reserve plus fees", s.Writer.Address(), acct.BalanceDrops)
		}
		tx.Sequence = acct.Sequence
		tx.LastLedgerSequence = st.ValidatedLedger + 20
		tx.FeeDrops = fee
		tx.SigningPubKey = s.Writer.PublicKey()
		tx.Account = s.Writer.AccountID()
		payload, err := codec.SigningPayload(tx)
		if err != nil {
			return "", 0, err
		}
		tx.TxnSignature = s.Writer.Sign(payload)
		blob, err := codec.Serialize(tx, true)
		if err != nil {
			return "", 0, err
		}
		hash = codec.Hash(blob)
		code, err := s.Client.Submit(blob)
		if err != nil {
			return "", 0, err
		}
		switch {
		case code == "tesSUCCESS" || code == "terQUEUED":
		case code == "tefPAST_SEQ" || code == "terPRE_SEQ":
			s.Sleep(4 * time.Second)
			continue
		default:
			return "", 0, fmt.Errorf("submit returned %s for tx %s", code, hash)
		}
		for i := 0; i < 45; i++ {
			s.Sleep(2 * time.Second)
			rec, err := s.Client.Tx(hash)
			if err == nil && rec.Validated {
				if rec.Result != "tesSUCCESS" {
					return "", 0, fmt.Errorf("tx %s validated with result %s", hash, rec.Result)
				}
				s.Dump.Txs = append(s.Dump.Txs, dump.Tx{Hash: hash, LedgerIndex: rec.LedgerIndex, Result: rec.Result, TxJSON: rec.Raw})
				if err := s.saveDump(); err != nil {
					return "", 0, err
				}
				return hash, rec.LedgerIndex, nil
			}
			cur, err := s.Client.ServerInfo()
			if err == nil && cur.ValidatedLedger > tx.LastLedgerSequence {
				break // expired; resubmit with a fresh sequence
			}
		}
	}
	return "", 0, fmt.Errorf("transaction did not validate after 3 attempts")
}

// NextSeq asks discovery for the latest backup so the new one supersedes it.
func NextSeq(c xrpl.Client, key *crypto.KeyFile, account string) (seq uint32, supersedes string, warnings []string, err error) {
	res, err := discover.Run(c, discover.FileKeys{E: key.Epoch, Key: key.Key}, account, key.Epoch)
	if err != nil {
		return 0, "", nil, err
	}
	warns := res.Warnings
	if key.Epoch > 0 && res.Latest == nil {
		// After a rotation the key file cannot read older epochs. That is
		// the design, not an attack, so say so instead of alarming.
		warns = []string{fmt.Sprintf("key file is epoch %d; backups from earlier epochs are not readable with it (expected after a rotation). This backup starts the new epoch at seq 1", key.Epoch)}
	}
	if res.Conflict != "" {
		// Do not add a third backup at the disputed seq. Start above it.
		return res.Candidates[0].Manifest.Seq + 1, "", append(warns, res.Conflict), nil
	}
	if res.Latest == nil {
		return 1, "", warns, nil
	}
	return res.Latest.Manifest.Seq + 1, res.Latest.Manifest.BackupID, warns, nil
}

// chunkTx builds the carrier transaction for chunk i. Exposed for tests.
func chunkTx(p *Plan, i int) *codec.Tx {
	return &codec.Tx{Type: codec.TxAccountSet, Memos: []codec.Memo{p.ChunkMemos[i]}}
}
