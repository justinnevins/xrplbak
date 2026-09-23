package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/justinnevins/xrplbak/internal/pubattest"
	"github.com/justinnevins/xrplbak/internal/xrpl/sign"
)

// attestKeyName is the attestation key file, kept beside xrplbak.key.
const attestKeyName = "xrplbak-attest.key"

// attestKey is the delegated attestation key: which validator it speaks
// for, under which delegation sequence, and the ed25519 seed.
type attestKey struct {
	VPK  string // nHB...
	DSeq uint32
	Priv ed25519.PrivateKey
}

// attestKeyLen: version(1) | vpk(33) | dseq(4) | seed(32) | sha256 of the rest(32).
const attestKeyLen = 1 + 33 + 4 + ed25519.SeedSize + sha256.Size

func (k *attestKey) encode() ([]byte, error) {
	vpk, err := sign.DecodeNodePublic(k.VPK)
	if err != nil {
		return nil, err
	}
	b := []byte{1}
	b = append(b, vpk...)
	b = binary.BigEndian.AppendUint32(b, k.DSeq)
	b = append(b, k.Priv.Seed()...)
	sum := sha256.Sum256(b)
	return append(b, sum[:]...), nil
}

func decodeAttestKey(b []byte) (*attestKey, error) {
	if len(b) != attestKeyLen || b[0] != 1 {
		return nil, fmt.Errorf("not an xrplbak attestation key file (want %d bytes, version 1)", attestKeyLen)
	}
	body, sum := b[:len(b)-sha256.Size], b[len(b)-sha256.Size:]
	if want := sha256.Sum256(body); !bytes.Equal(want[:], sum) {
		return nil, fmt.Errorf("attestation key file is damaged (checksum mismatch); make a new one with xrplbak attest-key and publish a new delegation")
	}
	off := 1
	vpk := body[off : off+33]
	off += 33
	dseq := binary.BigEndian.Uint32(body[off : off+4])
	off += 4
	return &attestKey{VPK: sign.EncodeNodePublic(vpk), DSeq: dseq, Priv: ed25519.NewKeyFromSeed(body[off:])}, nil
}

func (k *attestKey) pub() ed25519.PublicKey { return k.Priv.Public().(ed25519.PublicKey) }

func loadAttestKey(path string) (*attestKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fail(exitUsage, "no attestation key at %s; create one with xrplbak attest-key --validator-key nHB...", path)
	}
	k, err := decodeAttestKey(b)
	if err != nil {
		return nil, fail(exitAuth, "%s: %v", path, err)
	}
	return k, nil
}

// cmdAttestKey creates the delegated attestation key and prints the one
// string the validator master key signs, offline, to delegate to it. The
// master key signs it once, in the same offline session as the validator
// token, and again only to replace a stolen attestation key.
func cmdAttestKey(args []string) error {
	fs := newFlags("attest-key", "create the delegated attestation key and print the delegation string for the master key to sign once")
	vpk := fs.String("validator-key", "", "the validator master public key (nHB..., ed25519) this key will speak for")
	dseq := fs.Uint("dseq", 1, "delegation sequence: 1 for the first key; one higher to replace a stolen or lost key")
	key := fs.String("key", "", "xrplbak.key path, for the writer account (default: found next to the config or here)")
	out := fs.String("out", "", "directory for "+attestKeyName+" (default: beside xrplbak.key)")
	if err := fs.Parse(args); err != nil {
		return parseError(err)
	}
	if *vpk == "" {
		return fail(exitUsage, "attest-key needs --validator-key nHB...")
	}
	pub, err := sign.DecodeNodePublic(*vpk)
	if err != nil {
		return fail(exitUsage, "--validator-key: %v", err)
	}
	if len(pub) != 33 || pub[0] != 0xED {
		return fail(exitUsage, "--validator-key must be an ed25519 validator key (nHB...)")
	}
	if *dseq == 0 || *dseq > 1<<32-1 {
		return fail(exitUsage, "--dseq must be between 1 and 4294967295")
	}
	cfgPath, _ := findConfig("")
	keyPath, err := findKeyFile(*key, cfgPath)
	if err != nil {
		return err
	}
	kf, err := loadKeyFile(keyPath, false)
	if err != nil {
		return err
	}
	account := sign.EncodeAddress(kf.AccountID[:])
	dir := *out
	if dir == "" {
		dir = filepath.Dir(keyPath)
	}
	path := filepath.Join(dir, attestKeyName)
	if _, err := os.Stat(path); err == nil {
		return fail(exitWrite, "%s already exists. Move it away first; attest-key never overwrites a key file", path)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	k := &attestKey{VPK: *vpk, DSeq: uint32(*dseq), Priv: priv}
	b, err := k.encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fail(exitWrite, "%v", err)
	}
	hr("Attestation key")
	fmt.Fprintf(stdout, "  key file:   %s\n", path)
	fmt.Fprintf(stdout, "  validator:  %s\n", k.VPK)
	fmt.Fprintf(stdout, "  account:    %s\n", account)
	fmt.Fprintf(stdout, "  dseq:       %d\n", k.DSeq)
	hr("Delegate to it, once")
	fmt.Fprintln(stdout, "  On the offline machine that holds validator-keys.json, sign this exact string:")
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "    validator-keys sign \"%s\"\n", pubattest.DelegationString(k.VPK, account, k.pub(), k.DSeq))
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "  Then publish the delegation with your next backup:")
	fmt.Fprintln(stdout, "    xrplbak backup --submit --rpc mainnet --attest --attest-delegation-sig <hex>")
	fmt.Fprintln(stdout, "  After that, --attest alone attests each backup. The master key stays offline.")
	fmt.Fprintln(stdout, "  To retire this key, run attest-key again with --dseq "+strconv.FormatUint(uint64(k.DSeq)+1, 10)+" and publish that delegation.")
	return nil
}
