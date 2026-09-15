package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

// AES-256-GCM: 12-byte nonce, 16-byte tag. Chunk and bundle nonces are
// counters: their key is used for exactly one backup_id, and backup_id
// commits to their plaintext, so a (key, nonce) pair repeats only when the
// message is byte-identical. Manifest nonces carry a random prefix because
// the manifest is not committed by backup_id (see ManifestNonceLen).
const (
	TagLen   = 16
	nonceLen = 12
)

// Domains bind each ciphertext to its role via the AAD prefix.
const (
	domainChunk    = "xrplbak/v1/chunk"
	domainManifest = "xrplbak/v1/manifest"
	domainBundle   = "xrplbak/v1/bundle"
)

// FrameLen is the plaintext size of one bundle stream frame.
const FrameLen = 64 * 1024

func gcm(key [KeyLen]byte) cipher.AEAD {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return g
}

func counterNonce(v uint32) []byte {
	n := make([]byte, nonceLen)
	binary.BigEndian.PutUint32(n, v)
	return n
}

func chunkAAD(domain string, backupID []byte, idx, total uint16) []byte {
	b := []byte(domain)
	b = append(b, backupID...)
	b = binary.BigEndian.AppendUint16(b, idx)
	b = binary.BigEndian.AppendUint16(b, total)
	return b
}

// SealChunk encrypts on-chain chunk idx of total.
func SealChunk(key [KeyLen]byte, backupID []byte, idx, total uint16, plain []byte) []byte {
	return gcm(key).Seal(nil, counterNonce(uint32(idx)), plain, chunkAAD(domainChunk, backupID, idx, total))
}

// OpenChunk decrypts and authenticates one on-chain chunk.
func OpenChunk(key [KeyLen]byte, backupID []byte, idx, total uint16, ct []byte) ([]byte, error) {
	p, err := gcm(key).Open(nil, counterNonce(uint32(idx)), ct, chunkAAD(domainChunk, backupID, idx, total))
	if err != nil {
		return nil, ErrAuth
	}
	return p, nil
}

// ManifestNonceLen is the random prefix carried in every manifest memo.
// The manifest is not committed by backup_id (it holds tx hashes and a
// timestamp), so a resumed or repeated run would otherwise re-encrypt a
// different manifest under the same (key, nonce). A fresh random prefix per
// sealing run plus the part index makes every manifest nonce unique.
const ManifestNonceLen = 10

// NewManifestNonce draws the random prefix for one sealing run.
func NewManifestNonce() ([]byte, error) {
	n := make([]byte, ManifestNonceLen)
	_, err := rand.Read(n)
	return n, err
}

func manifestNonce(prefix []byte, idx uint16) []byte {
	n := make([]byte, nonceLen)
	copy(n, prefix)
	binary.BigEndian.PutUint16(n[ManifestNonceLen:], idx)
	return n
}

// SealManifest encrypts manifest part idx of total under nonce prefix||idx.
func SealManifest(key [KeyLen]byte, backupID, prefix []byte, idx, total uint16, plain []byte) []byte {
	if len(prefix) != ManifestNonceLen {
		panic("manifest nonce prefix must be 10 bytes")
	}
	return gcm(key).Seal(nil, manifestNonce(prefix, idx), plain, chunkAAD(domainManifest, backupID, idx, total))
}

// OpenManifest decrypts and authenticates one manifest part.
func OpenManifest(key [KeyLen]byte, backupID, prefix []byte, idx, total uint16, ct []byte) ([]byte, error) {
	if len(prefix) != ManifestNonceLen {
		return nil, ErrAuth
	}
	p, err := gcm(key).Open(nil, manifestNonce(prefix, idx), ct, chunkAAD(domainManifest, backupID, idx, total))
	if err != nil {
		return nil, ErrAuth
	}
	return p, nil
}

// Bundle stream format:
//   magic "XBK1" (4) || backup_id (16) || frames...
//   frame: u32be ciphertext length || ciphertext
// Frame nonce: u32be index || 7 zero bytes || final(1). AAD: domain ||
// backup_id. The final flag lives in the nonce so a truncated stream fails
// to authenticate its last frame.

var bundleMagic = []byte("XBK1")

// SealBundle writes the encrypted bundle stream for plain.
func SealBundle(key [KeyLen]byte, backupID []byte, plain []byte) []byte {
	g := gcm(key)
	aad := append([]byte(domainBundle), backupID...)
	out := append([]byte{}, bundleMagic...)
	out = append(out, backupID...)
	frames := (len(plain) + FrameLen - 1) / FrameLen
	if frames == 0 {
		frames = 1
	}
	for i := 0; i < frames; i++ {
		lo := i * FrameLen
		hi := lo + FrameLen
		if hi > len(plain) {
			hi = len(plain)
		}
		final := byte(0)
		if i == frames-1 {
			final = 1
		}
		n := counterNonce(uint32(i))
		n[nonceLen-1] = final
		ct := g.Seal(nil, n, plain[lo:hi], aad)
		out = binary.BigEndian.AppendUint32(out, uint32(len(ct)))
		out = append(out, ct...)
	}
	return out
}

// BundleID reads the backup_id from a bundle stream header without a key.
func BundleID(stream []byte) ([]byte, error) {
	if len(stream) < 20 || !bytes.Equal(stream[:4], bundleMagic) {
		return nil, fmt.Errorf("not an xrplbak bundle (bad header)")
	}
	return stream[4:20], nil
}

// OpenBundle decrypts a bundle stream and rejects truncation or reordering.
func OpenBundle(key [KeyLen]byte, backupID []byte, stream []byte) ([]byte, error) {
	id, err := BundleID(stream)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(id, backupID) {
		return nil, fmt.Errorf("bundle is for backup %x, expected %x", id, backupID)
	}
	g := gcm(key)
	aad := append([]byte(domainBundle), backupID...)
	r := bytes.NewReader(stream[20:])
	var out []byte
	for i := uint32(0); ; i++ {
		var l uint32
		if err := binary.Read(r, binary.BigEndian, &l); err == io.EOF {
			return nil, fmt.Errorf("bundle truncated: no final frame")
		} else if err != nil {
			return nil, err
		}
		if l > FrameLen+TagLen {
			return nil, fmt.Errorf("bundle frame %d claims %d bytes; the limit is %d", i, l, FrameLen+TagLen)
		}
		ct := make([]byte, l)
		if _, err := io.ReadFull(r, ct); err != nil {
			return nil, fmt.Errorf("bundle truncated inside frame %d", i)
		}
		final := byte(0)
		if r.Len() == 0 {
			final = 1
		}
		n := counterNonce(i)
		n[nonceLen-1] = final
		p, err := g.Open(nil, n, ct, aad)
		if err != nil {
			return nil, ErrAuth
		}
		out = append(out, p...)
		if final == 1 {
			return out, nil
		}
	}
}
