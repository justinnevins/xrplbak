// Package crypto holds every cryptographic operation in xrplbak. It uses the
// Go standard library only: HKDF-SHA256 for derivation, AES-256-GCM for
// authenticated encryption, HMAC-SHA256 for the anchor tag, PBKDF2 for the
// optional key file passphrase. Nothing here is novel; see docs/crypto.md.
package crypto

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// KeyLen is the length of every key in the hierarchy.
const KeyLen = 32

// Salt is the fixed HKDF salt. The version string is part of the domain
// separation, so a v2 format cannot collide with v1 keys.
var Salt = []byte("xrplbak/v1")

// RootKey is the Recovery Root Key. It exists only on paper (words or
// shares) and in memory during init, rotate, and restore.
type RootKey [KeyLen]byte

// EpochKey lives on the host. It can decrypt backups of one epoch only.
type EpochKey [KeyLen]byte

// NewRootKey draws 32 bytes from crypto/rand.
func NewRootKey() (RootKey, error) {
	var k RootKey
	_, err := rand.Read(k[:])
	return k, err
}

func derive(ikm []byte, info []byte) [KeyLen]byte {
	out, err := hkdf.Key(sha256.New, ikm, Salt, string(info), KeyLen)
	if err != nil {
		panic("hkdf: " + err.Error()) // only fails on impossible lengths
	}
	var k [KeyLen]byte
	copy(k[:], out)
	return k
}

// DeriveEpochKey computes K_e = HKDF(RRK, "epoch" || u32be e).
func (r RootKey) DeriveEpochKey(epoch uint32) EpochKey {
	info := append([]byte("epoch"), u32(epoch)...)
	return EpochKey(derive(r[:], info))
}

// BackupKey computes K_b = HKDF(K_e, "backup" || backup_id).
func (e EpochKey) BackupKey(backupID []byte) [KeyLen]byte {
	return derive(e[:], append([]byte("backup"), backupID...))
}

// BundleKey computes HKDF(K_e, "bundle" || backup_id).
func (e EpochKey) BundleKey(backupID []byte) [KeyLen]byte {
	return derive(e[:], append([]byte("bundle"), backupID...))
}

// AnchorKey computes HKDF(K_e, "anchor").
func (e EpochKey) AnchorKey() [KeyLen]byte {
	return derive(e[:], []byte("anchor"))
}

// AnchorMAC returns HMAC-SHA256(K_anchor, data)[0:16].
func (e EpochKey) AnchorMAC(data []byte) []byte {
	k := e.AnchorKey()
	m := hmac.New(sha256.New, k[:])
	m.Write(data)
	return m.Sum(nil)[:16]
}

// BackupID is SHA-256(container || u32be epoch || u32be seq)[0:16]. It
// commits to the plaintext, so identical input at the same epoch and seq
// yields identical output, and two backups never share an id.
func BackupID(container []byte, epoch, seq uint32) []byte {
	h := sha256.New()
	h.Write(container)
	h.Write(u32(epoch))
	h.Write(u32(seq))
	return h.Sum(nil)[:16]
}

// Zero wipes a key from memory. Best effort only.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func u32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

// ErrAuth is returned for every authentication failure so callers can map
// it to one exit code and one explanation.
var ErrAuth = errors.New("authentication failed")
