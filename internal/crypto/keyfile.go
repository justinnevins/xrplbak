package crypto

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// KeyFile is what lives on the host: the epoch key plus the writer account.
// It never contains the root key.
type KeyFile struct {
	Epoch      uint32
	Key        EpochKey
	AccountID  [20]byte
	WriterSeed [16]byte
}

var (
	keyMagic     = []byte("XBKK")
	wrappedMagic = []byte("XBKW")
	keyfileAAD   = []byte("xrplbak/v1/keyfile")
)

// PBKDF2 iteration count for the optional passphrase wrap. The wrap is a
// convenience against casual disk reads, not the primary secret.
const pbkdf2Iterations = 600_000

const keyFileLen = 4 + 1 + 4 + KeyLen + 20 + 16

// Encode renders the plain key file bytes.
func (k *KeyFile) Encode() []byte {
	b := append([]byte{}, keyMagic...)
	b = append(b, 1)
	b = binary.BigEndian.AppendUint32(b, k.Epoch)
	b = append(b, k.Key[:]...)
	b = append(b, k.AccountID[:]...)
	b = append(b, k.WriterSeed[:]...)
	return b
}

// EncodeWrapped renders the key file encrypted under a passphrase.
func (k *KeyFile) EncodeWrapped(passphrase []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	wk, err := pbkdf2.Key(sha256.New, string(passphrase), salt, pbkdf2Iterations, KeyLen)
	if err != nil {
		return nil, err
	}
	var key [KeyLen]byte
	copy(key[:], wk)
	ct := gcm(key).Seal(nil, make([]byte, nonceLen), k.Encode(), keyfileAAD)
	out := append([]byte{}, wrappedMagic...)
	out = append(out, 1)
	out = append(out, salt...)
	return append(out, ct...), nil
}

// IsWrapped reports whether the bytes need a passphrase.
func IsWrapped(b []byte) bool { return len(b) > 4 && bytes.Equal(b[:4], wrappedMagic) }

// DecodeKeyFile parses plain or wrapped bytes. passphrase is ignored for
// plain files.
func DecodeKeyFile(b []byte, passphrase []byte) (*KeyFile, error) {
	if IsWrapped(b) {
		if len(b) < 4+1+16+TagLen {
			return nil, errors.New("key file is truncated")
		}
		if passphrase == nil {
			return nil, errors.New("key file is passphrase protected; pass --key-passphrase")
		}
		salt := b[5:21]
		wk, err := pbkdf2.Key(sha256.New, string(passphrase), salt, pbkdf2Iterations, KeyLen)
		if err != nil {
			return nil, err
		}
		var key [KeyLen]byte
		copy(key[:], wk)
		plain, err := gcm(key).Open(nil, make([]byte, nonceLen), b[21:], keyfileAAD)
		if err != nil {
			// AEAD cannot tell these apart, so the message must not
			// pick one. Naming only the passphrase sent an operator with
			// the right passphrase and a damaged file looking in the
			// wrong place, in the middle of a recovery.
			return nil, errors.New("wrong key file passphrase, or the key file is damaged")
		}
		b = plain
	}
	if len(b) != keyFileLen || !bytes.Equal(b[:4], keyMagic) {
		return nil, errors.New("not an xrplbak key file")
	}
	if b[4] != 1 {
		return nil, fmt.Errorf("unsupported key file version %d", b[4])
	}
	k := &KeyFile{Epoch: binary.BigEndian.Uint32(b[5:9])}
	copy(k.Key[:], b[9:9+KeyLen])
	copy(k.AccountID[:], b[9+KeyLen:9+KeyLen+20])
	copy(k.WriterSeed[:], b[9+KeyLen+20:])
	return k, nil
}
