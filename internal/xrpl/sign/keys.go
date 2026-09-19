// Package sign holds the ed25519 key handling for the writer account:
// family seed encoding, address derivation, and transaction signing.
// Only ed25519 is supported. The tool never creates secp256k1 keys.
package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"

	"github.com/justinnevins/xrplbak/internal/xrpl/sign/ripemd160"
)

// SeedLen is the entropy length of an XRPL family seed.
const SeedLen = 16

// Key is an ed25519 XRPL account key pair derived from a 16-byte seed.
type Key struct {
	seed [SeedLen]byte
	priv ed25519.PrivateKey
}

// NewKey draws a fresh 16-byte seed from crypto/rand.
func NewKey() (*Key, error) {
	var seed [SeedLen]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	return KeyFromSeed(seed[:])
}

// KeyFromSeed derives the ed25519 key the way rippled does:
// private key = SHA-512Half(seed).
func KeyFromSeed(seed []byte) (*Key, error) {
	if len(seed) != SeedLen {
		return nil, errors.New("seed must be 16 bytes")
	}
	k := &Key{}
	copy(k.seed[:], seed)
	h := sha512.Sum512(seed)
	k.priv = ed25519.NewKeyFromSeed(h[:32])
	return k, nil
}

// KeyFromFamilySeed parses an "sEd..." family seed string.
func KeyFromFamilySeed(s string) (*Key, error) {
	seed, err := DecodeBase58Check(s, prefixSeedEd25519, SeedLen)
	if err != nil {
		return nil, err
	}
	return KeyFromSeed(seed)
}

// Seed returns the raw 16-byte seed.
func (k *Key) Seed() []byte { return k.seed[:] }

// FamilySeed returns the base58 "sEd..." form for use in other XRPL tools.
func (k *Key) FamilySeed() string { return EncodeBase58Check(prefixSeedEd25519, k.seed[:]) }

// PublicKey returns the 33-byte XRPL public key: 0xED || ed25519 key.
func (k *Key) PublicKey() []byte {
	pub := k.priv.Public().(ed25519.PublicKey)
	return append([]byte{0xED}, pub...)
}

// AccountID returns RIPEMD160(SHA256(publicKey)).
func (k *Key) AccountID() []byte { return AccountIDFromPublicKey(k.PublicKey()) }

// Address returns the classic "r..." address.
func (k *Key) Address() string { return EncodeBase58Check(prefixAccountID, k.AccountID()) }

// Sign signs msg with raw ed25519. rippled does not pre-hash for ed25519.
func (k *Key) Sign(msg []byte) []byte { return ed25519.Sign(k.priv, msg) }

// AccountIDFromPublicKey computes the 20-byte account ID of a public key.
func AccountIDFromPublicKey(pub []byte) []byte {
	s := sha256.Sum256(pub)
	r := ripemd160.New()
	r.Write(s[:])
	return r.Sum(nil)
}

// DecodeAddress parses an "r..." address into its 20-byte account ID.
func DecodeAddress(addr string) ([]byte, error) {
	id, err := DecodeBase58Check(addr, prefixAccountID, 20)
	if err != nil {
		return nil, errors.New("not a valid XRPL classic address: " + addr)
	}
	return id, nil
}

// EncodeAddress renders a 20-byte account ID as an "r..." address.
func EncodeAddress(id []byte) string { return EncodeBase58Check(prefixAccountID, id) }

// DecodeNodePublic parses an "n..." validator or node public key (33 bytes).
// EncodeNodePublic renders a 33-byte validator public key as its nHB... form.
func EncodeNodePublic(pub []byte) string { return EncodeBase58Check(prefixNodePublic, pub) }

func DecodeNodePublic(s string) ([]byte, error) {
	pub, err := DecodeBase58Check(s, prefixNodePublic, 33)
	if err != nil {
		return nil, errors.New("not a valid node public key: " + s)
	}
	return pub, nil
}

// VerifyEd25519 checks an ed25519 signature made by a 33-byte XRPL public key.
func VerifyEd25519(pub33, msg, sig []byte) bool {
	if len(pub33) != 33 || pub33[0] != 0xED {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub33[1:]), msg, sig)
}
