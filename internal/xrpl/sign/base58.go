package sign

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/big"
)

// XRPL uses its own base58 alphabet, not Bitcoin's.
const alphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

var (
	prefixAccountID  = []byte{0x00}
	prefixNodePublic = []byte{0x1C}
	// Ed25519 family seeds carry a 3-byte prefix so they render as "sEd...".
	prefixSeedEd25519 = []byte{0x01, 0xE1, 0x4B}
)

var decodeMap [256]int8

func init() {
	for i := range decodeMap {
		decodeMap[i] = -1
	}
	for i, c := range alphabet {
		decodeMap[c] = int8(i)
	}
}

func checksum(payload []byte) []byte {
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	return second[:4]
}

// EncodeBase58Check returns the XRPL base58check encoding of prefix||payload.
func EncodeBase58Check(prefix []byte, payload []byte) string {
	buf := make([]byte, 0, len(prefix)+len(payload)+4)
	buf = append(buf, prefix...)
	buf = append(buf, payload...)
	buf = append(buf, checksum(buf)...)
	return encodeBase58(buf)
}

// DecodeBase58Check verifies the checksum and prefix and returns the payload.
func DecodeBase58Check(s string, prefix []byte, payloadLen int) ([]byte, error) {
	raw, err := decodeBase58(s)
	if err != nil {
		return nil, err
	}
	n := len(prefix)
	if len(raw) != n+payloadLen+4 {
		return nil, errors.New("base58: wrong length")
	}
	if !bytes.Equal(raw[:n], prefix) {
		return nil, errors.New("base58: wrong prefix")
	}
	body := raw[:n+payloadLen]
	if !bytes.Equal(checksum(body), raw[n+payloadLen:]) {
		return nil, errors.New("base58: bad checksum")
	}
	return raw[n : n+payloadLen], nil
}

func encodeBase58(b []byte) string {
	x := new(big.Int).SetBytes(b)
	base := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	for x.Sign() > 0 {
		x.DivMod(x, base, mod)
		out = append(out, alphabet[mod.Int64()])
	}
	for _, c := range b {
		if c != 0 {
			break
		}
		out = append(out, alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func decodeBase58(s string) ([]byte, error) {
	x := new(big.Int)
	base := big.NewInt(58)
	for _, c := range []byte(s) {
		v := decodeMap[c]
		if v < 0 {
			return nil, errors.New("base58: invalid character")
		}
		x.Mul(x, base)
		x.Add(x, big.NewInt(int64(v)))
	}
	out := x.Bytes()
	zeros := 0
	for zeros < len(s) && s[zeros] == alphabet[0] {
		zeros++
	}
	return append(make([]byte, zeros), out...), nil
}
