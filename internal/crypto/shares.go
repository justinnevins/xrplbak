package crypto

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/justinnevins/xrplbak/internal/crypto/shamir"
)

// Shares use HashiCorp Vault's Shamir implementation over GF(2^8), copied
// verbatim under MPL-2.0 (see NOTICE). Each share is 33 bytes: 32 bytes of
// y values plus a 1-byte x coordinate. We append a 2-byte SHA-256 checksum
// and render as Crockford base32 in groups of 7 for hand transcription.

var crockford = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// MaxShares bounds N to keep the paper ceremony manageable.
const MaxShares = 16

// Split produces n shares of which t reconstruct the key.
func (r RootKey) Split(n, t int) ([]string, error) {
	if t < 2 || n < t || n > MaxShares {
		return nil, fmt.Errorf("need 2 <= threshold <= shares <= %d", MaxShares)
	}
	raw, err := shamir.Split(r[:], n, t)
	if err != nil {
		return nil, err
	}
	out := make([]string, n)
	for i, s := range raw {
		out[i] = encodeShare(s)
	}
	return out, nil
}

// Combine reconstructs the key from at least t shares. It cannot know t,
// so it also checks the result against a caller-supplied verifier when
// one exists (the epoch key file or a decryptable manifest).
func Combine(shares []string) (RootKey, error) {
	var r RootKey
	if len(shares) < 2 {
		return r, fmt.Errorf("need at least 2 shares")
	}
	raw := make([][]byte, len(shares))
	for i, s := range shares {
		b, err := decodeShare(s)
		if err != nil {
			return r, fmt.Errorf("share %d: %w", i+1, err)
		}
		raw[i] = b
	}
	secret, err := shamir.Combine(raw)
	if err != nil {
		return r, err
	}
	if len(secret) != KeyLen {
		return r, fmt.Errorf("shares did not combine to a 32-byte key")
	}
	copy(r[:], secret)
	return r, nil
}

func encodeShare(s []byte) string {
	sum := sha256.Sum256(s)
	enc := crockford.EncodeToString(append(append([]byte{}, s...), sum[0], sum[1]))
	var groups []string
	for len(enc) > 7 {
		groups = append(groups, enc[:7])
		enc = enc[7:]
	}
	groups = append(groups, enc)
	return strings.Join(groups, "-")
}

func decodeShare(s string) ([]byte, error) {
	clean := strings.ToUpper(strings.NewReplacer("-", "", " ", "", "O", "0", "I", "1", "L", "1").Replace(strings.TrimSpace(s)))
	b, err := crockford.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("not a valid share (bad characters)")
	}
	if len(b) != KeyLen+shamir.ShareOverhead+2 {
		return nil, fmt.Errorf("not a valid share (wrong length)")
	}
	body, check := b[:len(b)-2], b[len(b)-2:]
	sum := sha256.Sum256(body)
	if sum[0] != check[0] || sum[1] != check[1] {
		return nil, fmt.Errorf("share checksum failed: a character is wrong")
	}
	return body, nil
}
