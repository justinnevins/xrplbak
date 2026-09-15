package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/justinnevins/xrplbak/internal/crypto/shamir"
)

// Shares use HashiCorp Vault's Shamir implementation over GF(2^8), copied
// verbatim under MPL-2.0 (see NOTICE). Each encoded share is:
//   u8 threshold | split_id(2) | 33 Shamir bytes | sha256(prefix)[0:2]
// rendered as Crockford base32 in groups of 7 for hand transcription. The
// threshold and split id let Combine refuse too few shares or shares from
// different splits instead of returning a garbage key.

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
	var splitID [2]byte
	if _, err := rand.Read(splitID[:]); err != nil {
		return nil, err
	}
	out := make([]string, n)
	for i, s := range raw {
		out[i] = encodeShare(byte(t), splitID, s)
	}
	return out, nil
}

// Combine reconstructs the key from at least t shares of one split.
func Combine(shares []string) (RootKey, error) {
	var r RootKey
	if len(shares) < 2 {
		return r, fmt.Errorf("need at least 2 shares")
	}
	raw := make([][]byte, len(shares))
	var threshold byte
	var splitID [2]byte
	for i, s := range shares {
		t, id, b, err := decodeShare(s)
		if err != nil {
			return r, fmt.Errorf("share %d: %w", i+1, err)
		}
		if i == 0 {
			threshold, splitID = t, id
		} else if t != threshold || id != splitID {
			return r, fmt.Errorf("share %d belongs to a different split than share 1", i+1)
		}
		raw[i] = b
	}
	if len(shares) < int(threshold) {
		return r, fmt.Errorf("these shares need %d of them to recover; %d given", threshold, len(shares))
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

func encodeShare(threshold byte, splitID [2]byte, s []byte) string {
	body := append([]byte{threshold, splitID[0], splitID[1]}, s...)
	sum := sha256.Sum256(body)
	enc := crockford.EncodeToString(append(body, sum[0], sum[1]))
	var groups []string
	for len(enc) > 7 {
		groups = append(groups, enc[:7])
		enc = enc[7:]
	}
	groups = append(groups, enc)
	return strings.Join(groups, "-")
}

func decodeShare(s string) (threshold byte, splitID [2]byte, share []byte, err error) {
	clean := strings.ToUpper(strings.NewReplacer("-", "", " ", "", "O", "0", "I", "1", "L", "1").Replace(strings.TrimSpace(s)))
	b, derr := crockford.DecodeString(clean)
	if derr != nil {
		return 0, splitID, nil, fmt.Errorf("not a valid share (bad characters)")
	}
	if len(b) != 3+KeyLen+shamir.ShareOverhead+2 {
		return 0, splitID, nil, fmt.Errorf("not a valid share (wrong length)")
	}
	body, check := b[:len(b)-2], b[len(b)-2:]
	sum := sha256.Sum256(body)
	if sum[0] != check[0] || sum[1] != check[1] {
		return 0, splitID, nil, fmt.Errorf("share checksum failed: a character is wrong")
	}
	copy(splitID[:], body[1:3])
	return body[0], splitID, body[3:], nil
}
