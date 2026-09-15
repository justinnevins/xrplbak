package crypto

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
	"math/big"
	"strings"
)

// BIP39 English word list, sha256 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda.
//
//go:embed bip39-english.txt
var wordlistRaw string

var (
	wordlist  []string
	wordIndex map[string]int
)

func init() {
	wordlist = strings.Split(strings.TrimSpace(wordlistRaw), "\n")
	if len(wordlist) != 2048 {
		panic("bip39 wordlist must have 2048 words")
	}
	wordIndex = make(map[string]int, 2048)
	for i, w := range wordlist {
		wordIndex[w] = i
	}
}

// WordCount is the mnemonic length for a 32-byte root key.
const WordCount = 24

// ToWords encodes the root key as 24 BIP39 words (256 bits + 8 checksum bits).
func (r RootKey) ToWords() []string {
	sum := sha256.Sum256(r[:])
	bits := new(big.Int).SetBytes(r[:])
	bits.Lsh(bits, 8)
	bits.Or(bits, big.NewInt(int64(sum[0])))
	words := make([]string, WordCount)
	mask := big.NewInt(2047)
	for i := WordCount - 1; i >= 0; i-- {
		idx := new(big.Int).And(bits, mask).Int64()
		words[i] = wordlist[idx]
		bits.Rsh(bits, 11)
	}
	return words
}

// FromWords parses 24 words, checks the BIP39 checksum, and returns the key.
func FromWords(words []string) (RootKey, error) {
	var r RootKey
	if len(words) != WordCount {
		return r, fmt.Errorf("expected %d words, got %d", WordCount, len(words))
	}
	bits := new(big.Int)
	for i, w := range words {
		idx, ok := wordIndex[strings.ToLower(strings.TrimSpace(w))]
		if !ok {
			return r, fmt.Errorf("word %d (%q) is not in the BIP39 list", i+1, w)
		}
		bits.Lsh(bits, 11)
		bits.Or(bits, big.NewInt(int64(idx)))
	}
	check := byte(new(big.Int).And(bits, big.NewInt(255)).Int64())
	bits.Rsh(bits, 8)
	bits.FillBytes(r[:])
	sum := sha256.Sum256(r[:])
	if sum[0] != check {
		return RootKey{}, fmt.Errorf("checksum mismatch: one or more words are wrong")
	}
	return r, nil
}

// ParseWords splits free text on whitespace and commas.
func ParseWords(s string) []string {
	f := strings.FieldsFunc(s, func(c rune) bool { return c == ' ' || c == '\n' || c == '\t' || c == ',' || c == '\r' })
	return f
}
