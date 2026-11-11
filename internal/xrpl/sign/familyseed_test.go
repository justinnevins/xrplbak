package sign

// KeyFromFamilySeed parses an "sEd..." family seed string.
func KeyFromFamilySeed(s string) (*Key, error) {
	seed, err := DecodeBase58Check(s, prefixSeedEd25519, SeedLen)
	if err != nil {
		return nil, err
	}
	return KeyFromSeed(seed)
}

// FamilySeed returns the base58 "sEd..." form for use in other XRPL tools.
func (k *Key) FamilySeed() string { return EncodeBase58Check(prefixSeedEd25519, k.seed[:]) }
