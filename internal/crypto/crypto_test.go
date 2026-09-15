package crypto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func fixedRoot() RootKey {
	var r RootKey
	for i := range r {
		r[i] = byte(i)
	}
	return r
}

func TestWordsRoundTrip(t *testing.T) {
	r := fixedRoot()
	w := r.ToWords()
	if len(w) != 24 {
		t.Fatal(len(w))
	}
	back, err := FromWords(w)
	if err != nil || back != r {
		t.Fatal("round trip", err)
	}
	// BIP39 test vector: entropy 00..00 (32 bytes) -> "abandon" x23 + "art".
	var zero RootKey
	zw := zero.ToWords()
	if zw[0] != "abandon" || zw[23] != "art" {
		t.Fatalf("bip39 vector: %v", zw)
	}
	w[5] = "zoo"
	if _, err := FromWords(w); err == nil {
		t.Fatal("checksum must catch a wrong word")
	}
}

func TestSharesRoundTrip(t *testing.T) {
	r := fixedRoot()
	shares, err := r.Split(3, 2)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Combine([]string{shares[0], shares[2]})
	if err != nil || back != r {
		t.Fatal("2 of 3 must combine", err)
	}
	back, err = Combine([]string{shares[1], shares[2]})
	if err != nil || back != r {
		t.Fatal("other 2 of 3 must combine", err)
	}
	if _, err := Combine([]string{shares[0]}); err == nil {
		t.Fatal("1 of 3 must fail")
	}
	big, _ := r.Split(5, 3)
	if _, err := Combine([]string{big[0], big[1]}); err == nil || !strings.Contains(err.Error(), "need 3") {
		t.Fatal("2 of a 3-of-5 split must be refused, got", err)
	}
	if _, err := Combine([]string{shares[0], big[1]}); err == nil {
		t.Fatal("shares from different splits must be refused")
	}
	bad := "A" + shares[0][1:]
	if _, err := Combine([]string{bad, shares[1]}); err == nil {
		t.Fatal("share checksum must catch a wrong character")
	}
	if _, err := r.Split(2, 3); err == nil {
		t.Fatal("threshold above shares must fail")
	}
}

func TestDerivationDeterministic(t *testing.T) {
	r := fixedRoot()
	a := r.DeriveEpochKey(0)
	b := r.DeriveEpochKey(0)
	c := r.DeriveEpochKey(1)
	if a != b || a == c {
		t.Fatal("epoch derivation")
	}
	id := a.BackupID([]byte("x"), 0, 1)
	if a.BackupKey(id) != b.BackupKey(id) || a.BackupKey(id) == a.BundleKey(id) {
		t.Fatal("backup key derivation")
	}
	// Pin the derivation so a future change is a deliberate version bump.
	if got := hex.EncodeToString(a[:]); got != knownEpoch0 {
		t.Fatalf("epoch 0 key changed: %s", got)
	}
}

const knownEpoch0 = "7559b98f543d540f7973a84d3c2fca670f550fc1316f1f0e8bc8e9c31e053daf"

func TestChunkAEAD(t *testing.T) {
	r := fixedRoot()
	e := r.DeriveEpochKey(0)
	id := e.BackupID([]byte("plain"), 0, 1)
	k := e.BackupKey(id)
	plain := bytes.Repeat([]byte{7}, 960)
	ct := SealChunk(k, id, 2, 5, plain)
	if len(ct) != 960+TagLen {
		t.Fatal(len(ct))
	}
	if !bytes.Equal(ct, SealChunk(k, id, 2, 5, plain)) {
		t.Fatal("chunk encryption must be deterministic")
	}
	back, err := OpenChunk(k, id, 2, 5, ct)
	if err != nil || !bytes.Equal(back, plain) {
		t.Fatal("open", err)
	}
	if _, err := OpenChunk(k, id, 3, 5, ct); err != ErrAuth {
		t.Fatal("wrong index must fail")
	}
	if _, err := OpenChunk(r.DeriveEpochKey(1).BackupKey(id), id, 2, 5, ct); err != ErrAuth {
		t.Fatal("wrong epoch must fail")
	}
	pfx, _ := NewManifestNonce()
	m := SealManifest(k, id, pfx, 0, 1, []byte("manifest"))
	if _, err := OpenChunk(k, id, 0, 1, m); err != ErrAuth {
		t.Fatal("manifest must not open as chunk")
	}
	if p, err := OpenManifest(k, id, pfx, 0, 1, m); err != nil || string(p) != "manifest" {
		t.Fatal("manifest round trip", err)
	}
	pfx2, _ := NewManifestNonce()
	if bytes.Equal(SealManifest(k, id, pfx2, 0, 1, []byte("manifest")), m) {
		t.Fatal("two sealing runs must not share a nonce")
	}
	if _, err := OpenManifest(k, id, pfx2, 0, 1, m); err != ErrAuth {
		t.Fatal("wrong prefix must fail")
	}
}

func TestBundleStream(t *testing.T) {
	r := fixedRoot()
	e := r.DeriveEpochKey(0)
	id := e.BackupID([]byte("plain"), 0, 1)
	k := e.BundleKey(id)
	plain := bytes.Repeat([]byte{9}, FrameLen*2+100)
	ct := SealBundle(k, id, plain)
	back, err := OpenBundle(k, id, ct)
	if err != nil || !bytes.Equal(back, plain) {
		t.Fatal("open", err)
	}
	// Drop the last frame: the previous frame lacks the final flag.
	cut := ct[:20+4+FrameLen+TagLen+4+FrameLen+TagLen]
	if _, err := OpenBundle(k, id, cut); err == nil {
		t.Fatal("truncation must fail")
	}
	if _, err := OpenBundle(k, id, ct[:len(ct)-1]); err == nil {
		t.Fatal("partial frame must fail")
	}
	empty := SealBundle(k, id, nil)
	if b, err := OpenBundle(k, id, empty); err != nil || len(b) != 0 {
		t.Fatal("empty bundle", err)
	}
}

func TestKeyFile(t *testing.T) {
	kf := &KeyFile{Epoch: 3}
	kf.Key = fixedRoot().DeriveEpochKey(3)
	kf.AccountID[0] = 1
	kf.WriterSeed[15] = 2
	back, err := DecodeKeyFile(kf.Encode(), nil)
	if err != nil || *back != *kf {
		t.Fatal("plain round trip", err)
	}
	w, err := kf.EncodeWrapped([]byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeKeyFile(w, nil); err == nil {
		t.Fatal("wrapped needs passphrase")
	}
	if _, err := DecodeKeyFile(w, []byte("wrong")); err == nil {
		t.Fatal("wrong passphrase must fail")
	}
	back, err = DecodeKeyFile(w, []byte("pw"))
	if err != nil || *back != *kf {
		t.Fatal("wrapped round trip", err)
	}
}
