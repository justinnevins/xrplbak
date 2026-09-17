package codec

import (
	"encoding/hex"
	"testing"
)

// The Batch below validated on XRPL Devnet on 2026-09-17 as transaction
// 3C4C3D3B5FEA20ACBE389B97AB0B56279152107D05600AB0AF5CCC2DC0F5AED1 in
// ledger 5385553 (rippled 3.4.0-rc6, BatchV1_1 enabled): tfAllOrNothing,
// three inner transactions (two AccountSet memo carriers and a DIDSet),
// fee 50 drops for a 10 drop rate. The server reported every inner
// transaction under the hash pinned here. That real ledger is the oracle
// for this serializer, not the tool's own reading of the spec.
const devnetBatchBlob = "" +
	"12004722000100002400522d47201b00522eac6840000000000000327321ede0ea65f355ba88" +
	"0fca1aab199c544b8e4e4a5ed4f9bc105d8c13a5456ef7cc34744036c4b73adc02d239c4938a" +
	"0441c9bc971ed8918d5f54dbdabbc232c98be629e90f4795495778f7d4ce41c729341a28cbdd" +
	"ab6b3167c8a6e899deeb4f8f3af20881141033615f892655b206f643d73aa6a3dc00099f81f0" +
	"1ee02212000322400000002400522d48684000000000000000730081141033615f892655b206" +
	"f643d73aa6a3dc00099f81f9ea7c0d7872706c62616b2f70726f62657d0c696e6e6572203120" +
	"6f662033e1f1e1e02212000322400000002400522d4968400000000000000073008114103361" +
	"5f892655b206f643d73aa6a3dc00099f81f9ea7c0d7872706c62616b2f70726f62657d0c696e" +
	"6e65722032206f662033e1f1e1e02212003122400000002400522d4a68400000000000000073" +
	"00701b0c70726f626520616e63686f7281141033615f892655b206f643d73aa6a3dc00099f81" +
	"e1f1"

var devnetBatchInnerHashes = []string{
	"59E65A3994A37B5F1D4E0AA23C3DF013E499070E187CA84C287C7619D681D4DF",
	"D80D2F0EC9EF380947F5585DBEC30CAACC4E3645DC1CCB201DD95C3ACCB0E1A7",
	"330E510BFE6E5EDF95213004F18238D2CAAEA04FC5F47699A52BD2D38CA243C9",
}

const devnetBatchHash = "3C4C3D3B5FEA20ACBE389B97AB0B56279152107D05600AB0AF5CCC2DC0F5AED1"

func TestBatchMatchesTheDevnetLedger(t *testing.T) {
	blob, err := hex.DecodeString(devnetBatchBlob)
	if err != nil {
		t.Fatal(err)
	}
	if got := Hash(blob); got != devnetBatchHash {
		t.Fatalf("outer hash %s, want %s", got, devnetBatchHash)
	}
	tx, err := Deserialize(blob)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Type != TxBatch || tx.Flags != FlagAllOrNothing || len(tx.Inner) != 3 {
		t.Fatalf("decoded type %d flags %#x inner %d", tx.Type, tx.Flags, len(tx.Inner))
	}
	if tx.FeeDrops != 50 || tx.Sequence != 5385543 {
		t.Fatalf("fee %d seq %d", tx.FeeDrops, tx.Sequence)
	}
	for i, in := range tx.Inner {
		if !in.IsInner() || in.FeeDrops != 0 || len(in.SigningPubKey) != 0 || len(in.TxnSignature) != 0 {
			t.Fatalf("inner %d is not an unsigned zero-fee inner transaction: %+v", i, in)
		}
		if in.Sequence != tx.Sequence+1+uint32(i) {
			t.Fatalf("inner %d sequence %d, want %d", i, in.Sequence, tx.Sequence+1+uint32(i))
		}
		h, err := InnerHash(in)
		if err != nil {
			t.Fatal(err)
		}
		if h != devnetBatchInnerHashes[i] {
			t.Fatalf("inner %d hash %s, want %s (the hash Devnet reported)", i, h, devnetBatchInnerHashes[i])
		}
	}
	if tx.Inner[0].Type != TxAccountSet || len(tx.Inner[0].Memos) != 1 || tx.Inner[2].Type != TxDIDSet || string(tx.Inner[2].Data) != "probe anchor" {
		t.Fatalf("inner shapes: %+v", tx.Inner)
	}
	again, err := Serialize(tx, true)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(again) != devnetBatchBlob {
		t.Fatalf("re-serialized blob differs from the one Devnet validated")
	}
}

func TestBatchSerializerRefusesWhatRippledRefuses(t *testing.T) {
	blob, _ := hex.DecodeString(devnetBatchBlob)
	good, _ := Deserialize(blob)
	clone := func() *Tx {
		c := *good
		c.Inner = nil
		for _, in := range good.Inner {
			ic := *in
			c.Inner = append(c.Inner, &ic)
		}
		return &c
	}
	cases := map[string]func(*Tx){
		"one inner": func(tx *Tx) { tx.Inner = tx.Inner[:1] },
		"nine inners": func(tx *Tx) {
			for len(tx.Inner) < 9 {
				tx.Inner = append(tx.Inner, tx.Inner[0])
			}
		},
		"inner without flag":   func(tx *Tx) { tx.Inner[0].Flags = 0 },
		"inner with fee":       func(tx *Tx) { tx.Inner[0].FeeDrops = 1 },
		"inner signed":         func(tx *Tx) { tx.Inner[0].SigningPubKey = good.SigningPubKey },
		"nested batch":         func(tx *Tx) { tx.Inner[0].Type = TxBatch },
		"inners on AccountSet": func(tx *Tx) { tx.Type = TxAccountSet },
	}
	for name, mutate := range cases {
		tx := clone()
		mutate(tx)
		if _, err := Serialize(tx, true); err == nil {
			t.Errorf("%s: serialized without error", name)
		}
	}
}
