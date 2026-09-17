// Package codec serializes the four transaction types xrplbak submits:
// AccountSet (memo carrier), DIDSet (anchor), DIDDelete, and Batch (the
// atomic wrapper, XLS-56). Field codes come from rippled
// include/xrpl/protocol/detail/sfields.macro. Fields are written in
// canonical order: by type code, then field code.
package codec

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Transaction type codes (transactions.macro).
const (
	TxAccountSet uint16 = 3
	TxDIDSet     uint16 = 49
	TxDIDDelete  uint16 = 50
	TxBatch      uint16 = 71
)

// Batch flags (rippled TxFlags.h). An outer Batch carries exactly one of
// the four mode flags; every inner transaction carries FlagInnerBatchTxn
// and nothing else the tool sets.
const (
	FlagAllOrNothing  uint32 = 0x00010000
	FlagInnerBatchTxn uint32 = 0x40000000
)

// MaxBatchInner is rippled's kMaxBatchTxCount (Protocol.h).
const MaxBatchInner = 8

// MaxMemosSerialized is the rippled limit on the serialized Memos array.
const MaxMemosSerialized = 1024

// Memo is one entry of the Memos array. MemoFormat is optional.
type Memo struct {
	Type   []byte
	Data   []byte
	Format []byte
}

// Tx is the subset of transaction fields the tool uses.
type Tx struct {
	Type               uint16
	Flags              uint32
	Sequence           uint32
	LastLedgerSequence uint32
	FeeDrops           uint64
	SigningPubKey      []byte // 33 bytes
	TxnSignature       []byte // empty until signed
	Account            []byte // 20-byte account ID
	URI                []byte // DIDSet only, unused by the tool
	DIDDocument        []byte // DIDSet only, unused by the tool
	Data               []byte // DIDSet only
	Memos              []Memo
	Inner              []*Tx // Batch only: the RawTransactions array
}

// IsInner reports whether this transaction is an inner batch transaction:
// unsigned, zero fee, and carrying FlagInnerBatchTxn.
func (tx *Tx) IsInner() bool { return tx.Flags&FlagInnerBatchTxn != 0 }

// Serialize writes the canonical binary form. If includeSignature is false,
// TxnSignature is left out (the form that gets signed).
func Serialize(tx *Tx, includeSignature bool) ([]byte, error) {
	var b []byte
	b = appendHeader(b, 1, 2) // TransactionType UInt16
	b = append(b, byte(tx.Type>>8), byte(tx.Type))
	if tx.Flags != 0 {
		b = appendHeader(b, 2, 2)
		b = appendU32(b, tx.Flags)
	}
	b = appendHeader(b, 2, 4) // Sequence
	b = appendU32(b, tx.Sequence)
	if tx.LastLedgerSequence != 0 {
		b = appendHeader(b, 2, 27)
		b = appendU32(b, tx.LastLedgerSequence)
	}
	b = appendHeader(b, 6, 8) // Fee, XRP amount: bit 62 set, drops in low bits
	if tx.FeeDrops >= 1<<62 {
		return nil, errors.New("fee too large")
	}
	if tx.IsInner() {
		// rippled Batch::preflight: an inner transaction has a zero fee, an
		// empty SigningPubKey, and no TxnSignature. The outer signature
		// covers it.
		if tx.FeeDrops != 0 {
			return nil, errors.New("inner batch transaction must have a zero fee")
		}
		if len(tx.SigningPubKey) != 0 || len(tx.TxnSignature) != 0 {
			return nil, errors.New("inner batch transaction must not be signed")
		}
		if tx.Type == TxBatch {
			return nil, errors.New("a Batch cannot nest a Batch")
		}
	} else if len(tx.SigningPubKey) != 33 {
		return nil, errors.New("SigningPubKey must be 33 bytes")
	}
	b = appendU64(b, (1<<62)|tx.FeeDrops)
	b = appendHeader(b, 7, 3)
	b = appendVL(b, tx.SigningPubKey)
	if includeSignature && !tx.IsInner() {
		if len(tx.TxnSignature) == 0 {
			return nil, errors.New("transaction is not signed")
		}
		b = appendHeader(b, 7, 4)
		b = appendVL(b, tx.TxnSignature)
	}
	if tx.Type == TxDIDSet {
		if len(tx.URI) > 0 {
			b = appendHeader(b, 7, 5)
			b = appendVL(b, tx.URI)
		}
		if len(tx.DIDDocument) > 0 {
			b = appendHeader(b, 7, 26)
			b = appendVL(b, tx.DIDDocument)
		}
		if len(tx.Data) > 256 {
			return nil, errors.New("DIDSet Data must be at most 256 bytes")
		}
		if len(tx.Data) > 0 {
			b = appendHeader(b, 7, 27)
			b = appendVL(b, tx.Data)
		}
	}
	if len(tx.Account) != 20 {
		return nil, errors.New("Account must be a 20-byte account ID")
	}
	b = appendHeader(b, 8, 1)
	b = appendVL(b, tx.Account)
	if len(tx.Memos) > 0 {
		m, err := SerializeMemos(tx.Memos)
		if err != nil {
			return nil, err
		}
		b = append(b, m...)
	}
	if tx.Type == TxBatch {
		r, err := serializeInner(tx.Inner)
		if err != nil {
			return nil, err
		}
		b = append(b, r...)
	} else if len(tx.Inner) > 0 {
		return nil, errors.New("only a Batch carries inner transactions")
	}
	return b, nil
}

// serializeInner writes the RawTransactions array (STArray field 30, each
// entry an STObject RawTransaction, field 34). rippled requires at least
// two entries and at most MaxBatchInner.
func serializeInner(inner []*Tx) ([]byte, error) {
	if len(inner) < 2 || len(inner) > MaxBatchInner {
		return nil, fmt.Errorf("a Batch carries 2 to %d inner transactions, not %d", MaxBatchInner, len(inner))
	}
	var b []byte
	b = appendHeader(b, 15, 30)
	for _, in := range inner {
		if !in.IsInner() {
			return nil, errors.New("inner transaction lacks the tfInnerBatchTxn flag")
		}
		body, err := Serialize(in, false)
		if err != nil {
			return nil, err
		}
		b = appendHeader(b, 14, 34)
		b = append(b, body...)
		b = append(b, 0xE1)
	}
	return append(b, 0xF1), nil
}

// InnerHash returns the transaction hash of an inner batch transaction. It
// has no signature, so the hash covers the whole serialized form, and it is
// known before the batch is submitted.
func InnerHash(in *Tx) (string, error) {
	body, err := Serialize(in, false)
	if err != nil {
		return "", err
	}
	return Hash(body), nil
}

// SerializeMemos returns the Memos array bytes and enforces the 1 KB cap.
func SerializeMemos(memos []Memo) ([]byte, error) {
	var b []byte
	b = appendHeader(b, 15, 9) // Memos STArray
	for _, m := range memos {
		b = appendHeader(b, 14, 10) // Memo STObject
		if len(m.Type) > 0 {
			b = appendHeader(b, 7, 12)
			b = appendVL(b, m.Type)
		}
		if len(m.Data) > 0 {
			b = appendHeader(b, 7, 13)
			b = appendVL(b, m.Data)
		}
		if len(m.Format) > 0 {
			b = appendHeader(b, 7, 14)
			b = appendVL(b, m.Format)
		}
		b = append(b, 0xE1) // object end
	}
	b = append(b, 0xF1) // array end
	if len(b) > MaxMemosSerialized {
		return nil, fmt.Errorf("serialized Memos is %d bytes, limit is %d", len(b), MaxMemosSerialized)
	}
	return b, nil
}

// SigningPayload returns the bytes an ed25519 key signs: "STX\0" || tx.
func SigningPayload(tx *Tx) ([]byte, error) {
	body, err := Serialize(tx, false)
	if err != nil {
		return nil, err
	}
	return append([]byte{0x53, 0x54, 0x58, 0x00}, body...), nil
}

// Hash returns the transaction hash: SHA-512Half("TXN\0" || signed tx).
func Hash(signed []byte) string {
	h := sha512.Sum512(append([]byte{0x54, 0x58, 0x4E, 0x00}, signed...))
	return strings.ToUpper(hex.EncodeToString(h[:32]))
}

func appendHeader(b []byte, typ, field int) []byte {
	switch {
	case typ < 16 && field < 16:
		return append(b, byte(typ<<4|field))
	case typ < 16:
		return append(b, byte(typ<<4), byte(field))
	case field < 16:
		return append(b, byte(field), byte(typ))
	default:
		return append(b, 0, byte(typ), byte(field))
	}
}

func appendVL(b, v []byte) []byte {
	n := len(v)
	switch {
	case n <= 192:
		b = append(b, byte(n))
	case n <= 12480:
		n -= 193
		b = append(b, byte(193+n>>8), byte(n))
	default:
		n -= 12481
		b = append(b, byte(241+n>>16), byte(n>>8), byte(n))
	}
	return append(b, v...)
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendU64(b []byte, v uint64) []byte {
	return append(b, byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
