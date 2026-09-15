// Package chunk maps ciphertext to and from memo payloads.
//
// MemoData layout: u8 version=1 | backup_id(16) | u16 idx | u16 total | ciphertext
// (21 header bytes + 976 ciphertext bytes = 997; serialized Memos = 1018 <= 1024)
// MemoType is "xrplbak/v1/c" for on-chain container chunks and
// "xrplbak/v1/m" for manifest parts. No MemoFormat.
package chunk

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/justinnevins/xrplbak/internal/container"
	"github.com/justinnevins/xrplbak/internal/crypto"
	"github.com/justinnevins/xrplbak/internal/xrpl/codec"
)

const (
	TypeChunk    = "xrplbak/v1/c"
	TypeManifest = "xrplbak/v1/m"
	Version      = 1
	headerLen    = 1 + 16 + 2 + 2
	// MaxChunks caps on-chain container size at 8 x 960 bytes of plaintext.
	MaxChunks = 8
)

// Payload is a decoded memo.
type Payload struct {
	Type       string
	BackupID   [16]byte
	Index      uint16
	Total      uint16
	Ciphertext []byte
}

// Encode builds the memo for one ciphertext piece.
func Encode(typ string, backupID []byte, idx, total uint16, ct []byte) (codec.Memo, error) {
	if len(backupID) != 16 {
		return codec.Memo{}, errors.New("backup id must be 16 bytes")
	}
	data := make([]byte, 0, headerLen+len(ct))
	data = append(data, Version)
	data = append(data, backupID...)
	data = binary.BigEndian.AppendUint16(data, idx)
	data = binary.BigEndian.AppendUint16(data, total)
	data = append(data, ct...)
	m := codec.Memo{Type: []byte(typ), Data: data}
	if _, err := codec.SerializeMemos([]codec.Memo{m}); err != nil {
		return codec.Memo{}, err
	}
	return m, nil
}

// Decode parses a memo. It returns ok=false for memos that are not ours.
func Decode(m codec.Memo) (Payload, bool) {
	typ := string(m.Type)
	if typ != TypeChunk && typ != TypeManifest {
		return Payload{}, false
	}
	if len(m.Data) < headerLen+crypto.TagLen || m.Data[0] != Version {
		return Payload{}, false
	}
	p := Payload{Type: typ}
	copy(p.BackupID[:], m.Data[1:17])
	p.Index = binary.BigEndian.Uint16(m.Data[17:19])
	p.Total = binary.BigEndian.Uint16(m.Data[19:21])
	p.Ciphertext = m.Data[headerLen:]
	return p, true
}

// Split slices packed plaintext into BlockLen pieces.
func Split(packed []byte) ([][]byte, error) {
	if len(packed) == 0 || len(packed)%container.BlockLen != 0 {
		return nil, errors.New("plaintext is not block aligned")
	}
	n := len(packed) / container.BlockLen
	out := make([][]byte, n)
	for i := range out {
		out[i] = packed[i*container.BlockLen : (i+1)*container.BlockLen]
	}
	return out, nil
}

// MissingError names exactly which piece is absent.
type MissingError struct {
	Kind    string
	Index   int
	Total   int
	Account string
	MinLgr  int64
	MaxLgr  int64
}

func (e *MissingError) Error() string {
	return fmt.Sprintf("%s %d of %d missing from account %s in searched ledgers %d to %d; use a server with more history or the dump file", e.Kind, e.Index+1, e.Total, e.Account, e.MinLgr, e.MaxLgr)
}
