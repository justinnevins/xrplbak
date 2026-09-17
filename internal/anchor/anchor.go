// Package anchor encodes the DID Data record that points at the latest
// manifest. Layout (77 bytes):
//
//	u8 version=1 | backup_id(16) | manifest_tx_hash(32) | u32 manifest_ledger
//	| u32 epoch | u32 seq | hmac(16)
//
// The HMAC is keyed from the epoch key so a writer-key thief cannot forge a
// record that verifies.
package anchor

import (
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/justinnevins/xrplbak/internal/crypto"
)

// Len is the encoded record size.
const Len = 1 + 16 + 32 + 4 + 4 + 4 + 16

// Record is the decoded anchor.
type Record struct {
	BackupID       [16]byte
	ManifestTxHash [32]byte
	// ManifestLedger is the ledger that closed the manifest's first part,
	// or 0 when the anchor and the manifest went out in one Batch and
	// share a ledger the anchor could not know when it was built. Nothing
	// reads it but the operator's report.
	ManifestLedger uint32
	Epoch          uint32
	Seq            uint32
}

// Encode renders and MACs the record.
func Encode(k crypto.EpochKey, r *Record) []byte {
	b := make([]byte, 0, Len)
	b = append(b, 1)
	b = append(b, r.BackupID[:]...)
	b = append(b, r.ManifestTxHash[:]...)
	b = binary.BigEndian.AppendUint32(b, r.ManifestLedger)
	b = binary.BigEndian.AppendUint32(b, r.Epoch)
	b = binary.BigEndian.AppendUint32(b, r.Seq)
	return append(b, k.AnchorMAC(b)...)
}

// Parse decodes without checking the MAC (the epoch is needed to pick the
// key, and the epoch is inside the record).
func Parse(b []byte) (*Record, error) {
	if len(b) != Len || b[0] != 1 {
		return nil, errors.New("DID Data is not an xrplbak v1 anchor")
	}
	r := &Record{}
	copy(r.BackupID[:], b[1:17])
	copy(r.ManifestTxHash[:], b[17:49])
	r.ManifestLedger = binary.BigEndian.Uint32(b[49:53])
	r.Epoch = binary.BigEndian.Uint32(b[53:57])
	r.Seq = binary.BigEndian.Uint32(b[57:61])
	return r, nil
}

// Verify checks the MAC with the given epoch key.
func Verify(k crypto.EpochKey, b []byte) bool {
	if len(b) != Len {
		return false
	}
	return hmac.Equal(k.AnchorMAC(b[:Len-16]), b[Len-16:])
}

// TxHashHex renders the manifest hash the way RPC expects it.
func (r *Record) TxHashHex() string { return strings.ToUpper(hex.EncodeToString(r.ManifestTxHash[:])) }
