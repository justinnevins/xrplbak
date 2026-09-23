// Package pubattest is the public, cleartext validator-backup attestation.
//
// The private attestation in the manifest binds a backup to a validator key
// but lives inside the encrypted manifest, so only a holder of the recovery
// key can read it. This package is the opposite: a statement published on
// the ledger in the clear, verifiable by anyone who knows the validator's
// public key, with no recovery key and no decryption.
//
// It says exactly one thing: the holder of validator master key VPK vouches
// that XRPL account ACCOUNT published backup BACKUPID at epoch/seq. The
// validator master key signs it offline with `validator-keys sign`, the
// same raw-ed25519-over-ASCII convention the manifest attestation uses
// (see internal/xrpl/sign vectors_test.go). Nothing here proves the
// operator can still restore; it proves identity, existence and recency.
//
// Memo layout, MemoType "xrplbak/v1/a", cleartext:
//
//	u8 version=1 | vpk(33) | u32 epoch | u32 seq | backup_id(16) | sig(64)
//
// The account is not in the memo. The verifier takes it from the enclosing
// transaction and rebuilds the signed string, so a signature cannot be
// replayed under a different account.
package pubattest

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/justinnevins/xrplbak/internal/xrpl/codec"
	"github.com/justinnevins/xrplbak/internal/xrpl/sign"
)

// MemoType is the cleartext attestation memo type.
const MemoType = "xrplbak/v1/a"

// Version is the memo layout version.
const Version = 1

const (
	vpkLen = 33
	sigLen = 64
	// bodyLen is everything but the signature: version, vpk, epoch, seq, id.
	bodyLen = 1 + vpkLen + 4 + 4 + 16
	memoLen = bodyLen + sigLen
)

// Record is a decoded public attestation.
type Record struct {
	// Version is 1 for a master-key attestation, 2 for a delegated one.
	Version byte
	// DSeq names the delegation a version 2 attestation was signed under.
	DSeq     uint32
	VPK      []byte // 33-byte validator public key, ED-prefixed
	Epoch    uint32
	Seq      uint32
	BackupID [16]byte
	Sig      []byte // 64-byte ed25519 signature
}

// SignString is the exact ASCII the validator master key signs. It binds the
// validator key to the account and the backup, so the on-chain memo cannot
// be lifted onto another account or another backup.
func SignString(vpkNodePublic, account string, epoch, seq uint32, backupID string) string {
	return "xrplbak/v1/attest-public " + vpkNodePublic + " " + account + " " +
		strconv.FormatUint(uint64(epoch), 10) + " " +
		strconv.FormatUint(uint64(seq), 10) + " " + strings.ToLower(backupID)
}

// Memo builds the cleartext attestation memo. vpkNodePublic is the nHB...
// key, sigHex is the offline signature over SignString for this backup.
func Memo(vpkNodePublic string, epoch, seq uint32, backupID string, sigHex string) (codec.Memo, error) {
	vpk, err := sign.DecodeNodePublic(vpkNodePublic)
	if err != nil {
		return codec.Memo{}, err
	}
	if len(vpk) != vpkLen || vpk[0] != 0xED {
		return codec.Memo{}, errors.New("public attestation needs an ed25519 validator key (nHB...); secp256k1 keys are not supported in v1")
	}
	id, err := hex.DecodeString(backupID)
	if err != nil || len(id) != 16 {
		return codec.Memo{}, errors.New("backup id must be 16 bytes of hex")
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != sigLen {
		return codec.Memo{}, errors.New("attestation signature must be 64 bytes of hex")
	}
	data := make([]byte, 0, memoLen)
	data = append(data, Version)
	data = append(data, vpk...)
	data = binary.BigEndian.AppendUint32(data, epoch)
	data = binary.BigEndian.AppendUint32(data, seq)
	data = append(data, id...)
	data = append(data, sig...)
	m := codec.Memo{Type: []byte(MemoType), Data: data}
	if _, err := codec.SerializeMemos([]codec.Memo{m}); err != nil {
		return codec.Memo{}, err
	}
	return m, nil
}

// Decode parses an attestation memo. ok is false for memos that are not ours
// or are malformed, so a junk memo of our type can never masquerade as one.
func Decode(m codec.Memo) (Record, bool) {
	if string(m.Type) != MemoType {
		return Record{}, false
	}
	switch {
	case len(m.Data) == memoLen && m.Data[0] == Version:
	case len(m.Data) == v2MemoLen && m.Data[0] == VersionDelegated:
	default:
		return Record{}, false
	}
	r := Record{Version: m.Data[0], VPK: make([]byte, vpkLen), Sig: make([]byte, sigLen)}
	copy(r.VPK, m.Data[1:1+vpkLen])
	if r.VPK[0] != 0xED {
		return Record{}, false
	}
	off := 1 + vpkLen
	if r.Version == VersionDelegated {
		r.DSeq = binary.BigEndian.Uint32(m.Data[off : off+4])
		off += 4
	}
	r.Epoch = binary.BigEndian.Uint32(m.Data[off : off+4])
	r.Seq = binary.BigEndian.Uint32(m.Data[off+4 : off+8])
	copy(r.BackupID[:], m.Data[off+8:off+24])
	copy(r.Sig, m.Data[off+24:])
	return r, true
}

// Verify checks the signature against the account that published the memo.
// It is the whole check a third party runs: rebuild the signed string from
// the account and the memo's own fields, then verify the ed25519 signature
// under the memo's validator key. A true result means the holder of that
// validator key vouched for this account and this backup.
func (r Record) Verify(account string) bool {
	if r.Version != Version {
		return false // a delegated attestation is checked by Evaluate
	}
	msg := SignString(r.NodePublic(), account, r.Epoch, r.Seq, hex.EncodeToString(r.BackupID[:]))
	return sign.VerifyEd25519(r.VPK, []byte(msg), r.Sig)
}

// Check reports whether sigHex is a valid signature by vpkNodePublic over
// SignString for this backup. backup --submit runs it before publishing,
// because an attestation is permanent and a signature that does not verify
// is worse than none: it tells every third party the operator cannot sign
// for the key they claim.
func Check(vpkNodePublic, account string, epoch, seq uint32, backupID, sigHex string) bool {
	vpk, err := sign.DecodeNodePublic(vpkNodePublic)
	if err != nil {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != sigLen {
		return false
	}
	msg := SignString(vpkNodePublic, account, epoch, seq, backupID)
	return sign.VerifyEd25519(vpk, []byte(msg), sig)
}

// NodePublic renders the validator key as its nHB... form.
func (r Record) NodePublic() string { return sign.EncodeNodePublic(r.VPK) }

// BackupIDHex renders the backup id.
func (r Record) BackupIDHex() string { return hex.EncodeToString(r.BackupID[:]) }

// String is a one-line human summary, without claiming recoverability.
func (r Record) String() string {
	return fmt.Sprintf("validator %s, epoch %d seq %d, backup %s", r.NodePublic(), r.Epoch, r.Seq, r.BackupIDHex())
}
