package pubattest

// Delegated attestation.
//
// Signing every attestation with the validator master key would take that
// key out of cold storage for routine work. XRPL validators already avoid
// this for validations: the master key signs a manifest once, delegating to
// a signing key that lives on the host. This file applies the same pattern.
//
// Once, offline, the master key signs a delegation naming an ed25519
// attestation key, a writer account and a delegation sequence (dseq). The
// delegation goes on the ledger as a cleartext memo. Routine attestations
// (layout version 2) are then signed by the attestation key on the host.
// A delegation with a higher dseq replaces the earlier one from its ledger
// onward, which is how a stolen attestation key is retired. There is no
// expiry, the same as a validator token.
//
// Delegation memo, MemoType "xrplbak/v1/d", cleartext:
//
//	u8 version=1 | vpk(33) | u8 alg=1 (ed25519) | attest_pub(32) | u32 dseq | sig(64)
//
// Delegated attestation, MemoType "xrplbak/v1/a", version 2:
//
//	u8 version=2 | vpk(33) | u32 dseq | u32 epoch | u32 seq | backup_id(16) | sig(64)
//
// As in version 1, the account is not in either memo. The verifier takes it
// from the enclosing transaction and rebuilds each signed string, so neither
// record can be replayed under another account.

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/justinnevins/xrplbak/internal/xrpl"
	"github.com/justinnevins/xrplbak/internal/xrpl/codec"
	"github.com/justinnevins/xrplbak/internal/xrpl/sign"
)

// DelegationMemoType is the cleartext delegation memo type.
const DelegationMemoType = "xrplbak/v1/d"

// VersionDelegated is the attestation layout signed by a delegated key.
const VersionDelegated = 2

// AlgEd25519 is the only attestation key algorithm in this version.
const AlgEd25519 = 1

const (
	delegationLen = 1 + vpkLen + 1 + ed25519.PublicKeySize + 4 + sigLen
	v2BodyLen     = 1 + vpkLen + 4 + 4 + 4 + 16
	v2MemoLen     = v2BodyLen + sigLen
)

// Delegation is a decoded delegation record.
type Delegation struct {
	VPK       []byte
	AttestPub ed25519.PublicKey
	DSeq      uint32
	Sig       []byte
}

// DelegationString is the exact ASCII the validator master key signs,
// offline, with `validator-keys sign`.
func DelegationString(vpkNodePublic, account string, attestPub ed25519.PublicKey, dseq uint32) string {
	return "xrplbak/v1/delegate " + vpkNodePublic + " " + account + " ed25519 " +
		hex.EncodeToString(attestPub) + " " + strconv.FormatUint(uint64(dseq), 10)
}

// DelegatedSignString is the exact ASCII the attestation key signs for one
// backup. Its prefix differs from SignString so a master-key attestation
// and a delegated one can never be mistaken for each other.
func DelegatedSignString(vpkNodePublic, account string, dseq, epoch, seq uint32, backupID string) string {
	return "xrplbak/v1/attest-delegated " + vpkNodePublic + " " + account + " " +
		strconv.FormatUint(uint64(dseq), 10) + " " +
		strconv.FormatUint(uint64(epoch), 10) + " " +
		strconv.FormatUint(uint64(seq), 10) + " " + strings.ToLower(backupID)
}

func edVPK(vpkNodePublic string) ([]byte, error) {
	vpk, err := sign.DecodeNodePublic(vpkNodePublic)
	if err != nil {
		return nil, err
	}
	if len(vpk) != vpkLen || vpk[0] != 0xED {
		return nil, errors.New("public attestation needs an ed25519 validator key (nHB...); secp256k1 keys are not supported")
	}
	return vpk, nil
}

// CheckDelegation reports whether sigHex is the master key's signature over
// DelegationString. backup runs it before publishing a delegation.
func CheckDelegation(vpkNodePublic, account string, attestPub ed25519.PublicKey, dseq uint32, sigHex string) bool {
	vpk, err := edVPK(vpkNodePublic)
	if err != nil {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != sigLen {
		return false
	}
	return sign.VerifyEd25519(vpk, []byte(DelegationString(vpkNodePublic, account, attestPub, dseq)), sig)
}

// DelegationMemo builds the cleartext delegation memo.
func DelegationMemo(vpkNodePublic string, attestPub ed25519.PublicKey, dseq uint32, sigHex string) (codec.Memo, error) {
	vpk, err := edVPK(vpkNodePublic)
	if err != nil {
		return codec.Memo{}, err
	}
	if len(attestPub) != ed25519.PublicKeySize {
		return codec.Memo{}, errors.New("attestation public key must be 32 bytes")
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != sigLen {
		return codec.Memo{}, errors.New("delegation signature must be 64 bytes of hex")
	}
	data := make([]byte, 0, delegationLen)
	data = append(data, 1)
	data = append(data, vpk...)
	data = append(data, AlgEd25519)
	data = append(data, attestPub...)
	data = binary.BigEndian.AppendUint32(data, dseq)
	data = append(data, sig...)
	return codec.Memo{Type: []byte(DelegationMemoType), Data: data}, nil
}

// DecodeDelegation parses a delegation memo. ok is false for anything that
// is not a well-formed delegation.
func DecodeDelegation(m codec.Memo) (Delegation, bool) {
	if string(m.Type) != DelegationMemoType || len(m.Data) != delegationLen || m.Data[0] != 1 {
		return Delegation{}, false
	}
	off := 1
	d := Delegation{VPK: append([]byte(nil), m.Data[off:off+vpkLen]...)}
	off += vpkLen
	if d.VPK[0] != 0xED || m.Data[off] != AlgEd25519 {
		return Delegation{}, false
	}
	off++
	d.AttestPub = append(ed25519.PublicKey(nil), m.Data[off:off+ed25519.PublicKeySize]...)
	off += ed25519.PublicKeySize
	d.DSeq = binary.BigEndian.Uint32(m.Data[off : off+4])
	off += 4
	d.Sig = append([]byte(nil), m.Data[off:]...)
	return d, true
}

// Verify checks the master key's signature against the publishing account.
func (d Delegation) Verify(account string) bool {
	msg := DelegationString(sign.EncodeNodePublic(d.VPK), account, d.AttestPub, d.DSeq)
	return sign.VerifyEd25519(d.VPK, []byte(msg), d.Sig)
}

// DelegatedMemo signs and builds a version 2 attestation memo with the
// attestation private key.
func DelegatedMemo(vpkNodePublic, account string, attestPriv ed25519.PrivateKey, dseq, epoch, seq uint32, backupID string) (codec.Memo, error) {
	vpk, err := edVPK(vpkNodePublic)
	if err != nil {
		return codec.Memo{}, err
	}
	id, err := hex.DecodeString(backupID)
	if err != nil || len(id) != 16 {
		return codec.Memo{}, errors.New("backup id must be 16 bytes of hex")
	}
	sig := ed25519.Sign(attestPriv, []byte(DelegatedSignString(vpkNodePublic, account, dseq, epoch, seq, backupID)))
	data := make([]byte, 0, v2MemoLen)
	data = append(data, VersionDelegated)
	data = append(data, vpk...)
	data = binary.BigEndian.AppendUint32(data, dseq)
	data = binary.BigEndian.AppendUint32(data, epoch)
	data = binary.BigEndian.AppendUint32(data, seq)
	data = append(data, id...)
	data = append(data, sig...)
	return codec.Memo{Type: []byte(MemoType), Data: data}, nil
}

// Status is the outcome of Evaluate.
type Status int

const (
	// None: the account publishes no attestation.
	None Status = iota
	// Valid: the newest attestation verifies.
	Valid
	// Invalid: the newest attestation does not verify.
	Invalid
)

// Finding is what Evaluate concluded about an account's newest attestation.
type Finding struct {
	Status Status
	Record Record
	Ledger uint32
	// Delegated is set for a version 2 attestation that verified.
	Delegated   bool
	Delegation  Delegation
	DelegLedger uint32
	// Reason says why an attestation is Invalid.
	Reason string
}

type placed struct {
	d      Delegation
	ledger uint32
	order  int
}

// Evaluate reads an account's history (oldest first, as AccountTx returns
// it) and judges the newest attestation. A delegated attestation is valid
// only when all of these hold:
//
//   - a delegation with the same validator key and dseq verifies under the
//     master key for this account, and landed no later than the attestation;
//   - no valid delegation with a higher dseq for that key landed before it;
//   - its own signature verifies under the delegated key.
//
// Delegation memos whose master signature fails are ignored: whoever holds
// the writer seed can post memos, but cannot sign for the master key.
func Evaluate(txs []xrpl.TxRecord, account string) Finding {
	var dels []placed
	var att *Record
	var attLedger uint32
	attOrder := -1
	order := 0
	for i := range txs {
		t := txs[i]
		if t.Account != account || t.Result != "tesSUCCESS" {
			continue
		}
		for _, m := range t.Memos {
			order++
			if d, ok := DecodeDelegation(m); ok {
				if d.Verify(account) {
					dels = append(dels, placed{d, t.LedgerIndex, order})
				}
				continue
			}
			if r, ok := Decode(m); ok && t.LedgerIndex >= attLedger {
				rec := r
				att, attLedger, attOrder = &rec, t.LedgerIndex, order
			}
		}
	}
	if att == nil {
		return Finding{Status: None}
	}
	f := Finding{Record: *att, Ledger: attLedger}
	if att.Version != VersionDelegated {
		if att.Verify(account) {
			f.Status = Valid
		} else {
			f.Status, f.Reason = Invalid, "the master key signature does not verify"
		}
		return f
	}
	var match *placed
	for i := range dels {
		p := dels[i]
		if string(p.d.VPK) != string(att.VPK) || p.order > attOrder {
			continue
		}
		if p.d.DSeq == att.DSeq {
			match = &dels[i]
		}
		if p.d.DSeq > att.DSeq && p.order < attOrder {
			f.Status = Invalid
			f.Reason = "delegated key " + strconv.FormatUint(uint64(att.DSeq), 10) + " was replaced by key " +
				strconv.FormatUint(uint64(p.d.DSeq), 10) + " in ledger " + strconv.FormatUint(uint64(p.ledger), 10) + ", earlier than this attestation"
			return f
		}
	}
	if match == nil {
		f.Status, f.Reason = Invalid, "no valid delegation for this validator key and dseq was published before the attestation"
		return f
	}
	msg := DelegatedSignString(att.NodePublic(), account, att.DSeq, att.Epoch, att.Seq, att.BackupIDHex())
	if !ed25519.Verify(match.d.AttestPub, []byte(msg), att.Sig) {
		f.Status, f.Reason = Invalid, "the delegated key signature does not verify"
		return f
	}
	f.Status, f.Delegated, f.Delegation, f.DelegLedger = Valid, true, match.d, match.ledger
	return f
}
