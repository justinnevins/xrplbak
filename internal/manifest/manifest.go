// Package manifest defines the v1 backup manifest: the encrypted index that
// names every chunk, every file, and the bundle. Encoding is JSON with
// sorted keys and no whitespace so the bytes are stable.
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Version of the manifest format. Changing any field is a bump.
const Version = 1

// Chunk is one on-chain ciphertext piece and where it landed.
type Chunk struct {
	Index  int    `json:"i"`
	TxHash string `json:"tx"`
	Ledger uint32 `json:"ledger"`
	SHA256 string `json:"sha256"`
}

// File is one restored path.
type File struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256"`
	Where  string `json:"where"` // "onchain", "bundle", or "onchain+bundle"
}

// Redaction summarizes one move for the operator.
type Redaction struct {
	Stanza string `json:"stanza"`
	Lines  int    `json:"lines"`
	To     string `json:"to"`
}

// Attestation is the optional validator-master signature (team option).
type Attestation struct {
	Scheme string `json:"scheme"`
	VPK    string `json:"vpk"`
	Sig    string `json:"sig"`
}

// Manifest is the plaintext structure.
type Manifest struct {
	V        int    `json:"v"`
	Epoch    uint32 `json:"epoch"`
	Seq      uint32 `json:"seq"`
	BackupID string `json:"backup_id"`
	Created  string `json:"created"`
	Tool     string `json:"tool"`
	Node     struct {
		Role          string `json:"role"`
		VPKSHA256     string `json:"vpk_sha256,omitempty"`
		ServerVersion string `json:"server_version,omitempty"`
	} `json:"node"`
	OnChain struct {
		PlainSHA256 string  `json:"plain_sha256"`
		PlainLen    int     `json:"plain_len"`
		Chunks      []Chunk `json:"chunks"`
	} `json:"onchain"`
	Bundle struct {
		PlainSHA256  string `json:"plain_sha256"`
		CipherSHA256 string `json:"cipher_sha256"`
		Len          int    `json:"len"`
	} `json:"bundle"`
	Files       []File       `json:"files"`
	Redactions  []Redaction  `json:"redactions"`
	Supersedes  string       `json:"supersedes"`
	Tombstone   bool         `json:"tombstone"`
	Attestation *Attestation `json:"attestation,omitempty"`
}

// Marshal renders canonical bytes: keys sorted, no whitespace.
func Marshal(m *Manifest) ([]byte, error) {
	m.V = Version
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(generic); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Unmarshal parses and checks the version.
func Unmarshal(b []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("manifest is not valid JSON: %w", err)
	}
	if m.V != Version {
		return nil, fmt.Errorf("manifest version %d is not supported by this tool (wants %d)", m.V, Version)
	}
	if len(m.BackupID) != 32 {
		return nil, errors.New("manifest has no backup id")
	}
	return &m, nil
}

// Newer reports whether a supersedes b by (epoch, seq).
func Newer(a, b *Manifest) bool {
	if a.Epoch != b.Epoch {
		return a.Epoch > b.Epoch
	}
	return a.Seq > b.Seq
}

// AttestString is the exact text the validator master key signs.
func AttestString(backupID, onchainSHA, bundleSHA string) string {
	return "xrplbak/v1/attest " + backupID + " " + onchainSHA + " " + bundleSHA
}
