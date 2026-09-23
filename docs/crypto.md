# Cryptography

Everything is from the Go standard library. No novel constructions.

| Need | Choice | Why |
|---|---|---|
| Root key | 32 bytes from crypto/rand | 256-bit security, quantum-safe by size |
| Derivation | HKDF-SHA256 (crypto/hkdf) with fixed salt and role strings | Standard, domain separated |
| Encryption | AES-256-GCM (crypto/aes, crypto/cipher) | Hardware-accelerated and constant-time on both release targets. Chunk and bundle nonces are counters under keys bound to one backup_id that commits to the plaintext. Manifest nonces carry a random 10-byte prefix because the manifest is not committed by backup_id. |
| Anchor tag | HMAC-SHA256 truncated to 128 bits | Fits the 256-byte DID field with room to spare |
| Human key form | BIP39 24 words | Transcription-friendly, checksummed |
| Threshold | Shamir over GF(2^8), HashiCorp Vault implementation copied verbatim | Reviewed code, no dependency graph |
| Key file passphrase | PBKDF2-HMAC-SHA256, 600,000 iterations | Standard library. argon2id would need an external module. The wrap protects a file that already sits on a host the attacker must control. |
| Account keys | ed25519 (crypto/ed25519), seed derivation SHA-512Half as rippled does | Verified against XRPLF/xrpl.js ripple-keypairs fixtures |

Why no X25519 or RSA: any public-key ciphertext on a permanent public ledger is a harvest-now-decrypt-later target. Symmetric only means a quantum computer halves the security level to 128 bits and nothing more.

Where public-key crypto remains: signatures only. The writer account signs its transactions with ed25519, and a public attestation is an ed25519 signature by the validator master key. A quantum computer that breaks ed25519 could forge both, but neither protects the secrecy or the authenticity of a backup. Go 1.27 ships ML-DSA (FIPS 204) in `crypto/mldsa`, so a post-quantum attestation needs no new dependency once XRPL validator keys support one. See the README section on quantum computers.

Why the host holds a key at all: the host already has the plaintext config. An epoch key that decrypts this host's own backups adds no exposure. It never derives the root key or other epochs.

Test vectors: `internal/crypto/crypto_test.go` pins the epoch-0 derivation of a fixed root key; `internal/xrpl/codec/codec_test.go` pins DIDSet and DIDDelete serialization to xrpl.js fixtures; `internal/xrpl/sign/keys_test.go` pins ed25519 seed, address, and signature.
