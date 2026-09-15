# Cryptography

Everything is from the Go standard library. No novel constructions.

| Need | Choice | Why |
|---|---|---|
| Root key | 32 bytes from crypto/rand | 256-bit security, quantum-safe by size |
| Derivation | HKDF-SHA256 (crypto/hkdf) with fixed salt and role strings | Standard, domain separated |
| Encryption | AES-256-GCM (crypto/aes, crypto/cipher) with counter nonces | Hardware-accelerated and constant-time on both release targets. Nonces never repeat under a key because each key is bound to one backup_id which commits to the plaintext. |
| Anchor tag | HMAC-SHA256 truncated to 128 bits | Fits the 256-byte DID field with room to spare |
| Human key form | BIP39 24 words | Transcription-friendly, checksummed |
| Threshold | Shamir over GF(2^8), HashiCorp Vault implementation copied verbatim | Reviewed code, no dependency graph |
| Key file passphrase | PBKDF2-HMAC-SHA256, 600,000 iterations | Standard library. argon2id would need an external module. The wrap protects a file that already sits on a host the attacker must control. |
| Account keys | ed25519 (crypto/ed25519), seed derivation SHA-512Half as rippled does | Verified against XRPLF/xrpl.js ripple-keypairs fixtures |

Why no X25519 or RSA: any public-key ciphertext on a permanent public ledger is a harvest-now-decrypt-later target. Symmetric only means a quantum computer halves the security level to 128 bits and nothing more.

Why the host holds a key at all: the host already has the plaintext config. An epoch key that decrypts this host's own backups adds no exposure. It never derives the root key or other epochs.

Test vectors: `internal/crypto/crypto_test.go` pins the epoch-0 derivation of a fixed root key; `internal/xrpl/codec/codec_test.go` pins DIDSet and DIDDelete serialization to xrpl.js fixtures; `internal/xrpl/sign/keys_test.go` pins ed25519 seed, address, and signature.
