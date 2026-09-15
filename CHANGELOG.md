# Changelog

## v1.0.0 (unreleased)

- Commands: init, redact, backup, verify, restore.
- On-chain: AccountSet memo chunks (v1 layout), encrypted manifest memos, DID Data anchor.
- Off-chain: encrypted bundle (validator token, topology, includes) and transaction dump.
- Crypto: HKDF-SHA256 hierarchy, AES-256-GCM with counter nonces, HMAC-SHA256 anchor tag, BIP39 words, Shamir shares (Vault implementation), optional PBKDF2 key file wrap.
- Zero external Go dependencies.
- Security review fixes (pre-release): random manifest nonces with resume reuse, junk-resistant manifest discovery, port credential redaction, seed scan on key stanzas, restore path and mode hardening, share threshold headers, epoch rotation (`init --rotate`), `--force-seq`, page and frame caps, pinned toolchain, scoped CI permissions.
- Verified end to end on XRPL Testnet 2026-09-15: backup, supersede (seq 2), verify, restore from server, restore from dump, restore --write.
