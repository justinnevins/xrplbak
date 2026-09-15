# Changelog

## v1.0.0 (unreleased)

- Commands: init, redact, backup, verify, restore.
- On-chain: AccountSet memo chunks (v1 layout), encrypted manifest memos, DID Data anchor.
- Off-chain: encrypted bundle (validator token, topology, includes) and transaction dump.
- Crypto: HKDF-SHA256 hierarchy, AES-256-GCM with counter nonces, HMAC-SHA256 anchor tag, BIP39 words, Shamir shares (Vault implementation), optional PBKDF2 key file wrap.
- Zero external Go dependencies.
- Security review fixes (pre-release): random manifest nonces with resume reuse, junk-resistant manifest discovery, port credential redaction, seed scan on key stanzas, restore path and mode hardening, share threshold headers, epoch rotation (`init --rotate`), `--force-seq`, page and frame caps, pinned toolchain, scoped CI permissions.
- Redaction: hostname rules. Names under private-network suffixes move to the bundle anywhere; single-label names move in host-valued stanzas and in `[port_*] ip =`.
- Attestation: the `validator-keys sign` byte convention is confirmed against ripple/validator-keys-tool and rippled source, and pinned by tests. Key derivation is pinned against rippled's 95 ed25519 test vectors.
- CI: every GitHub Action is pinned to a commit SHA, checkout runs with `persist-credentials: false`, and `contents: write` is confined to a separate tag-only release job.
- Verified end to end on XRPL Testnet 2026-09-15: backup, supersede (seq 2), verify, restore from server, restore from dump, restore --write.
