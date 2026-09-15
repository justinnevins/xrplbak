# Changelog

## Unreleased

- Fuzz targets for config parsing, redaction, the container, chunks, the manifest, the anchor, and the AEAD layer, with a committed corpus and a CI smoke job.
- Fix: an empty stanza header is no longer moved to the bundle. It held no content, and moving it wrote a marker line the original never had, so restore reported a correct backup as changed.
- Fix: canonical form is now a fixed point. A nameless stanza with no lines wrote a separator that re-parsing could not recover, so the same config hashed two different ways.
- Fix: a stanza header with a trailing comment, such as `[server] # ports`, now parses as a header. It was read as a value line, which silently moved every following line into the wrong stanza.

## v1.0.0 (2026-09-15)

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
