# Changelog

## v1.0.0 (unreleased)

- Commands: init, redact, backup, verify, restore.
- On-chain: AccountSet memo chunks (v1 layout), encrypted manifest memos, DID Data anchor.
- Off-chain: encrypted bundle (validator token, topology, includes) and transaction dump.
- Crypto: HKDF-SHA256 hierarchy, AES-256-GCM with counter nonces, HMAC-SHA256 anchor tag, BIP39 words, Shamir shares (Vault implementation), optional PBKDF2 key file wrap.
- Zero external Go dependencies.
- Verified end to end on XRPL Testnet 2026-09-15: backup, supersede (seq 2), verify, restore from server, restore from dump, restore --write.
