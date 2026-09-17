# Changelog

## Unreleased

- Fix: the redaction plan printed by `backup` and `redact` names the lines before the first stanza instead of `[]`, and says when a move was only comments, the same wording the restore todo already used.
- AEAD tag test: every single-byte change to a chunk, manifest part, or bundle frame is refused by the crypto layer, pinned in `internal/crypto` (the corpus rows prove refusal at the command level but the manifest field check masks the tag check there).
- Adversarial corpus: 38 table-driven refusal cases in `cmd/xrplbak/corpus_test.go`, each asserting a named exit code. `main` is now `run(args, stdin, stdout, stderr) int` so tests drive the real command surface; flag errors return exit 1 instead of exiting inside the flag package.
- Breaking: verify and restore refuse when two different backups authenticate at the same epoch and seq (exit 4) instead of picking the later one with a warning. New `--backup-id <hex prefix>` names one explicitly. `backup` picks the next seq above the disputed one.
- Fix: a DID anchor whose epoch or seq disagrees with the manifest it names is no longer reported as verified.
- Fix: `restore --write` refused when two files in the backup share a basename. It wrote both to the same target path and listed that path twice as written.
- Fix: a manifest or container path that is not a clean absolute path is refused with exit 3 before any file is written, including into the dry-run directory. Such paths exited 1 and could leave earlier files in the temp dir.
- Fix: a container entry the manifest does not list is refused (exit 3) instead of being restored as an extra file.
- Fix: a dump file with an entry that is not a transaction is refused whole (exit 1). Bad entries were skipped, so the run reported a chunk as missing from history when the file was at fault.
- Fix: errors while writing the dry-run directory exit 6, not 1.
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
