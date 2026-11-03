# Changelog

## Unreleased

- Removed: `backup --attestation` and `--attestation-key` (the team attestation inside the encrypted manifest). Only a holder of the recovery words could check it, and `backup` published it without checking the signature. A signature over the wrong string, or over the string a dry run printed for seq 1 when the ledger already held a backup, was stored for good and read as INVALID. Both flags now refuse with exit 1 and point to `--attest`. `verify` still reads team attestations in older backups. Use `--attest` (delegated key) or `--attest-public-key` for a public attestation.

## v1.1.5 (2026-10-23)

- Build: Go 1.27.3. Go 1.27.2 carries GO-2026-6809 in crypto/x509 (`Certificate.Verify` did not refuse intermediate certificates that are no longer trusted; govulncheck, published 2026-10-21). The RPC client verifies HTTPS server certificates through crypto/x509, so the fix applies to every `--rpc` call over HTTPS.
- Fix: `init` discarded the recovery words on one mistyped word in the re-entry check, or on one Ctrl-C before the key file was written, and the operator had to start over with 24 new words. Each word now gets three tries, and a miss says the words on paper are still the right ones. The first Ctrl-C explains that init has not stopped; a second one stops and says nothing was saved. The key file is still written only after the check passes.
- `init` offers to clear the words from the screen once the key file is written, and says a terminal may keep them in its scrollback anyway. `--yes` asks nothing.
- `init` no longer says "fund from a fresh path". It says what that meant: the funding payment is public and links the funding account to this backup.
- `restore` says that a backup keeps each file's mode, not its owner or group, and `--write` says how to give the xrpld service user read access. `docs/restore-ceremony.md` step 9 spells out both safe settings.
- `restore`: a file reads `complete` only through a proof that the SHA-256 of its bytes equals the manifest's, checked again against the bytes each time it is read. No other code path can mark a file complete.
- Tests: a property target, `FuzzEveryBuiltPlanIsDiscovered`, submits every plan `backup` accepts to the fake ledger and checks that discovery finds it and restore marks it complete. Run against the code before the F-057 fix, it fails. `FuzzCompleteMeansHashMatches` pins the completeness rule. Both run in CI.
- Docs: `docs/trusted-base.md` lists what the tool trusts without checking. The README says the daily live run is on Testnet. The AI assistant guide covers the root shell and the public funding link.

## v1.1.4 (2026-10-19)

- Fix: `backup --submit` resumed from a dump file without asking the ledger it was writing to. A dump written against another network, or before a Devnet reset, made it skip every chunk and the manifest as "already on ledger", then write an anchor naming a manifest that ledger did not hold, and exit 0. Each transaction the dump records for the backup is now confirmed on the target ledger (validated, `tesSUCCESS`, sent by the writer account) before it counts. One that is not there is resent. If the ledger cannot be asked, the resume stops with exit 2 instead of guessing.
- Fix: `verify` and `restore` with a DID anchor naming a backup whose manifest was not in the history being read (a thinned dump, a server with partial history) picked the newest backup they could find, called it a "possible rollback", and exited 0. `restore --write` wrote that older backup. They now refuse with exit 5, name the anchored backup and where its manifest should be, and say to read from a server with full history or pass `--backup-id` to use the older backup on purpose. The rollback warning remains for the case it was written for: a backup newer than the anchor.
- Fix: `verify` and `restore` exited 4 (authentication) when the server failed while chunks were being fetched (an HTTP error on the `tx` call). That is a network failure and now exits 2. A missing chunk still exits 5 and a chunk that does not authenticate still exits 4.
- Fix: with the recovery words, `verify` and `restore` could not open a backup more than 64 epochs below the DID anchor's epoch, and `--epoch` did not help: the anchor's epoch replaced the operator's starting epoch, and the 64-epoch window hung below that. `--backup-id` for such a backup failed with exit 4. The anchor now only moves the start of the search up; the window still reaches 64 epochs below the epoch the operator gave (`--epoch`, the key file, or 0). A key file still opens only its own epoch.

## v1.1.3 (2026-10-16)

- Build: Go 1.27.2. Go 1.27.1 carries standard library vulnerabilities in net/http, net/textproto and crypto/tls (govulncheck, 2026-10-12). The gosec job now reads the Go version from go.mod like the other jobs.
- Fix: `backup` with enough `--include` files to push the manifest past 16 parts (about 80 files, depending on path length) built, submitted and anchored a backup that `verify` and `restore` could never find. They then reported the previous backup as complete with exit 0. `backup` now refuses at plan time with exit 1 and says to use fewer `--include` files. `verify` and `restore` count a manifest above the limit as rejected and warn, instead of ignoring it.
- Fix: `init --rotate` moved the old key file to `xrplbak.key.epochN` even when a file with that name existed, and replaced it. It now picks a free name (`.epochN.2`, `.epochN.3`, ...) and prints it. No file is ever overwritten.

## v1.1.2 (2026-10-05)

- Fix: `init --rotate` on a passphrase-protected key file wrote the new key file without a passphrase unless `--key-passphrase` was given again. The new file now keeps the passphrase that was just entered. `--key-passphrase` still chooses a new one.
- Fix: `init --rotate` at the last epoch (4294967295) wrapped to epoch 0. It now refuses with exit 3. `backup` after seq 4294967295 planned seq 0, which sorts below every older backup. It now refuses with exit 3 and says to rotate, and `--force-seq` does not override that.
- Breaking: `backup` refuses `--delete-anchor` without `--tombstone`, `--tombstone` with `--include`, and `--tombstone` with any attestation flag (`--attest`, `--attest-public-key`, `--attestation`), with exit 1. Each was ignored or, for a public attestation, published next to the tombstone.
- Fix: `backup --tombstone --delete-anchor` left the deleted DID anchor in the dump file it wrote, so an offline restore from that dump reported an anchor the ledger no longer had.
- Fix: `verify` crashed with a Go stack trace (exit 2) when the newest backup was a tombstone and `--bundle` was not given. It now says the backup is a tombstone, does not check a bundle, and exits 5, as the exit-code table already said. `--backup-id` verifies an older backup. A short bundle hash in a manifest no longer crashes verify either.
- Fix: `verify` and `restore` with the recovery words found no backup more than 8 epochs above the start of the search when the DID anchor was gone. A newer backup or tombstone at, say, epoch 12 was skipped, and the epoch 0 backup was restored with exit 0. The search now reaches 64 epochs above the newest epoch it finds, and moves up again with each epoch found.
- Warning: `verify`, `restore` and `backup` warn when a manifest that this key cannot open landed after the selected backup. It may be a newer backup from another epoch, or junk from someone holding the writer key. Manifests that landed before it, such as older epochs after a rotation, do not warn. Exit codes are unchanged.
- Fix: `restore --allow-tombstoned` with `--backup-id` naming a tombstone restored the newest backup, even one newer than that tombstone. It now restores the newest backup older than the tombstone it chose, says which one, and gives the same stale-epoch warnings as `--backup-id`.
- Docs: the build steps and the AI assistant guide name v1.1.2.

## v1.1.1 (2026-09-30)

- `backup` no longer prints the team attestation string in every plan. It appears on a dry run with `--attestation-key`, the flag it belongs to. `--attestation` and `--attestation-key` still go together on `--submit`.
- `backup --submit` says what it published: the delegation, and the public attestation with the key that signed it and the `attest-verify` command to check it.
- The closing `verify anytime` hint is a command that works as printed: the `--rpc` value as given (`testnet`, not the resolved URL), the key file, and the bundle. Without `--key`, verify asked for the recovery words.
- Help text says which attestation flags most operators want (`--attest`) and marks the others as team or advanced options.
- Docs: the build steps and the AI assistant guide name v1.1.1.

## v1.1.0 (2026-09-30)

- Fix: `backup` refuses a file named more than once, for example an `--include` equal to `--config` or `--validators`, with exit 1. Such a backup exited 0, and `restore` then wrote that file with its content doubled while reporting PARTIAL. `restore` also refuses (exit 3) a manifest that lists one path twice, so backups made before this fix cannot write a doubled file.
- Fix: the PEM header check ignores letter case, in the config and in `--include` files, and so does the `secret_key` check on `--include` files. A lowercase header was not refused.
- Public attestation by delegated key. `attest-key` creates an ed25519 attestation key and prints one string for the validator master key to sign offline. `backup --attest --attest-delegation-sig` publishes the delegation, and `backup --attest` attests later backups without the master key. A higher `--dseq` retires a stolen key. `attest-verify` checks the whole chain and accepts `--dump`. Master-key attestations (`--attest-public-key`) still work. Formats: docs/wire-format.md.
- Redaction: an `admin` or `secure_gateway` line that lists only loopback addresses (127.0.0.0/8, ::1) stays on-chain. Any other address still moves the line to the bundle.
- New `--peers=bundle|onchain` on `redact` and `backup`. `onchain` puts the public lines of `[ips_fixed]` on the ledger after the operator types `PUBLISH PEERS`. Private addresses and internal names still go to the bundle.
- Docs: data-classification.md described the old canonical form; it now describes byte fidelity.
- Build: Go 1.27.1. Go 1.24 no longer receives security fixes, and the v1.0.0 binaries built with go1.24.7 carry known standard library vulnerabilities, including in crypto/tls and net/url (govulncheck, binary mode).
- Fix: `verify` and `restore` refuse an `--epoch` above 4294967295 with exit 1. A larger value wrapped to a different epoch without a word.
- Warning: `verify` and `restore` with `--backup-id` warn when the named backup is from an older epoch than the newest one that authenticates, and warn again when it landed on the ledger after the first backup of the newer epoch. `init --rotate` keeps the writer account, so whoever kept the old key file can still post old-epoch backups that the recovery words authenticate. Exit codes are unchanged.
- Batch (XLS-56, amendment BatchV1_1): `backup --submit` wraps the chunks, the manifest parts and the DID anchor in one all-or-nothing Batch transaction when the server has the amendment enabled, so the ledger never holds an anchor without its manifest. Larger backups send the chunks in a Batch first, then the manifest and the anchor together. New `--batch=auto|on|off` (default auto). Verify and restore are unchanged: inner transactions keep their own hashes in `account_tx`, `tx` and the dump. The codec is pinned to a Batch that validated on Devnet.
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
