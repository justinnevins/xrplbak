# xrplbak

Back up and restore xrpld / rippled configuration with the XRP Ledger as the integrity anchor and discovery log. One static Go binary. No dependencies outside the Go standard library.

## What this is

- `redact` splits your config into what may go on-chain (encrypted) and what stays off-chain (encrypted bundle). It refuses master keys and node seeds.
- `backup` encrypts the on-chain part into memo chunks, writes an encrypted manifest, and points a DID entry at it. It writes the bundle and an offline dump file next to it. Dry run by default.
- `verify` finds every backup for your account, authenticates each one, and reports the latest.
- `restore` rebuilds the files into a temp dir and tells you what to check. It writes into a live directory only with `--write --target`.

Recovery needs three things: the 24 recovery words (or 2 of 3 shares), the writer account address, and either a server with history or the dump file. The bundle file adds back the validator token and private topology.

## What this is not

- Not a vault for validator master keys, node seeds, wallet.db, or TLS keys. The tool refuses them.
- Not a ledger-data backup. Re-sync instead.
- Not a hosted service. No telemetry, no auto-update, no network except the `--rpc` server you name.

## Threat model in 10 lines

1. The ledger is public forever. Only redacted config goes there, as AES-256-GCM ciphertext under keys derived from your recovery key.
2. No public-key encryption anywhere, so harvest-now-decrypt-later and quantum attacks buy nothing.
3. The host keeps only an epoch key and the writer account seed. Seizing the host reveals that host's config and its epoch's backups, nothing older or newer.
4. A stolen writer key can post junk or move the anchor. Junk fails authentication. Anchor rollback is detected by scanning history.
5. A lying history server can withhold data. It cannot forge it. Errors name the searched ledger range.
6. Validator tokens and private addresses never go on-chain, even encrypted.
7. Master keys never enter the tool.
8. Every write is a dry run unless you say `--submit` or `--write`.
9. Builds are reproducible. Compare hashes or rebuild.
10. Losing the recovery words loses everything. Write them on paper.

Full text: [docs/threat-model.md](docs/threat-model.md).

## What never goes on-chain

validator-keys.json, `[validation_seed]`, `[node_seed]`, wallet.db, TLS private keys (refused outright). `[validator_token]`, `[ips_fixed]`, `[cluster_nodes]`, admin access lists, private addresses, `[rpc_startup]` (bundle only). See [docs/data-classification.md](docs/data-classification.md).

## Build from source (canonical)

```
git clone https://github.com/justinnevins/xrplbak
cd xrplbak
git checkout v1.0.0
make build
sha256sum bin/*
```

Go 1.27.1, the version named in `go.mod`. An older `go` command downloads it automatically. `make build` is `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -buildid="`, so two people on two machines with the same Go version get the same bytes.

Build from a git clone with the tag checked out, not from a source zip or tarball. Go stamps the commit hash and the module version into the binary, so a tree without `.git` produces different bytes and will not match the published checksums. v1.0.0 was reproduced this way on a second machine, byte for byte.

## Optional binary + checksum verification

Prefer building from the tagged commit. Published binaries are a convenience. Compare SHA256. If hashes do not match, do not use the binary.

```
sha256sum -c SHA256SUMS
```

## Usage

```
xrplbak init                              # once, on any machine: words, key file, writer account
xrplbak init --rotate                     # after a host compromise: next epoch key from the words
xrplbak redact                            # see the split; nothing is written or sent
xrplbak backup                            # dry run: plan, bundle file, attest string
xrplbak backup --submit --rpc mainnet     # writes chunks, manifest, anchor; saves dump + bundle
xrplbak verify --rpc mainnet              # find and authenticate backups
xrplbak verify --dump xrplbak-out/<id>.dump.json
xrplbak restore --rpc mainnet --bundle xrplbak-out/<id>.bundle          # to a temp dir
xrplbak restore --dump <dump> --bundle <bundle> --write --target /etc/xrpld
xrplbak restore --rpc mainnet --account <address> --words-file words.txt  # fresh host: no key file
```

The config path is auto-detected (`/etc/xrpld/xrpld.cfg`, then the legacy rippled paths). The key file is found next to the config or in the working directory. Every flag is listed by `xrplbak <command> -h`.

### What a backup contains

Your file, all of it. Comments, blank lines and the order you wrote the stanzas in are part of the backup, and a restore with the bundle reproduces the file byte for byte. rippled ignores comments; the person who has to read the config in two years does not.

Where your comments go is the one choice you have about them:

```
xrplbak backup                            # comments go in the off-chain bundle (default)
xrplbak backup --comments=onchain         # comments go in the on-chain ciphertext too
```

The default keeps them off the ledger because a comment is free text the tool cannot classify. `--comments=onchain` asks you to type an acknowledgment first, because those bytes are public and permanent and anyone who ever obtains the backup key can read them. Either way the comments are kept, and either way the redaction scanners read them: a comment holding a key, a private address or an internal hostname moves to the bundle whichever mode you pick.

A restore without the bundle still boots. Every line that moved leaves a `# xrplbak:` marker in its place, so the gaps are visible in the file rather than silently absent.

Fund the writer account with at least 1.5 XRP: 1 XRP base reserve, 0.2 XRP DID reserve, and fees of about 10 drops per transaction.

### Exit codes

Scripts branch on the code. Humans read the message.

| Code | Meaning |
|---|---|
| 0 | done |
| 1 | usage: bad flags, unreadable input file, or the operator cancelled at a prompt. `backup --submit` and `restore --write` ask before acting; pass `--yes` to answer up front in a script |
| 2 | network: the XRPL server could not be read |
| 3 | refused: the input holds something the tool will not handle (a seed, PEM material, a restore marker, an unsafe path in a backup) |
| 4 | authentication: nothing authenticates with this key, a chunk, manifest, bundle, or share fails its check, or two different backups claim the same seq |
| 5 | incomplete: a chunk is missing from the searched history, or the newest backup is a tombstone. A restore that is only missing bundle content is PARTIAL, not incomplete, and exits 0 |
| 6 | write: `--write` refused (file exists, two files share a name, target under /var/lib) or failed |

When two different backups authenticate at the same epoch and seq, verify and restore refuse to pick one. Name the backup with `--backup-id <hex prefix>` after checking who else holds the writer key.

## Recovery ceremony

1. Get the recovery words (or 2 of 3 shares) and the writer account address from paper.
2. Get the bundle file if you have it. Without it, restore still works, but the validator token and private topology must be re-entered.
3. On the new host, build xrplbak from the tagged source. `xrplbak version` prints what a binary was built as; `dev` means an unstamped local build.
4. Run `xrplbak restore --rpc mainnet --account <address> --bundle <file>`, or with `--dump <file>` in place of `--rpc` when you have the dump file and no server. Enter the words when asked. Read the report and the temp files.
5. If the report marks a file PARTIAL, do the listed steps: regenerate the validator token from the master key, re-enter `[ips_fixed]` and admin lists. PARTIAL means content that lived only in the bundle is missing from the file; the backup is not damaged. A bundle-less restore is the expected case and it exits 0, so do not read exit 0 as "nothing missing": read the PARTIAL lines and the steps. Exit code 5 is a different case, a chunk missing from the ledger or a tombstone, covered in the exit-code table above.
6. Stop the old host if it still exists. One token, one running validator.
7. Run `xrplbak restore ... --write --target /etc/xrpld`.
8. Start xrpld. Confirm `server_info` shows the expected `pubkey_validator`.
9. Run `xrplbak init` on the new host only if the key file is gone, then take a fresh backup.

## Try it in one minute

A real Testnet backup of the fake example config ships in `examples/testnet-demo` with its recovery words. It restores offline from the dump file. See that directory's README for the two commands.

## Tested

Unit tests cover redaction refusals, chunk sizing, reassembly, truncated history, wrong key, rollback, tombstones, resume, and the HTTP client against a fake ledger. An adversarial corpus (`cmd/xrplbak/corpus_test.go`) drives 38 hostile inputs through the real command surface and asserts the exit code of each refusal: flipped ciphertext per layer, missing, swapped, and foreign chunks, forged and mislabelled anchors, duplicate seq, tombstones, `--write` collisions, hostile manifest paths, damaged dump files, wrong words and corrupt shares. Fuzz targets run in CI. The full flow ran on XRPL Testnet on 2026-09-15 (backup, second backup superseding the first, verify, restore from server, restore from the dump file, `--write`).

## MainNet vs future amendments

v1 uses AccountSet, DIDSet, DIDDelete, account_tx, tx, ledger_entry, and feature. All are live on MainNet (DID since 2024-10-30). Batch (BatchV1_1, XLS-56) is used wherever the server reports it enabled and skipped everywhere else; it reached majority on MainNet on 2026-09-15 and is live on Devnet. DynamicMPT and Sponsor are not used. MPT metadata was evaluated and rejected: 1024 immutable bytes with token semantics lose to DID's 256 mutable bytes. See [docs/mainnet-assumptions.md](docs/mainnet-assumptions.md).

### Batch: one transaction, or none

`backup --submit` checks whether the server has the Batch amendment. When it does, the chunks, the manifest parts and the DID anchor go out inside one all-or-nothing Batch transaction, so the ledger never holds an anchor without the manifest it names, or half a manifest. Up to eight transactions fit in a Batch; a backup that needs more sends its chunks in one Batch first, then the manifest and the anchor together. The fee is the per-transaction rate times the number of transactions plus two. `--max-fee` still caps the rate.

```
xrplbak backup --submit --rpc mainnet               # batched when the server offers it
xrplbak backup --submit --rpc mainnet --batch=off   # one transaction at a time
xrplbak backup --submit --rpc mainnet --batch=on    # refuse to run without Batch
```

Inside a Batch each inner transaction keeps its own hash and its own place in `account_tx`, so verify and restore read a batched backup exactly as they read an older one, from a server or from a dump file. A batched manifest records ledger 0 for a chunk that landed beside it, and a batched anchor records manifest ledger 0; those numbers are informational.

## Do not use this if

- You want your validator master key backed up. Use an encrypted USB in a safe.
- You cannot keep 24 words or 2 of 3 shares safe. There is no reset.
- You expect the ledger to hold your private topology or tokens. It never will.
- You run a config larger than 8 chunks (7680 bytes compressed) on-chain and will not move stanzas to the bundle.

## Primary references

- Memos and the 1 KB serialized limit: https://xrpl.org/docs/references/protocol/transactions/common-fields
- DID: https://xrpl.org/docs/references/protocol/ledger-data/ledger-entry-types/did
- Backing up a validator: https://github.com/XRPLF/rippled/wiki/Back-up-a-validator-(also-for-migrating-a-validator-to-a-new-machine)
- Validator keys and tokens: https://xrpl.org/docs/infrastructure/configuration/server-modes/run-rippled-as-a-validator
- xrpld migration paths: https://xrpl.org/docs/infrastructure/installation/migrate-to-xrpld
- Amendment status: https://xrpl.org/resources/known-amendments

License: MIT. The Shamir code in `internal/crypto/shamir` is from HashiCorp Vault under MPL-2.0 (see NOTICE).
