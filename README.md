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

Go 1.24 or newer. `make build` is `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -buildid="`, so two people on two machines get the same bytes.

## Optional binary + checksum verification

Prefer building from the tagged commit. Published binaries are a convenience. Compare SHA256. If hashes do not match, do not use the binary.

```
sha256sum -c SHA256SUMS
```

## Usage

```
xrplbak init                              # once, on any machine: words, key file, writer account
xrplbak redact                            # see the split; nothing is written or sent
xrplbak backup                            # dry run: plan, bundle file, attest string
xrplbak backup --submit --rpc mainnet     # writes chunks, manifest, anchor; saves dump + bundle
xrplbak verify --rpc mainnet              # find and authenticate backups
xrplbak verify --dump xrplbak-out/<id>.dump.json
xrplbak restore --rpc mainnet --bundle xrplbak-out/<id>.bundle          # to a temp dir
xrplbak restore --dump <dump> --bundle <bundle> --write --target /etc/xrpld
```

The config path is auto-detected (`/etc/xrpld/xrpld.cfg`, then the legacy rippled paths). The key file is found next to the config or in the working directory. Every flag is listed by `xrplbak <command> -h`.

Fund the writer account with at least 1.5 XRP: 1 XRP base reserve, 0.2 XRP DID reserve, and fees of about 10 drops per transaction.

## Recovery ceremony

1. Get the recovery words (or 2 of 3 shares) and the writer account address from paper.
2. Get the bundle file if you have it. Without it, restore still works, but the validator token and private topology must be re-entered.
3. On the new host, build xrplbak from the tagged source.
4. Run `xrplbak restore --rpc mainnet --bundle <file>`. Enter the words when asked. Read the report and the temp files.
5. If the report says INCOMPLETE, do the listed steps: regenerate the validator token from the master key, re-enter `[ips_fixed]` and admin lists.
6. Stop the old host if it still exists. One token, one running validator.
7. Run `xrplbak restore ... --write --target /etc/xrpld`.
8. Start xrpld. Confirm `server_info` shows the expected `pubkey_validator`.
9. Run `xrplbak init` on the new host only if the key file is gone, then take a fresh backup.

## Try it in one minute

A real Testnet backup of the fake example config ships in `examples/testnet-demo` with its recovery words. It restores offline from the dump file. See that directory's README for the two commands.

## Tested

Unit tests cover redaction refusals, chunk sizing, reassembly, truncated history, wrong key, rollback, tombstones, resume, and the HTTP client against a fake ledger. The full flow ran on XRPL Testnet on 2026-09-15 (backup, second backup superseding the first, verify, restore from server, restore from the dump file, `--write`).

## MainNet vs future amendments

v1 uses AccountSet, DIDSet, DIDDelete, account_tx, tx, and ledger_entry. All are live on MainNet (DID since 2024-10-30). Batch (BatchV1_1), DynamicMPT, and Sponsor are not enabled and are not used. MPT metadata was evaluated and rejected: 1024 immutable bytes with token semantics lose to DID's 256 mutable bytes. See [docs/mainnet-assumptions.md](docs/mainnet-assumptions.md).

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
