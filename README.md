# xrplbak

xrplbak backs up the configuration of an XRP Ledger validator or node, and gets it back when the machine is gone.

It encrypts your `xrpld.cfg` and `validators.txt`, stores the encrypted copy on the XRP Ledger itself, and keeps the few truly private lines in a small encrypted file that you store yourself. To recover, you need the 24 words on paper, the address of the account that wrote the backup, and any XRPL server with full history (or the offline dump file the backup saved). No server of ours, no subscription, no copy of the old machine.

One static Go binary. No dependencies outside the Go standard library. No telemetry, no auto-update, and no network traffic except to the XRPL server you name.

## Why

A validator's config holds months of small decisions: peers, ports, retention, pinned validator lists, comments explaining why. When a host dies, most operators rebuild it from memory. xrplbak makes that rebuild a two-command job, and it proves the result is byte for byte what you had.

## How it works

```
your config  --redact-->  public part  --encrypt-->  XRPL ledger (memos + a DID anchor)
                          private part --encrypt-->  bundle file (you keep it)
recovery words ----------> derive every key, find every backup, decrypt, verify
```

- **Redact.** xrplbak splits the config. Settings that are safe to publish, once encrypted, go in the on-chain part. Your validator token, fixed peers, admin lists and private addresses go in the bundle only. Master keys and node seeds are refused outright.
- **Back up.** The on-chain part is encrypted with AES-256-GCM and written as transaction memos from a small account of its own, the writer account. A DID entry on that account, the anchor, points at the newest backup.
- **Restore.** From the words and the writer account, xrplbak finds every backup on the ledger, checks each one, and rebuilds the files in a temporary directory for you to inspect. It writes into `/etc/xrpld` only when you ask it to.

Without the bundle file, a restore still produces a config that boots. Every private line that lived only in the bundle is marked in place, and the tool lists what to re-enter.

## Is it for you

Use xrplbak if you run xrpld or rippled and want a recoverable, verifiable copy of its configuration.

Do not use it if:

- You want your validator master key backed up. The tool never touches it. Keep it offline, for example on an encrypted USB drive in a safe.
- You cannot keep 24 words (or 2 of 3 shares) safe. There is no reset.
- You want the ledger to hold your validator token or private topology. It never will.
- Your on-chain config is larger than 8 chunks (7680 bytes compressed) and you will not move stanzas to the bundle.

xrplbak is not a ledger-data backup (re-sync instead) and not a hosted service.

## Quick start

Build it (see [Build from source](#build-from-source)), then:

```
xrplbak init                      # 24 words, a key file, and a new writer account
```

Write the 24 words and the writer account address on paper. Fund the writer account with at least 1.5 XRP: 1 XRP base reserve, 0.2 XRP for the DID entry, and about 10 drops per transaction.

```
xrplbak redact                    # show what goes where; writes nothing
xrplbak backup                    # dry run: the plan and the bundle file, nothing sent
xrplbak backup --submit --rpc mainnet
```

Keep the bundle file (`xrplbak-out/<id>.bundle`) somewhere other than the validator. The dump file beside it lets you restore without a server.

Back up again after you change the config. Validator configs change rarely, so a manual backup after each change is the normal pattern.

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
xrplbak attest-key --validator-key <nHB...>             # once: key for public attestations
xrplbak backup --submit --rpc mainnet --attest          # attest this backup publicly
xrplbak attest-verify --rpc mainnet --account <address>  # anyone: check an attestation
```

The config path is found automatically (`/etc/xrpld/xrpld.cfg`, then the legacy rippled paths). The key file is found next to the config or in the working directory. `xrplbak <command> -h` lists every flag.

An epoch is one generation of the host key. `init --rotate` starts the next one after a compromise. The recovery words open every epoch.

## Public attestation

A validator can publish, in the clear, that it backs up its configuration. Anyone can check it with `attest-verify`, using only the writer account address. It proves which validator vouches for the account and when the latest backup landed. It does not prove the operator can still restore.

The validator master key stays in cold storage, as XRPL intends. It signs once, offline, to delegate to an attestation key that lives beside `xrplbak.key`, the same way it delegates to a validator token:

1. `xrplbak attest-key --validator-key <nHB...>` writes `xrplbak-attest.key` and prints one string.
2. On the offline machine, run `validator-keys sign "<that string>"`.
3. `xrplbak backup --submit --rpc mainnet --attest --attest-delegation-sig <hex>` publishes the delegation with that backup.

After that, `--attest` alone attests each backup. If the attestation key is stolen, run `attest-key --dseq 2` and repeat steps 2 and 3. The new delegation retires the old key from that ledger on. Attestations made before the replacement stay valid.

The tool refuses to publish an attestation that would not verify.

## Recovering a lost host

1. Get the 24 words (or 2 of 3 shares) and the writer account address from paper.
2. Get the bundle file if you have it. Without it, you re-enter the validator token and private topology by hand.
3. On the new host, build xrplbak from the tagged source. `xrplbak version` shows what a binary was built as.
4. Run a dry restore and enter the words when asked:
   `xrplbak restore --rpc mainnet --account <address> --bundle <file>`
   With the dump file and no server, use `--dump <file>` instead of `--rpc`.
5. Read the report and the files in the temporary directory. A file marked `complete` matches the original byte for byte. A file marked `PARTIAL` is missing only lines that lived in the bundle, and the report lists them. PARTIAL exits 0, so read the report, not just the exit code.
6. Stop the old host if it still exists. One validator token must run in one place.
7. Write the files: `xrplbak restore ... --write --target /etc/xrpld`
8. Start xrpld and confirm `server_info` shows the expected `pubkey_validator`.
9. Run `xrplbak init` on the new host only if the key file is gone, then take a fresh backup.

The full checklist is in [docs/restore-ceremony.md](docs/restore-ceremony.md).

Running xrpld in Docker? Run xrplbak on the host against the mounted config folder. See [docs/docker.md](docs/docker.md).

## What goes where

| Where | What |
|---|---|
| Refused, never handled | validator-keys.json, `[validation_seed]`, `[node_seed]`, wallet.db, TLS private keys |
| Bundle only, never on the ledger | `[validator_token]`, `[cluster_nodes]`, `[rpc_startup]`, admin access lists other than loopback, private addresses and internal hostnames |
| Bundle by default, on the ledger if you ask | `[ips_fixed]` (with `--peers=onchain`) |
| On the ledger, encrypted | everything else in `xrpld.cfg`, and `validators.txt` |

Details: [docs/data-classification.md](docs/data-classification.md).

### Fixed peers

`[ips_fixed]` goes in the bundle by default. If your fixed peers are public hubs you do not mind naming, put them on the ledger so a bundle-less restore keeps them:

```
xrplbak backup --submit --rpc mainnet --peers=onchain
```

The tool asks you to type an acknowledgment first. Each peer line is still checked, so a private address or an internal hostname stays in the bundle.

### Comments

A backup keeps your whole file: comments, blank lines, and the order you wrote the stanzas in. A restore with the bundle reproduces the file byte for byte.

Comments go in the bundle by default, because a comment is free text the tool cannot classify:

```
xrplbak backup                            # comments go in the off-chain bundle (default)
xrplbak backup --comments=onchain         # comments go in the on-chain ciphertext too
```

`--comments=onchain` asks you to type an acknowledgment first, because those bytes are permanent on a public ledger and anyone who ever gets the backup key can read them. In both modes the redaction scanners read every comment, so a comment holding a key, a private address or an internal hostname moves to the bundle regardless.

## Security

The short version, in ten lines:

1. The ledger is public forever. Only redacted config goes there, encrypted with AES-256-GCM under keys derived from your recovery words.
2. There is no public-key encryption anywhere, so nothing recorded today can be decrypted later by breaking a public key.
3. The host keeps only an epoch key and the writer account seed. Seizing the host reveals that host's config and that epoch's backups, nothing older or newer.
4. A stolen writer key can post junk or move the anchor. Junk fails authentication. A moved anchor is caught by scanning the account history.
5. A lying history server can hide data. It cannot forge it. Errors name the ledger range that was searched.
6. The validator token and private addresses never go on the ledger, even encrypted.
7. Master keys never enter the tool.
8. Nothing is sent or written unless you pass `--submit` or `--write`.
9. Builds are reproducible. Compare hashes, or rebuild and compare.
10. Losing the recovery words loses everything. Write them on paper.

Full threat model: [docs/threat-model.md](docs/threat-model.md). Cryptography: [docs/crypto.md](docs/crypto.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

### Quantum computers

A large quantum computer would break today's public-key signatures (ed25519, secp256k1) and weaken symmetric keys by half their bits. Here is where that leaves xrplbak.

**Your backups stay secret.** Everything that protects the content is symmetric: a 256-bit root key from the 24 words, HKDF-SHA256, AES-256-GCM and HMAC-SHA256. Against a quantum computer these still hold about 128 bits of security, which is considered safe. The share split is Shamir secret sharing: fewer shares than the threshold reveal nothing, whatever the computer. Ciphertext written to the ledger today stays unreadable.

**Your backups stay authentic.** Every chunk, manifest and bundle is checked with a symmetric authentication tag, so a quantum attacker cannot forge a backup that restores.

**Two parts are not quantum-safe:**

- **The writer account.** Like every XRPL account today, it signs with ed25519. A quantum attacker could forge its transactions: post junk, move or delete the anchor, or spend its small balance. That is the same power as a stolen writer key. It cannot read or forge a backup. When the XRP Ledger offers post-quantum accounts, move the writer account to one.
- **Public attestation.** An attestation is signed with ed25519, by an attestation key that the validator's ed25519 master key delegates to. A quantum attacker could forge either, so attestations lose their proof value once such machines exist. An attestation can never be stronger than the validator key behind it. The attestation format is versioned, and xrplbak builds with Go 1.27, whose standard library includes ML-DSA (FIPS 204), so a post-quantum attestation needs no new dependency once XRPL validator keys support it.

The connection to your XRPL server uses TLS, which is not yet post-quantum either. It carries only data that is already encrypted.

As of September 2026, the XRP Ledger has no post-quantum signatures on mainnet. Ripple's published plan targets full readiness by 2028, and ML-DSA signatures are being tested on AlphaNet. See [Post-Quantum Readiness on the XRP Ledger](https://ripple.com/insights/post-quantum-readiness-on-the-xrp-ledger/).

## Build from source

The source at a tagged commit is the root of trust. Binaries are a convenience.

```
git clone https://github.com/justinnevins/xrplbak
cd xrplbak
git checkout v1.0.0
make build
sha256sum bin/*
```

Go 1.27.1, the version named in `go.mod`. An older `go` command downloads it automatically. `make build` is `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -buildid="`, so two people on two machines with the same Go version get the same bytes.

Build from a git clone with the tag checked out, not from a source zip. Go stamps the commit hash into the binary, so a tree without `.git` produces different bytes and will not match the published checksums. v1.0.0 was reproduced this way on a second machine, byte for byte.

To use a published binary instead, check it against the release checksums first. If a hash does not match, do not use the binary.

```
sha256sum -c SHA256SUMS
```

## Try it in one minute

A real Testnet backup of a fake example config ships in `examples/testnet-demo`, with its recovery words. It restores offline from the dump file. That directory's README has the two commands.

## Reference

### Exit codes

Scripts branch on the code. People read the message.

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

### Batch: one transaction, or none

`backup --submit` checks whether the server has the Batch amendment (XLS-56). When it does, the chunks, the manifest and the anchor go out in one all-or-nothing Batch transaction, so the ledger never holds an anchor without the manifest it names. Up to eight transactions fit in a Batch. A backup that needs more sends its chunks in one Batch first, then the manifest and the anchor together. The fee is the per-transaction rate times the number of transactions plus two. `--max-fee` still caps the rate.

```
xrplbak backup --submit --rpc mainnet               # batched when the server offers it
xrplbak backup --submit --rpc mainnet --batch=off   # one transaction at a time
xrplbak backup --submit --rpc mainnet --batch=on    # refuse to run without Batch
```

Inside a Batch each inner transaction keeps its own hash and its own place in `account_tx`, so verify and restore read a batched backup exactly like an older one. A batched manifest records ledger 0 for a chunk that landed beside it, and a batched anchor records manifest ledger 0. Those numbers are informational.

### Ledger features used

v1 uses AccountSet, DIDSet, DIDDelete, account_tx, tx, ledger_entry, and feature. All are live on MainNet (DID since 2024-10-30). Batch (BatchV1_1) is used wherever the server reports it enabled and skipped everywhere else. It reached majority on MainNet on 2026-09-15 and is live on Devnet. MPT metadata was evaluated and rejected: 1024 immutable bytes with token semantics lose to DID's 256 mutable bytes. See [docs/mainnet-assumptions.md](docs/mainnet-assumptions.md).

### Tested

Unit tests cover redaction refusals, chunk sizing, reassembly, truncated history, wrong keys, rollback, tombstones, resume, and the HTTP client against a fake ledger. An adversarial corpus (`cmd/xrplbak/corpus_test.go`) drives 38 hostile inputs through the real command surface and checks the exit code of each refusal. Fuzz targets run in CI, as do govulncheck, gosec, CodeQL and OpenSSF Scorecard. The full flow ran on XRPL Testnet on 2026-09-15, and a full backup and restore runs against Devnet every day.

### Primary references

- Memos and the 1 KB serialized limit: https://xrpl.org/docs/references/protocol/transactions/common-fields
- DID: https://xrpl.org/docs/references/protocol/ledger-data/ledger-entry-types/did
- Backing up a validator: https://github.com/XRPLF/rippled/wiki/Back-up-a-validator-(also-for-migrating-a-validator-to-a-new-machine)
- Validator keys and tokens: https://xrpl.org/docs/infrastructure/configuration/server-modes/run-rippled-as-a-validator
- xrpld migration paths: https://xrpl.org/docs/infrastructure/installation/migrate-to-xrpld
- Amendment status: https://xrpl.org/resources/known-amendments

License: MIT. The Shamir code in `internal/crypto/shamir` is from HashiCorp Vault under MPL-2.0 (see NOTICE).
