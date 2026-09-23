# Threat model

## Assets

| Asset | Class | Where it may live |
|---|---|---|
| validator-keys.json secret, [validation_seed], [node_seed], wallet.db, TLS private keys | C0 | Nowhere. The tool refuses them. |
| [validator_token], [validator_key_revocation] | C1 | Off-chain bundle only |
| [ips_fixed], [cluster_nodes], [rpc_startup], [ssl_cert], [peer_private], admin and secure_gateway lines, private addresses, --include files | C2 | Off-chain bundle only |
| Remaining xrpld.cfg stanzas, validators.txt | C3 | On-chain ciphertext and bundle |
| Validator public key, writer account | C4 | Public. The validator key is stored only as a SHA-256 inside ciphertext. |

## Adversaries

| Adversary | What they get | What stops them |
|---|---|---|
| Anyone reading the ledger forever | Ciphertext, chunk count, timing, the writer account | AES-256-GCM under per-backup keys. No public-key encryption, so no harvest-now-decrypt-later. |
| Holder of the operator's hot wallet | Nothing. The writer account is separate. | |
| Thief of the writer key or the host key file | Can post junk, move or delete the anchor, decrypt that epoch's backups, spend the small balance | Junk fails authentication and cannot shadow real parts (every ciphertext per index is tried). A moved anchor triggers a rollback warning. Rotate the epoch with `init --rotate`. |
| Lying or partial history server | Can withhold | Every error names the searched range. Verify against a second source or the dump. |
| Disk seizure of the validator | That host's config, that epoch's backups | Same data the host already had. Nothing from other epochs. |
| Future quantum computer | Forged writer account signatures (post junk, move or delete the anchor, spend the balance) and forged public attestations, both ed25519 | Backup secrecy and authenticity are symmetric only (AES-256-GCM, HMAC-SHA256, 256-bit root key), about 128-bit security against Grover. Move the writer account to a post-quantum key when the XRP Ledger offers one. |
| Malicious release binary | Everything | Reproducible build, SHA256SUMS in CI, README trust policy, no update channel. |
| Operator at 3am | Wrong account, wrong words, overwrite | BIP39 and share checksums, dry runs by default, refusal to overwrite without --force. |

## Properties

- Confidentiality on-chain: C3 only, encrypted, padded to 960-byte blocks.
- Integrity and authenticity: AEAD tags under keys only the operator can derive, plus the ledger's own signatures on every transaction, plus an HMAC on the DID anchor.
- Availability: on-chain chunks plus a dump file plus a bundle file. Any full-history server or the dump restores C3. The bundle restores C1/C2.
- Rotation: `xrplbak init --rotate` derives the next epoch key from the recovery words and rewrites the key file. Old epochs stay readable to whoever held the old key, which is data they already had. Restores with the words find every epoch.
- Least privilege: the host never holds the recovery root key or the validator master key.

## Non-goals

Not a master-key vault. Not a hosted service. Not a protocol change. Not a ledger-data backup.
