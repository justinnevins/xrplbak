# Wire format v1

All integers big-endian. Every format carries a version byte. Changing any layout is a version bump.

## Keys

```
Salt = "xrplbak/v1"
K_e      = HKDF-SHA256(RRK,  Salt, "epoch"  || u32 epoch)
K_b      = HKDF-SHA256(K_e,  Salt, "backup" || backup_id)
K_bundle = HKDF-SHA256(K_e,  Salt, "bundle" || backup_id)
K_anchor = HKDF-SHA256(K_e,  Salt, "anchor")
backup_id = SHA-256(onchain_packed || bundle_packed || u32 epoch || u32 seq)[0:16]
```

RRK is 32 random bytes shown as 24 BIP39 words or split with Shamir over GF(2^8) (33-byte shares, 2-byte SHA-256 checksum, Crockford base32 in groups of 7).

## Container (XBC1)

```
"XBC1" | u32 count | entries (sorted by path)
entry: u16 pathLen | path | u32 mode | u64 size | sha256(32) | data
```
Then deflate level 9, then pad to a multiple of 960 bytes with the pad length in the last two bytes.

## AEAD

AES-256-GCM. 12-byte nonces are counters. Keys are unique per backup_id, and backup_id commits to the plaintext, so a repeated (key, nonce) implies an identical message.

| Object | Key | Nonce | AAD |
|---|---|---|---|
| chunk i of n | K_b | u32 i, zero padded | "xrplbak/v1/chunk" \| backup_id \| u16 i \| u16 n |
| manifest part i of n | K_b | u32 (0xFFFFFFFF - i) | "xrplbak/v1/manifest" \| backup_id \| u16 i \| u16 n |
| bundle frame i | K_bundle | u32 i \| 7 zero \| u8 final | "xrplbak/v1/bundle" \| backup_id |

Bundle stream: `"XBK1" | backup_id(16) | frames`, frame = `u32 len | ciphertext`. Frames hold 64 KiB of plaintext. The final flag in the nonce makes truncation fail.

## Memos

AccountSet with no fields carries one memo. MemoType is `xrplbak/v1/c` (chunk) or `xrplbak/v1/m` (manifest). No MemoFormat.

```
MemoData = u8 1 | backup_id(16) | u16 index | u16 total | ciphertext
```
Chunk plaintext is 960 bytes, ciphertext 976, MemoData 997, serialized Memos 1018 bytes (limit 1024). At most 8 chunks per backup.

## Manifest (plaintext JSON, sorted keys, no whitespace)

See `internal/manifest`. Fields: v, epoch, seq, backup_id, created, tool, node{role, vpk_sha256, server_version}, onchain{plain_sha256, plain_len, chunks[{i, tx, ledger, sha256}]}, bundle{plain_sha256, cipher_sha256, len}, files[{path, mode, sha256, where}], redactions[{stanza, lines, to}], supersedes, tombstone, attestation{scheme, vpk, sig}.

## DID anchor (77 bytes in DIDSet Data)

```
u8 1 | backup_id(16) | manifest_tx_hash(32) | u32 manifest_ledger | u32 epoch | u32 seq | HMAC-SHA256(K_anchor, preceding bytes)[0:16]
```

## Key file (XBKK, 77 bytes)

```
"XBKK" | u8 1 | u32 epoch | K_e(32) | account_id(20) | writer_seed(16)
```
Optional wrap: `"XBKW" | u8 1 | salt(16) | AES-256-GCM(PBKDF2-HMAC-SHA256(passphrase, salt, 600000), zero nonce, plain, AAD "xrplbak/v1/keyfile")`.

## Attestation

The validator master key signs the ASCII string `xrplbak/v1/attest <backup_id> <onchain plain_sha256> <bundle plain_sha256>`. v1 verifies ed25519 keys only. The exact bytes signed by `validator-keys sign` must be confirmed against a live vector before relying on this.
