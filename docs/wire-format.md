# Wire format v1

All integers big-endian. Every format carries a version byte. Changing any layout is a version bump.

## Keys

```
Salt = "xrplbak/v1"
K_e      = HKDF-SHA256(RRK,  Salt, "epoch"  || u32 epoch)
K_b      = HKDF-SHA256(K_e,  Salt, "backup" || backup_id)
K_bundle = HKDF-SHA256(K_e,  Salt, "bundle" || backup_id)
K_anchor = HKDF-SHA256(K_e,  Salt, "anchor")
backup_id = HMAC-SHA256(K_e, onchain_packed || bundle_packed || u32 epoch || u32 seq)[0:16]
```

RRK is 32 random bytes shown as 24 BIP39 words or split with Shamir over GF(2^8). Each share is `u8 threshold | split_id(2) | 33 Shamir bytes | sha256(prefix)[0:2]`, Crockford base32 in groups of 7. Combine refuses too few shares or shares from different splits.

## Container (XBC1)

```
"XBC1" | u32 count | entries (sorted by path)
entry: u16 pathLen | path | u32 mode | u64 size | sha256(32) | data
```
Then deflate level 9, then pad to a multiple of 960 bytes with the pad length in the last two bytes.

## AEAD

AES-256-GCM. Chunk and bundle nonces are counters: their keys are unique per backup_id, and backup_id commits to their plaintext, so a repeated (key, nonce) implies an identical message. The manifest is not committed by backup_id (it holds tx hashes and a timestamp), so each sealing run draws a random 10-byte nonce prefix that travels in the memo header; a resumed run reuses the manifest already on the ledger instead of sealing again.

| Object | Key | Nonce | AAD |
|---|---|---|---|
| chunk i of n | K_b | u32 i, zero padded | "xrplbak/v1/chunk" \| backup_id \| u16 i \| u16 n |
| manifest part i of n | K_b | random(10) \| u16 i | "xrplbak/v1/manifest" \| backup_id \| u16 i \| u16 n |
| bundle frame i | K_bundle | u32 i \| 7 zero \| u8 final | "xrplbak/v1/bundle" \| backup_id |

Bundle stream: `"XBK1" | backup_id(16) | frames`, frame = `u32 len | ciphertext`. Frames hold 64 KiB of plaintext. The final flag in the nonce makes truncation fail.

## Memos

AccountSet with no fields carries one memo. MemoType is `xrplbak/v1/c` (chunk) or `xrplbak/v1/m` (manifest). No MemoFormat.

```
chunk:    MemoData = u8 1 | backup_id(16) | u16 index | u16 total | ciphertext
manifest: MemoData = u8 1 | backup_id(16) | u16 index | u16 total | nonce(10) | ciphertext
```
Chunk plaintext is 960 bytes, ciphertext 976, MemoData 997, serialized Memos 1018 bytes (limit 1024). At most 8 chunks per backup. Manifest parts hold 944 plaintext bytes (MemoData at most 991). Discovery groups manifest parts by (backup_id, nonce) and keeps every ciphertext seen per index, so junk posted with a stolen writer key cannot shadow a real part.

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

The validator master key signs the ASCII string `xrplbak/v1/attest <backup_id> <onchain plain_sha256> <bundle plain_sha256>`. v1 verifies ed25519 keys only.

The signed bytes were confirmed against source on 2026-09-15:

- `validator-keys sign <data>` calls `strHex(xrpl::sign(publicKey, secretKey, makeSlice(data)))` (ripple/validator-keys-tool `src/ValidatorKeys.cpp`, `ValidatorKeys::sign`). The argument is signed as its raw bytes. It is not hex-decoded first. The output is hex.
- `xrpl::sign` signs the message bytes directly for `KeyType::Ed25519`: no domain prefix, no pre-hash (XRPLF/rippled `src/libxrpl/protocol/SecretKey.cpp`). Only the `Secp256k1` branch takes SHA-512Half first.
- `create_keys` always builds master keys with `KeyType::Ed25519` (ripple/validator-keys-tool `src/ValidatorKeysTool.cpp`, `createKeyFile`), so a key file from any current version verifies here.

So verification is raw ed25519 over the ASCII attest string. `internal/xrpl/sign/vectors_test.go` pins this with a deterministic signature and asserts that the SHA-512Half variant does not verify. Key derivation is pinned against rippled's own 95 ed25519 test vectors in `tests/fixtures/rippled-ed25519-vectors.json`.
