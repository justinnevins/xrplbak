# MainNet assumptions (checked 2026-09-14)

v1 depends on these being true. Verify with the `feature` admin RPC or https://xrpscan.com/amendments before trusting a release.

| Primitive | Used for | Status |
|---|---|---|
| AccountSet with Memos | chunk and manifest carrier | Core protocol |
| Memos serialized limit 1024 bytes | chunk sizing | Core protocol (rippled STTx.cpp) |
| DIDSet / DIDDelete, Data field 256 bytes | anchor | DID amendment enabled 2024-10-30 |
| account_tx, tx, ledger_entry(did), account_info, server_info, fee | discovery and submit | Public API |
| Base fee 10 drops, base reserve 1 XRP, owner reserve 0.2 XRP | cost estimates | Fee voting can change these |

Used when the server offers it:

- BatchV1_1 (XLS-56). Reached majority on MainNet 2026-09-15 14:06 UTC (activation two weeks later if the votes hold); enabled on Devnet, not yet on Testnet as of 2026-09-17. `backup --submit` asks the `feature` RPC for amendment `9F287AED3CDB50A7BD1ACEC24296A30C9B5230CCD136219317AC790E3B884377` and wraps the backup in a tfAllOrNothing Batch when it is enabled. Rules the tool relies on, read from rippled `Batch.cpp` and proven against Devnet: 2 to 8 inner transactions; each inner transaction carries tfInnerBatchTxn (0x40000000), a zero fee, an empty SigningPubKey and no signature; inner sequences are the outer sequence plus 1, 2, ...; the fee is base * (n + 2) plus nothing for a single signer; every inner transaction lands in `account_tx` under its own hash with `ParentBatchID` in its metadata. A rejected amendment costs nothing: `--batch=auto` falls back to one transaction at a time.

Not used, and gated out of v1:
- DynamicMPT, MPT metadata: rejected. 1024 immutable bytes with token semantics lose to DID.
- Sponsor: not enabled. Could pay the writer account's reserve later.

History facts that shape the design: default servers keep about 15 minutes of ledgers. Full history is about 39 TB. `account_tx` reports the range it searched; the tool prints it in every error.
