# MainNet assumptions (checked 2026-09-14)

v1 depends on these being true. Verify with the `feature` admin RPC or https://xrpscan.com/amendments before trusting a release.

| Primitive | Used for | Status |
|---|---|---|
| AccountSet with Memos | chunk and manifest carrier | Core protocol |
| Memos serialized limit 1024 bytes | chunk sizing | Core protocol (rippled STTx.cpp) |
| DIDSet / DIDDelete, Data field 256 bytes | anchor | DID amendment enabled 2024-10-30 |
| account_tx, tx, ledger_entry(did), account_info, server_info, fee | discovery and submit | Public API |
| Base fee 10 drops, base reserve 1 XRP, owner reserve 0.2 XRP | cost estimates | Fee voting can change these |

Not used, and gated out of v1:

- BatchV1_1 (open for voting, not enabled): would let chunks, manifest, and anchor land atomically. If enabled, a later version can add it behind a flag.
- DynamicMPT, MPT metadata: rejected. 1024 immutable bytes with token semantics lose to DID.
- Sponsor: not enabled. Could pay the writer account's reserve later.

History facts that shape the design: default servers keep about 15 minutes of ledgers. Full history is about 39 TB. `account_tx` reports the range it searched; the tool prints it in every error.
