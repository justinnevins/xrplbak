# Trusted base

This page lists what xrplbak trusts without checking it, and what would
shrink each item. Everything else is checked: by the code at run time, by
a test, or by a fuzz target in CI.

The invariant every item serves: no input, however malformed or hostile, may
cause xrplbak to write a file whose bytes differ from what a correct backup
contained, or to report a backup as complete when it is not.

A bug in an item on this list can break that invariant without any test
failing. Work that removes an item, or narrows what the tool needs from it,
is worth more than another test that runs on top of it.

## The list

| Item | What xrplbak relies on | Why it is trusted | What would shrink it |
|---|---|---|---|
| Go standard library cryptography | AES-256-GCM, HKDF-SHA256, HMAC-SHA256, SHA-256, PBKDF2, ed25519, crypto/rand | Widely reviewed, maintained by the Go security team, no third-party code. See [crypto.md](crypto.md). | Nothing planned. Using the standard library only is the policy, not a gap. |
| The BIP39 English word list | `internal/crypto/bip39-english.txt`, embedded at build time | The published list. The code refuses to start unless it has exactly 2048 words. | A test pinning the file's SHA-256 to the published list. |
| The vendored Shamir code | `internal/crypto/shamir`, copied from HashiCorp Vault (MPL-2.0) | Reviewed, widely deployed code with no dependency graph. xrplbak also checks share bounds itself in `RootKey.Split`. | A proof that Combine(Split(s)) returns s and that fewer shares than the threshold refuse. |
| The Go compiler, runtime and linker | That the binary does what the source says | The toolchain version is pinned in `go.mod`. Releases are rebuilt from a clean clone and must reproduce `SHA256SUMS` byte for byte. | Nothing cheap. A machine-checked proof at the binary level would remove it for that claim only. |
| The model of rippled | How rippled reads a config, how Batch and memos behave, what `account_tx`, `tx` and `ledger_entry` return | The config reader is a model written from rippled's source and checked by a differential fuzz target. The Batch codec is pinned to a Batch that validated on Devnet. A daily run against Testnet exercises the rest against a real server. | More differential targets written from rippled's source, and the live run. |
| The ledger server's answers | That a server returns the transactions it has, even if it withholds some | A server can withhold history. It cannot forge an authenticated manifest or chunk, and every error names the ledger range searched. | Reading from two servers and comparing. The dump file is a second, offline source. |
| The operating system's filesystem | Temp directories, file modes, writes landing as written | Standard POSIX behaviour. Restore writes only into a fresh temp directory unless `--write` is given. | Reading every written file back and comparing its hash before reporting. |
| The fake ledger in the tests | That `internal/xrpl/fake` behaves like rippled for the calls the tests make | Kept small, and modelled on the rippled rules the code relies on. It marks every transaction it records as validated, so it never models an unvalidated one. | The live Testnet run, which does not use it. |
| The test oracles | That each test checks the right thing | Every new test is shown to fail before the fix it pins. Mutation passes check that tests fail when the code under them is broken. An oracle must not call the helper it is checking. | More mutation passes, and properties stated independently of the code. |

## What is not on the list

- **The ledger itself, for secrecy.** Everything written on-chain is
  encrypted with AES-256-GCM under per-backup keys. Anyone can read it. No
  one without the recovery words or the key file can decrypt it.
- **The writer account's keys, for authenticity.** A thief of the writer
  seed can post transactions. Manifests and chunks are authenticated with
  keys derived from the recovery key, so posted junk fails authentication.
- **A release binary.** The tagged source is the root of trust. A binary is
  checked by rebuilding it from a git clone of the tag and comparing hashes.

## Where "complete" comes from

A restored file reads `complete` only when the SHA-256 of its bytes equals
the hash in the authenticated manifest. That status is a proof object that
only the comparison can create, and it is checked again against the bytes
each time it is read. See `internal/restore/restore.go` and
`internal/restore/complete_test.go`.
