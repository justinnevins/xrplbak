# Security

## Reporting

Email the maintainer listed in the GitHub profile, or open a GitHub security advisory on this repository. Do not open a public issue for a vulnerability. Expect an acknowledgement within 7 days.

## Facts you should know before using this tool

- On-chain ciphertext is permanent. Every full-history server keeps it forever. The only defense is the key. If your recovery words leak, every backup of every epoch is readable by whoever has them. Rotate (`init` a new key, take a new backup, `--tombstone` the old account) and treat the old config as public.
- Never download an unverified binary onto a validator host. Build from the tagged commit, or verify SHA256SUMS against a build you made elsewhere.
- The host key file (`xrplbak.key`) can decrypt every backup of its epoch and can spend the writer account. Keep it 0600 and keep the account balance small.
- The tool refuses master keys and node seeds. If you see it accept one, that is a bug. Report it.
- `--submit` and `--write` are the only actions that change anything outside the output directory.

## Scope

In scope: key derivation, encryption, redaction misses, anchor or manifest forgery, restore writing where it should not, build reproducibility.

Out of scope: xrpld itself, public RPC servers, the operator's paper handling.
