# Off-host copy scripts (optional)

After a backup, the bundle file and the dump file have to be copied off the validator, and each copy checked. These scripts do that in one step from your own computer.

They are a convenience. They are not part of the xrplbak binary and are not covered by its release checksums. Read the one you use before you run it: each is one short file.

| File | For |
|---|---|
| `Pull-XrplbakBackup.ps1` and `.cmd` | Windows, with PuTTY (plink) or OpenSSH |
| `pull-xrplbak-backup.sh` | macOS and Linux, with ssh |

What a script does:

1. Runs `xrplbak export` on the validator over SSH. Nothing else runs there.
2. Refuses an answer that was cut off, or that holds any name that is not a backup file.
3. Checks every file against the SHA-256 sums the validator computed.
4. Copies the files to one or two folders and checks each copy.
5. Never overwrites: a file that exists with other content stops the run.

Setup on the validator (one sudo rule), settings, and how to undo it: [docs/off-host-copies.md](../../docs/off-host-copies.md).

The copies need no secrecy of their own. The bundle is encrypted with the recovery key, and the dump holds only what is already on the public ledger.

Tests: `sh contrib/off-host-copy/test/run.sh /path/to/xrplbak` runs both scripts against a fake connection. CI runs it on Linux with PowerShell 7 and on Windows with Windows PowerShell 5.
