# Restore ceremony

Print this. Keep it with the recovery words.

## You need

- The 24 recovery words, or 2 of the 3 shares.
- The writer account address (r...).
- One of: a server with history (`--rpc mainnet` works for recent backups; older ones need a full-history server), or the dump file `<id>.dump.json`.
- The bundle file `<id>.bundle` if you have it.
- xrplbak built from the tagged source on the new host.

## Steps

1. Build: `git clone https://github.com/justinnevins/xrplbak && cd xrplbak && git checkout v1.0.0 && make build`.
2. Dry run: `bin/xrplbak-linux-amd64 restore --rpc mainnet --bundle /path/to/<id>.bundle`. Enter the words when asked. Without a key file the tool asks for the account address too.
3. Read the Discovery block. The starred line is the backup that will be restored. A WARNING about rollback means someone moved the anchor; the tool already picked the newest authenticated backup.
4. Read the Files block. `complete` means the bytes match the original. `PARTIAL` means content is missing from the file (the bundle was missing or only partly present); the "Before starting the server" list says what to re-enter.
5. Look at the temp directory it printed. Compare with what you expect.
6. If the old host still exists, stop xrpld there. One validator token must run in one place.
7. Write: add `--write --target /etc/xrpld` (or the legacy path). Add `--force` only if you mean to overwrite.
8. If the validator token was not restored, run `validator-keys create_token` with the offline master key, add `[validator_token]`, and update the offline key file's backup.
9. `chown` the files to the xrpld user, `chmod 0600` the config, start xrpld, check `server_info`.
10. Take a fresh backup from the new host.

## If something fails

- "no backup authenticates": wrong words, wrong account, or wrong epoch. Try `--epoch N` if you rotated.
- "chunk k of n missing ... searched ledgers A to B": the server lacks history. Use a full-history server or the dump file.
- "bundle belongs to backup X": you have a bundle from another run. Find the one whose id matches the starred backup.
