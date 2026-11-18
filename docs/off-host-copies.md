# Off-host copies

After every backup, two files must leave the validator: the bundle and the dump. This page shows how to copy and check them in one step from your own computer.

`backup --submit` writes both files into its `--out` folder and prints their SHA-256. The bundle is the only copy of what stays off the ledger, the validator token among it. If the host dies with it, you re-enter that content by hand. The dump lets you restore without a server.

## Summary

1. Once, on the validator: add one sudo rule (below). Skip this if your login user can already read the backup folder.
2. Once, on your computer: put your SSH target and your folders at the top of the script in [`contrib/off-host-copy`](../contrib/off-host-copy).
3. After each backup: run the script. It ends with `PASS` or `FAIL`.

## The export command

`xrplbak export --out DIR` prints every backup file in DIR as one archive. It only reads.

The output is text on stdout: a `XRPLBAK-EXPORT-BEGIN` line, a base64 tar.gz, and a `XRPLBAK-EXPORT-END` line. The archive holds each `<id>.bundle` and `<id>.dump.json` and a `SHA256SUMS` file over them. Text survives a terminal and a PowerShell pipe, which damage binary output. An answer with no END line was cut off.

The command refuses the whole folder, and prints nothing, when the folder holds anything that is not a backup file:

- a symlink, or the folder itself being a symlink
- any other name: a key file, a settings file, a note, a subfolder
- a `<id>.dump.json.tmp` file, which an interrupted backup leaves behind

| Exit code | Meaning |
|---|---|
| 0 | the archive was printed |
| 1 | usage: no `--out`, an extra argument, or `--out` names a file |
| 3 | refused: the folder holds something that is not a backup file. The message names it |
| 5 | incomplete: the folder is empty or does not exist. No backup has been written there |

## Setup on the validator

One sudo rule lets your login user run that one command as root, and nothing else. You need it when the backup folder belongs to root, which is the case when you run `xrplbak backup` in a root shell.

Open a root shell with `sudo -i`, check that `echo "$SUDO_USER"` prints your login name, then run:

```
printf '%s ALL=(root) NOPASSWD: /usr/local/bin/xrplbak export --out /root/xrplbak/xrplbak-out\n' "$SUDO_USER" > /etc/sudoers.d/xrplbak-export
chmod 0440 /etc/sudoers.d/xrplbak-export
visudo -cf /etc/sudoers.d/xrplbak-export || rm -f /etc/sudoers.d/xrplbak-export
```

The last line must print `parsed OK`. If it does not, the rule is removed and nothing changed.

Change the two paths to match your host: where the binary is, and the `--out` folder your backups use. Both must be full paths. The command in the script on your computer must use the same words.

What the rule allows:

- That exact command with those exact arguments. sudo compares every argument, so another folder, an extra word or another xrplbak command still asks for a password. This was tested with sudo 1.9.15.
- Nothing that writes. `export` opens files for reading only.

What you must keep true:

- `/usr/local/bin/xrplbak` belongs to root and only root can write it (`root:root`, mode 0755). Whoever can replace that file can run anything as root through the rule.
- The backup folder holds backup files only. `export` refuses anything else, so a stray file stops the copy until you move it.

Test it as your normal user:

```
sudo -n /usr/local/bin/xrplbak export --out /root/xrplbak/xrplbak-out | head -2
```

Expect `XRPLBAK-EXPORT-BEGIN` and one line of base64.

To undo the setup: `sudo rm /etc/sudoers.d/xrplbak-export`.

## The scripts

The scripts in [`contrib/off-host-copy`](../contrib/off-host-copy) run the export over SSH, check the files and copy them. They are optional, they are not part of the binary, and the release checksums do not cover them. Each is one short file. Read the one you use.

| Computer | File | Needs |
|---|---|---|
| Windows | `Pull-XrplbakBackup.cmd` (double-click) and `Pull-XrplbakBackup.ps1` | PuTTY with a saved session, or OpenSSH |
| macOS, Linux | `pull-xrplbak-backup.sh` | ssh |

Settings are at the top of each script: how to reach the validator, the remote command, the folder for the copies, and an optional second folder such as a synced cloud folder.

A script does this, in order:

1. Runs the export on the validator. You type your login password if SSH asks.
2. Stops if the answer has no END line.
3. Lists the archive before unpacking and stops at any name that is not a backup file.
4. Checks every file against the validator's SHA-256 sums.
5. Copies each file into your folders and checks each copy.

It never overwrites. A file that is already there with the same content is reported as `had`. A file with other content stops the run.

## By hand

The same steps work without a script, on macOS or Linux:

```
ssh me@validator 'sudo -n /usr/local/bin/xrplbak export --out /root/xrplbak/xrplbak-out' > export.txt
sed '1d;$d' export.txt | base64 -d > export.tgz
mkdir files && tar -xzf export.tgz -C files
cd files && sha256sum -c SHA256SUMS
```

On macOS, use `shasum -a 256 -c SHA256SUMS`.

## What the check proves

The check proves that each copy is the same file the validator holds. It does not prove that the backup restores.

`backup --submit` proved that when it ran: it read the backup back from the ledger and printed `read-back: PASS`. To prove it again from your computer, run `xrplbak verify --dump <id>.dump.json --bundle <id>.bundle --account <address>`. That needs the 24 recovery words, because the key file stays on the validator. Keep it for a restore drill, not for every backup.

## Secrecy

The copies need no secrecy of their own. The bundle is encrypted with a key that comes from your recovery words. The dump holds ciphertext and data that is already on the public ledger. A synced cloud folder is a reasonable second place.

The recovery words are what need care. Never put them beside the copies.
