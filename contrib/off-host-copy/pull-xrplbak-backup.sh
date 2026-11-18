#!/bin/sh
# pull-xrplbak-backup.sh
#
# Copies every xrplbak bundle and dump file from a validator to this
# computer and checks each copy's SHA-256 against the sums the validator
# computed. It runs "xrplbak export" on the validator over ssh; nothing
# else runs there. It never overwrites a file: a copy that exists with
# other content stops the run.
#
# This script is a convenience outside the xrplbak binary. Read it before
# you use it. Setup on the validator: docs/off-host-copies.md.
#
# For macOS and Linux. Needs ssh, tar, base64, and sha256sum or shasum.

# --- Settings: edit these, or set them in the environment. ---

# The ssh target, such as me@validator.example or a Host from ~/.ssh/config.
SSH_TARGET="${SSH_TARGET:-}"

# The command the sudo rule on the validator allows, word for word.
REMOTE_COMMAND="${REMOTE_COMMAND:-sudo -n /usr/local/bin/xrplbak export --out /root/xrplbak/xrplbak-out}"

# Where the copies go on this computer.
DEST="${DEST:-$HOME/xrplbak-backups}"

# Optional second copy, for example a synced cloud folder. Empty skips it.
SECOND_COPY="${SECOND_COPY:-}"

# --- End of settings. ---

set -eu

fail() {
    printf '\nFAIL: %s\n' "$1" >&2
    exit 1
}

sha() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

backup_name() {
    printf '%s\n' "$1" | grep -Eq '^[0-9a-f]{32}\.(bundle|dump\.json)$'
}

[ -n "$SSH_TARGET" ] || fail 'Set SSH_TARGET at the top of this script.'

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/files"

# 1. Run the export on the validator.
printf 'Connecting to %s.\n' "$SSH_TARGET"
code=0
# shellcheck disable=SC2029  # the command is meant to run on the validator
ssh "$SSH_TARGET" "$REMOTE_COMMAND" > "$tmp/answer" || code=$?
case $code in
    0) ;;
    5) fail 'The validator has no backup files yet (xrplbak export: exit 5). Run a backup first.' ;;
    3) fail 'xrplbak export refused the backup folder (exit 3). Its message is above: something in the folder is not a backup file.' ;;
    *) fail "The export did not run (exit $code). Check the sudo rule in docs/off-host-copies.md." ;;
esac

# 2. Take the text between the BEGIN and END lines. No END line means
#    the transfer was cut off.
grep -q '^XRPLBAK-EXPORT-BEGIN' "$tmp/answer" || fail 'The validator answer has no export block.'
grep -q '^XRPLBAK-EXPORT-END' "$tmp/answer" || fail 'The export was cut off before its END line. Nothing was copied. Run it again.'
sed -n '/^XRPLBAK-EXPORT-BEGIN/,/^XRPLBAK-EXPORT-END/p' "$tmp/answer" | sed '1d;$d' | tr -d '\r' > "$tmp/b64"
base64 -d < "$tmp/b64" > "$tmp/export.tgz" 2>/dev/null ||
    base64 -D < "$tmp/b64" > "$tmp/export.tgz" 2>/dev/null ||
    fail 'The export block is not valid base64.'

# 3. Read the list of names before unpacking anything. Only backup file
#    names and SHA256SUMS may be in the archive.
tar -tzf "$tmp/export.tgz" > "$tmp/names" 2>/dev/null || fail 'The archive could not be read.'
while IFS= read -r n; do
    [ "$n" = SHA256SUMS ] || backup_name "$n" || fail "Unexpected name in the archive: $n"
done < "$tmp/names"
grep -qx SHA256SUMS "$tmp/names" || fail 'The archive has no SHA256SUMS.'
tar -xzf "$tmp/export.tgz" -C "$tmp/files" || fail 'The archive could not be unpacked.'

# 4. Check every file against the validator's sums, both ways: each
#    listed file is there and matches, and no file is unlisted.
count=0
while IFS= read -r line; do
    hash=${line%%  *}
    name=${line#*  }
    printf '%s\n' "$hash" | grep -Eq '^[0-9a-f]{64}$' || fail "Bad SHA256SUMS line: $line"
    backup_name "$name" || fail "Unexpected file name in SHA256SUMS: $name"
    [ -f "$tmp/files/$name" ] || fail "$name is listed but was not sent."
    [ "$(sha "$tmp/files/$name")" = "$hash" ] || fail "$name changed in transit."
    count=$((count + 1))
done < "$tmp/files/SHA256SUMS"
[ "$count" -gt 0 ] || fail 'The validator sent no files.'
while IFS= read -r n; do
    [ "$n" = SHA256SUMS ] || grep -q "  $n\$" "$tmp/files/SHA256SUMS" || fail "$n was sent but is not in SHA256SUMS."
done < "$tmp/names"

# 5. Copy into each destination and check the copy. A file that is
#    already there must be identical; it is never replaced.
for t in "$DEST" "$SECOND_COPY"; do
    [ -n "$t" ] || continue
    mkdir -p "$t"
    while IFS= read -r line; do
        hash=${line%%  *}
        name=${line#*  }
        if [ -e "$t/$name" ]; then
            [ "$(sha "$t/$name")" = "$hash" ] || fail "$t/$name exists with different content. Nothing was overwritten."
            printf '  had   %s  (%s)\n' "$name" "$t"
            continue
        fi
        cp "$tmp/files/$name" "$t/$name"
        [ "$(sha "$t/$name")" = "$hash" ] || fail "The copy at $t/$name does not match."
        printf '  new   %s  (%s)\n' "$name" "$t"
    done < "$tmp/files/SHA256SUMS"
done

printf "\nPASS: %s files match the validator's SHA-256 sums.\n" "$count"
