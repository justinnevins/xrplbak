#!/bin/sh
# Tests for the pull scripts. No network and no validator: a fake ssh and
# a fake plink stand in for the connection and run a real "xrplbak export"
# on a folder made here, or send one of several damaged answers.
#
#   sh contrib/off-host-copy/test/run.sh /path/to/xrplbak
#
# The PowerShell script is tested when PowerShell is installed (it is on
# GitHub's runners). Set NEED_PWSH=1 to fail instead of skipping without
# it, and PWSH=powershell to test with Windows PowerShell 5.
set -eu

XRPLBAK=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
HERE=$(cd "$(dirname "$0")/.." && pwd)
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT

A=0123456789abcdef0123456789abcdef
B=fedcba9876543210fedcba9876543210
SRC=$ROOT/validator-out
mkdir -p "$SRC" "$ROOT/bin" "$ROOT/empty"
printf 'bundle a \000\377 bytes' > "$SRC/$A.bundle"
printf '{"v":1}\n' > "$SRC/$A.dump.json"
printf 'bundle b' > "$SRC/$B.bundle"
printf '{"v":1,"b":true}\n' > "$SRC/$B.dump.json"

# The fake client. FAKE_MODE picks the answer.
cat > "$ROOT/bin/fake-client" <<FAKE
#!/bin/sh
frame() { echo XRPLBAK-EXPORT-BEGIN; base64 "\$1"; echo XRPLBAK-EXPORT-END; }
# Git Bash on Windows marks each name with "*"; xrplbak writes two spaces.
sums() { (cd "\$1" && sha256sum [0-9a-f]* | sed 's/ \*/  /') > "\$1/SHA256SUMS"; }
w=\$(mktemp -d)
case "\${FAKE_MODE:-ok}" in
  ok)      exec "$XRPLBAK" export --out "$SRC" ;;
  empty)   exec "$XRPLBAK" export --out "$ROOT/empty" ;;
  refused) echo "error: export refused, nothing was sent" >&2; exit 3 ;;
  nosudo)  echo "sudo: a password is required" >&2; exit 1 ;;
  cut)     "$XRPLBAK" export --out "$SRC" | sed '\$d' ;;
  noblock) echo "Welcome to the validator" ;;
  evil)    mkdir "\$w/d"; cp "$SRC/$A.bundle" "\$w/d/"; sums "\$w/d"; echo owned > "\$w/evil"
           tar -czf "\$w/x.tgz" -P -C "\$w/d" $A.bundle SHA256SUMS ../evil; frame "\$w/x.tgz" ;;
  badsum)  mkdir "\$w/d"; cp "$SRC/$A.bundle" "\$w/d/"; sums "\$w/d"; echo changed > "\$w/d/$A.bundle"
           tar -czf "\$w/x.tgz" -C "\$w/d" $A.bundle SHA256SUMS; frame "\$w/x.tgz" ;;
  unlisted) mkdir "\$w/d"; cp "$SRC/$A.bundle" "\$w/d/"; sums "\$w/d"; cp "$SRC/$B.bundle" "\$w/d/"
           tar -czf "\$w/x.tgz" -C "\$w/d" $A.bundle $B.bundle SHA256SUMS; frame "\$w/x.tgz" ;;
  missing) mkdir "\$w/d"; cp "$SRC/$A.bundle" "$SRC/$B.bundle" "\$w/d/"; sums "\$w/d"
           tar -czf "\$w/x.tgz" -C "\$w/d" $A.bundle SHA256SUMS; frame "\$w/x.tgz" ;;
  keyfile) mkdir "\$w/d"; cp "$SRC/$A.bundle" "\$w/d/"; echo secret > "\$w/d/xrplbak.key"
           (cd "\$w/d" && sha256sum $A.bundle xrplbak.key | sed 's/ \*/  /' > SHA256SUMS)
           tar -czf "\$w/x.tgz" -C "\$w/d" $A.bundle xrplbak.key SHA256SUMS; frame "\$w/x.tgz" ;;
  nosums)  tar -czf "\$w/x.tgz" -C "$SRC" $A.bundle; frame "\$w/x.tgz" ;;
esac
rm -rf "\$w"
FAKE
chmod +x "$ROOT/bin/fake-client"
cp "$ROOT/bin/fake-client" "$ROOT/bin/ssh"
cp "$ROOT/bin/fake-client" "$ROOT/bin/plink"
# Windows PowerShell starts programs by extension, so there the fakes also
# get a .cmd that hands over to the same script.
case $(uname -s) in
  MINGW*|MSYS*)
    for n in ssh plink; do
        printf '@bash "%%~dp0fake-client" %%*\r\n@exit /b %%errorlevel%%\r\n' > "$ROOT/bin/$n.cmd"
    done ;;
esac
PATH=$ROOT/bin:$PATH
export PATH

fails=0
bad() { echo "  NOT OK: $1"; fails=$((fails + 1)); }

# pull FLAVOR MODE DEST SECOND: runs one script, leaves its output in
# $ROOT/out and its exit code in $code.
pull() {
    code=0
    case $1 in
      sh)   FAKE_MODE=$2 SSH_TARGET=me@validator DEST=$3 SECOND_COPY=$4 sh "$HERE/pull-xrplbak-backup.sh" > "$ROOT/out" 2>&1 || code=$? ;;
      pwsh)     set -- "$2" "$3" "$4" -Session my-session ;;
      pwsh-ssh) set -- "$2" "$3" "$4" -SshTarget me@validator ;;
    esac
    [ "$#" -eq 5 ] || return 0
    # An empty argument does not survive every shell on the way to
    # PowerShell, so the second folder is passed only when there is one.
    if [ -n "$3" ]; then
        FAKE_MODE=$1 "$PWSH" -NoProfile -ExecutionPolicy Bypass -File "$HERE/Pull-XrplbakBackup.ps1" "$4" "$5" -Dest "$2" -SecondCopy "$3" -NoPause > "$ROOT/out" 2>&1 || code=$?
    else
        FAKE_MODE=$1 "$PWSH" -NoProfile -ExecutionPolicy Bypass -File "$HERE/Pull-XrplbakBackup.ps1" "$4" "$5" -Dest "$2" -NoPause > "$ROOT/out" 2>&1 || code=$?
    fi
}

# refused FLAVOR MODE WORDS: the run must fail, say WORDS, and copy nothing.
refused() {
    d=$ROOT/$1-$2
    pull "$1" "$2" "$d/one" "$d/two"
    [ "$code" = 1 ] || bad "$1 $2: exit $code, want 1"
    grep -q "FAIL:.*$3" "$ROOT/out" || { bad "$1 $2: output does not say \"$3\""; sed 's/^/      /' "$ROOT/out"; }
    grep -q 'PASS' "$ROOT/out" && bad "$1 $2: printed PASS"
    if [ -n "$(find "$d" -type f 2>/dev/null)" ]; then bad "$1 $2: files were copied: $(find "$d" -type f)"; fi
    [ -z "$(find "$ROOT" /tmp -maxdepth 3 -name evil -newer "$ROOT/bin/ssh" 2>/dev/null | grep -v "^$ROOT/tmp" || true)" ] || bad "$1 $2: a file named evil was written"
}

# PWSH names the PowerShell to test with: pwsh (PowerShell 7, the default)
# or powershell (Windows PowerShell 5, on a Windows runner under Git Bash).
PWSH=${PWSH:-pwsh}
flavors="sh"
if command -v "$PWSH" >/dev/null 2>&1; then
    flavors="sh pwsh pwsh-ssh"
elif [ "${NEED_PWSH:-}" = 1 ]; then
    echo "$PWSH is not installed and NEED_PWSH=1"; exit 1
else
    echo "$PWSH is not installed: the PowerShell script is NOT tested in this run"
fi

for f in $flavors; do
    echo "== $f"
    d=$ROOT/$f-ok
    # A whole export lands in both folders, byte for byte.
    pull "$f" ok "$d/one" "$d/two"
    [ "$code" = 0 ] || { bad "$f ok: exit $code"; sed 's/^/      /' "$ROOT/out"; }
    grep -q 'PASS: 4 files' "$ROOT/out" || bad "$f ok: no PASS line for 4 files"
    for t in one two; do
        for n in "$A.bundle" "$A.dump.json" "$B.bundle" "$B.dump.json"; do
            cmp -s "$SRC/$n" "$d/$t/$n" || bad "$f ok: $t/$n differs from the validator's file"
        done
        [ "$(find "$d/$t" -type f | wc -l)" -eq 4 ] || bad "$f ok: $t holds other files too"
    done
    # A second run finds them and copies nothing.
    pull "$f" ok "$d/one" "$d/two"
    [ "$code" = 0 ] || bad "$f again: exit $code"
    [ "$(grep -c '  had  ' "$ROOT/out")" -eq 8 ] || bad "$f again: want 8 'had' lines"
    grep -q '  new  ' "$ROOT/out" && bad "$f again: copied a file that was there"
    # A copy that differs is never replaced, in either folder.
    for t in one two; do
        echo edited > "$d/$t/$B.bundle"
        pull "$f" ok "$d/one" "$d/two"
        [ "$code" = 1 ] || bad "$f differs in $t: exit $code, want 1"
        grep -q 'exists with different content' "$ROOT/out" || bad "$f differs in $t: no message"
        [ "$(cat "$d/$t/$B.bundle")" = edited ] || bad "$f differs in $t: the file was replaced"
        cp "$SRC/$B.bundle" "$d/$t/$B.bundle"
    done
    # No second folder is fine.
    pull "$f" ok "$ROOT/$f-single" ""
    [ "$code" = 0 ] || bad "$f single folder: exit $code"

    refused "$f" empty    'no backup files'
    refused "$f" refused  'refused the backup folder'
    refused "$f" nosudo   'did not run'
    refused "$f" cut      'cut off'
    refused "$f" noblock  'no export block'
    refused "$f" evil     'Unexpected name in the archive'
    refused "$f" keyfile  'Unexpected name in the archive'
    refused "$f" badsum   'changed in transit'
    refused "$f" unlisted 'not in SHA256SUMS'
    refused "$f" missing  'listed but was not sent'
    refused "$f" nosums   'no SHA256SUMS'
done

if [ "$fails" -gt 0 ]; then echo "$fails check(s) failed"; exit 1; fi
echo "all checks passed ($flavors)"
