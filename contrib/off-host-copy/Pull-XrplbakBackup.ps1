# Pull-XrplbakBackup.ps1
#
# Copies every xrplbak bundle and dump file from a validator to this
# computer and checks each copy's SHA-256 against the sums the validator
# computed. It runs "xrplbak export" on the validator over SSH; nothing
# else runs there. It never overwrites a file: a copy that exists with
# other content stops the run.
#
# This script is a convenience outside the xrplbak binary. Read it before
# you use it. Setup on the validator: docs/off-host-copies.md.
#
# Works with Windows PowerShell 5 and PowerShell 7.

param(
    # --- Settings: edit the values on the right, or pass them as flags. ---

    # How to reach the validator. Fill in ONE of the two.
    # A PuTTY saved session (uses plink.exe):
    [string]$Session = '',
    # Or an OpenSSH target such as 'me@validator.example' (uses ssh):
    [string]$SshTarget = '',

    # The command the sudo rule on the validator allows, word for word.
    [string]$RemoteCommand = 'sudo -n /usr/local/bin/xrplbak export --out /root/xrplbak/xrplbak-out',

    # Where the copies go on this computer.
    [string]$Dest = (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'xrplbak-backups'),

    # Optional second copy, for example a synced cloud folder. '' skips it.
    [string]$SecondCopy = '',

    # --- End of settings. ---

    # Do not wait for Enter at the end (for scripts).
    [switch]$NoPause
)

$ErrorActionPreference = 'Stop'

function Finish([int]$code) {
    if (-not $NoPause) { Read-Host 'Press Enter to close' | Out-Null }
    exit $code
}

function Fail([string]$msg) {
    Write-Host ''
    Write-Host "FAIL: $msg" -ForegroundColor Red
    Finish 1
}

function Sha([string]$path) {
    (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower()
}

# Find-Tool returns the first of the given full paths that exists, then
# falls back to the name on PATH.
function Find-Tool([string]$name, [string[]]$first) {
    foreach ($p in $first) {
        if ($p -and (Test-Path -LiteralPath $p)) { return $p }
    }
    $cmd = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    return $null
}

# On Windows, a path under a missing variable would start at the drive
# root, so the fixed locations are used only when the variable is set.
function Under([string]$base, [string]$rest) {
    if ($base) { return (Join-Path $base $rest) }
    return ''
}

$NamePattern = '^[0-9a-f]{32}\.(bundle|dump\.json)$'

# 1. Pick the SSH client.
if ($Session -and $SshTarget) { Fail 'Set $Session or $SshTarget, not both.' }
if (-not $Session -and -not $SshTarget) { Fail 'Set $Session (PuTTY) or $SshTarget (OpenSSH) at the top of this script.' }
if ($Session) {
    $client = Find-Tool 'plink' @()
    if (-not $client) { $client = Find-Tool 'plink' @((Under $env:ProgramFiles 'PuTTY\plink.exe'), (Under ${env:ProgramFiles(x86)} 'PuTTY\plink.exe')) }
    if (-not $client) { Fail 'plink was not found. It comes with the PuTTY installer.' }
    $clientArgs = @('-load', $Session, $RemoteCommand)
    Write-Host "Connecting to the PuTTY session $Session."
} else {
    $client = Find-Tool 'ssh' @()
    if (-not $client) { $client = Find-Tool 'ssh' @((Under $env:SystemRoot 'System32\OpenSSH\ssh.exe')) }
    if (-not $client) { Fail 'ssh was not found.' }
    $clientArgs = @($SshTarget, $RemoteCommand)
    Write-Host "Connecting to $SshTarget."
}
Write-Host 'If asked, type your validator login password.'

# 2. Run the export on the validator.
$lines = & $client @clientArgs
$code = $LASTEXITCODE
if ($code -eq 5) { Fail 'The validator has no backup files yet (xrplbak export: exit 5). Run a backup first.' }
if ($code -eq 3) { Fail 'xrplbak export refused the backup folder (exit 3). Its message is above: something in the folder is not a backup file.' }
if ($code -ne 0) { Fail "The export did not run (exit $code). Check the sudo rule in docs/off-host-copies.md." }

# 3. Take the text between the BEGIN and END lines. No END line means
#    the transfer was cut off.
$text  = ($lines -join "`n")
$begin = 'XRPLBAK-EXPORT-BEGIN'
$end   = 'XRPLBAK-EXPORT-END'
$b = $text.IndexOf($begin)
$e = $text.IndexOf($end)
if ($b -lt 0) { Fail 'The validator answer has no export block.' }
if ($e -lt $b) { Fail 'The export was cut off before its END line. Nothing was copied. Run it again.' }
$b64 = $text.Substring($b + $begin.Length, $e - $b - $begin.Length) -replace '\s', ''
try { $bytes = [Convert]::FromBase64String($b64) } catch { Fail 'The export block is not valid base64.' }

# Windows ships its own tar. It comes first: a tar from Git or MSYS earlier
# on PATH reads the C: of a Windows path as a remote host name.
$tar = Find-Tool 'tar' @((Under $env:SystemRoot 'System32\tar.exe'))
if (-not $tar) { Fail 'tar was not found. Windows 10 and later include it.' }

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('xrplbak-pull-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
$failure = $null
$count = 0
try {
    $archive = Join-Path $tmp 'export.tgz'
    $unpack  = Join-Path $tmp 'files'
    New-Item -ItemType Directory -Path $unpack | Out-Null
    [IO.File]::WriteAllBytes($archive, $bytes)

    # 4. Read the list of names before unpacking anything. Only backup
    #    file names and SHA256SUMS may be in the archive.
    $names = @(& $tar -tzf $archive)
    if ($LASTEXITCODE -ne 0) { throw 'The archive could not be read.' }
    foreach ($n in $names) {
        if ($n -ne 'SHA256SUMS' -and $n -notmatch $NamePattern) { throw "Unexpected name in the archive: $n" }
    }
    if ($names -notcontains 'SHA256SUMS') { throw 'The archive has no SHA256SUMS.' }
    & $tar -xzf $archive -C $unpack
    if ($LASTEXITCODE -ne 0) { throw 'The archive could not be unpacked.' }

    # 5. Check every file against the validator's sums, both ways: each
    #    listed file is there and matches, and no file is unlisted.
    $sums = @()
    foreach ($line in Get-Content -LiteralPath (Join-Path $unpack 'SHA256SUMS')) {
        if ($line -notmatch '^([0-9a-f]{64})  (\S+)$') { throw "Bad SHA256SUMS line: $line" }
        $sums += [pscustomobject]@{ Hash = $Matches[1]; Name = $Matches[2] }
    }
    if ($sums.Count -eq 0) { throw 'The validator sent no files.' }
    foreach ($s in $sums) {
        if ($s.Name -notmatch $NamePattern) { throw "Unexpected file name in SHA256SUMS: $($s.Name)" }
        $f = Join-Path $unpack $s.Name
        if (-not (Test-Path -LiteralPath $f)) { throw "$($s.Name) is listed but was not sent." }
        if ((Sha $f) -ne $s.Hash) { throw "$($s.Name) changed in transit." }
    }
    $listed = @($sums | ForEach-Object { $_.Name })
    foreach ($n in $names) {
        if ($n -ne 'SHA256SUMS' -and $listed -notcontains $n) { throw "$n was sent but is not in SHA256SUMS." }
    }

    # 6. Copy into each destination and check the copy. A file that is
    #    already there must be identical; it is never replaced.
    $targets = @($Dest)
    if ($SecondCopy) { $targets += $SecondCopy }
    foreach ($t in $targets) {
        New-Item -ItemType Directory -Path $t -Force | Out-Null
        foreach ($s in $sums) {
            $dst = Join-Path $t $s.Name
            if (Test-Path -LiteralPath $dst) {
                if ((Sha $dst) -ne $s.Hash) { throw "$dst exists with different content. Nothing was overwritten." }
                Write-Host "  had   $($s.Name)  ($t)"
                continue
            }
            Copy-Item -LiteralPath (Join-Path $unpack $s.Name) -Destination $dst
            if ((Sha $dst) -ne $s.Hash) { throw "The copy at $dst does not match." }
            Write-Host "  new   $($s.Name)  ($t)" -ForegroundColor Cyan
        }
    }
    $count = $sums.Count
}
catch {
    $failure = "$_"
}
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
if ($failure) { Fail $failure }

Write-Host ''
Write-Host "PASS: $count files match the validator's SHA-256 sums." -ForegroundColor Green
Finish 0
