#!/bin/sh
# Reference only. Checks that a bundle file matches the cipher_sha256 in a
# manifest JSON. The real check is "xrplbak verify --bundle FILE".
set -eu
manifest_json="$1"; bundle="$2"
want=$(sed -n 's/.*"cipher_sha256":"\([0-9a-f]*\)".*/\1/p' "$manifest_json")
have=$(sha256sum "$bundle" | cut -d' ' -f1)
[ "$want" = "$have" ] && echo "bundle matches" || { echo "bundle MISMATCH"; exit 1; }
