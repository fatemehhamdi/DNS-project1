#!/usr/bin/env bash
# Rebuild the vulnerable base binary from the bundled source snapshot.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
gcc -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 "$HERE/src/base"/csvsum.c -o "$HERE/bin/base.bin"
echo "rebuilt: $HERE/bin/base.bin  sha256=$(sha256sum "$HERE/bin/base.bin" | cut -d' ' -f1)"
echo "recorded sha256: ddda9657df8d3e63284e2a1dc97b0ac61dea550deb132ce820d99c6652afc3b1  (may differ if the toolchain differs)"
