#!/usr/bin/env bash
# Fetches the pinned static musl BusyBox used by the milestone-2 workload
# tests into test_data/ (gitignored; BusyBox is GPL-2.0 and is not part of
# this repository). Tests that need it are skipped when it is absent.
set -euo pipefail
cd "$(dirname "$0")/.."

URL="https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"
SHA256="6e123e7f3202a8c1e9b1f94d8941580a25135382b99e8d3e34fb858bba311348"
OUT="test_data/busybox-musl"

if [ -f "$OUT" ] && echo "$SHA256  $OUT" | sha256sum -c --quiet 2>/dev/null; then
    echo "$OUT already present and verified."
    exit 0
fi

curl -fsSL -o "$OUT.tmp" "$URL"
echo "$SHA256  $OUT.tmp" | sha256sum -c --quiet
mv "$OUT.tmp" "$OUT"
chmod +x "$OUT"
echo "Fetched and verified $OUT (BusyBox 1.35.0 x86_64 musl, GPL-2.0)."
