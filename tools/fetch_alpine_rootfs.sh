#!/usr/bin/env bash
# Fetches the pinned Alpine minirootfs used by the milestone-3 dynamic-linking
# workload tests into test_data/alpine-minirootfs/ (gitignored; Alpine
# packages carry their own licenses and are not part of this repository).
# It provides the musl dynamic linker and a dynamically linked BusyBox.
# Tests that need it are skipped when it is absent.
set -euo pipefail
cd "$(dirname "$0")/.."

URL="https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz"
SHA256="d4e6fd67dcf75e40c451560ac7265166c2b72a0f38ddc9aae756a7de3d1efa0c"
OUT_DIR="test_data/alpine-minirootfs"

if [ -f "$OUT_DIR/lib/ld-musl-x86_64.so.1" ]; then
    echo "$OUT_DIR already present."
    exit 0
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
curl -fsSL -o "$TMP" "$URL"
echo "$SHA256  $TMP" | sha256sum -c --quiet
mkdir -p "$OUT_DIR"
tar -xzf "$TMP" -C "$OUT_DIR"
echo "Fetched and verified $OUT_DIR (Alpine minirootfs 3.20.3 x86_64)."
