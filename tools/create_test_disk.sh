#!/usr/bin/env bash
set -euo pipefail

image_path="${1:-/tmp/tos_test.img}"
size_mb="${TOS_TEST_DISK_MB:-64}"
size_bytes=$((size_mb * 1024 * 1024))

mkdir -p "$(dirname "$image_path")"

if [[ -f "$image_path" ]]; then
  current_bytes=$(stat -c '%s' "$image_path")
  if [[ "$current_bytes" -ge "$size_bytes" ]]; then
    echo "[test-disk] reusing $image_path"
    exit 0
  fi
  echo "[test-disk] expanding $image_path from $current_bytes bytes to ${size_mb}M"
  truncate -s "${size_mb}M" "$image_path"
  exit 0
fi

if command -v truncate >/dev/null 2>&1; then
  truncate -s "${size_mb}M" "$image_path"
else
  dd if=/dev/zero of="$image_path" bs=1M count="$size_mb" status=none
fi

echo "[test-disk] created $image_path (${size_mb}M raw)"
