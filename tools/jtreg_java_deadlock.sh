#!/usr/bin/env bash
set -euo pipefail

runtime_manifest="${TOS_RUNTIME_MANIFEST:-base_image.runtime.jtreg.manifest}"
qemu_timeout="${QEMU_TIMEOUT:-900}"
qemu_memory="${QEMU_MEMORY:-2048M}"
image_path="${TOS_JTREG_DEADLOCK_IMG:-/tmp/tos_jtreg_deadlock.img}"
log_path="${TOS_JTREG_DEADLOCK_LOG:-/tmp/tos_jtreg_deadlock.log}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

kernel_elf64="target/x86_64-unknown-tos/release/tos"
kernel_elf32="target/tos_32.elf"
base_test_image="${TOS_BASE_TEST_IMG:-/tmp/tos_test.img}"

export TOS_RUNTIME_MANIFEST="$runtime_manifest"
export TOS_RUNTIME_SMOKE_FOCUS="java"
export TOS_JAVA_SMOKE_FOCUS="jtreg-deadlock"

echo "[jtreg-deadlock] build: TOS_RUNTIME_MANIFEST=$TOS_RUNTIME_MANIFEST"
cargo build --release --target x86_64-unknown-tos.json
objcopy -I elf64-x86-64 -O elf32-i386 "$kernel_elf64" "$kernel_elf32"

if [[ ! -f "$base_test_image" ]]; then
  tools/create_test_disk.sh "$base_test_image"
fi

cp "$base_test_image" "$image_path"

qemu_exit=0
: >"$log_path"
timeout "$qemu_timeout" \
  stdbuf -o0 -e0 qemu-system-x86_64 \
    -m "$qemu_memory" \
    -serial "file:$log_path" \
    -display none \
    -kernel "$kernel_elf32" \
    -device virtio-net-pci,netdev=n0 \
    -netdev user,id=n0 \
    -drive "file=$image_path,format=raw,if=ide" \
    -no-reboot \
    -no-shutdown \
  2>>"$log_path" || qemu_exit=$?

if [[ "$qemu_exit" -ne 0 && "$qemu_exit" -ne 124 ]]; then
  echo "[jtreg-deadlock] qemu failed: exit=$qemu_exit log=$log_path" >&2
  tail -120 "$log_path" >&2 || true
  exit "$qemu_exit"
fi

echo "[jtreg-deadlock] log=$log_path"
