#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tools/jtreg_java_base_smoke.sh [options]

Boot TOS with a jtreg-enabled runtime bundle and run the first-pass OpenJDK 11
java.base-heavy whitelist inside the guest.

This script assumes the runtime manifest already embeds:
  - /usr/lib/jvm/java-11-openjdk-amd64/...
  - /jdk/jtreg/lib/jtreg.jar
  - /jdk/test/jdk/...
  - /jdk/test/lib/...
  - /jdk/test/jtreg-ext/...

Recommended starting point:
  tools/prepare_jtreg_assets.sh
  tools/jtreg_java_base_smoke.sh

Options:
  --runtime-manifest PATH   Runtime manifest to embed
                            (default: base_image.runtime.jtreg.manifest)
  --qemu-timeout SECONDS    QEMU timeout in seconds (default: 420)
  --qemu-memory SIZE        Guest RAM size (default: 1536M)
  --image PATH              Disk image path
  --log PATH                Serial log path
  --keep-artifacts          Keep generated image/log artifacts
  -h, --help                Show this help
EOF
}

runtime_manifest="${TOS_RUNTIME_MANIFEST:-base_image.runtime.jtreg.manifest}"
qemu_timeout="${QEMU_TIMEOUT:-420}"
qemu_memory="${QEMU_MEMORY:-1536M}"
image_path=""
log_path=""
keep_artifacts=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime-manifest)
      runtime_manifest="$2"
      shift 2
      ;;
    --qemu-timeout)
      qemu_timeout="$2"
      shift 2
      ;;
    --qemu-memory)
      qemu_memory="$2"
      shift 2
      ;;
    --image)
      image_path="$2"
      shift 2
      ;;
    --log)
      log_path="$2"
      shift 2
      ;;
    --keep-artifacts)
      keep_artifacts=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

kernel_elf64="target/x86_64-unknown-tos/release/tos"
kernel_elf32="target/tos_32.elf"
base_test_image="${TOS_BASE_TEST_IMG:-/tmp/tos_test.img}"
default_image="/tmp/tos_jtreg_java_base.img"
default_log="/tmp/tos_jtreg_java_base.log"

if [[ ! -f "$runtime_manifest" ]]; then
  echo "runtime manifest not found: $runtime_manifest" >&2
  echo "run tools/prepare_jtreg_assets.sh first" >&2
  exit 1
fi

if ! grep -Eq '^[[:space:]]*(/jdk/jtreg/lib/jtreg\.jar|@tree /jdk/jtreg)[[:space:]]*=' "$runtime_manifest"; then
  echo "runtime manifest is missing jtreg payload under /jdk/jtreg: $runtime_manifest" >&2
  exit 1
fi

if [[ -z "$image_path" ]]; then
  image_path="$default_image"
fi
if [[ -z "$log_path" ]]; then
  log_path="$default_log"
fi

export TOS_RUNTIME_MANIFEST="$runtime_manifest"
export TOS_RUNTIME_SMOKE_FOCUS="java"
export TOS_JAVA_SMOKE_FOCUS="jtreg"

echo "[jtreg] build: TOS_RUNTIME_MANIFEST=$TOS_RUNTIME_MANIFEST"
cargo build --release --target x86_64-unknown-tos.json
objcopy -I elf64-x86-64 -O elf32-i386 "$kernel_elf64" "$kernel_elf32"

if [[ ! -f "$base_test_image" ]]; then
  tools/create_test_disk.sh "$base_test_image"
fi

cp "$base_test_image" "$image_path"

qemu_exit=0
: >"$log_path"
timeout "$qemu_timeout" \
  qemu-system-x86_64 \
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
  echo "[jtreg] qemu failed: exit=$qemu_exit log=$log_path" >&2
  tail -80 "$log_path" >&2 || true
  exit "$qemu_exit"
fi

require_line() {
  local pattern="$1"
  if ! grep -aEq "$pattern" "$log_path"; then
    echo "[jtreg] missing log pattern: $pattern" >&2
    tail -120 "$log_path" >&2 || true
    exit 1
  fi
}

require_no_line() {
  local pattern="$1"
  if grep -aEq "$pattern" "$log_path"; then
    echo "[jtreg] forbidden log pattern: $pattern" >&2
    tail -120 "$log_path" >&2 || true
    exit 1
  fi
}

require_no_line 'Page fault|GP fault|TRAP|panic|SIGABRT|KERNEL PANIC'
# jtreg helper VMs use protocol exit codes (95..99) for pass/fail/error/not-run.
# Rely on jtreg's own summary instead of treating every non-zero helper exit as
# a guest runtime failure.
require_line '\[JAVA\] launching jtreg java\.base smoke subset'
require_line 'Test results:.*passed:[[:space:]][1-9][0-9]*'
require_no_line 'Test results:.*failed:[[:space:]][1-9][0-9]*'
require_no_line 'Test results:.*error:[[:space:]][1-9][0-9]*'
require_line '\[linux_compat\] exit_group: agent=[0-9]+ status=0'

echo "[jtreg] validation passed: log=$log_path"

if [[ "$keep_artifacts" -eq 0 ]]; then
  rm -f "$image_path" "$log_path"
fi
