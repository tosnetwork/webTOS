#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tools/jtreg_java_lang.sh [options]

Boot TOS with a jtreg-enabled runtime bundle and run the full OpenJDK 11
`test/jdk/java/lang` tree inside the guest.

Options:
  --runtime-manifest PATH   Runtime manifest to embed
                            (default: base_image.runtime.jtreg.manifest)
  --target PATH             Guest jtreg target path
                            (default: /jdk/test/jdk/java/lang)
  --qemu-timeout SECONDS    QEMU timeout in seconds (default: 1800)
  --qemu-memory SIZE        Guest RAM size (default: 2048M)
  --image PATH              Disk image path
  --log PATH                Serial log path
  --keep-artifacts          Keep generated image/log artifacts
  -h, --help                Show this help
EOF
}

runtime_manifest="${TOS_RUNTIME_MANIFEST:-base_image.runtime.jtreg.manifest}"
jtreg_target="${TOS_JTREG_LANG_TARGET:-/jdk/test/jdk/java/lang}"
qemu_timeout="${QEMU_TIMEOUT:-1800}"
qemu_memory="${QEMU_MEMORY:-2048M}"
image_path=""
log_path=""
keep_artifacts=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime-manifest)
      runtime_manifest="$2"
      shift 2
      ;;
    --target)
      jtreg_target="$2"
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
jtreg_launcher_src="test_data/test_java_jtreg_lang_execve.c"
jtreg_launcher_elf="test_data/test_java_jtreg_lang_execve.elf"
base_test_image="${TOS_BASE_TEST_IMG:-/tmp/tos_test.img}"
default_image="/tmp/tos_jtreg_java_lang.img"
default_log="/tmp/tos_jtreg_java_lang.log"
test_disk_mb="${TOS_TEST_DISK_MB:-512}"

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
export TOS_JAVA_SMOKE_FOCUS="jtreg-lang"

echo "[jtreg-lang] build: TOS_RUNTIME_MANIFEST=$TOS_RUNTIME_MANIFEST"
echo "[jtreg-lang] target: $jtreg_target"
gcc -nostdlib -static -Os -s -Wl,-Ttext=0x40000000 \
  -DJTREG_LANG_TARGET="\"$jtreg_target\"" \
  -o "$jtreg_launcher_elf" "$jtreg_launcher_src"
cargo build --release --target x86_64-unknown-tos.json
objcopy -I elf64-x86-64 -O elf32-i386 "$kernel_elf64" "$kernel_elf32"

TOS_TEST_DISK_MB="$test_disk_mb" tools/create_test_disk.sh "$base_test_image"

cp "$base_test_image" "$image_path"

qemu_exit=0
timeout "$qemu_timeout" \
  stdbuf -o0 -e0 qemu-system-x86_64 \
    -m "$qemu_memory" \
    -serial stdio \
    -display none \
    -kernel "$kernel_elf32" \
    -device virtio-net-pci,netdev=n0 \
    -netdev user,id=n0 \
    -drive "file=$image_path,format=raw,if=ide" \
    -no-reboot \
    -no-shutdown \
  >"$log_path" 2>&1 || qemu_exit=$?

if [[ "$qemu_exit" -ne 0 && "$qemu_exit" -ne 124 ]]; then
  echo "[jtreg-lang] qemu failed: exit=$qemu_exit log=$log_path" >&2
  tail -80 "$log_path" >&2 || true
  exit "$qemu_exit"
fi

require_line() {
  local pattern="$1"
  if ! grep -aEq "$pattern" "$log_path"; then
    echo "[jtreg-lang] missing log pattern: $pattern" >&2
    tail -120 "$log_path" >&2 || true
    exit 1
  fi
}

require_no_line() {
  local pattern="$1"
  if grep -aEq "$pattern" "$log_path"; then
    echo "[jtreg-lang] forbidden log pattern: $pattern" >&2
    tail -120 "$log_path" >&2 || true
    exit 1
  fi
}

require_no_line 'Page fault|GP fault|TRAP|panic|SIGABRT|KERNEL PANIC'
require_line "\\[JAVA\\] launching jtreg java\\.lang tree: ${jtreg_target//\//\\/}"
require_line 'Test results:.*passed:[[:space:]][1-9][0-9]*'
require_no_line 'Test results:.*failed:[[:space:]][1-9][0-9]*'
require_no_line 'Test results:.*error:[[:space:]][1-9][0-9]*'
require_line '\[linux_compat\] exit_group: agent=[0-9]+ status=0'

echo "[jtreg-lang] validation passed: log=$log_path"

if [[ "$keep_artifacts" -eq 0 ]]; then
  rm -f "$image_path" "$log_path"
fi
