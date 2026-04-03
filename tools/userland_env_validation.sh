#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tools/userland_env_validation.sh [options]

Build and boot TOS with a runtime manifest that includes a minimal Linux
userland tool subset, then validate `/usr/bin/env -> /bin/sh` execution,
standard guest paths, proc/dev access, and a small shell-driven tool workflow
inside the guest.

Options:
  --runtime-manifest PATH   Use an existing runtime manifest
  --output-manifest PATH    Path for an auto-generated manifest
                            (default: /tmp/tos_userland_env.manifest)
  --qemu-timeout SECONDS    QEMU timeout in seconds (default: 45)
  --qemu-memory SIZE        Guest RAM size (default: 1024M)
  --image PATH              Disk image path
  --log PATH                Serial log path
  -h, --help                Show this help
EOF
}

runtime_manifest="${TOS_RUNTIME_MANIFEST:-}"
output_manifest="/tmp/tos_userland_env.manifest"
qemu_timeout="${QEMU_TIMEOUT:-45}"
qemu_memory="${QEMU_MEMORY:-1024M}"
image_path="/tmp/tos_userland_env.img"
log_path="/tmp/tos_userland_env.log"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime-manifest)
      runtime_manifest="$2"
      shift 2
      ;;
    --output-manifest)
      output_manifest="$2"
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
base_manifest="base_image.manifest"

if [[ -z "$runtime_manifest" ]]; then
  python3 tools/generate_runtime_manifest.py \
    --output "$output_manifest" \
    --runtimes java \
    --linux-tools minimal
  runtime_manifest="$output_manifest"
fi

if [[ ! -f "$runtime_manifest" ]]; then
  echo "[userland-env] runtime manifest not found: $runtime_manifest" >&2
  exit 1
fi

require_manifest_entry() {
  local tos_path="$1"
  if ! grep -Eq "^[[:space:]]*${tos_path//\//\\/}[[:space:]]*=" "$runtime_manifest" \
    && ! grep -Eq "^[[:space:]]*${tos_path//\//\\/}[[:space:]]*=" "$base_manifest"; then
    echo "[userland-env] merged manifest set missing entry: $tos_path" >&2
    exit 1
  fi
}

for required_path in \
  /bin/sh \
  /usr/bin/env \
  /bin/mkdir \
  /bin/rm \
  /bin/rmdir \
  /bin/ln \
  /bin/mv \
  /bin/touch \
  /bin/sleep \
  /bin/cat \
  /bin/pwd \
  /usr/bin/ps \
  /usr/bin/uname \
  /usr/lib/tos-tests/shell_env_probe.sh
do
  require_manifest_entry "$required_path"
done

kernel_elf64="target/x86_64-unknown-tos/release/tos"
kernel_elf32="target/tos_32.elf"
base_test_image="${TOS_BASE_TEST_IMG:-/tmp/tos_test.img}"

export TOS_RUNTIME_MANIFEST="$runtime_manifest"
export TOS_RUNTIME_SMOKE_FOCUS="java"
export TOS_JAVA_SMOKE_FOCUS="jar"
export TOS_USERLAND_ENV_SMOKE=1

build_key="$(
  printf '%s\n%s\n%s\n%s\n' \
    "$TOS_RUNTIME_MANIFEST" \
    "$TOS_RUNTIME_SMOKE_FOCUS" \
    "$TOS_JAVA_SMOKE_FOCUS" \
    "$TOS_USERLAND_ENV_SMOKE" \
  | sha256sum | cut -c1-16
)"
export CARGO_TARGET_DIR="${TOS_CARGO_TARGET_DIR:-/tmp/tos-target-$build_key}"
kernel_elf64="$CARGO_TARGET_DIR/x86_64-unknown-tos/release/tos"
kernel_elf32="$CARGO_TARGET_DIR/tos_32.elf"

echo "[userland-env] build: TOS_RUNTIME_MANIFEST=$TOS_RUNTIME_MANIFEST"
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
  echo "[userland-env] qemu failed: exit=$qemu_exit log=$log_path" >&2
  tail -80 "$log_path" >&2 || true
  exit "$qemu_exit"
fi

require_line() {
  local pattern="$1"
  if ! grep -aEq "$pattern" "$log_path"; then
    echo "[userland-env] missing log pattern: $pattern" >&2
    grep -aE 'TOS-USERLAND-(LAYOUT|TOOLS|ENV-OK)' "$log_path" >&2 || true
    tail -120 "$log_path" >&2 || true
    exit 1
  fi
}

require_no_line() {
  local pattern="$1"
  if grep -aEq "$pattern" "$log_path"; then
    echo "[userland-env] forbidden log pattern: $pattern" >&2
    grep -aE 'TOS-USERLAND-(LAYOUT|TOOLS|ENV-OK)' "$log_path" >&2 || true
    tail -120 "$log_path" >&2 || true
    exit 1
  fi
}

show_userland_markers() {
  grep -aE 'TOS-USERLAND-(LAYOUT|TOOLS|ENV-OK)' "$log_path" || true
}

require_line '\[USERLAND\] launching /usr/bin/env -> /bin/sh smoke'
require_line 'TOS-USERLAND-LAYOUT bin=ok usrbin=ok tmp=ok dev=ok proc=ok tmp_root=/tmp'
require_line 'TOS-USERLAND-TOOLS mkdir=ok touch=ok mv=ok ln=ok cat=ok pwd=/[^ ]* ps=ok sleep=ok uname=Linux'
require_line 'TOS-USERLAND-ENV-OK payload=payload-from-sh probe=ok shell=/usr/lib/tos-tests/shell_env_probe.sh proc_exe=ok dev_null=ok'
require_no_line 'Page fault|GP fault|TRAP|panic|SIGABRT'

show_userland_markers
echo "[userland-env] validation passed: manifest=$runtime_manifest log=$log_path"
