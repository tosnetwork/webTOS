#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tools/phase5_runtime_validation.sh [options]

Validate the Phase-5 Linux runtime path through the existing build/QEMU flow.

Options:
  --runtime-manifest PATH   Host-specific runtime manifest to embed
                            (default: $TOS_RUNTIME_MANIFEST, otherwise
                            profile-specific defaults:
                            java -> base_image.runtime.manifest
                            python -> base_image.runtime.python.manifest
                            node -> base_image.runtime.node.manifest)
  --profile NAME            Validation profile: java, python, node, all
                            (default: all)
  --qemu-timeout SECONDS    QEMU timeout in seconds (default: 45)
  --qemu-memory SIZE        Guest RAM size passed to QEMU (default: 512M)
  --image PATH              Reuse or write the disk image at PATH
  --log PATH                Write the QEMU serial log to PATH
  --build-only              Build and stage the kernel, but do not boot QEMU
  --keep-artifacts          Keep temporary image/log artifacts when generated
  -h, --help                Show this help

The script expects the current repo layout and the existing single-node test
image at /tmp/tos_test.img. It validates the runtime smoke markers that are
already emitted by the root agent:
  - Java:   [JAVA] launch line + TOS-JAVA-JAR payload marker + clean exit
  - Python: [PYTHON] launch line + runtime output "1" + clean exit
  - Node:   [NODE] launch line + runtime output "1" + clean exit

Use TOS_RUNTIME_MANIFEST to point the build at a chosen runtime manifest
profile, or pass --runtime-manifest explicitly.
EOF
}

profile="all"
runtime_manifest="${TOS_RUNTIME_MANIFEST:-}"
qemu_timeout="${QEMU_TIMEOUT:-45}"
qemu_memory="${QEMU_MEMORY:-512M}"
runtime_focus="${TOS_RUNTIME_SMOKE_FOCUS:-}"
java_focus="${TOS_JAVA_SMOKE_FOCUS:-}"
image_path=""
log_path=""
build_only=0
keep_artifacts=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime-manifest)
      runtime_manifest="$2"
      shift 2
      ;;
    --profile)
      profile="$2"
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
    --build-only)
      build_only=1
      shift
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

if [[ -z "$runtime_focus" ]]; then
  case "$profile" in
    java) runtime_focus="java" ;;
    python) runtime_focus="python" ;;
    node) runtime_focus="node" ;;
    all) runtime_focus="all" ;;
    *)
      echo "unknown profile: $profile" >&2
      exit 2
      ;;
  esac
fi

if [[ -z "$java_focus" ]]; then
  java_focus="jar"
fi

if [[ -z "$runtime_manifest" ]]; then
  case "$profile" in
    java)
      runtime_manifest="base_image.runtime.manifest"
      ;;
    python)
      runtime_manifest="base_image.runtime.python.manifest"
      ;;
    node)
      runtime_manifest="base_image.runtime.node.manifest"
      ;;
    all)
      runtime_manifest="base_image.runtime.manifest"
      ;;
    *)
      echo "unknown profile: $profile" >&2
      exit 2
      ;;
  esac
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

kernel_elf64="target/x86_64-unknown-tos/release/tos"
kernel_elf32="target/tos_32.elf"
base_test_image="${TOS_BASE_TEST_IMG:-/tmp/tos_test.img}"
default_image="/tmp/tos_phase5_runtime.img"
default_log="/tmp/tos_phase5_runtime.log"

if [[ ! -f "$runtime_manifest" ]]; then
  echo "runtime manifest not found: $runtime_manifest" >&2
  exit 1
fi

if [[ -z "$image_path" ]]; then
  image_path="$default_image"
fi
if [[ -z "$log_path" ]]; then
  log_path="$default_log"
fi

export TOS_RUNTIME_MANIFEST="$runtime_manifest"
export TOS_RUNTIME_SMOKE_FOCUS="$runtime_focus"
export TOS_JAVA_SMOKE_FOCUS="$java_focus"

echo "[phase5] build: TOS_RUNTIME_MANIFEST=$TOS_RUNTIME_MANIFEST TOS_RUNTIME_SMOKE_FOCUS=$TOS_RUNTIME_SMOKE_FOCUS TOS_JAVA_SMOKE_FOCUS=$TOS_JAVA_SMOKE_FOCUS"
cargo build --release --target x86_64-unknown-tos.json

objcopy -I elf64-x86-64 -O elf32-i386 "$kernel_elf64" "$kernel_elf32"

if [[ "$build_only" -eq 1 ]]; then
  echo "[phase5] build-only complete: $kernel_elf32"
  exit 0
fi

if [[ ! -f "$base_test_image" ]]; then
  tools/create_test_disk.sh "$base_test_image"
fi

cp "$base_test_image" "$image_path"

qemu_exit=0
timeout "$qemu_timeout" \
  qemu-system-x86_64 \
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
  echo "[phase5] qemu failed: exit=$qemu_exit log=$log_path" >&2
  tail -40 "$log_path" >&2 || true
  exit "$qemu_exit"
fi

require_line() {
  local pattern="$1"
  if ! grep -aEq "$pattern" "$log_path"; then
    echo "[phase5] missing log pattern: $pattern" >&2
    tail -80 "$log_path" >&2 || true
    exit 1
  fi
}

require_line_after() {
  local start_pattern="$1"
  local follow_pattern="$2"
  local start_line
  start_line="$(grep -aEn -m1 "$start_pattern" "$log_path" | cut -d: -f1 || true)"
  if [[ -z "$start_line" ]]; then
    echo "[phase5] missing ordered log sequence start: $start_pattern" >&2
    tail -120 "$log_path" >&2 || true
    exit 1
  fi
  if ! python3 - "$log_path" "$start_line" "$follow_pattern" <<'PY'
import re
import sys

path = sys.argv[1]
start_line = int(sys.argv[2])
follow = re.compile(sys.argv[3].encode())

with open(path, "rb") as f:
    for lineno, line in enumerate(f, 1):
        if lineno <= start_line:
            continue
        if follow.search(line.rstrip(b"\n")):
            sys.exit(0)
sys.exit(1)
PY
  then
    echo "[phase5] missing ordered log sequence: $start_pattern -> $follow_pattern" >&2
    tail -120 "$log_path" >&2 || true
    exit 1
  fi
}

require_no_line_after() {
  local start_pattern="$1"
  local forbidden_pattern="$2"
  local start_line
  start_line="$(grep -aEn -m1 "$start_pattern" "$log_path" | cut -d: -f1 || true)"
  if [[ -z "$start_line" ]]; then
    echo "[phase5] missing ordered log sequence start: $start_pattern" >&2
    tail -120 "$log_path" >&2 || true
    exit 1
  fi
  if python3 - "$log_path" "$start_line" "$forbidden_pattern" <<'PY'
import re
import sys

path = sys.argv[1]
start_line = int(sys.argv[2])
forbidden = re.compile(sys.argv[3].encode())

with open(path, "rb") as f:
    for lineno, line in enumerate(f, 1):
        if lineno <= start_line:
            continue
        if forbidden.search(line.rstrip(b"\n")):
            sys.exit(0)
sys.exit(1)
PY
  then
    echo "[phase5] forbidden log pattern after start: $start_pattern -> $forbidden_pattern" >&2
    tail -120 "$log_path" >&2 || true
    exit 1
  fi
}

require_line '=== Results: 67 passed, 0 failed out of 62 syscalls ==='
require_line 'TOS-SIGNAL-OK'

case "$profile" in
  java)
    require_line 'TOS-JAVA-JAR payload=jar-ok'
    require_line '\[linux_compat\] exit_group: agent=[0-9]+ status=0'
    ;;
  python)
    require_line '\[PYTHON\] launching /usr/bin/python3( -S)? -c print\(1\)'
    require_line_after '\[PYTHON\] launching /usr/bin/python3( -S)? -c print\(1\)' '^1$'
    require_line '\[linux_compat\] exit_group: agent=[0-9]+ status=0'
    ;;
  node)
    require_line '\[NODE\] launching /usr/bin/node -e console\.log\(1\)'
    require_line_after '\[NODE\] launching /usr/bin/node -e console\.log\(1\)' '^1$'
    require_line_after '\[NODE\] launching /usr/bin/node -e console\.log\(1\)' '\[linux_compat\] exit_group: agent=[0-9]+ status=0'
    require_no_line_after '\[NODE\] launching /usr/bin/node -e console\.log\(1\)' 'terminated by SIG|exit_group: agent=[0-9]+ status=134'
    ;;
  all)
    require_line '\[PYTHON\] launching /usr/bin/python3( -S)? -c print\(1\)'
    require_line_after '\[PYTHON\] launching /usr/bin/python3( -S)? -c print\(1\)' '^1$'
    require_line '\[NODE\] launching /usr/bin/node -e console\.log\(1\)'
    require_line_after '\[NODE\] launching /usr/bin/node -e console\.log\(1\)' '^1$'
    require_line 'TOS-JAVA-JAR payload=jar-ok'
    require_line_after '\[NODE\] launching /usr/bin/node -e console\.log\(1\)' '\[linux_compat\] exit_group: agent=[0-9]+ status=0'
    require_no_line_after '\[NODE\] launching /usr/bin/node -e console\.log\(1\)' 'terminated by SIG|exit_group: agent=[0-9]+ status=134'
    ;;
  *)
    echo "unknown profile: $profile" >&2
    exit 2
    ;;
esac

echo "[phase5] validation passed: profile=$profile manifest=$runtime_manifest log=$log_path"

if [[ "$keep_artifacts" -eq 0 ]]; then
  rm -f "$image_path" "$log_path"
fi
