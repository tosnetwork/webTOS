#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tools/node_api_validation.sh [options]

Run the Node.js API-subset validation on top of the existing runtime matrix.

Options:
  --runtime-manifest PATH   Host-specific runtime manifest to embed
                            (default: base_image.runtime.node.manifest)
  --qemu-timeout SECONDS    QEMU timeout in seconds (default: 90)
  --qemu-memory SIZE        Guest RAM size passed to QEMU (default: 2048M)
  --image PATH              Reuse or write the disk image at PATH
  --log PATH                Write the QEMU serial log to PATH
  --keep-artifacts          Keep generated image/log artifacts
  -h, --help                Show this help
EOF
}

runtime_manifest="${TOS_RUNTIME_MANIFEST:-base_image.runtime.node.manifest}"
qemu_timeout="${QEMU_TIMEOUT:-90}"
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

if [[ -z "$image_path" ]]; then
  image_path="/tmp/tos_node_api_validation.img"
fi
if [[ -z "$log_path" ]]; then
  log_path="/tmp/tos_node_api_validation.log"
fi

tools/phase6_runtime_validation.sh \
  --profile node \
  --runtime-manifest "$runtime_manifest" \
  --qemu-timeout "$qemu_timeout" \
  --qemu-memory "$qemu_memory" \
  --image "$image_path" \
  --log "$log_path" \
  --keep-artifacts

require_line() {
  local pattern="$1"
  if ! grep -aEq "$pattern" "$log_path"; then
    echo "[node-api] missing log pattern: $pattern" >&2
    tail -120 "$log_path" >&2 || true
    exit 1
  fi
}

require_no_line() {
  local pattern="$1"
  if grep -aEq "$pattern" "$log_path"; then
    echo "[node-api] forbidden log pattern: $pattern" >&2
    tail -120 "$log_path" >&2 || true
    exit 1
  fi
}

require_no_line 'TOS-NODE-API-FAIL|TOS-NODE-THREAD-FAIL'
require_line '\[NODE\] launching node child-process smoke'
require_line 'TOS-NODE-FS-OK entries=[0-9]+ bytes=[0-9]+'
require_line 'TOS-NODE-PATH-OK relative='
require_line 'TOS-NODE-CHILD stdout=7 status=0'
require_line 'TOS-NODE-CHILD-ENV-OK value=ready:PIPE'
require_line 'TOS-NODE-TIMER-OK'
require_line 'TOS-NODE-IMMEDIATE-OK'
require_line 'TOS-NODE-STREAM-OK bytes=[0-9]+'
require_line 'TOS-NODE-NET-OK bytes=[0-9]+'
require_line 'TOS-NODE-THREAD-MSG-OK workers=[0-9]+'
require_line 'TOS-NODE-THREAD-OK total=[0-9]+'
require_line 'TOS-NODE-API-OK'

echo "[node-api] validation passed: log=$log_path"

if [[ "$keep_artifacts" -eq 0 ]]; then
  rm -f "$image_path" "$log_path"
fi
