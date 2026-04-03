#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

log_path="${1:-/tmp/tos_python_api.log}"
image_path="${2:-/tmp/tos_python_api.img}"
manifest_path="${3:-/tmp/tos_python_api.manifest}"

python3 tools/generate_runtime_manifest.py \
  --output "$manifest_path" \
  --runtimes python \
  --python-stdlib full \
  --linux-tools minimal

TOS_PYTHON_SMOKE_FOCUS=full \
  tools/phase5_runtime_validation.sh \
    --profile python \
    --runtime-manifest "$manifest_path" \
    --qemu-timeout 75 \
    --qemu-memory 1024M \
    --log "$log_path" \
    --image "$image_path" \
    --keep-artifacts

require_line() {
  local pattern="$1"
  if ! grep -aEq "$pattern" "$log_path"; then
    echo "[python-api] missing log pattern: $pattern" >&2
    tail -120 "$log_path" >&2 || true
    exit 1
  fi
}

require_no_line() {
  local pattern="$1"
  if grep -aEq "$pattern" "$log_path"; then
    echo "[python-api] forbidden log pattern: $pattern" >&2
    tail -120 "$log_path" >&2 || true
    exit 1
  fi
}

require_no_line 'Traceback \(most recent call last\)|ModuleNotFoundError|AssertionError'
require_line 'TOS-PY-API os=ok'
require_line 'TOS-PY-API io=ok'
require_line 'TOS-PY-API pathlib=ok'
require_line 'TOS-PY-API filesystem=ok'
require_line 'TOS-PY-API subprocess=ok'
require_line 'TOS-PY-API mmap=(ok|skip)'
require_line 'TOS-PY-API signal=ok'
require_line 'TOS-PY-API socket=(ok|skip)'
require_line 'TOS-PY-API threading=ok'
require_line 'TOS-PY-API queue=ok'
require_line 'TOS-PY-API-OK total=10'

echo "[python-api] validation passed: log=$log_path"
