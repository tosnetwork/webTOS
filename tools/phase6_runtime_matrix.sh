#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

run_profile() {
  local profile="$1"
  local timeout="${2:-60}"
  local image="/tmp/tos_phase6_${profile}.img"
  local log="/tmp/tos_phase6_${profile}.log"

  echo "[phase6-matrix] running profile=${profile} timeout=${timeout}s"
  tools/phase6_runtime_validation.sh \
    --profile "$profile" \
    --qemu-timeout "$timeout" \
    --image "$image" \
    --log "$log" \
    --keep-artifacts
}

run_profile java 60
run_profile python 60
run_profile node 60

echo "[phase6-matrix] all runtime profiles passed"
