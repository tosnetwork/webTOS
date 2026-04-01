#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

run_profile() {
  local profile="$1"
  local timeout="${2:-45}"
  local image="/tmp/atos_phase5_${profile}.img"
  local log="/tmp/atos_phase5_${profile}.log"

  echo "[phase5-matrix] running profile=${profile} timeout=${timeout}s"
  tools/phase5_runtime_validation.sh \
    --profile "$profile" \
    --qemu-timeout "$timeout" \
    --image "$image" \
    --log "$log" \
    --keep-artifacts
}

run_profile java 45
run_profile python 45
run_profile node 45

echo "[phase5-matrix] all runtime profiles passed"
