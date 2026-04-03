#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

tools/phase6_runtime_matrix.sh
tools/java_runtime_validation.sh
tools/python_api_validation.sh
tools/node_api_validation.sh
tools/userland_env_validation.sh

echo "[linux-maturity] validation passed"
