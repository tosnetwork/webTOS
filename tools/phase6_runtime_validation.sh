#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tools/phase6_runtime_validation.sh [options]

Run the Phase-6 runtime validation matrix for one runtime family or all
families. This reuses the existing Phase-5 build/QEMU flow and adds checks for
the new child-process and multi-threaded smokes.

Options:
  --runtime-manifest PATH   Host-specific runtime manifest to embed
  --profile NAME            Validation profile: java, python, node, all
                            (default: all)
  --qemu-timeout SECONDS    QEMU timeout in seconds
                            (default: java -> 75, others -> 60)
  --qemu-memory SIZE        Guest RAM size passed to QEMU
                            (default: java -> 1024M, node -> 2048M, others -> 512M)
  --image PATH              Reuse or write the disk image at PATH
  --log PATH                Write the QEMU serial log to PATH
  --keep-artifacts          Keep generated image/log artifacts
  -h, --help                Show this help
EOF
}

profile="all"
runtime_manifest="${TOS_RUNTIME_MANIFEST:-}"
qemu_timeout="${QEMU_TIMEOUT:-}"
qemu_memory="${QEMU_MEMORY:-}"
image_path=""
log_path=""
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

default_manifest_for_profile() {
  case "$1" in
    java) echo "base_image.runtime.manifest" ;;
    python) echo "base_image.runtime.python.manifest" ;;
    node) echo "base_image.runtime.node.manifest" ;;
    *)
      echo "unknown profile: $1" >&2
      exit 2
      ;;
  esac
}

default_memory_for_profile() {
  case "$1" in
    java) echo "1024M" ;;
    node) echo "2048M" ;;
    *) echo "512M" ;;
  esac
}

default_timeout_for_profile() {
  case "$1" in
    java) echo "75" ;;
    *) echo "60" ;;
  esac
}

require_line() {
  local pattern="$1"
  local log="$2"
  if ! grep -aEq "$pattern" "$log"; then
    echo "[phase6] missing log pattern: $pattern" >&2
    tail -120 "$log" >&2 || true
    exit 1
  fi
}

require_no_line() {
  local pattern="$1"
  local log="$2"
  if grep -aEq "$pattern" "$log"; then
    echo "[phase6] forbidden log pattern: $pattern" >&2
    tail -120 "$log" >&2 || true
    exit 1
  fi
}

validate_phase6_log() {
  local current_profile="$1"
  local log="$2"

  require_no_line 'Page fault|GP fault|TRAP|panic|SIGABRT' "$log"

  case "$current_profile" in
    java)
      require_line 'TOS-JAVA-JAR payload=jar-ok' "$log"
      require_line 'TOS-JAVA-CHILD line=.* status=0' "$log"
      require_line 'TOS-JAVA-THREAD-OK total=[0-9]+' "$log"
      ;;
    python)
      require_line '\[PYTHON\] launching python child-process smoke' "$log"
      require_line 'TOS-PY-CHILD exit=7 status=0' "$log"
      ;;
    node)
      require_line '\[NODE\] launching node child-process smoke' "$log"
      require_line 'TOS-NODE-CHILD stdout=7 status=0' "$log"
      require_line '\[NODE\] launching node thread smoke' "$log"
      require_line 'TOS-NODE-THREAD-OK total=[0-9]+' "$log"
      ;;
    *)
      echo "unknown profile: $current_profile" >&2
      exit 2
      ;;
  esac
}

run_profile() {
  local current_profile="$1"
  local current_manifest="$runtime_manifest"
  local current_image="$image_path"
  local current_log="$log_path"

  if [[ -z "$current_manifest" ]]; then
    current_manifest="$(default_manifest_for_profile "$current_profile")"
  fi
  if [[ -z "$qemu_timeout" ]]; then
    qemu_timeout="$(default_timeout_for_profile "$current_profile")"
  fi
  if [[ -z "$qemu_memory" ]]; then
    qemu_memory="$(default_memory_for_profile "$current_profile")"
  fi
  if [[ -z "$current_image" ]]; then
    current_image="/tmp/tos_phase6_${current_profile}.img"
  fi
  if [[ -z "$current_log" ]]; then
    current_log="/tmp/tos_phase6_${current_profile}.log"
  fi

  if [[ "$current_profile" == "java" ]]; then
    TOS_JAVA_SMOKE_FOCUS="${TOS_JAVA_SMOKE_FOCUS:-phase6}" \
      tools/phase5_runtime_validation.sh \
        --profile "$current_profile" \
        --runtime-manifest "$current_manifest" \
        --qemu-timeout "$qemu_timeout" \
        --qemu-memory "$qemu_memory" \
        --image "$current_image" \
        --log "$current_log" \
        --keep-artifacts
  else
    tools/phase5_runtime_validation.sh \
      --profile "$current_profile" \
      --runtime-manifest "$current_manifest" \
      --qemu-timeout "$qemu_timeout" \
      --qemu-memory "$qemu_memory" \
      --image "$current_image" \
      --log "$current_log" \
      --keep-artifacts
  fi

  validate_phase6_log "$current_profile" "$current_log"
  echo "[phase6] validation passed: profile=$current_profile manifest=$current_manifest log=$current_log"

  if [[ "$keep_artifacts" -eq 0 ]]; then
    rm -f "$current_image" "$current_log"
  fi
}

case "$profile" in
  all)
    run_profile java
    run_profile python
    run_profile node
    echo "[phase6] all runtime profiles passed"
    ;;
  java|python|node)
    run_profile "$profile"
    ;;
  *)
    echo "unknown profile: $profile" >&2
    exit 2
    ;;
esac
