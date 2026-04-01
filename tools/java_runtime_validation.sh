#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tools/java_runtime_validation.sh [options]

Run the current TOS Java runtime smoke package end-to-end. This is the
practical Java API and stability harness that exists today, before a guest-side
jtreg bundle is embedded.

The harness validates these Java smoke paths in one boot:
  - java -version
  - Hello.class classpath launch
  - java.nio.file / java.io filesystem probe
  - java -jar resource loading
  - ProcessBuilder child-process launch
  - Thread / CountDownLatch / AtomicLong concurrency smoke

Options:
  --runtime-manifest PATH   Runtime manifest to embed
                            (default: base_image.runtime.manifest)
  --qemu-timeout SECONDS    QEMU timeout in seconds (default: 90)
  --qemu-memory SIZE        Guest RAM size (default: 1024M)
  --image PATH              Disk image path
  --log PATH                Serial log path
  --repeat N                Repeat the full validation N times (default: 1)
  --keep-artifacts          Keep generated image/log artifacts
  -h, --help                Show this help

Related planning asset:
  tools/jtreg-java-base-whitelist.txt
EOF
}

runtime_manifest="${TOS_RUNTIME_MANIFEST:-base_image.runtime.manifest}"
qemu_timeout="${QEMU_TIMEOUT:-90}"
qemu_memory="${QEMU_MEMORY:-1024M}"
image_path=""
log_path=""
repeat_count=1
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
    --repeat)
      repeat_count="$2"
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

if [[ ! -f "$runtime_manifest" ]]; then
  echo "runtime manifest not found: $runtime_manifest" >&2
  exit 1
fi

if ! [[ "$repeat_count" =~ ^[1-9][0-9]*$ ]]; then
  echo "repeat count must be a positive integer: $repeat_count" >&2
  exit 2
fi

require_line() {
  local pattern="$1"
  local log="$2"
  if ! grep -aEq "$pattern" "$log"; then
    echo "[java-test] missing log pattern: $pattern" >&2
    tail -120 "$log" >&2 || true
    exit 1
  fi
}

require_no_line() {
  local pattern="$1"
  local log="$2"
  if grep -aEq "$pattern" "$log"; then
    echo "[java-test] forbidden log pattern: $pattern" >&2
    tail -120 "$log" >&2 || true
    exit 1
  fi
}

validate_java_log() {
  local log="$1"

  require_no_line 'Page fault|GP fault|TRAP|panic|SIGABRT|KERNEL PANIC' "$log"
  require_no_line '\[linux_compat\] exit_group: agent=[0-9]+ status=[1-9][0-9]*' "$log"
  require_line 'openjdk version "11\.[0-9]+\.[0-9]+"' "$log"
  require_line 'TOS-JAVA-HELLO' "$log"
  require_line 'TOS-JAVA-FS count=[0-9]+' "$log"
  require_line 'TOS-JAVA-FS first=' "$log"
  require_line 'TOS-JAVA-JAR payload=jar-ok' "$log"
  require_line 'TOS-JAVA-CHILD line=.* status=0' "$log"
  require_line 'TOS-JAVA-THREAD-OK total=[0-9]+' "$log"
  require_line '\[linux_compat\] exit_group: agent=[0-9]+ status=0' "$log"
}

for run_idx in $(seq 1 "$repeat_count"); do
  current_image="${image_path:-/tmp/tos_java_validation_${run_idx}.img}"
  current_log="${log_path:-/tmp/tos_java_validation_${run_idx}.log}"

  echo "[java-test] run=${run_idx}/${repeat_count} manifest=${runtime_manifest} memory=${qemu_memory} timeout=${qemu_timeout}s"

  TOS_JAVA_SMOKE_FOCUS=full \
    tools/phase5_runtime_validation.sh \
      --profile java \
      --runtime-manifest "$runtime_manifest" \
      --qemu-timeout "$qemu_timeout" \
      --qemu-memory "$qemu_memory" \
      --image "$current_image" \
      --log "$current_log" \
      --keep-artifacts

  validate_java_log "$current_log"
  echo "[java-test] validation passed: run=${run_idx} log=${current_log}"

  if [[ "$keep_artifacts" -eq 0 ]]; then
    rm -f "$current_image" "$current_log"
  fi
done

echo "[java-test] all runs passed"
