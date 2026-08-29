#!/usr/bin/env bash
# Build the locked OpenFox source twice and require the locked binary bytes.
set -euo pipefail
umask 022

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
SRC="${OPENFOX_SRC:-$HOME/openfox}"
EXPECTED_COMMIT="6b997b638b7a99dd95f56bf6f35e91557f1cf7cf"
EXPECTED_GO="go1.25.13"
TEMP="$(mktemp -d)"
trap 'rm -rf "$TEMP"' EXIT

if [ "$(git -C "$SRC" rev-parse HEAD)" != "$EXPECTED_COMMIT" ] || \
   [ -n "$(git -C "$SRC" status --porcelain)" ]; then
    echo "OpenFox source must be clean at $EXPECTED_COMMIT" >&2
    exit 1
fi
if [ "$(GOTOOLCHAIN=local go env GOVERSION)" != "$EXPECTED_GO" ]; then
    echo "OpenFox reproducibility gate requires $EXPECTED_GO" >&2
    exit 1
fi
EXPECTED_SHA="$(python3 - "$ROOT/workloads/LOCK.json" <<'PY'
import json, sys
lock = json.load(open(sys.argv[1]))
item = next(item for item in lock["workloads"] if item["id"] == "openfox")
print(item["files"][0]["sha256"])
PY
)"

build() {
    local output="$1"
    (
        cd "$SRC"
        GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
            go build -mod=readonly -trimpath -tags goolm,stdjson \
            -o "$output" ./cmd/openfox
    )
}

TZ=Pacific/Honolulu build "$TEMP/a"
TZ=Asia/Tokyo build "$TEMP/b"
cmp "$TEMP/a" "$TEMP/b"
ACTUAL_SHA="$(sha256sum "$TEMP/a" | awk '{print $1}')"
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    echo "OpenFox bytes are $ACTUAL_SHA, expected $EXPECTED_SHA" >&2
    exit 1
fi
echo "Reproducible OpenFox: $ACTUAL_SHA"
