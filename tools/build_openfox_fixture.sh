#!/usr/bin/env bash
# Builds the OpenFox milestone-6 workload fixture into test_data/ (gitignored;
# OpenFox is its own repository). The build is static (CGO disabled, pure-Go
# olm) so the guest needs no shared libraries. Tests skip when absent.
set -euo pipefail
cd "$(dirname "$0")/.."

SRC="${OPENFOX_SRC:-$HOME/openfox}"
OUT="test_data/openfox"
EXPECTED_COMMIT="6b997b638b7a99dd95f56bf6f35e91557f1cf7cf"
EXPECTED_GO="go1.25.13"

if [ ! -f "$SRC/go.mod" ]; then
    echo "OpenFox source not found at $SRC (set OPENFOX_SRC)" >&2
    exit 1
fi

COMMIT=$(git -C "$SRC" rev-parse HEAD)
if [ "$COMMIT" != "$EXPECTED_COMMIT" ] || [ -n "$(git -C "$SRC" status --porcelain)" ]; then
    echo "OpenFox source must be clean at $EXPECTED_COMMIT, found $COMMIT" >&2
    exit 1
fi
if [ "$(GOTOOLCHAIN=local go env GOVERSION)" != "$EXPECTED_GO" ]; then
    echo "OpenFox fixture requires $EXPECTED_GO, found $(GOTOOLCHAIN=local go env GOVERSION)" >&2
    exit 1
fi

EXPECTED_SHA="$(python3 - "$PWD/workloads/LOCK.json" <<'PY'
import json, sys
lock = json.load(open(sys.argv[1]))
item = next(item for item in lock["workloads"] if item["id"] == "openfox")
print(item["files"][0]["sha256"])
PY
)"
TEMP="$(mktemp)"
trap 'rm -f "$TEMP"' EXIT

(cd "$SRC" && GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -mod=readonly -trimpath -tags goolm,stdjson -o "$TEMP" ./cmd/openfox)
ACTUAL_SHA="$(sha256sum "$TEMP" | awk '{print $1}')"
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    echo "OpenFox bytes are $ACTUAL_SHA, expected $EXPECTED_SHA" >&2
    exit 1
fi
chmod 0755 "$TEMP"
mv "$TEMP" "$OUT"
trap - EXIT
echo "$COMMIT" > "$OUT.commit"
echo "Built $OUT from $SRC @ $COMMIT ($(du -h "$OUT" | cut -f1))"
