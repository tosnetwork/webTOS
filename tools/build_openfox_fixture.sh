#!/usr/bin/env bash
# Builds the OpenFox milestone-6 workload fixture into test_data/ (gitignored;
# OpenFox is its own repository). The build is static (CGO disabled, pure-Go
# olm) so the guest needs no shared libraries. Tests skip when absent.
set -euo pipefail
cd "$(dirname "$0")/.."

SRC="${OPENFOX_SRC:-$HOME/openfox}"
OUT="test_data/openfox"

if [ ! -f "$SRC/go.mod" ]; then
    echo "OpenFox source not found at $SRC (set OPENFOX_SRC)" >&2
    exit 1
fi

COMMIT=$(git -C "$SRC" rev-parse HEAD)
if [ -n "$(git -C "$SRC" status --porcelain)" ]; then
    COMMIT="$COMMIT-dirty"
fi

(cd "$SRC" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -tags goolm,stdjson -o "$OLDPWD/$OUT" ./cmd/openfox)
echo "$COMMIT" > "$OUT.commit"
echo "Built $OUT from $SRC @ $COMMIT ($(du -h "$OUT" | cut -f1))"
