#!/usr/bin/env bash
# Build the release twice in isolated target directories and compare bytes.
set -euo pipefail
umask 022

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
FINAL_OUT="$ROOT/dist"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ALLOW_DIRTY="${WEBTOS_RELEASE_ALLOW_DIRTY:-0}"
ALLOW_NONCANONICAL_HOST="${WEBTOS_RELEASE_ALLOW_NONCANONICAL_HOST:-0}"
if [ "$ALLOW_DIRTY" != "1" ] && [ -n "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]; then
    echo "reproducibility gate requires a clean worktree" >&2
    exit 1
fi
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
EPOCH="$(git -C "$ROOT" show -s --format=%ct "$COMMIT")"

# Fetch is deliberately separate from the frozen builds. Both builds below
# run without dependency resolution or network access.
(
    cd "$ROOT/crates"
    cargo fetch --locked --target wasm32-unknown-unknown
)

WEBTOS_RELEASE_ALLOW_DIRTY="$ALLOW_DIRTY" \
WEBTOS_RELEASE_ALLOW_NONCANONICAL_HOST="$ALLOW_NONCANONICAL_HOST" \
RUSTFLAGS="-C opt-level=0" \
CARGO_TARGET_DIR="$TMP/poison-target" \
CARGO_PROFILE_RELEASE_OPT_LEVEL=0 \
TZ=Pacific/Honolulu \
    "$ROOT/tools/build_release.sh" \
        --source-commit "$COMMIT" \
        --source-epoch "$EPOCH" \
        --out-dir "$TMP/out-a" \
        --target-dir "$TMP/target-a"

WEBTOS_RELEASE_ALLOW_DIRTY="$ALLOW_DIRTY" \
WEBTOS_RELEASE_ALLOW_NONCANONICAL_HOST="$ALLOW_NONCANONICAL_HOST" \
TZ=Asia/Tokyo \
    "$ROOT/tools/build_release.sh" \
        --source-commit "$COMMIT" \
        --source-epoch "$EPOCH" \
        --out-dir "$TMP/out-b" \
        --target-dir "$TMP/target-b"

ARCHIVE_A="$(find "$TMP/out-a" -maxdepth 1 -name 'webtos-runtime-*.tar' -type f -print -quit)"
ARCHIVE_B="$TMP/out-b/$(basename "$ARCHIVE_A")"
cmp "$ARCHIVE_A" "$ARCHIVE_B"
cmp "$ARCHIVE_A.sha256" "$ARCHIVE_B.sha256"
python3 "$ROOT/tools/package_release.py" verify "$ARCHIVE_A"
python3 "$ROOT/tools/package_release.py" verify "$ARCHIVE_B"

mkdir -p "$FINAL_OUT"
cp "$ARCHIVE_A" "$FINAL_OUT/"
cp "$ARCHIVE_A.sha256" "$FINAL_OUT/"
echo "Reproducible: $(basename "$ARCHIVE_A")"
cat "$ARCHIVE_A.sha256"
