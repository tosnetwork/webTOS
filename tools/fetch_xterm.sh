#!/usr/bin/env bash
# Fetches the pinned terminal emulator used by the browser terminal demo into
# web/vendor/xterm/ (gitignored; xterm.js is MIT-licensed and is not part of
# this repository). web/terminal.html reports the missing dependency and does
# nothing when it is absent.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="6.0.0"
CORE_URL="https://registry.npmjs.org/@xterm/xterm/-/xterm-${VERSION}.tgz"
CORE_SHA256="908e66e04af6c8dc6b00dd3b54de088e2e81e5ed866284fd6c2fb3c2d1c7a3f6"
FIT_VERSION="0.11.0"
FIT_URL="https://registry.npmjs.org/@xterm/addon-fit/-/addon-fit-${FIT_VERSION}.tgz"
FIT_SHA256="26003b4517a132b64e4ff228fd88a5fda3fff5e606c76093f6dcff772e9ecec0"
OUT_DIR="web/vendor/xterm"

if [ -f "$OUT_DIR/xterm.js" ] && [ -f "$OUT_DIR/xterm.css" ] && [ -f "$OUT_DIR/addon-fit.js" ]; then
    echo "$OUT_DIR already present."
    exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
curl -fsSL -o "$TMP/xterm.tgz" "$CORE_URL"
echo "$CORE_SHA256  $TMP/xterm.tgz" | sha256sum -c --quiet
curl -fsSL -o "$TMP/fit.tgz" "$FIT_URL"
echo "$FIT_SHA256  $TMP/fit.tgz" | sha256sum -c --quiet

mkdir -p "$TMP/core" "$TMP/fit" "$OUT_DIR"
tar -xzf "$TMP/xterm.tgz" -C "$TMP/core" package/lib/xterm.js package/css/xterm.css package/LICENSE
tar -xzf "$TMP/fit.tgz" -C "$TMP/fit" package/lib/addon-fit.js package/LICENSE
cp "$TMP/core/package/lib/xterm.js" "$OUT_DIR/xterm.js"
cp "$TMP/core/package/css/xterm.css" "$OUT_DIR/xterm.css"
cp "$TMP/core/package/LICENSE" "$OUT_DIR/LICENSE"
cp "$TMP/fit/package/lib/addon-fit.js" "$OUT_DIR/addon-fit.js"
cp "$TMP/fit/package/LICENSE" "$OUT_DIR/LICENSE.addon-fit"
echo "Fetched and verified $OUT_DIR (xterm.js ${VERSION} + addon-fit ${FIT_VERSION}, MIT)."
