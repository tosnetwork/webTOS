#!/usr/bin/env bash
# Builds the webTOS wasm engine and stages the demo page's assets in web/.
set -euo pipefail
cd "$(dirname "$0")/.."

(cd crates && cargo build -p webtos-web --target wasm32-unknown-unknown --release)
cp crates/target/wasm32-unknown-unknown/release/webtos_web.wasm web/
cp test_data/hello_linux.elf web/
if [ -f test_data/busybox-musl ]; then
    cp test_data/busybox-musl web/
else
    echo "note: test_data/busybox-musl missing; run tools/fetch_busybox.sh for the BusyBox demo"
fi
if [ -f test_data/openfox ]; then
    cp test_data/openfox web/
fi
if [ ! -f web/vendor/xterm/xterm.js ]; then
    echo "note: web/vendor/xterm missing; run tools/fetch_xterm.sh for the terminal demo"
fi

echo "Staged web/webtos_web.wasm and guest images."
echo "Serve with:  python3 -m http.server -d web 8080"
echo "Then open:   http://localhost:8080/           (one-shot commands)"
echo "             http://localhost:8080/terminal.html  (interactive shell)"
