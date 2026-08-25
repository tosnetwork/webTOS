#!/usr/bin/env bash
# Builds the webTOS wasm engine and stages the demo page's assets in web/.
set -euo pipefail
cd "$(dirname "$0")/.."

(cd crates && cargo build -p webtos-web --target wasm32-unknown-unknown --release)
cp crates/target/wasm32-unknown-unknown/release/webtos_web.wasm web/
cp test_data/hello_linux.elf web/

echo "Staged web/webtos_web.wasm and web/hello_linux.elf."
echo "Serve with:  python3 -m http.server -d web 8080"
echo "Then open:   http://localhost:8080/"
