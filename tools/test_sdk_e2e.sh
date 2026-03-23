#!/bin/bash
# SDK End-to-End Test
# Builds a WASM agent from source, validates it, and verifies CLI tools work
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== AOS SDK End-to-End Test ==="
echo "Repo: $REPO_ROOT"
echo ""

# 1. Build WASM agent from source
echo "[1/4] Building WASM agent with aos-wasm-sdk..."
cd "$REPO_ROOT/sdk/aos-wasm-sdk"
cargo build --target wasm32-unknown-unknown --release --example hello 2>/dev/null
WASM="$REPO_ROOT/sdk/aos-wasm-sdk/target/wasm32-unknown-unknown/release/examples/hello.wasm"
if [ -f "$WASM" ]; then
    SIZE=$(stat -c%s "$WASM")
    echo "  PASS  WASM agent built: hello.wasm ($SIZE bytes)"
else
    echo "  FAIL  WASM build produced no output"
    exit 1
fi

# Verify WASM magic bytes (\0asm)
MAGIC=$(xxd -l 4 "$WASM" | awk '{print $2$3}' | tr -d ' ')
if [[ "$MAGIC" == "0061736d" ]]; then
    echo "  PASS  WASM magic bytes valid (\\0asm)"
else
    echo "  FAIL  Bad WASM magic: $MAGIC"
    exit 1
fi

# Enforce AOS 64 KB code size limit
if [ "$SIZE" -gt 65536 ]; then
    echo "  FAIL  WASM binary exceeds AOS 64 KB limit ($SIZE bytes)"
    exit 1
else
    echo "  PASS  Size within AOS 64 KB limit"
fi

# 2. Build aos-cli and validate binary with deploy command
echo ""
echo "[2/4] Building aos-cli and validating WASM binary..."
cd "$REPO_ROOT/sdk/aos-cli"
cargo build --release 2>/dev/null

# The build target depends on the host; find the binary
CLI=$(find "$REPO_ROOT/sdk/aos-cli/target" -name "aos" -type f | head -1)
if [ -z "$CLI" ]; then
    echo "  FAIL  aos CLI binary not found after build"
    exit 1
fi
echo "  PASS  aos CLI built: $CLI"

DEPLOY_OUT=$("$CLI" deploy "$WASM" 2>&1)
if echo "$DEPLOY_OUT" | grep -q "\[aos-deploy\] WASM version: 1"; then
    echo "  PASS  aos deploy validated WASM (version 1)"
else
    echo "  FAIL  aos deploy did not recognise WASM binary"
    echo "$DEPLOY_OUT"
    exit 1
fi

SECTIONS=$(echo "$DEPLOY_OUT" | grep "Sections:" | awk '{print $NF}')
echo "  PASS  WASM sections parsed: $SECTIONS"

# 3. Verify proof / verify sub-command is present
echo ""
echo "[3/4] Verifying CLI sub-commands are present..."
USAGE=$("$CLI" --help 2>&1 || true)
for CMD in build deploy replay inspect verify; do
    if echo "$USAGE" | grep -q "$CMD"; then
        echo "  PASS  Command present: $CMD"
    else
        echo "  FAIL  Missing command: $CMD"
        exit 1
    fi
done

# 4. Verify aos-sdk (native) compiles cleanly
echo ""
echo "[4/4] Building aos-sdk (native agent SDK)..."
cd "$REPO_ROOT/sdk/aos-sdk"
cargo build --release 2>/dev/null
echo "  PASS  aos-sdk compiled"

# Summary
echo ""
echo "==================================================="
echo "=== AOS SDK End-to-End Test: ALL CHECKS PASSED ==="
echo "==================================================="
echo ""
echo "Artifacts:"
echo "  WASM agent : $WASM"
echo "  CLI binary : $CLI"
