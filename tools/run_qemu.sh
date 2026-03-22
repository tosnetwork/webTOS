#!/bin/bash
# Run AOS kernel in QEMU with serial output to stdio
set -e

KERNEL="${1:-target/x86_64-unknown-none/debug/aos0}"

if [ ! -f "$KERNEL" ]; then
    echo "Kernel binary not found: $KERNEL"
    echo "Run 'cargo build' first."
    exit 1
fi

exec qemu-system-x86_64 \
    -serial stdio \
    -display none \
    -kernel "$KERNEL" \
    -no-reboot \
    -no-shutdown
