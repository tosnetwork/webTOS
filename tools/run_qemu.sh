#!/bin/bash
# Run TOS kernel in QEMU with serial output to stdio
set -e

KERNEL="${1:-target/x86_64-unknown-tos/debug/tos}"
QEMU_MEMORY="${QEMU_MEMORY:-1024M}"

if [ ! -f "$KERNEL" ]; then
    echo "Kernel binary not found: $KERNEL"
    echo "Run 'cargo build' first."
    exit 1
fi

exec qemu-system-x86_64 \
    -m "$QEMU_MEMORY" \
    -serial stdio \
    -display none \
    -kernel "$KERNEL" \
    -no-reboot \
    -no-shutdown
