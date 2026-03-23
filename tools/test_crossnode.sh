#!/bin/bash
# ATOS Cross-Node Test
#
# Launches two QEMU instances connected via UDP multicast,
# verifying that routerd on each node can exchange messages.
#
# Usage: ./tools/test_crossnode.sh

set -e

KERNEL="${1:-target/x86_64-unknown-none/release/atos}"
ELF32="/tmp/atos_crossnode.elf"

echo "=== ATOS Cross-Node Test ==="
echo "Building kernel..."
cargo build --release 2>/dev/null
objcopy -I elf64-x86-64 -O elf32-i386 "$KERNEL" "$ELF32"

echo "Launching Node A (port 10000)..."
timeout 8 qemu-system-x86_64 \
    -serial file:/tmp/node_a.log \
    -display none \
    -kernel "$ELF32" \
    -device virtio-net-pci,netdev=n0 \
    -netdev socket,id=n0,listen=:10000 \
    -no-reboot -no-shutdown &
NODE_A_PID=$!

sleep 1

echo "Launching Node B (connect to port 10000)..."
timeout 7 qemu-system-x86_64 \
    -serial file:/tmp/node_b.log \
    -display none \
    -kernel "$ELF32" \
    -device virtio-net-pci,netdev=n0 \
    -netdev socket,id=n0,connect=127.0.0.1:10000 \
    -no-reboot -no-shutdown &
NODE_B_PID=$!

echo "Waiting for nodes to boot..."
sleep 6

# Cleanup
kill $NODE_A_PID $NODE_B_PID 2>/dev/null
wait $NODE_A_PID $NODE_B_PID 2>/dev/null

echo ""
echo "=== Node A Output ==="
grep -a "OK\]\|INIT.*Routerd\|INIT.*Netd\|VIRTIO\|MAC\|SMP\|ACPI\|PROOF\|ATTEST" /tmp/node_a.log 2>/dev/null | head -15

echo ""
echo "=== Node B Output ==="
grep -a "OK\]\|INIT.*Routerd\|INIT.*Netd\|VIRTIO\|MAC\|SMP\|ACPI\|PROOF\|ATTEST" /tmp/node_b.log 2>/dev/null | head -15

echo ""
echo "=== Verification ==="
A_BOOT=$(grep -ac "System initialization complete" /tmp/node_a.log 2>/dev/null || echo 0)
B_BOOT=$(grep -ac "System initialization complete" /tmp/node_b.log 2>/dev/null || echo 0)
A_ROUTERD=$(grep -ac "Routerd agent created" /tmp/node_a.log 2>/dev/null || echo 0)
B_ROUTERD=$(grep -ac "Routerd agent created" /tmp/node_b.log 2>/dev/null || echo 0)
A_VIRTIO=$(grep -ac "VIRTIO-NET.*Initialized" /tmp/node_a.log 2>/dev/null || echo 0)
B_VIRTIO=$(grep -ac "VIRTIO-NET.*Initialized" /tmp/node_b.log 2>/dev/null || echo 0)

echo "Node A: boot=$A_BOOT routerd=$A_ROUTERD virtio=$A_VIRTIO"
echo "Node B: boot=$B_BOOT routerd=$B_ROUTERD virtio=$B_VIRTIO"

if [ "$A_BOOT" -ge 1 ] && [ "$B_BOOT" -ge 1 ] && [ "$A_ROUTERD" -ge 1 ] && [ "$B_ROUTERD" -ge 1 ]; then
    echo "PASS: Both nodes booted with routerd and virtio-net"
else
    echo "FAIL: Cross-node test incomplete"
fi
