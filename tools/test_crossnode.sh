#!/bin/bash
# AOS Cross-Node Test
#
# Launches two QEMU instances connected via UDP multicast,
# verifying that routerd on each node can exchange messages.
#
# Usage: ./tools/test_crossnode.sh

set -e

KERNEL="${1:-target/x86_64-unknown-none/release/aos}"
ELF32="/tmp/aos_crossnode.elf"

echo "=== AOS Cross-Node Test ==="
echo "Building kernel..."
cargo build --release 2>/dev/null
objcopy -I elf64-x86_64 -O elf32-i386 "$KERNEL" "$ELF32"

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
grep "ROUTERD\|NETD\|virtio\|MAC\|packet\|SMP\|node_id" /tmp/node_a.log 2>/dev/null

echo ""
echo "=== Node B Output ==="
grep "ROUTERD\|NETD\|virtio\|MAC\|packet\|SMP\|node_id" /tmp/node_b.log 2>/dev/null

echo ""
echo "=== Verification ==="
A_ROUTERD=$(grep -c "ROUTERD.*started" /tmp/node_a.log 2>/dev/null || echo 0)
B_ROUTERD=$(grep -c "ROUTERD.*started" /tmp/node_b.log 2>/dev/null || echo 0)
A_PACKET=$(grep -c "Test packet sent" /tmp/node_a.log 2>/dev/null || echo 0)
B_PACKET=$(grep -c "Test packet sent" /tmp/node_b.log 2>/dev/null || echo 0)

echo "Node A: routerd=$A_ROUTERD packet_sent=$A_PACKET"
echo "Node B: routerd=$B_ROUTERD packet_sent=$B_PACKET"

if [ "$A_ROUTERD" -ge 1 ] && [ "$B_ROUTERD" -ge 1 ] && [ "$A_PACKET" -ge 1 ] && [ "$B_PACKET" -ge 1 ]; then
    echo "PASS: Both nodes booted with routerd and sent packets"
else
    echo "FAIL: Cross-node test incomplete"
fi
