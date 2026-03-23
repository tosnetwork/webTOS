//! AOS Intel e1000 Ethernet Driver
//!
//! Minimal e1000/e1000e driver for real hardware and QEMU.
//! Uses MMIO registers and DMA descriptor rings for packet TX/RX.
//!
//! QEMU: -device e1000,netdev=n0 -netdev user,id=n0

use crate::serial_println;
use crate::arch::x86_64::paging;

// e1000 register offsets (MMIO from BAR0)
const REG_CTRL: u32 = 0x0000;    // Device Control
const REG_STATUS: u32 = 0x0008;  // Device Status
#[allow(dead_code)]
const REG_EERD: u32 = 0x0014;    // EEPROM Read
const REG_ICR: u32 = 0x00C0;     // Interrupt Cause Read
#[allow(dead_code)]
const REG_IMS: u32 = 0x00D0;     // Interrupt Mask Set
const REG_IMC: u32 = 0x00D8;     // Interrupt Mask Clear
const REG_RCTL: u32 = 0x0100;    // Receive Control
const REG_TCTL: u32 = 0x0400;    // Transmit Control
const REG_RDBAL: u32 = 0x2800;   // RX Descriptor Base Low
const REG_RDBAH: u32 = 0x2804;   // RX Descriptor Base High
const REG_RDLEN: u32 = 0x2808;   // RX Descriptor Length
const REG_RDH: u32 = 0x2810;     // RX Descriptor Head
const REG_RDT: u32 = 0x2818;     // RX Descriptor Tail
const REG_TDBAL: u32 = 0x3800;   // TX Descriptor Base Low
const REG_TDBAH: u32 = 0x3804;   // TX Descriptor Base High
const REG_TDLEN: u32 = 0x3808;   // TX Descriptor Length
const REG_TDH: u32 = 0x3810;     // TX Descriptor Head
const REG_TDT: u32 = 0x3818;     // TX Descriptor Tail
const REG_RAL: u32 = 0x5400;     // Receive Address Low
const REG_RAH: u32 = 0x5404;     // Receive Address High

// Control register bits
const CTRL_RST: u32 = 1 << 26;   // Device Reset
const CTRL_SLU: u32 = 1 << 6;    // Set Link Up

// RX Control bits
const RCTL_EN: u32 = 1 << 1;     // Receive Enable
const RCTL_BAM: u32 = 1 << 15;   // Broadcast Accept Mode
const RCTL_BSIZE_4096: u32 = 3 << 16; // Buffer size 4096
const RCTL_SECRC: u32 = 1 << 26; // Strip Ethernet CRC

// TX Control bits
const TCTL_EN: u32 = 1 << 1;     // Transmit Enable
const TCTL_PSP: u32 = 1 << 3;    // Pad Short Packets

const QUEUE_SIZE: usize = 8;

/// RX descriptor (legacy format, 16 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
struct RxDesc {
    addr: u64,      // Buffer physical address
    length: u16,    // Packet length
    checksum: u16,
    status: u8,
    errors: u8,
    special: u16,
}

/// TX descriptor (legacy format, 16 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
struct TxDesc {
    addr: u64,
    length: u16,
    cso: u8,
    cmd: u8,        // Command bits
    status: u8,
    css: u8,
    special: u16,
}

/// e1000 driver state
struct E1000 {
    bar0: u64,
    mac: [u8; 6],
    rx_descs: u64,      // Physical address of RX descriptor ring
    tx_descs: u64,      // Physical address of TX descriptor ring
    rx_buffers: [u64; QUEUE_SIZE],
    tx_buffers: [u64; QUEUE_SIZE],
    rx_tail: u16,
    tx_tail: u16,
    initialized: bool,
}

// Safety: single-core access in Stage-4; no concurrent mutation.
unsafe impl Send for E1000 {}
unsafe impl Sync for E1000 {}

static mut E1000_DEV: E1000 = E1000 {
    bar0: 0,
    mac: [0; 6],
    rx_descs: 0,
    tx_descs: 0,
    rx_buffers: [0; QUEUE_SIZE],
    tx_buffers: [0; QUEUE_SIZE],
    rx_tail: 0,
    tx_tail: 0,
    initialized: false,
};

// MMIO helpers
unsafe fn read_reg(offset: u32) -> u32 {
    core::ptr::read_volatile((E1000_DEV.bar0 + offset as u64) as *const u32)
}

unsafe fn write_reg(offset: u32, val: u32) {
    core::ptr::write_volatile((E1000_DEV.bar0 + offset as u64) as *mut u32, val);
}

/// Initialize the e1000 device from PCI BAR0 MMIO address
pub fn init(bar0: u64) -> bool {
    if bar0 == 0 { return false; }

    unsafe {
        E1000_DEV.bar0 = bar0;

        // Reset device
        write_reg(REG_CTRL, read_reg(REG_CTRL) | CTRL_RST);
        // Wait for reset to complete
        for _ in 0..100_000 { core::hint::spin_loop(); }

        // Read MAC address from RAL/RAH
        let ral = read_reg(REG_RAL);
        let rah = read_reg(REG_RAH);
        E1000_DEV.mac[0] = (ral & 0xFF) as u8;
        E1000_DEV.mac[1] = ((ral >> 8) & 0xFF) as u8;
        E1000_DEV.mac[2] = ((ral >> 16) & 0xFF) as u8;
        E1000_DEV.mac[3] = ((ral >> 24) & 0xFF) as u8;
        E1000_DEV.mac[4] = (rah & 0xFF) as u8;
        E1000_DEV.mac[5] = ((rah >> 8) & 0xFF) as u8;

        serial_println!("[e1000] MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            E1000_DEV.mac[0], E1000_DEV.mac[1], E1000_DEV.mac[2],
            E1000_DEV.mac[3], E1000_DEV.mac[4], E1000_DEV.mac[5]);

        // Set link up
        write_reg(REG_CTRL, read_reg(REG_CTRL) | CTRL_SLU);

        // Disable interrupts
        write_reg(REG_IMC, 0xFFFFFFFF);
        let _ = read_reg(REG_ICR); // Clear pending

        // Allocate RX descriptor ring
        let rx_ring_phys = paging::alloc_frame().expect("e1000 RX ring");
        core::ptr::write_bytes(rx_ring_phys as *mut u8, 0, 4096);
        E1000_DEV.rx_descs = rx_ring_phys;

        // Allocate RX buffers and fill descriptors
        let rx_ring = rx_ring_phys as *mut RxDesc;
        for i in 0..QUEUE_SIZE {
            let buf = paging::alloc_frame().expect("e1000 RX buffer");
            core::ptr::write_bytes(buf as *mut u8, 0, 4096);
            E1000_DEV.rx_buffers[i] = buf;
            (*rx_ring.add(i)).addr = buf;
            (*rx_ring.add(i)).status = 0;
        }

        // Set up RX registers
        write_reg(REG_RDBAL, (rx_ring_phys & 0xFFFFFFFF) as u32);
        write_reg(REG_RDBAH, (rx_ring_phys >> 32) as u32);
        write_reg(REG_RDLEN, (QUEUE_SIZE * 16) as u32);
        write_reg(REG_RDH, 0);
        write_reg(REG_RDT, (QUEUE_SIZE - 1) as u32);
        write_reg(REG_RCTL, RCTL_EN | RCTL_BAM | RCTL_BSIZE_4096 | RCTL_SECRC);

        // Allocate TX descriptor ring
        let tx_ring_phys = paging::alloc_frame().expect("e1000 TX ring");
        core::ptr::write_bytes(tx_ring_phys as *mut u8, 0, 4096);
        E1000_DEV.tx_descs = tx_ring_phys;

        // Allocate TX buffers
        for i in 0..QUEUE_SIZE {
            let buf = paging::alloc_frame().expect("e1000 TX buffer");
            core::ptr::write_bytes(buf as *mut u8, 0, 4096);
            E1000_DEV.tx_buffers[i] = buf;
        }

        // Set up TX registers
        write_reg(REG_TDBAL, (tx_ring_phys & 0xFFFFFFFF) as u32);
        write_reg(REG_TDBAH, (tx_ring_phys >> 32) as u32);
        write_reg(REG_TDLEN, (QUEUE_SIZE * 16) as u32);
        write_reg(REG_TDH, 0);
        write_reg(REG_TDT, 0);
        write_reg(REG_TCTL, TCTL_EN | TCTL_PSP);

        E1000_DEV.initialized = true;
        serial_println!("[e1000] Initialized: RX/TX queues ready ({} descriptors)", QUEUE_SIZE);
    }

    true
}

/// Check if device is initialized
pub fn is_initialized() -> bool {
    unsafe { E1000_DEV.initialized }
}

/// Send a raw Ethernet frame
pub fn send_packet(data: &[u8]) -> Result<(), &'static str> {
    if !is_initialized() { return Err("not initialized"); }
    if data.len() > 4096 { return Err("packet too large"); }

    unsafe {
        let idx = E1000_DEV.tx_tail as usize % QUEUE_SIZE;
        let buf = E1000_DEV.tx_buffers[idx];

        core::ptr::copy_nonoverlapping(data.as_ptr(), buf as *mut u8, data.len());

        let tx_ring = E1000_DEV.tx_descs as *mut TxDesc;
        (*tx_ring.add(idx)).addr = buf;
        (*tx_ring.add(idx)).length = data.len() as u16;
        (*tx_ring.add(idx)).cmd = 0x0B; // EOP | IFCS | RS
        (*tx_ring.add(idx)).status = 0;

        E1000_DEV.tx_tail = ((E1000_DEV.tx_tail as usize + 1) % QUEUE_SIZE) as u16;
        write_reg(REG_TDT, E1000_DEV.tx_tail as u32);
    }

    Ok(())
}

/// Receive a packet (non-blocking)
pub fn recv_packet(buf: &mut [u8]) -> usize {
    if !is_initialized() { return 0; }

    unsafe {
        let idx = E1000_DEV.rx_tail as usize % QUEUE_SIZE;
        let rx_ring = E1000_DEV.rx_descs as *const RxDesc;
        let desc = &*rx_ring.add(idx);

        if desc.status & 1 == 0 { return 0; } // DD bit not set

        let len = desc.length as usize;
        let copy_len = len.min(buf.len());

        core::ptr::copy_nonoverlapping(
            E1000_DEV.rx_buffers[idx] as *const u8,
            buf.as_mut_ptr(),
            copy_len,
        );

        // Reset descriptor and advance tail
        let rx_ring_mut = E1000_DEV.rx_descs as *mut RxDesc;
        (*rx_ring_mut.add(idx)).status = 0;

        E1000_DEV.rx_tail = ((E1000_DEV.rx_tail as usize + 1) % QUEUE_SIZE) as u16;
        write_reg(REG_RDT, E1000_DEV.rx_tail as u32);

        copy_len
    }
}

/// Get MAC address
pub fn mac_address() -> [u8; 6] {
    unsafe { E1000_DEV.mac }
}
