//! AOS Intel e1000 Ethernet Driver
//!
//! Minimal e1000/e1000e driver for real hardware and QEMU.
//! Uses MMIO registers and DMA descriptor rings for packet TX/RX.
//!
//! QEMU: -device e1000,netdev=n0 -netdev user,id=n0

use crate::serial_println;
use crate::arch::x86_64::paging;
use crate::arch::x86_64::pci;

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

/// Find the e1000 device on the PCI bus and return its MMIO BAR0 address.
///
/// The e1000 can appear under several device IDs:
///   8086:100E — e1000 (QEMU default)
///   8086:100F — e1000 (82545EM)
///   8086:10D3 — e1000e
fn find_e1000_bar0() -> Option<u64> {
    // Known Intel e1000 / e1000e device IDs
    const E1000_IDS: &[(u16, u16)] = &[
        (0x8086, 0x100E), // 82540EM (QEMU default e1000)
        (0x8086, 0x100F), // 82545EM Gigabit
        (0x8086, 0x10D3), // 82574L (e1000e)
        (0x8086, 0x1533), // I210
        (0x8086, 0x1521), // I350
        (0x8086, 0x107C), // 82541PI
        (0x8086, 0x1076), // 82541GI
    ];

    for &(vendor, device) in E1000_IDS {
        if let Some(dev) = pci::find_device(vendor, device) {
            serial_println!("[e1000] Found device {:04x}:{:04x} at PCI {}:{}.{}",
                vendor, device, dev.bus, dev.device, dev.function);

            // BAR0 should be a 32-bit or 64-bit MMIO BAR for e1000
            let bar0_addr = match dev.bars[0] {
                pci::BarType::Mmio32(addr) => addr as u64,
                pci::BarType::Mmio64(addr) => addr,
                pci::BarType::IoPort(_) => {
                    // e1000 sometimes also exposes an I/O BAR at BAR2; try BAR1 MMIO
                    match dev.bars[1] {
                        pci::BarType::Mmio32(addr) => addr as u64,
                        pci::BarType::Mmio64(addr) => addr,
                        _ => {
                            serial_println!("[e1000] No MMIO BAR found, skipping");
                            continue;
                        }
                    }
                }
                pci::BarType::None => {
                    serial_println!("[e1000] BAR0 is None, skipping");
                    continue;
                }
            };

            if bar0_addr == 0 {
                serial_println!("[e1000] BAR0 address is 0, skipping");
                continue;
            }

            // Enable bus mastering in PCI command register so DMA works
            let cmd = pci::read_config(dev.bus, dev.device, dev.function, 0x04);
            pci::write_config(dev.bus, dev.device, dev.function, 0x04,
                cmd | 0x04 /* Bus Master */ | 0x02 /* Memory Space Enable */);

            serial_println!("[e1000] BAR0 MMIO base: {:#x}", bar0_addr);
            return Some(bar0_addr);
        }
    }

    // Fallback: scan by class code 0x02 (Network), subclass 0x00 (Ethernet)
    // and check vendor == Intel
    if let Some(dev) = pci::find_by_class(0x02, 0x00) {
        if dev.vendor_id == 0x8086 {
            serial_println!("[e1000] Found Intel Ethernet via class scan: device={:#x} at PCI {}:{}.{}",
                dev.device_id, dev.bus, dev.device, dev.function);

            let bar0_addr = match dev.bars[0] {
                pci::BarType::Mmio32(addr) => addr as u64,
                pci::BarType::Mmio64(addr) => addr,
                _ => return None,
            };

            if bar0_addr != 0 {
                let cmd = pci::read_config(dev.bus, dev.device, dev.function, 0x04);
                pci::write_config(dev.bus, dev.device, dev.function, 0x04, cmd | 0x06);
                serial_println!("[e1000] BAR0 MMIO base: {:#x}", bar0_addr);
                return Some(bar0_addr);
            }
        }
    }

    None
}

/// Initialize the e1000 device — discovers PCI device automatically.
/// Returns true if a device was found and initialized.
pub fn init() -> bool {
    let bar0 = match find_e1000_bar0() {
        Some(addr) => addr,
        None => {
            serial_println!("[e1000] No device found on PCI bus");
            return false;
        }
    };
    init_with_bar0(bar0)
}

/// Initialize the e1000 device from PCI BAR0 MMIO address
pub fn init_with_bar0(bar0: u64) -> bool {
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

/// Send a raw Ethernet frame.
///
/// Uses the legacy TX descriptor format. The cmd byte 0x0F sets:
///   bit 0 (EOP)  — End Of Packet
///   bit 1 (IFCS) — Insert FCS/CRC
///   bit 2 (IC)   — Insert Checksum (unused here)
///   bit 3 (RS)   — Report Status (set DD bit when done)
pub fn send_packet(data: &[u8]) -> Result<(), &'static str> {
    if !is_initialized() { return Err("not initialized"); }
    if data.len() > 4096 { return Err("packet too large"); }
    if data.len() == 0 { return Err("empty packet"); }

    unsafe {
        let idx = E1000_DEV.tx_tail as usize;
        let tx_ring = E1000_DEV.tx_descs as *mut TxDesc;

        // Wait for the descriptor to be done if RS was set previously.
        // Spin for at most ~10k iterations to avoid deadlock on a bare-metal stall.
        let mut spins = 0usize;
        while (*tx_ring.add(idx)).status & 0x01 == 0
            && (*tx_ring.add(idx)).length != 0  // descriptor was used before
        {
            core::hint::spin_loop();
            spins += 1;
            if spins > 100_000 { return Err("TX timeout"); }
        }

        let buf = E1000_DEV.tx_buffers[idx];
        core::ptr::copy_nonoverlapping(data.as_ptr(), buf as *mut u8, data.len());

        (*tx_ring.add(idx)).addr = buf;
        (*tx_ring.add(idx)).length = data.len() as u16;
        (*tx_ring.add(idx)).cso = 0;
        (*tx_ring.add(idx)).cmd = 0x0B; // EOP | IFCS | RS
        (*tx_ring.add(idx)).status = 0; // clear DD; hardware will set it when done
        (*tx_ring.add(idx)).css = 0;
        (*tx_ring.add(idx)).special = 0;

        // Advance tail to signal packet to NIC
        let next_tail = (idx + 1) % QUEUE_SIZE;
        E1000_DEV.tx_tail = next_tail as u16;

        // Memory barrier before notifying device
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        write_reg(REG_TDT, next_tail as u32);
    }

    Ok(())
}

/// Receive a packet (non-blocking).
///
/// The e1000 RX ring works as follows:
///   - RDH (head): NIC advances this pointer after writing a packet.
///   - RDT (tail): driver advances this to give descriptors back to NIC.
///   - rx_tail tracks the slot the driver will check next (one past the
///     last descriptor given to hardware). A descriptor is ready when its
///     DD (Descriptor Done) bit is set.
pub fn recv_packet(buf: &mut [u8]) -> usize {
    if !is_initialized() { return 0; }

    unsafe {
        // The next slot to check is rx_tail (pointing to last slot we gave the NIC + 1).
        // We track the consumer index separately via rx_tail used as "next to read".
        // On init we set RDT = QUEUE_SIZE-1, meaning all descriptors 0..QUEUE_SIZE-1
        // are owned by hardware. When DD is set on a descriptor, we own it.
        // We scan from the next expected slot.
        let next = (E1000_DEV.rx_tail as usize + 1) % QUEUE_SIZE;
        let rx_ring = E1000_DEV.rx_descs as *mut RxDesc;
        let desc = &*rx_ring.add(next);

        if desc.status & 0x01 == 0 { return 0; } // DD bit not set — no packet ready

        let len = desc.length as usize;
        if len == 0 {
            // Empty descriptor — clear and recycle
            (*rx_ring.add(next)).status = 0;
            E1000_DEV.rx_tail = next as u16;
            write_reg(REG_RDT, next as u32);
            return 0;
        }

        let copy_len = len.min(buf.len());

        core::ptr::copy_nonoverlapping(
            E1000_DEV.rx_buffers[next] as *const u8,
            buf.as_mut_ptr(),
            copy_len,
        );

        // Clear status and give descriptor back to hardware by advancing RDT
        (*rx_ring.add(next)).status = 0;
        E1000_DEV.rx_tail = next as u16;
        write_reg(REG_RDT, next as u32);

        copy_len
    }
}

/// Get MAC address
pub fn mac_address() -> [u8; 6] {
    unsafe { E1000_DEV.mac }
}
