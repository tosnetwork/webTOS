//! ATOS Virtio-Net Driver (Legacy PCI I/O)
//!
//! Minimal virtio-net driver for QEMU. Uses legacy (0.9.5) virtio
//! interface via PCI I/O ports. Supports basic packet send/receive
//! for the netd system agent.

use crate::serial_println;
use super::serial::{inb, outb};
use super::paging;

// ─── Virtio PCI I/O Port offsets ─────────────────────────────────────────

const VIRTIO_PCI_DEVICE_FEATURES: u16 = 0x00;
const VIRTIO_PCI_GUEST_FEATURES: u16 = 0x04;
const VIRTIO_PCI_QUEUE_ADDR: u16 = 0x08;
const VIRTIO_PCI_QUEUE_SIZE: u16 = 0x0C;
const VIRTIO_PCI_QUEUE_SELECT: u16 = 0x0E;
const VIRTIO_PCI_QUEUE_NOTIFY: u16 = 0x10;
const VIRTIO_PCI_DEVICE_STATUS: u16 = 0x12;
#[allow(dead_code)]
const VIRTIO_PCI_ISR_STATUS: u16 = 0x13;
const VIRTIO_PCI_MAC_ADDR: u16 = 0x14; // 6 bytes for network device

// ─── Virtio Status Bits ──────────────────────────────────────────────────

const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
#[allow(dead_code)]
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;

// ─── Virtqueue Descriptor ────────────────────────────────────────────────

#[allow(dead_code)]
const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2; // buffer is device-writable (for receive)

#[repr(C)]
#[derive(Clone, Copy)]
struct VringDesc {
    addr: u64,    // physical address of buffer
    len: u32,     // buffer length
    flags: u16,   // VRING_DESC_F_*
    next: u16,    // next descriptor in chain
}

#[repr(C)]
struct VringAvail {
    flags: u16,
    idx: u16,
    ring: [u16; 256],
}

#[repr(C)]
struct VringUsed {
    flags: u16,
    idx: u16,
    ring: [VringUsedElem; 256],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VringUsedElem {
    id: u32,
    len: u32,
}

// ─── Virtio-Net Header ───────────────────────────────────────────────────

const VIRTIO_NET_HDR_SIZE: usize = 10;

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioNetHeader {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
}

// ─── Driver State ────────────────────────────────────────────────────────

const QUEUE_SIZE: usize = 16; // small queue for Stage-3
const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;

struct VirtioNet {
    io_base: u16,           // PCI BAR0 I/O port base
    mac: [u8; 6],
    // RX virtqueue
    rx_descs: *mut VringDesc,
    rx_avail: *mut VringAvail,
    rx_used: *mut VringUsed,
    rx_buffers: [u64; QUEUE_SIZE], // physical addresses of RX buffers
    rx_last_used: u16,
    // TX virtqueue
    tx_descs: *mut VringDesc,
    tx_avail: *mut VringAvail,
    tx_used: *mut VringUsed,
    tx_buffers: [u64; QUEUE_SIZE],
    tx_last_used: u16,
    initialized: bool,
}

// Safety: single-core access in Stage-3; no concurrent mutation.
unsafe impl Send for VirtioNet {}
unsafe impl Sync for VirtioNet {}

static mut VIRTIO_NET: VirtioNet = VirtioNet {
    io_base: 0,
    mac: [0; 6],
    rx_descs: core::ptr::null_mut(),
    rx_avail: core::ptr::null_mut(),
    rx_used: core::ptr::null_mut(),
    rx_buffers: [0; QUEUE_SIZE],
    rx_last_used: 0,
    tx_descs: core::ptr::null_mut(),
    tx_avail: core::ptr::null_mut(),
    tx_used: core::ptr::null_mut(),
    tx_buffers: [0; QUEUE_SIZE],
    tx_last_used: 0,
    initialized: false,
};

// ─── Port I/O helpers (16-bit and 32-bit) ────────────────────────────────

#[inline]
unsafe fn inw(port: u16) -> u16 {
    let val: u16;
    core::arch::asm!(
        "in ax, dx",
        out("ax") val,
        in("dx") port,
        options(nomem, nostack, preserves_flags),
    );
    val
}

#[inline]
unsafe fn outw(port: u16, val: u16) {
    core::arch::asm!(
        "out dx, ax",
        in("dx") port,
        in("ax") val,
        options(nomem, nostack, preserves_flags),
    );
}

#[inline]
unsafe fn inl(port: u16) -> u32 {
    let val: u32;
    core::arch::asm!(
        "in eax, dx",
        out("eax") val,
        in("dx") port,
        options(nomem, nostack, preserves_flags),
    );
    val
}

#[inline]
unsafe fn outl(port: u16, val: u32) {
    core::arch::asm!(
        "out dx, eax",
        in("dx") port,
        in("eax") val,
        options(nomem, nostack, preserves_flags),
    );
}

// ─── PCI Discovery ───────────────────────────────────────────────────────

/// Scan PCI bus for virtio-net device (vendor=0x1AF4, device=0x1000)
fn find_virtio_net_pci() -> Option<u16> {
    for bus in 0..256u32 {
        for dev in 0..32u32 {
            let addr = 0x80000000 | (bus << 16) | (dev << 11);
            unsafe {
                outl(0xCF8, addr);
                let id = inl(0xCFC);
                let vendor = (id & 0xFFFF) as u16;
                let device = ((id >> 16) & 0xFFFF) as u16;

                if vendor == 0x1AF4 && device == 0x1000 {
                    // Found virtio-net! Read BAR0 for I/O base
                    outl(0xCF8, addr | 0x10); // BAR0
                    let bar0 = inl(0xCFC);
                    if bar0 & 1 != 0 {
                        // I/O port BAR
                        let io_base = (bar0 & 0xFFFC) as u16;
                        serial_println!("[VIRTIO-NET] Found at PCI {}:{}, BAR0 I/O={:#x}",
                            bus, dev, io_base);
                        return Some(io_base);
                    }
                }
            }
        }
    }
    None
}

// ─── Initialization ──────────────────────────────────────────────────────

/// Initialize the virtio-net device.
/// Returns true if a device was found and initialized.
pub fn init() -> bool {
    let io_base = match find_virtio_net_pci() {
        Some(base) => base,
        None => {
            serial_println!("[VIRTIO-NET] No device found");
            return false;
        }
    };

    unsafe {
        VIRTIO_NET.io_base = io_base;

        // 1. Reset device
        outb(io_base + VIRTIO_PCI_DEVICE_STATUS, 0);

        // 2. Acknowledge
        outb(io_base + VIRTIO_PCI_DEVICE_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);

        // 3. Driver loaded
        outb(io_base + VIRTIO_PCI_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

        // 4. Read device features, accept basic features
        let _features = inl(io_base + VIRTIO_PCI_DEVICE_FEATURES);
        outl(io_base + VIRTIO_PCI_GUEST_FEATURES, 0); // accept no optional features

        // 5. Read MAC address
        for i in 0..6 {
            VIRTIO_NET.mac[i] = inb(io_base + VIRTIO_PCI_MAC_ADDR + i as u16);
        }
        serial_println!("[VIRTIO-NET] MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            VIRTIO_NET.mac[0], VIRTIO_NET.mac[1], VIRTIO_NET.mac[2],
            VIRTIO_NET.mac[3], VIRTIO_NET.mac[4], VIRTIO_NET.mac[5]);

        // 6. Set up RX virtqueue (queue 0)
        setup_queue(io_base, RX_QUEUE, true);

        // 7. Set up TX virtqueue (queue 1)
        setup_queue(io_base, TX_QUEUE, false);

        // 8. Driver ready
        outb(io_base + VIRTIO_PCI_DEVICE_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_DRIVER_OK);

        VIRTIO_NET.initialized = true;
        serial_println!("[VIRTIO-NET] Initialized, RX/TX queues ready");
    }

    true
}

/// Set up a virtqueue (RX=0, TX=1)
unsafe fn setup_queue(io_base: u16, queue_idx: u16, is_rx: bool) {
    // Select queue
    outw(io_base + VIRTIO_PCI_QUEUE_SELECT, queue_idx);

    // Read queue size
    let size = inw(io_base + VIRTIO_PCI_QUEUE_SIZE) as usize;
    let queue_size = size.min(QUEUE_SIZE);

    if queue_size == 0 {
        serial_println!("[VIRTIO-NET] Queue {} not available", queue_idx);
        return;
    }

    // Allocate queue memory (descriptors + avail + used)
    // Need: queue_size * 16 (descs) + 6 + queue_size * 2 (avail) + 6 + queue_size * 8 (used)
    // Allocate 2 pages to be safe
    let queue_phys = paging::alloc_frame().expect("Failed to allocate virtqueue");
    let queue_phys2 = paging::alloc_frame().expect("Failed to allocate virtqueue page 2");

    // Zero the pages (identity-mapped, so phys addr == virt addr)
    core::ptr::write_bytes(queue_phys as *mut u8, 0, 4096);
    core::ptr::write_bytes(queue_phys2 as *mut u8, 0, 4096);

    // Layout: descs at page start, avail after descs, used at page 2
    let descs = queue_phys as *mut VringDesc;
    let avail = (queue_phys + (queue_size * 16) as u64) as *mut VringAvail;
    let used = queue_phys2 as *mut VringUsed;

    if is_rx {
        VIRTIO_NET.rx_descs = descs;
        VIRTIO_NET.rx_avail = avail;
        VIRTIO_NET.rx_used = used;

        // Allocate RX buffers and populate descriptors
        for i in 0..queue_size {
            let buf = paging::alloc_frame().expect("Failed to allocate RX buffer");
            core::ptr::write_bytes(buf as *mut u8, 0, 4096);
            VIRTIO_NET.rx_buffers[i] = buf;

            (*descs.add(i)).addr = buf;
            (*descs.add(i)).len = 4096;
            (*descs.add(i)).flags = VRING_DESC_F_WRITE; // device writes to this buffer
            (*descs.add(i)).next = 0;

            // Add to available ring
            (*avail).ring[i] = i as u16;
        }
        (*avail).idx = queue_size as u16;
    } else {
        VIRTIO_NET.tx_descs = descs;
        VIRTIO_NET.tx_avail = avail;
        VIRTIO_NET.tx_used = used;

        // Allocate TX buffers
        for i in 0..queue_size {
            let buf = paging::alloc_frame().expect("Failed to allocate TX buffer");
            core::ptr::write_bytes(buf as *mut u8, 0, 4096);
            VIRTIO_NET.tx_buffers[i] = buf;
        }
    }

    // Tell device where the queue is
    outl(io_base + VIRTIO_PCI_QUEUE_ADDR, (queue_phys >> 12) as u32);
}

// ─── Send/Receive ────────────────────────────────────────────────────────

/// Check if the driver is initialized
pub fn is_initialized() -> bool {
    unsafe { VIRTIO_NET.initialized }
}

/// Send a raw Ethernet frame
pub fn send_packet(data: &[u8]) -> Result<(), &'static str> {
    if !is_initialized() { return Err("not initialized"); }
    if data.len() > 4096 - VIRTIO_NET_HDR_SIZE { return Err("packet too large"); }

    unsafe {
        let net = &mut VIRTIO_NET;

        // Find a free TX buffer (simple: use tx_last_used as index)
        let idx = (net.tx_last_used as usize) % QUEUE_SIZE;
        let buf_addr = net.tx_buffers[idx];

        // Write virtio-net header (all zeros for basic send)
        let hdr = VirtioNetHeader {
            flags: 0, gso_type: 0, hdr_len: 0, gso_size: 0,
            csum_start: 0, csum_offset: 0,
        };
        core::ptr::copy_nonoverlapping(
            &hdr as *const VirtioNetHeader as *const u8,
            buf_addr as *mut u8,
            VIRTIO_NET_HDR_SIZE,
        );

        // Copy packet data after header
        core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            (buf_addr as *mut u8).add(VIRTIO_NET_HDR_SIZE),
            data.len(),
        );

        // Set up descriptor
        (*net.tx_descs.add(idx)).addr = buf_addr;
        (*net.tx_descs.add(idx)).len = (VIRTIO_NET_HDR_SIZE + data.len()) as u32;
        (*net.tx_descs.add(idx)).flags = 0; // device reads this buffer

        // Add to available ring
        let avail_idx = (*net.tx_avail).idx as usize;
        (*net.tx_avail).ring[avail_idx % QUEUE_SIZE] = idx as u16;

        // Memory barrier
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        (*net.tx_avail).idx = (avail_idx + 1) as u16;

        // Notify device
        outw(net.io_base + VIRTIO_PCI_QUEUE_NOTIFY, TX_QUEUE);

        net.tx_last_used = (net.tx_last_used + 1) % QUEUE_SIZE as u16;
    }

    Ok(())
}

/// Receive a packet (non-blocking). Returns the number of bytes read, or 0 if no packet.
pub fn recv_packet(buf: &mut [u8]) -> usize {
    if !is_initialized() { return 0; }

    unsafe {
        let net = &mut VIRTIO_NET;
        let used_idx = (*net.rx_used).idx;

        if net.rx_last_used == used_idx {
            return 0; // no new packets
        }

        let used_elem = (*net.rx_used).ring[net.rx_last_used as usize % QUEUE_SIZE];
        let desc_idx = used_elem.id as usize;
        let total_len = used_elem.len as usize;

        if total_len <= VIRTIO_NET_HDR_SIZE {
            // No actual data
            net.rx_last_used += 1;
            return 0;
        }

        let data_len = total_len - VIRTIO_NET_HDR_SIZE;
        let copy_len = data_len.min(buf.len());

        let src = (net.rx_buffers[desc_idx] as *const u8).add(VIRTIO_NET_HDR_SIZE);
        core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), copy_len);

        // Re-add buffer to available ring
        let avail_idx = (*net.rx_avail).idx as usize;
        (*net.rx_avail).ring[avail_idx % QUEUE_SIZE] = desc_idx as u16;
        (*net.rx_avail).idx = (avail_idx + 1) as u16;

        // Notify device
        outw(net.io_base + VIRTIO_PCI_QUEUE_NOTIFY, RX_QUEUE);

        net.rx_last_used += 1;
        copy_len
    }
}

/// Get the MAC address
pub fn mac_address() -> [u8; 6] {
    unsafe { VIRTIO_NET.mac }
}
