//! AOS PCI Bus Enumeration
//!
//! Discovers PCI devices via configuration space access (ports 0xCF8/0xCFC).
//! Provides device registry and BAR decoding for NVMe, NIC, and other drivers.

use crate::serial_println;

const PCI_CONFIG_ADDR: u16 = 0x0CF8;
const PCI_CONFIG_DATA: u16 = 0x0CFC;
const MAX_PCI_DEVICES: usize = 32;

/// MSI-X capability ID in PCI config space
const PCI_CAP_MSIX: u8 = 0x11;

/// MSI-X capability information decoded from PCI config space
#[derive(Debug, Clone, Copy)]
pub struct MsixCapability {
    pub cap_offset: u8,     // Offset in config space where capability starts
    pub table_size: u16,    // Number of MSI-X vectors (field value + 1)
    pub table_bar: u8,      // BAR index (BIR) for the MSI-X table
    pub table_offset: u32,  // Byte offset within that BAR for the table
    pub pba_bar: u8,        // BAR index (BIR) for the Pending Bit Array
    pub pba_offset: u32,    // Byte offset within that BAR for the PBA
}

/// PCI BAR type
#[derive(Debug, Clone, Copy)]
pub enum BarType {
    None,
    IoPort(u16),         // I/O port address
    Mmio32(u32),         // 32-bit MMIO address
    Mmio64(u64),         // 64-bit MMIO address
}

/// A discovered PCI device
#[derive(Debug, Clone, Copy)]
pub struct PciDevice {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub header_type: u8,
    pub bars: [BarType; 6],
    pub irq_line: u8,
    pub msix_supported: bool,
    pub msix_cap: Option<MsixCapability>,
}

impl PciDevice {
    const fn empty() -> Self {
        PciDevice {
            bus: 0, device: 0, function: 0,
            vendor_id: 0, device_id: 0,
            class_code: 0, subclass: 0, prog_if: 0,
            header_type: 0,
            bars: [BarType::None; 6],
            irq_line: 0,
            msix_supported: false,
            msix_cap: None,
        }
    }
}

/// Global PCI device registry
static mut PCI_DEVICES: [Option<PciDevice>; MAX_PCI_DEVICES] = [const { None }; MAX_PCI_DEVICES];
static mut PCI_DEVICE_COUNT: usize = 0;

/// Port I/O helpers
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

/// Read a 32-bit value from PCI configuration space
pub fn read_config(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr: u32 = 0x80000000
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);
    unsafe {
        outl(PCI_CONFIG_ADDR, addr);
        inl(PCI_CONFIG_DATA)
    }
}

/// Write a 32-bit value to PCI configuration space
pub fn write_config(bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
    let addr: u32 = 0x80000000
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);
    unsafe {
        outl(PCI_CONFIG_ADDR, addr);
        outl(PCI_CONFIG_DATA, val);
    }
}

/// Decode a BAR register
fn decode_bar(bus: u8, dev: u8, func: u8, bar_index: usize) -> BarType {
    let offset = 0x10 + (bar_index as u8) * 4;
    let bar = read_config(bus, dev, func, offset);

    if bar == 0 { return BarType::None; }

    if bar & 1 != 0 {
        // I/O port BAR
        BarType::IoPort((bar & 0xFFFC) as u16)
    } else {
        // MMIO BAR
        let bar_type = (bar >> 1) & 0x3;
        match bar_type {
            0 => BarType::Mmio32(bar & 0xFFFFFFF0),
            2 => {
                // 64-bit MMIO: read next BAR for high 32 bits
                let high = read_config(bus, dev, func, offset + 4);
                let addr = ((high as u64) << 32) | ((bar & 0xFFFFFFF0) as u64);
                BarType::Mmio64(addr)
            }
            _ => BarType::None,
        }
    }
}

/// Find the MSI-X capability in a PCI device's capability list.
///
/// Walks the linked list of PCI capabilities starting from the Capabilities
/// Pointer (offset 0x34). Returns `Some(MsixCapability)` if MSI-X (cap ID
/// 0x11) is present, or `None` otherwise.
pub fn find_msix_capability(bus: u8, device: u8, func: u8) -> Option<MsixCapability> {
    // Status register (offset 0x06, upper halfword of dword at 0x04):
    // bit 4 of the Status register = Capabilities List present.
    let status_reg = read_config(bus, device, func, 0x04);
    let status = (status_reg >> 16) as u16;
    if status & (1 << 4) == 0 {
        return None; // No capabilities list
    }

    // Capabilities Pointer is at config offset 0x34 (bits 7:0 of the dword).
    let cap_ptr_reg = read_config(bus, device, func, 0x34);
    let mut ptr = (cap_ptr_reg & 0xFF) as u8;

    // Safety: guard against infinite loops (max 256 capabilities).
    let mut iterations = 0u8;
    while ptr != 0 && iterations < 48 {
        iterations += 1;

        // Each capability entry: byte 0 = cap ID, byte 1 = pointer to next.
        // They are DWORD-aligned; read the first dword which contains both.
        let cap_dword = read_config(bus, device, func, ptr);
        let cap_id = (cap_dword & 0xFF) as u8;
        let next_ptr = ((cap_dword >> 8) & 0xFF) as u8;

        if cap_id == PCI_CAP_MSIX {
            // MSI-X Message Control register is at cap_offset + 2 (upper halfword
            // of the dword at cap_offset).
            let msg_ctrl = (cap_dword >> 16) as u16;
            // bits 10:0 = Table Size - 1
            let table_size = (msg_ctrl & 0x07FF) + 1;

            // Table Offset/BIR dword at cap_offset + 4
            let table_dword = read_config(bus, device, func, ptr.wrapping_add(4));
            let table_bar = (table_dword & 0x07) as u8;
            let table_offset = table_dword & !0x07;

            // PBA Offset/BIR dword at cap_offset + 8
            let pba_dword = read_config(bus, device, func, ptr.wrapping_add(8));
            let pba_bar = (pba_dword & 0x07) as u8;
            let pba_offset = pba_dword & !0x07;

            return Some(MsixCapability {
                cap_offset: ptr,
                table_size,
                table_bar,
                table_offset,
                pba_bar,
                pba_offset,
            });
        }

        ptr = next_ptr;
    }

    None
}

/// Enable MSI-X for a device by setting bit 15 of the Message Control register.
///
/// After calling this, legacy INTx interrupts are automatically disabled by
/// the hardware. MSI-X table entries must be configured before unmasking them.
pub fn enable_msix(bus: u8, device: u8, func: u8, cap_offset: u8) {
    // Message Control is in the upper halfword of the dword at cap_offset.
    let dword = read_config(bus, device, func, cap_offset);
    // Set MSI-X Enable bit (bit 15 of Message Control = bit 31 of the dword)
    let new_dword = dword | (1u32 << 31);
    write_config(bus, device, func, cap_offset, new_dword);
}

/// Configure an entry in the MSI-X interrupt table.
///
/// Each entry is 16 bytes at `table_base + index * 16`:
///   [0..4]   Message Address Low  (0xFEE_xxxxx for Local APIC)
///   [4..8]   Message Address High (0 for 32-bit addressing)
///   [8..12]  Message Data         (interrupt vector number)
///   [12..16] Vector Control       (bit 0 = masked; 0 = unmasked)
///
/// # Safety
/// `table_base` must be a valid, identity-mapped MMIO address for the MSI-X
/// table BAR of the device.
pub unsafe fn configure_msix_entry(
    table_base: u64,
    index: u16,
    vector: u8,
    apic_id: u8,
) {
    let entry_addr = table_base + (index as u64) * 16;

    // Message Address: 0xFEEE_xxxx where xx = destination APIC ID (bits 19:12)
    let msg_addr_low: u32 = 0xFEE0_0000 | ((apic_id as u32) << 12);
    let msg_addr_high: u32 = 0;
    // Message Data: fixed interrupt delivery, level-triggered is fine for MSI-X,
    // but MSI-X is edge-triggered by definition. Set the vector number.
    let msg_data: u32 = vector as u32;
    // Vector Control: bit 0 = 0 means unmasked
    let vector_ctrl: u32 = 0;

    core::ptr::write_volatile((entry_addr + 0) as *mut u32, msg_addr_low);
    core::ptr::write_volatile((entry_addr + 4) as *mut u32, msg_addr_high);
    core::ptr::write_volatile((entry_addr + 8) as *mut u32, msg_data);
    core::ptr::write_volatile((entry_addr + 12) as *mut u32, vector_ctrl);
}

/// Enumerate all PCI devices on the bus
pub fn init() {
    serial_println!("[PCI] Scanning PCI bus...");

    unsafe { PCI_DEVICE_COUNT = 0; }

    for bus in 0..=255u16 {
        for dev in 0..32u8 {
            let id = read_config(bus as u8, dev, 0, 0);
            let vendor = (id & 0xFFFF) as u16;

            if vendor == 0xFFFF || vendor == 0 { continue; }

            let device_id = ((id >> 16) & 0xFFFF) as u16;
            let class_reg = read_config(bus as u8, dev, 0, 0x08);
            let class_code = ((class_reg >> 24) & 0xFF) as u8;
            let subclass = ((class_reg >> 16) & 0xFF) as u8;
            let prog_if = ((class_reg >> 8) & 0xFF) as u8;
            let header = read_config(bus as u8, dev, 0, 0x0C);
            let header_type = ((header >> 16) & 0xFF) as u8;
            let irq_reg = read_config(bus as u8, dev, 0, 0x3C);
            let irq_line = (irq_reg & 0xFF) as u8;

            let mut bars = [BarType::None; 6];
            let bar_count = if header_type & 0x7F == 0 { 6 } else { 2 };
            let mut i = 0;
            while i < bar_count {
                bars[i] = decode_bar(bus as u8, dev, 0, i);
                if matches!(bars[i], BarType::Mmio64(_)) { i += 1; } // skip next BAR (used by 64-bit)
                i += 1;
            }

            // Detect MSI-X capability by walking the PCI capability list
            let msix_cap = find_msix_capability(bus as u8, dev, 0);
            let msix_supported = msix_cap.is_some();

            let pci_dev = PciDevice {
                bus: bus as u8, device: dev, function: 0,
                vendor_id: vendor, device_id,
                class_code, subclass, prog_if, header_type,
                bars, irq_line,
                msix_supported,
                msix_cap,
            };

            unsafe {
                if PCI_DEVICE_COUNT < MAX_PCI_DEVICES {
                    PCI_DEVICES[PCI_DEVICE_COUNT] = Some(pci_dev);
                    PCI_DEVICE_COUNT += 1;
                }
            }

            let class_name = match (class_code, subclass) {
                (0x01, 0x08) => "NVMe",
                (0x02, 0x00) => "Ethernet",
                (0x03, _) => "VGA",
                (0x06, _) => "Bridge",
                _ => "Other",
            };

            if let Some(ref cap) = msix_cap {
                serial_println!("[PCI] {}:{}.{} vendor={:#06x} device={:#06x} class={:#04x}:{:#04x} ({}) MSI-X: {} vectors",
                    bus, dev, 0, vendor, device_id, class_code, subclass, class_name, cap.table_size);
            } else {
                serial_println!("[PCI] {}:{}.{} vendor={:#06x} device={:#06x} class={:#04x}:{:#04x} ({})",
                    bus, dev, 0, vendor, device_id, class_code, subclass, class_name);
            }
        }
    }

    unsafe {
        serial_println!("[PCI] Enumeration complete: {} device(s) found", PCI_DEVICE_COUNT);
    }
}

/// Find a PCI device by vendor and device ID
pub fn find_device(vendor_id: u16, device_id: u16) -> Option<&'static PciDevice> {
    unsafe {
        for i in 0..PCI_DEVICE_COUNT {
            if let Some(ref dev) = PCI_DEVICES[i] {
                if dev.vendor_id == vendor_id && dev.device_id == device_id {
                    return Some(dev);
                }
            }
        }
    }
    None
}

/// Find a PCI device by class and subclass
pub fn find_by_class(class_code: u8, subclass: u8) -> Option<&'static PciDevice> {
    unsafe {
        for i in 0..PCI_DEVICE_COUNT {
            if let Some(ref dev) = PCI_DEVICES[i] {
                if dev.class_code == class_code && dev.subclass == subclass {
                    return Some(dev);
                }
            }
        }
    }
    None
}

/// Get number of discovered devices
pub fn device_count() -> usize {
    unsafe { PCI_DEVICE_COUNT }
}
