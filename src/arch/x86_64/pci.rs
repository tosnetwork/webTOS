//! AOS PCI Bus Enumeration
//!
//! Discovers PCI devices via configuration space access (ports 0xCF8/0xCFC).
//! Provides device registry and BAR decoding for NVMe, NIC, and other drivers.

use crate::serial_println;

const PCI_CONFIG_ADDR: u16 = 0x0CF8;
const PCI_CONFIG_DATA: u16 = 0x0CFC;
const MAX_PCI_DEVICES: usize = 32;

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

            let pci_dev = PciDevice {
                bus: bus as u8, device: dev, function: 0,
                vendor_id: vendor, device_id,
                class_code, subclass, prog_if, header_type,
                bars, irq_line,
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

            serial_println!("[PCI] {}:{}.{} vendor={:#06x} device={:#06x} class={:#04x}:{:#04x} ({})",
                bus, dev, 0, vendor, device_id, class_code, subclass, class_name);
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
