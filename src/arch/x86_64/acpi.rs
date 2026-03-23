//! AOS ACPI Table Parser
//!
//! Parses RSDP, RSDT, and MADT tables to discover the Local APIC base
//! address and enumerate CPU cores for SMP bootstrap.

use crate::serial_println;

/// Maximum supported CPUs
pub const MAX_CPUS: usize = 16;

/// ACPI discovery results
pub struct AcpiInfo {
    pub lapic_base: u64,
    pub cpu_count: u8,
    pub cpu_apic_ids: [u8; MAX_CPUS],
}

/// RSDP (Root System Description Pointer) v1
#[repr(C, packed)]
struct Rsdp {
    signature: [u8; 8],     // "RSD PTR "
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
}

/// ACPI SDT header (common to RSDT, MADT, etc.)
#[repr(C, packed)]
struct SdtHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

/// MADT (Multiple APIC Description Table) header
#[repr(C, packed)]
struct MadtHeader {
    header: SdtHeader,
    lapic_address: u32,
    flags: u32,
    // followed by variable-length APIC entries
}

/// MADT entry header
#[repr(C, packed)]
struct MadtEntryHeader {
    entry_type: u8,
    length: u8,
}

/// MADT Local APIC entry (type 0)
#[repr(C, packed)]
struct MadtLocalApic {
    header: MadtEntryHeader,
    processor_id: u8,
    apic_id: u8,
    flags: u32,             // bit 0 = processor enabled
}

const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";
const RSDP_SEARCH_START: usize = 0x000E_0000;
const RSDP_SEARCH_END: usize = 0x000F_FFFF;

/// Initialize ACPI: find RSDP, parse RSDT, extract MADT.
/// Returns None if ACPI tables are not found.
pub fn init() -> Option<AcpiInfo> {
    // 1. Find RSDP by scanning BIOS area
    let rsdp = find_rsdp()?;

    let rsdt_addr = unsafe { core::ptr::addr_of!((*rsdp).rsdt_address).read_unaligned() };
    serial_println!("[ACPI] RSDP found at {:p}, RSDT at {:#x}", rsdp as *const _, rsdt_addr);

    // 2. Parse RSDT to find MADT
    let madt = find_madt(rsdt_addr as u64)?;

    let lapic_addr = unsafe { core::ptr::addr_of!((*madt).lapic_address).read_unaligned() };
    serial_println!("[ACPI] MADT found, LAPIC base = {:#x}", lapic_addr);

    // 3. Enumerate LAPIC entries in MADT
    let mut info = AcpiInfo {
        lapic_base: lapic_addr as u64,
        cpu_count: 0,
        cpu_apic_ids: [0; MAX_CPUS],
    };

    let madt_length = unsafe { core::ptr::addr_of!((*madt).header.length).read_unaligned() } as usize;
    let madt_base = madt as *const MadtHeader as usize;
    let entries_start = madt_base + core::mem::size_of::<MadtHeader>();
    let entries_end = madt_base + madt_length;

    let mut offset = entries_start;
    while offset + 2 <= entries_end {
        let entry = unsafe { &*(offset as *const MadtEntryHeader) };

        if entry.entry_type == 0 && entry.length >= 8 {
            // Local APIC entry
            let lapic_entry = unsafe { &*(offset as *const MadtLocalApic) };
            let flags = unsafe { core::ptr::addr_of!((*lapic_entry).flags).read_unaligned() };

            if flags & 1 != 0 { // Processor enabled
                if (info.cpu_count as usize) < MAX_CPUS {
                    info.cpu_apic_ids[info.cpu_count as usize] = lapic_entry.apic_id;
                    info.cpu_count += 1;
                }
            }
        }

        if entry.length == 0 { break; } // prevent infinite loop
        offset += entry.length as usize;
    }

    serial_println!("[ACPI] Found {} CPU(s): APIC IDs {:?}",
        info.cpu_count,
        &info.cpu_apic_ids[..info.cpu_count as usize]);

    Some(info)
}

/// Scan BIOS memory area for RSDP signature
fn find_rsdp() -> Option<&'static Rsdp> {
    let mut addr = RSDP_SEARCH_START;
    while addr < RSDP_SEARCH_END {
        let ptr = addr as *const u8;
        let sig = unsafe { core::slice::from_raw_parts(ptr, 8) };
        if sig == RSDP_SIGNATURE {
            // Validate checksum
            let rsdp = unsafe { &*(addr as *const Rsdp) };
            let bytes = unsafe { core::slice::from_raw_parts(addr as *const u8, 20) };
            let sum: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
            if sum == 0 {
                return Some(rsdp);
            }
        }
        addr += 16; // RSDP is always 16-byte aligned
    }
    None
}

/// Find MADT in RSDT entries
fn find_madt(rsdt_addr: u64) -> Option<&'static MadtHeader> {
    let rsdt = rsdt_addr as *const SdtHeader;
    let rsdt_length = unsafe { core::ptr::addr_of!((*rsdt).length).read_unaligned() } as usize;

    let header_size = core::mem::size_of::<SdtHeader>();
    let entry_count = (rsdt_length - header_size) / 4; // RSDT uses 32-bit pointers

    let entries = unsafe {
        core::slice::from_raw_parts(
            (rsdt_addr as usize + header_size) as *const u32,
            entry_count
        )
    };

    for &entry_addr in entries {
        let sdt = entry_addr as *const SdtHeader;
        let sig = unsafe { &(*sdt).signature };
        if sig == b"APIC" {
            return Some(unsafe { &*(entry_addr as *const MadtHeader) });
        }
    }

    None
}
