//! ATOS Large Message Support
//!
//! Enables agents to exchange data larger than the 256-byte mailbox
//! payload limit. The sender allocates a shared memory region, writes
//! data to it, and sends a region descriptor via the normal mailbox.
//! The receiver reads from the shared region.

use crate::agent::AgentId;
use crate::serial_println;

/// Maximum number of active shared regions
const MAX_REGIONS: usize = 32;

/// Maximum region size (64 KB)
pub const MAX_REGION_SIZE: usize = 65536;

/// A shared memory region descriptor
#[derive(Debug, Clone, Copy)]
pub struct RegionDescriptor {
    pub id: u32,
    pub phys_addr: u64,
    pub size: usize,
    pub owner: AgentId,
    pub active: bool,
}

impl RegionDescriptor {
    pub const fn empty() -> Self {
        RegionDescriptor {
            id: 0,
            phys_addr: 0,
            size: 0,
            owner: 0,
            active: false,
        }
    }
}

/// Serialized descriptor that fits in a mailbox payload (16 bytes)
#[repr(C)]
pub struct RegionMessage {
    pub region_id: u32,
    pub offset: u32,   // offset within region (for chunked transfers)
    pub length: u32,   // length of data at offset
    pub flags: u32,    // 0x01 = first chunk, 0x02 = last chunk
}

// Global region table
static mut REGIONS: [RegionDescriptor; MAX_REGIONS] = [RegionDescriptor::empty(); MAX_REGIONS];
static mut NEXT_REGION_ID: u32 = 1;

/// Allocate a shared memory region
pub fn allocate_region(owner: AgentId, size: usize) -> Option<u32> {
    if size == 0 || size > MAX_REGION_SIZE { return None; }

    // Find free slot
    unsafe {
        for i in 0..MAX_REGIONS {
            if !REGIONS[i].active {
                // Allocate physical frames for the region
                let phys_addr;

                // Allocate contiguous frames (best effort)
                if let Some(addr) = crate::arch::x86_64::paging::alloc_frame() {
                    phys_addr = addr;
                    // For multi-page regions, allocate more frames
                    // (simplified: only single-page regions for now)
                } else {
                    return None;
                }

                let id = NEXT_REGION_ID;
                NEXT_REGION_ID += 1;

                REGIONS[i] = RegionDescriptor {
                    id,
                    phys_addr,
                    size: size.min(4096), // Stage-3: single page max
                    owner,
                    active: true,
                };

                serial_println!("[LARGE_MSG] Region {} allocated: phys={:#x} size={} owner={}",
                    id, phys_addr, size.min(4096), owner);

                return Some(id);
            }
        }
    }

    None
}

/// Free a shared memory region
pub fn free_region(region_id: u32, requester: AgentId) -> bool {
    unsafe {
        for i in 0..MAX_REGIONS {
            if REGIONS[i].active && REGIONS[i].id == region_id {
                if REGIONS[i].owner == requester {
                    crate::arch::x86_64::paging::dealloc_frame(REGIONS[i].phys_addr);
                    REGIONS[i].active = false;
                    return true;
                }
                return false; // not owner
            }
        }
    }
    false
}

/// Get a region descriptor by ID
pub fn get_region(region_id: u32) -> Option<RegionDescriptor> {
    unsafe {
        for i in 0..MAX_REGIONS {
            if REGIONS[i].active && REGIONS[i].id == region_id {
                return Some(REGIONS[i]);
            }
        }
    }
    None
}

/// Write data to a shared region (kernel-side, used by the owner agent)
pub fn write_region(region_id: u32, offset: usize, data: &[u8]) -> Result<(), ()> {
    let region = get_region(region_id).ok_or(())?;
    if offset + data.len() > region.size { return Err(()); }

    unsafe {
        let dst = (region.phys_addr as *mut u8).add(offset);
        core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
    }
    Ok(())
}

/// Read data from a shared region
pub fn read_region(region_id: u32, offset: usize, buf: &mut [u8]) -> Result<usize, ()> {
    let region = get_region(region_id).ok_or(())?;
    let available = region.size.saturating_sub(offset);
    let len = buf.len().min(available);

    unsafe {
        let src = (region.phys_addr as *const u8).add(offset);
        core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), len);
    }
    Ok(len)
}
