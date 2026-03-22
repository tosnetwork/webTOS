//! AOS x86_64 Paging - Simple Frame Allocator
//!
//! Provides a basic bitmap frame allocator for physical 4KB pages.
//! Identity mapping is set up by boot.asm; this module manages frame
//! allocation for future use (agent address spaces, stacks, etc.).

use core::sync::atomic::{AtomicU64, Ordering};
use crate::serial_println;

/// Page/frame size: 4 KiB.
pub const PAGE_SIZE: usize = 4096;

/// Maximum physical memory managed (128 MB).
const MAX_MEMORY: usize = 128 * 1024 * 1024;

/// Total number of frames in the managed region.
const MAX_FRAMES: usize = MAX_MEMORY / PAGE_SIZE;

/// Number of u64 bitmap entries needed (each covers 64 frames).
const BITMAP_SIZE: usize = (MAX_FRAMES + 63) / 64;

// Bitmap: bit set = frame is allocated, bit clear = frame is free.
// Safety: single-core access in Stage-1.
static mut BITMAP: [u64; BITMAP_SIZE] = [0u64; BITMAP_SIZE];

// Next frame index to check (simple bump hint for fast allocation).
// Initialized to 0; set properly in init().
static NEXT_FREE: AtomicU64 = AtomicU64::new(0);

extern "C" {
    static __kernel_end: u8;
}

/// Initialize the frame allocator.
///
/// Reserves all frames from 0 up to __kernel_end (kernel code, BSS,
/// page tables, and stack). This prevents the allocator from handing
/// out frames that overlap with the running kernel.
pub fn init() {
    // Calculate the first safe frame: round __kernel_end up to the next page
    let kernel_end = unsafe { &__kernel_end as *const u8 as usize };
    let reserved_frames = (kernel_end + PAGE_SIZE - 1) / PAGE_SIZE;

    unsafe {
        for i in 0..reserved_frames {
            let word = i / 64;
            let bit = i % 64;
            BITMAP[word] |= 1u64 << bit;
        }
    }

    NEXT_FREE.store(reserved_frames as u64, Ordering::Relaxed);

    let available = MAX_FRAMES - reserved_frames;
    serial_println!("[paging] Frame allocator initialized: {} frames available ({} MB), kernel reserved {} frames ({} KB)",
        available,
        available * PAGE_SIZE / (1024 * 1024),
        reserved_frames,
        reserved_frames * PAGE_SIZE / 1024);
}

/// Allocate a single 4KB physical frame.
///
/// Returns the physical address of the frame, or None if out of memory.
pub fn alloc_frame() -> Option<u64> {
    let start = NEXT_FREE.load(Ordering::Relaxed) as usize;

    unsafe {
        // Search from hint forward
        for i in start..MAX_FRAMES {
            let word = i / 64;
            let bit = i % 64;
            if BITMAP[word] & (1u64 << bit) == 0 {
                // Found a free frame -- mark it allocated
                BITMAP[word] |= 1u64 << bit;
                NEXT_FREE.store((i + 1) as u64, Ordering::Relaxed);
                return Some((i * PAGE_SIZE) as u64);
            }
        }

        // Wrap around and search from frame 1 to start
        for i in 1..start {
            let word = i / 64;
            let bit = i % 64;
            if BITMAP[word] & (1u64 << bit) == 0 {
                BITMAP[word] |= 1u64 << bit;
                NEXT_FREE.store((i + 1) as u64, Ordering::Relaxed);
                return Some((i * PAGE_SIZE) as u64);
            }
        }
    }

    None // Out of memory
}

/// Free a previously allocated 4KB physical frame.
///
/// # Safety
/// The address must have been returned by `alloc_frame()` and must not
/// be freed more than once.
pub fn dealloc_frame(addr: u64) {
    let frame = addr as usize / PAGE_SIZE;
    if frame >= MAX_FRAMES {
        return;
    }
    let word = frame / 64;
    let bit = frame % 64;
    unsafe {
        BITMAP[word] &= !(1u64 << bit);
    }
    // Update hint if this frame is earlier
    let current = NEXT_FREE.load(Ordering::Relaxed) as usize;
    if frame < current {
        NEXT_FREE.store(frame as u64, Ordering::Relaxed);
    }
}

/// Read the current value of CR3 (page table base register).
pub fn read_cr3() -> u64 {
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3
}

// ─── Per-agent page table management ─────────────────────────────────────

/// Page table entry flags
pub const PTE_PRESENT: u64 = 1 << 0;
pub const PTE_WRITABLE: u64 = 1 << 1;
pub const PTE_USER: u64 = 1 << 2;
pub const PTE_WRITE_THROUGH: u64 = 1 << 3;
pub const PTE_NO_CACHE: u64 = 1 << 4;
pub const PTE_ACCESSED: u64 = 1 << 5;
pub const PTE_DIRTY: u64 = 1 << 6;
pub const PTE_HUGE: u64 = 1 << 7;
pub const PTE_GLOBAL: u64 = 1 << 8;
pub const PTE_NO_EXECUTE: u64 = 1 << 63;

/// Page table levels
const PT_LEVELS: usize = 4; // PML4 -> PDPT -> PD -> PT

/// Create a new independent page table hierarchy for an agent.
///
/// Allocates fresh PML4, PDPT, and PD frames. The kernel's identity-mapped
/// 2MB huge pages are copied into the new PD as supervisor-only entries.
/// This ensures that map_page() on the new address space does NOT modify
/// the boot page tables (which are shared by the kernel).
pub fn create_address_space() -> Option<u64> {
    // 1. Allocate fresh frames for PML4, PDPT, and PD
    let pml4_phys = alloc_frame()?;
    let pdpt_phys = alloc_frame()?;
    let pd_phys = alloc_frame()?;

    let pml4 = pml4_phys as *mut u64;
    let pdpt = pdpt_phys as *mut u64;
    let pd = pd_phys as *mut u64;

    unsafe {
        // 2. Zero all three tables
        core::ptr::write_bytes(pml4, 0, PAGE_SIZE / 8);
        core::ptr::write_bytes(pdpt, 0, PAGE_SIZE / 8);
        core::ptr::write_bytes(pd, 0, PAGE_SIZE / 8);

        // 3. Copy PD entries (2MB huge pages) from the boot page tables.
        //    This gives the new address space the same kernel identity mapping
        //    but in an INDEPENDENT PD that can be modified without affecting boot.
        let current_cr3 = read_cr3();
        let boot_pml4 = current_cr3 as *const u64;
        let boot_pml4_0 = core::ptr::read_volatile(boot_pml4);
        if boot_pml4_0 & PTE_PRESENT != 0 {
            let boot_pdpt = (boot_pml4_0 & 0x000F_FFFF_FFFF_F000) as *const u64;
            let boot_pdpt_0 = core::ptr::read_volatile(boot_pdpt);
            if boot_pdpt_0 & PTE_PRESENT != 0 {
                let boot_pd = (boot_pdpt_0 & 0x000F_FFFF_FFFF_F000) as *const u64;
                // Copy all 512 PD entries (2MB huge pages for kernel identity mapping)
                for i in 0..512 {
                    let entry = core::ptr::read_volatile(boot_pd.add(i));
                    core::ptr::write_volatile(pd.add(i), entry);
                }
            }
        }

        // 4. Wire up: PML4[0] → new PDPT, PDPT[0] → new PD
        core::ptr::write_volatile(pml4, pdpt_phys | PTE_PRESENT | PTE_WRITABLE | PTE_USER);
        core::ptr::write_volatile(pdpt, pd_phys | PTE_PRESENT | PTE_WRITABLE | PTE_USER);
    }

    Some(pml4_phys)
}

/// Destroy an agent's address space.
/// Frees the PML4 and all page table frames allocated for user-space mappings.
/// Does NOT free the kernel mappings (those are shared).
pub fn destroy_address_space(pml4_phys: u64) {
    // 1. Walk the PML4 entries that belong to user space (entries 4..256)
    // 2. For each present entry, walk down and free all page table frames
    // 3. Free the PML4 frame itself

    let pml4 = pml4_phys as *const u64;
    unsafe {
        // Only free user-space entries (4..256, skipping kernel entries 0..4 and 256..512)
        for i in 4..256 {
            let pml4e = core::ptr::read_volatile(pml4.add(i));
            if pml4e & PTE_PRESENT != 0 {
                let pdpt_phys = pml4e & 0x000F_FFFF_FFFF_F000;
                free_page_table_level(pdpt_phys, 3);
            }
        }
    }

    dealloc_frame(pml4_phys);
}

/// Recursively free page table frames at a given level.
/// level 3 = PDPT, 2 = PD, 1 = PT
unsafe fn free_page_table_level(table_phys: u64, level: usize) {
    let table = table_phys as *const u64;

    if level > 1 {
        for i in 0..512 {
            let entry = core::ptr::read_volatile(table.add(i));
            if entry & PTE_PRESENT != 0 && entry & PTE_HUGE == 0 {
                let next_phys = entry & 0x000F_FFFF_FFFF_F000;
                free_page_table_level(next_phys, level - 1);
            }
        }
    }

    dealloc_frame(table_phys);
}

/// Map a single 4KB page in an agent's address space.
/// Creates intermediate page table levels as needed.
pub fn map_page(pml4_phys: u64, virt_addr: u64, phys_addr: u64, flags: u64) -> Result<(), ()> {
    let pml4_idx = ((virt_addr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((virt_addr >> 30) & 0x1FF) as usize;
    let pd_idx = ((virt_addr >> 21) & 0x1FF) as usize;
    let pt_idx = ((virt_addr >> 12) & 0x1FF) as usize;

    unsafe {
        // Walk PML4 -> PDPT
        let pml4 = pml4_phys as *mut u64;
        let pdpt_phys = ensure_table_entry(pml4, pml4_idx, flags)?;

        // Walk PDPT -> PD
        let pdpt = pdpt_phys as *mut u64;
        let pd_phys = ensure_table_entry(pdpt, pdpt_idx, flags)?;

        // Walk PD -> PT
        let pd = pd_phys as *mut u64;
        let pt_phys = ensure_table_entry(pd, pd_idx, flags)?;

        // Set PT entry
        let pt = pt_phys as *mut u64;
        core::ptr::write_volatile(
            pt.add(pt_idx),
            (phys_addr & 0x000F_FFFF_FFFF_F000) | flags | PTE_PRESENT,
        );
    }

    Ok(())
}

/// Ensure a page table entry exists at the given index.
/// If not present, allocate a new frame for the next-level table.
/// Returns the physical address of the next-level table.
unsafe fn ensure_table_entry(table: *mut u64, index: usize, flags: u64) -> Result<u64, ()> {
    let entry = core::ptr::read_volatile(table.add(index));
    if entry & PTE_PRESENT != 0 {
        // Entry exists, return the physical address of the next table
        // Update flags (e.g., add USER bit if needed)
        let phys = entry & 0x000F_FFFF_FFFF_F000;
        let new_entry = phys | (entry & 0xFFF) | (flags & (PTE_USER | PTE_WRITABLE));
        core::ptr::write_volatile(table.add(index), new_entry);
        Ok(phys)
    } else {
        // Allocate a new frame for the next-level table
        let new_frame = alloc_frame().ok_or(())?;
        // Zero the new frame
        core::ptr::write_bytes(new_frame as *mut u8, 0, PAGE_SIZE);
        // Set the entry
        core::ptr::write_volatile(
            table.add(index),
            new_frame | PTE_PRESENT | PTE_WRITABLE | (flags & PTE_USER),
        );
        Ok(new_frame)
    }
}

/// Unmap a single 4KB page from an agent's address space.
/// Does NOT free intermediate page table frames (those are cleaned up by destroy_address_space).
pub fn unmap_page(pml4_phys: u64, virt_addr: u64) {
    let pml4_idx = ((virt_addr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((virt_addr >> 30) & 0x1FF) as usize;
    let pd_idx = ((virt_addr >> 21) & 0x1FF) as usize;
    let pt_idx = ((virt_addr >> 12) & 0x1FF) as usize;

    unsafe {
        let pml4 = pml4_phys as *const u64;
        let pml4e = core::ptr::read_volatile(pml4.add(pml4_idx));
        if pml4e & PTE_PRESENT == 0 { return; }

        let pdpt = (pml4e & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pdpte = core::ptr::read_volatile(pdpt.add(pdpt_idx));
        if pdpte & PTE_PRESENT == 0 { return; }

        let pd = (pdpte & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pde = core::ptr::read_volatile(pd.add(pd_idx));
        if pde & PTE_PRESENT == 0 { return; }

        let pt = (pde & 0x000F_FFFF_FFFF_F000) as *mut u64;
        core::ptr::write_volatile(pt.add(pt_idx), 0);

        // Invalidate TLB for this address
        invlpg(virt_addr);
    }
}

/// Invalidate a single TLB entry
pub fn invlpg(addr: u64) {
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) addr, options(nostack, preserves_flags));
    }
}
