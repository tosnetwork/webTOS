//! AOS x86_64 Paging - Simple Frame Allocator
//!
//! Provides a basic bitmap frame allocator for physical 4KB pages.
//! Boot.asm sets up dual mapping: identity (PML4[0]) + higher-half
//! (PML4[511]). Kernel code runs at KERNEL_VMA (0xFFFFFFFF80000000+)
//! but physical memory remains accessible via the identity mapping.

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

/// Higher-half kernel virtual base address.
/// Kernel code/data/BSS is linked at KERNEL_VMA + physical offset.
/// Physical memory remains accessible via the identity mapping (PML4[0]).
pub const KERNEL_VMA_OFFSET: usize = 0xFFFF_FFFF_8000_0000;

/// UEFI boot-info header placed at physical 0x7000 by the UEFI stub.
///
/// The stub writes this struct at 0x7000, then copies the raw UEFI memory
/// map directly after it (at 0x7000 + 64). `mmap_addr` points to that copy.
#[repr(C)]
pub struct BootInfo {
    /// Magic value — must equal 0xAE510EF1 to confirm UEFI boot.
    pub magic: u32,
    /// Physical address of the UEFI memory descriptor array.
    pub mmap_addr: u64,
    /// Total size of the memory map in bytes.
    pub mmap_size: u32,
    /// Size of a single EFI_MEMORY_DESCRIPTOR (may be > 40 bytes).
    pub desc_size: u32,
    /// Number of descriptors in the map.
    pub desc_count: u32,
    // ── Framebuffer info (from UEFI GOP) ──
    /// Physical address of the GOP framebuffer (0 if unavailable).
    pub fb_addr: u64,
    /// Horizontal resolution in pixels.
    pub fb_width: u32,
    /// Vertical resolution in pixels.
    pub fb_height: u32,
    /// Pixels per scan line (stride).
    pub fb_stride: u32,
    /// Pixel format: 0=RGBX, 1=BGRX.
    pub fb_pixel_format: u32,
}

/// EFI memory descriptor as defined by the UEFI specification.
///
/// The descriptor stride on the wire (`desc_size`) may be larger than
/// `core::mem::size_of::<EfiMemoryDescriptor>()` (40 bytes) due to
/// firmware-specific extensions; always walk by `desc_size`.
#[repr(C)]
struct EfiMemoryDescriptor {
    type_: u32,
    _pad: u32,
    physical_start: u64,
    virtual_start: u64,
    number_of_pages: u64,
    attribute: u64,
}

/// EFI memory type for usable RAM (EfiConventionalMemory).
const EFI_CONVENTIONAL_MEMORY: u32 = 7;

/// Initialize the frame allocator from a UEFI memory map.
///
/// Called on the UEFI boot path. Parses the descriptor array that the UEFI
/// stub copied to physical memory and marks only `EfiConventionalMemory`
/// (type 7) regions as available. All other regions remain reserved (bitmap
/// bit clear → allocated/reserved in the current scheme, which uses
/// bit-set = allocated).
///
/// Frames below `__kernel_end` are always reserved regardless of what the
/// firmware reported. The managed window is capped at `MAX_MEMORY` (128 MB).
///
/// # Arguments
/// * `mmap_ptr`  – physical address of the first EFI_MEMORY_DESCRIPTOR
/// * `mmap_size` – total byte length of the descriptor array
/// * `desc_size` – stride between consecutive descriptors (≥ 40 bytes)
pub fn init_from_uefi_mmap(mmap_ptr: u64, mmap_size: usize, desc_size: usize) {
    // Resolve __kernel_end physical address
    let kernel_end_virt = unsafe { &__kernel_end as *const u8 as usize };
    let kernel_end_phys = if kernel_end_virt >= KERNEL_VMA_OFFSET {
        kernel_end_virt - KERNEL_VMA_OFFSET
    } else {
        kernel_end_virt
    };
    let kernel_reserved_frames = (kernel_end_phys + PAGE_SIZE - 1) / PAGE_SIZE;

    // Sanity-check desc_size: it must be at least the size of our struct.
    let min_desc = core::mem::size_of::<EfiMemoryDescriptor>(); // 40
    if desc_size < min_desc || desc_size > 4096 {
        serial_println!("[paging] UEFI mmap: invalid desc_size {}, falling back to init()", desc_size);
        init();
        return;
    }

    // Sanity-check pointer
    if mmap_ptr == 0 || mmap_size == 0 {
        serial_println!("[paging] UEFI mmap: null/empty map, falling back to init()");
        init();
        return;
    }

    // Start with the bitmap fully set (all frames allocated/reserved).
    // We will clear bits only for frames that are EfiConventionalMemory.
    unsafe {
        for word in BITMAP.iter_mut() {
            *word = !0u64; // all bits set = all frames reserved
        }
    }

    let desc_count = mmap_size / desc_size;
    let mut available_frames: usize = 0;

    for i in 0..desc_count {
        let desc_ptr = (mmap_ptr as usize + i * desc_size) as *const EfiMemoryDescriptor;
        let desc = unsafe { &*desc_ptr };

        if desc.type_ != EFI_CONVENTIONAL_MEMORY {
            // Not usable RAM — leave as reserved (bit already set)
            continue;
        }

        // Mark conventional memory frames as free (clear the bits)
        let region_start = desc.physical_start as usize;
        let region_pages = desc.number_of_pages as usize;

        for p in 0..region_pages {
            let frame = region_start / PAGE_SIZE + p;

            // Skip frames below kernel end
            if frame < kernel_reserved_frames {
                continue;
            }

            // Cap at MAX_MEMORY
            if frame >= MAX_FRAMES {
                break;
            }

            // Clear bit → frame is free
            let word = frame / 64;
            let bit = frame % 64;
            unsafe {
                BITMAP[word] &= !(1u64 << bit);
            }
            available_frames += 1;
        }
    }

    // Set NEXT_FREE to first frame after kernel
    NEXT_FREE.store(kernel_reserved_frames as u64, Ordering::Relaxed);

    serial_println!(
        "[paging] UEFI mmap: {} descriptors parsed, {} frames available ({} MB), kernel reserved {} frames ({} KB)",
        desc_count,
        available_frames,
        available_frames * PAGE_SIZE / (1024 * 1024),
        kernel_reserved_frames,
        kernel_reserved_frames * PAGE_SIZE / 1024,
    );
}

/// Initialize the frame allocator.
///
/// Reserves all frames from 0 up to __kernel_end (kernel code, BSS,
/// page tables, and stack). This prevents the allocator from handing
/// out frames that overlap with the running kernel.
pub fn init() {
    // __kernel_end is linked at the higher-half VMA — convert to physical
    let kernel_end_virt = unsafe { &__kernel_end as *const u8 as usize };
    let kernel_end = if kernel_end_virt >= KERNEL_VMA_OFFSET {
        kernel_end_virt - KERNEL_VMA_OFFSET
    } else {
        kernel_end_virt
    };
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
/// Alias: NX (No-Execute) bit — same as PTE_NO_EXECUTE, prefer this name
/// when explicitly enforcing the NX policy on stack/data pages.
pub const PTE_NX: u64 = 1 << 63;

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

        // 5. Copy PML4[511] — higher-half kernel mapping (supervisor-only, shared)
        // This ensures the kernel remains accessible in the agent's address space.
        let boot_pml4_511 = core::ptr::read_volatile(boot_pml4.add(511));
        if boot_pml4_511 & PTE_PRESENT != 0 {
            core::ptr::write_volatile(pml4.add(511), boot_pml4_511);
        }
    }

    Some(pml4_phys)
}

/// Destroy an agent's address space.
/// Frees the PML4 and all page table frames allocated for user-space mappings.
/// Does NOT free the kernel mappings (those are shared).
pub fn destroy_address_space(pml4_phys: u64) {
    let pml4 = pml4_phys as *const u64;
    unsafe {
        // 1. Free PML4[0]'s PDPT and PD (allocated per-agent in create_address_space).
        //    We free only the PDPT and PD frames — NOT the huge page entries
        //    (those map shared physical memory, not allocated page tables).
        let pml4_0 = core::ptr::read_volatile(pml4);
        if pml4_0 & PTE_PRESENT != 0 {
            let pdpt_phys = pml4_0 & 0x000F_FFFF_FFFF_F000;
            let pdpt = pdpt_phys as *const u64;
            let pdpt_0 = core::ptr::read_volatile(pdpt);
            if pdpt_0 & PTE_PRESENT != 0 {
                // Free PD frame (contains huge page entries, not sub-tables)
                let pd_phys = pdpt_0 & 0x000F_FFFF_FFFF_F000;
                dealloc_frame(pd_phys);
            }
            // Free PDPT frame
            dealloc_frame(pdpt_phys);
        }

        // 2. Free user-space entries (PML4[4..256] — may have page tables
        //    allocated by map_page for user code/stack)
        for i in 4..256 {
            let pml4e = core::ptr::read_volatile(pml4.add(i));
            if pml4e & PTE_PRESENT != 0 {
                let pdpt_phys = pml4e & 0x000F_FFFF_FFFF_F000;
                free_page_table_level(pdpt_phys, 3);
            }
        }

        // 3. PML4[511] is the shared higher-half kernel mapping — do NOT free.
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

/// Map a stack or data page — always sets PTE_NX (No-Execute).
///
/// Use this for any page that should hold data but not be executable
/// (stacks, heap, BSS, message buffers, …).  The NX bit is forced on
/// regardless of what is passed in `flags`, so callers cannot accidentally
/// create a writable-and-executable data page.
pub fn map_data_page(pml4_phys: u64, virt_addr: u64, phys_addr: u64, flags: u64) -> Result<(), ()> {
    map_page(pml4_phys, virt_addr, phys_addr, flags | PTE_NX)
}

/// Map a code page — explicitly clears PTE_NX so the page is executable.
///
/// Use this only for read-only text segments.  Writable+executable pages
/// are refused: if `flags` contains `PTE_WRITABLE` the call returns `Err(())`.
pub fn map_code_page(pml4_phys: u64, virt_addr: u64, phys_addr: u64, flags: u64) -> Result<(), ()> {
    if flags & PTE_WRITABLE != 0 {
        // W^X: refuse to create a writable executable page
        return Err(());
    }
    map_page(pml4_phys, virt_addr, phys_addr, flags & !PTE_NX)
}

/// Map a single 4KB page in an agent's address space.
/// Creates intermediate page table levels as needed.
///
/// Prefer `map_data_page` / `map_code_page` over this function to ensure
/// the correct NX policy is applied automatically.
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
