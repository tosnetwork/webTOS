//! ATOS x86_64 Paging and Frame Allocation
//!
//! Provides page-table management together with a buddy-backed physical frame
//! allocator for 4 KiB pages.
//! Boot.asm sets up dual mapping: identity (PML4[0]) + higher-half
//! (PML4[511]). Kernel code runs at KERNEL_VMA (0xFFFFFFFF80000000+)
//! but physical memory remains accessible via the identity mapping.

use super::{frame_alloc, frame_meta, kaslr};
use crate::serial_println;
use crate::sync::SpinLock;

/// Page/frame size: 4 KiB.
pub const PAGE_SIZE: usize = 4096;

/// Maximum physical memory managed (1 GiB).
///
/// The boot page tables already provide a 1 GiB identity mapping
/// (512 × 2 MiB huge pages under PML4[0]), so the frame allocator can
/// safely manage the full window without needing extra early mappings.
const MAX_MEMORY: usize = frame_alloc::MAX_MEMORY;

/// Conservative fallback when the boot loader did not report RAM size.
const DEFAULT_MEMORY_LIMIT: usize = 512 * 1024 * 1024;

const MAX_TRACKED_ADDRESS_SPACES: usize = 128;

pub use frame_meta::FrameKind;

#[derive(Clone, Copy)]
struct AddressSpaceRef {
    root: u64,
    refs: u16,
    active: bool,
}

impl AddressSpaceRef {
    const fn empty() -> Self {
        Self {
            root: 0,
            refs: 0,
            active: false,
        }
    }
}

static ADDRESS_SPACE_REFS: SpinLock<[AddressSpaceRef; MAX_TRACKED_ADDRESS_SPACES]> =
    SpinLock::new([const { AddressSpaceRef::empty() }; MAX_TRACKED_ADDRESS_SPACES]);

extern "C" {
    static __kernel_end: u8;
}

/// Higher-half kernel virtual base address.
/// Kernel code/data/BSS is linked at KERNEL_VMA + physical offset.
/// Physical memory remains accessible via the identity mapping (PML4[0]).
pub const KERNEL_VMA_OFFSET: usize = 0xFFFF_FFFF_8000_0000;

/// Translate a physical address in the boot-mapped 0..1 GiB window into the
/// higher-half alias that remains valid in every address space.
#[inline]
pub const fn phys_to_virt(phys: u64) -> usize {
    KERNEL_VMA_OFFSET + phys as usize
}

#[inline]
const fn phys_to_const_ptr<T>(phys: u64) -> *const T {
    phys_to_virt(phys) as *const T
}

#[inline]
const fn phys_to_mut_ptr<T>(phys: u64) -> *mut T {
    phys_to_virt(phys) as *mut T
}

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
/// firmware reported. The managed window is capped at `MAX_MEMORY` (512 MB).
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
        serial_println!(
            "[paging] UEFI mmap: invalid desc_size {}, falling back to init()",
            desc_size
        );
        init();
        return;
    }

    // Sanity-check pointer
    if mmap_ptr == 0 || mmap_size == 0 {
        serial_println!("[paging] UEFI mmap: null/empty map, falling back to init()");
        init();
        return;
    }

    let desc_count = mmap_size / desc_size;
    let mut highest_frame_seen = kernel_reserved_frames;

    for i in 0..desc_count {
        let desc_ptr = (mmap_ptr as usize + i * desc_size) as *const EfiMemoryDescriptor;
        let desc = unsafe { &*desc_ptr };

        if desc.type_ != EFI_CONVENTIONAL_MEMORY {
            // Not usable RAM — leave as reserved (bit already set)
            continue;
        }

        let region_start = desc.physical_start as usize;
        let region_pages = desc.number_of_pages as usize;

        let region_start_frame = region_start / PAGE_SIZE;
        let region_end_frame = region_start_frame
            .saturating_add(region_pages)
            .min(frame_alloc::MAX_FRAMES);
        highest_frame_seen = highest_frame_seen.max(region_end_frame);
    }

    let managed_frames = highest_frame_seen.max(kernel_reserved_frames);
    frame_alloc::init_empty(managed_frames);
    frame_meta::init(managed_frames);

    for i in 0..desc_count {
        let desc_ptr = (mmap_ptr as usize + i * desc_size) as *const EfiMemoryDescriptor;
        let desc = unsafe { &*desc_ptr };

        if desc.type_ != EFI_CONVENTIONAL_MEMORY {
            continue;
        }

        let region_start = desc.physical_start as usize / PAGE_SIZE;
        let region_end = region_start
            .saturating_add(desc.number_of_pages as usize)
            .min(managed_frames);
        let free_start = region_start.max(kernel_reserved_frames);
        if free_start < region_end {
            frame_alloc::add_free_range(free_start, region_end);
            frame_meta::mark_free_range(free_start, region_end);
        }
    }

    let available_frames = frame_alloc::free_frames();

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
/// Reserves all frames from 0 up to the actual kernel end (including .data
/// and .bss which may be much larger than __kernel_end suggests). The kernel
/// end is computed by scanning the static BSS end address, since .data and
/// .bss contain large static arrays (AGENT_TABLE, KEYSPACES, LINUX_STATES,
/// BASE_IMAGE_STORE, etc.) that occupy megabytes of physical memory.
pub fn init() {
    init_with_memory_limit(DEFAULT_MEMORY_LIMIT);
}

pub fn init_with_memory_limit(total_memory_bytes: usize) {
    // __kernel_end is a linker symbol but doesn't account for all loaded
    // segments. Compute the actual kernel end from the highest BSS address.
    // The last BSS section ends at __bss_end, but initialized statics in
    // .data extend further. Use a conservative estimate: scan for the
    // highest known static address.
    let kernel_end_virt = unsafe { &__kernel_end as *const u8 as usize };
    let kernel_end_linker = if kernel_end_virt >= KERNEL_VMA_OFFSET {
        kernel_end_virt - KERNEL_VMA_OFFSET
    } else {
        kernel_end_virt
    };

    // The actual kernel footprint includes .data (initialized statics).
    // Compute from the kernel binary size: text + data + bss sections.
    // Conservative: reserve 16 MB to cover kernel + BSS + stack + headroom.
    let kernel_end = core::cmp::max(kernel_end_linker, 16 * 1024 * 1024);

    let managed_bytes = total_memory_bytes.clamp(PAGE_SIZE, MAX_MEMORY);
    let managed_frames = managed_bytes / PAGE_SIZE;
    let reserved_frames = ((kernel_end + PAGE_SIZE - 1) / PAGE_SIZE).min(managed_frames);

    // Apply heap ASLR: skip a random number of frames after the kernel image
    // so that the first heap allocation lands at a non-deterministic address.
    // kaslr::heap_skip_frames() returns 0 if kaslr::init() has not yet been
    // called (entropy = 0), which is safe but non-random.
    let skip = kaslr::heap_skip_frames();
    let first_free = (reserved_frames + skip).min(managed_frames);

    frame_alloc::init_empty(managed_frames);
    frame_meta::init(managed_frames);
    if first_free < managed_frames {
        frame_alloc::add_free_range(first_free, managed_frames);
        frame_meta::mark_free_range(first_free, managed_frames);
    }

    let available = frame_alloc::free_frames();
    serial_println!("[paging] Frame allocator initialized: {} frames available ({} MB), kernel reserved {} frames ({} KB), heap ASLR skip {} frames, managed RAM {} MB",
        available,
        available * PAGE_SIZE / (1024 * 1024),
        reserved_frames,
        reserved_frames * PAGE_SIZE / 1024,
        skip,
        managed_bytes / (1024 * 1024));
}

/// Allocate a single 4KB physical frame.
///
/// Returns the physical address of the frame, or None if out of memory.
pub fn alloc_frame() -> Option<u64> {
    alloc_frame_with_kind(FrameKind::Unknown)
}

/// Allocate a single 4KB frame and classify it with the supplied kind.
pub fn alloc_frame_with_kind(kind: FrameKind) -> Option<u64> {
    let frame = frame_alloc::alloc_frame()?;
    let _ = frame_meta::on_alloc(frame, kind);
    Some(frame)
}

/// Allocate an exact contiguous range of frames and classify them with the
/// supplied kind.
pub fn alloc_contiguous_frames_with_kind(num_pages: usize, kind: FrameKind) -> Option<u64> {
    if num_pages == 0 {
        return None;
    }
    let base = frame_alloc::alloc_contiguous(num_pages)?;
    let _ = frame_meta::on_alloc_range(base, num_pages, kind);
    Some(base)
}

/// Free a previously allocated 4KB physical frame.
///
/// # Safety
/// The address must have been returned by `alloc_frame()` and must not
/// be freed more than once.
pub fn dealloc_frame(addr: u64) {
    let _ = release_frame(addr);
}

/// Increase the reference count on a managed physical frame.
pub fn retain_frame(addr: u64) -> bool {
    frame_meta::retain(addr)
}

/// Release a managed physical frame.
///
/// Returns `true` if the frame metadata was updated. When the last reference
/// is dropped the backing page is returned to the buddy allocator.
pub fn release_frame(addr: u64) -> bool {
    match frame_meta::release(addr) {
        frame_meta::ReleaseResult::FreeNow => {
            frame_alloc::dealloc_frame(addr);
            true
        }
        frame_meta::ReleaseResult::StillReferenced(_) => true,
        frame_meta::ReleaseResult::AlreadyFree | frame_meta::ReleaseResult::Unmanaged => false,
    }
}

/// Release an exact contiguous range of frames that are not expected to be
/// shared.
pub fn release_contiguous_frames(addr: u64, num_pages: usize) -> bool {
    if num_pages == 0 {
        return false;
    }

    let start_frame = (addr as usize) / PAGE_SIZE;
    let end_frame = start_frame.saturating_add(num_pages);
    frame_meta::mark_free_range(start_frame, end_frame);
    frame_alloc::dealloc_contiguous(addr, num_pages);
    true
}

/// Update the classification for a managed frame.
pub fn set_frame_kind(addr: u64, kind: FrameKind) -> bool {
    frame_meta::set_kind(addr, kind)
}

/// Return the current reference count for a managed frame.
pub fn frame_refcount(addr: u64) -> u16 {
    frame_meta::refcount(addr)
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

fn create_address_space_inner(copy_low_identity: bool) -> Option<u64> {
    // 1. Allocate fresh frames for PML4, PDPT, and PD
    let pml4_phys = alloc_frame_with_kind(FrameKind::PageTable)?;
    let pdpt_phys = match alloc_frame_with_kind(FrameKind::PageTable) {
        Some(frame) => frame,
        None => {
            let _ = release_frame(pml4_phys);
            return None;
        }
    };
    let pd_phys = match alloc_frame_with_kind(FrameKind::PageTable) {
        Some(frame) => frame,
        None => {
            let _ = release_frame(pdpt_phys);
            let _ = release_frame(pml4_phys);
            return None;
        }
    };

    let pml4 = phys_to_mut_ptr::<u64>(pml4_phys);
    let pdpt = phys_to_mut_ptr::<u64>(pdpt_phys);
    let pd = phys_to_mut_ptr::<u64>(pd_phys);

    unsafe {
        // 2. Zero all three tables
        core::ptr::write_bytes(pml4, 0, PAGE_SIZE / 8);
        core::ptr::write_bytes(pdpt, 0, PAGE_SIZE / 8);
        core::ptr::write_bytes(pd, 0, PAGE_SIZE / 8);

        // 3. Optionally copy the low 1 GiB supervisor-only identity window.
        // Linux-compat address spaces intentionally leave this range empty so
        // low-address ET_EXEC binaries can be mapped at their link-time VAs.
        if copy_low_identity {
            let current_cr3 = read_cr3();
            let boot_pml4 = phys_to_const_ptr::<u64>(current_cr3);
            let boot_pml4_0 = core::ptr::read_volatile(boot_pml4);
            if boot_pml4_0 & PTE_PRESENT != 0 {
                let boot_pdpt = phys_to_const_ptr::<u64>(boot_pml4_0 & 0x000F_FFFF_FFFF_F000);
                let boot_pdpt_0 = core::ptr::read_volatile(boot_pdpt);
                if boot_pdpt_0 & PTE_PRESENT != 0 {
                    let boot_pd =
                        phys_to_const_ptr::<u64>(boot_pdpt_0 & 0x000F_FFFF_FFFF_F000);
                    for i in 0..512 {
                        let entry = core::ptr::read_volatile(boot_pd.add(i));
                        core::ptr::write_volatile(pd.add(i), entry & !PTE_USER);
                    }
                }
            }
        }

        // 4. Wire up PML4[0] → new PDPT. Low-address Linux mappings and the
        // deterministic mmap region both live under this slot.
        core::ptr::write_volatile(pml4, pdpt_phys | PTE_PRESENT | PTE_WRITABLE | PTE_USER);
        core::ptr::write_volatile(
            pdpt,
            pd_phys
                | PTE_PRESENT
                | PTE_WRITABLE
                | if copy_low_identity { 0 } else { PTE_USER },
        );

        // 5. Copy PML4[511] — higher-half kernel mapping (supervisor-only, shared)
        // This ensures the kernel remains accessible in the agent's address space.
        let current_cr3 = read_cr3();
        let boot_pml4 = phys_to_const_ptr::<u64>(current_cr3);
        let boot_pml4_511 = core::ptr::read_volatile(boot_pml4.add(511));
        if boot_pml4_511 & PTE_PRESENT != 0 {
            core::ptr::write_volatile(pml4.add(511), boot_pml4_511);
        }
    }

    if !track_address_space(pml4_phys) {
        destroy_address_space(pml4_phys);
        return None;
    }

    Some(pml4_phys)
}

/// Create a new independent page table hierarchy for a native/ATOS agent.
///
/// This preserves the historical low 1 GiB identity window.
pub fn create_address_space() -> Option<u64> {
    create_address_space_inner(true)
}

/// Create a Linux-compat address space with no pre-populated low identity
/// mapping so user-space can legally occupy low virtual addresses.
pub fn create_linux_address_space() -> Option<u64> {
    create_address_space_inner(false)
}

fn track_address_space(pml4_phys: u64) -> bool {
    let mut refs = ADDRESS_SPACE_REFS.lock();

    for entry in refs.iter_mut() {
        if entry.active && entry.root == pml4_phys {
            entry.refs = entry.refs.saturating_add(1);
            return true;
        }
    }

    for entry in refs.iter_mut() {
        if !entry.active {
            *entry = AddressSpaceRef {
                root: pml4_phys,
                refs: 1,
                active: true,
            };
            return true;
        }
    }

    false
}

/// Increment the reference count for a tracked user address space.
///
/// Returns `true` if the address space was tracked and retained. Returns
/// `false` for untracked roots such as the boot kernel CR3.
pub fn retain_address_space(pml4_phys: u64) -> bool {
    if pml4_phys == 0 {
        return false;
    }

    let mut refs = ADDRESS_SPACE_REFS.lock();
    for entry in refs.iter_mut() {
        if entry.active && entry.root == pml4_phys {
            entry.refs = entry.refs.saturating_add(1);
            return true;
        }
    }
    false
}

/// Release one reference to a tracked user address space.
///
/// When the last reference is dropped, the page tables are destroyed.
/// Returns `true` if the root was tracked, `false` otherwise.
pub fn release_address_space(pml4_phys: u64) -> bool {
    if pml4_phys == 0 {
        return false;
    }

    let mut destroy = false;
    {
        let mut refs = ADDRESS_SPACE_REFS.lock();
        for entry in refs.iter_mut() {
            if entry.active && entry.root == pml4_phys {
                if entry.refs > 1 {
                    entry.refs -= 1;
                } else {
                    *entry = AddressSpaceRef::empty();
                    destroy = true;
                }
                break;
            }
        }
    }

    if destroy {
        destroy_address_space(pml4_phys);
        return true;
    }

    let refs = ADDRESS_SPACE_REFS.lock();
    refs.iter().any(|entry| entry.active && entry.root == pml4_phys)
}

/// Translate a virtual address in `pml4_phys` into the higher-half alias of
/// the backing physical byte, if the mapping exists.
pub fn translate_virt(pml4_phys: u64, vaddr: u64) -> Option<u64> {
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;
    let page_off = vaddr & (PAGE_SIZE as u64 - 1);

    unsafe {
        let pml4 = phys_to_const_ptr::<u64>(pml4_phys);
        let pml4e = core::ptr::read_volatile(pml4.add(pml4_idx));
        if pml4e & PTE_PRESENT == 0 {
            return None;
        }

        let pdpt = phys_to_const_ptr::<u64>(pml4e & 0x000F_FFFF_FFFF_F000);
        let pdpte = core::ptr::read_volatile(pdpt.add(pdpt_idx));
        if pdpte & PTE_PRESENT == 0 {
            return None;
        }

        let pd = phys_to_const_ptr::<u64>(pdpte & 0x000F_FFFF_FFFF_F000);
        let pde = core::ptr::read_volatile(pd.add(pd_idx));
        if pde & PTE_PRESENT == 0 {
            return None;
        }

        if pde & PTE_HUGE != 0 {
            let base = pde & 0x000F_FFFF_FFE0_0000;
            return Some(base + (vaddr & 0x1F_FFFF));
        }

        let pt = phys_to_const_ptr::<u64>(pde & 0x000F_FFFF_FFFF_F000);
        let pte = core::ptr::read_volatile(pt.add(pt_idx));
        if pte & PTE_PRESENT == 0 {
            return None;
        }

        Some((pte & 0x000F_FFFF_FFFF_F000) + page_off)
    }
}

/// Destroy an agent's address space.
/// Frees the PML4 and all page table frames allocated for user-space mappings.
/// Does NOT free the kernel mappings (those are shared).
pub fn destroy_address_space(pml4_phys: u64) {
    let pml4 = phys_to_const_ptr::<u64>(pml4_phys);
    unsafe {
        // Free every lower-half PML4 entry. All ATOS user mappings currently
        // live under the low canonical half, including the per-agent copy of
        // PML4[0] that carries the 1 GiB identity window plus any user PTs we
        // allocate under it.
        for i in 0..256 {
            let pml4e = core::ptr::read_volatile(pml4.add(i));
            if pml4e & PTE_PRESENT != 0 {
                let pdpt_phys = pml4e & 0x000F_FFFF_FFFF_F000;
                free_page_table_level(pdpt_phys, 3);
            }
        }

        // PML4[511] is the shared higher-half kernel mapping — do NOT free.
    }

    let _ = release_frame(pml4_phys);
}

/// Recursively free page table frames at a given level.
/// level 3 = PDPT, 2 = PD, 1 = PT
unsafe fn free_page_table_level(table_phys: u64, level: usize) {
    let table = phys_to_const_ptr::<u64>(table_phys);

    if level > 1 {
        for i in 0..512 {
            let entry = core::ptr::read_volatile(table.add(i));
            if entry & PTE_PRESENT != 0 && entry & PTE_HUGE == 0 {
                let next_phys = entry & 0x000F_FFFF_FFFF_F000;
                free_page_table_level(next_phys, level - 1);
            }
        }
    }

    let _ = release_frame(table_phys);
}

/// Map a stack or data page — always sets PTE_NX (No-Execute).
///
/// Use this for any page that should hold data but not be executable
/// (stacks, heap, BSS, message buffers, …).  The NX bit is forced on
/// regardless of what is passed in `flags`, so callers cannot accidentally
/// create a writable-and-executable data page.
pub fn map_data_page(pml4_phys: u64, virt_addr: u64, phys_addr: u64, flags: u64) -> Result<(), ()> {
    let nx = if crate::arch::x86_64::security::nx_active() {
        PTE_NX
    } else {
        0
    };
    map_page(pml4_phys, virt_addr, phys_addr, flags | nx)
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

/// Update a leaf PTE with the exact caller-provided flags.
///
/// Unlike `map_page`, this helper does not force `PTE_PRESENT` on the final
/// mapping. It is used for cases like `mprotect(PROT_NONE)` where the leaf
/// entry must remain non-present while retaining the physical frame pointer.
pub fn set_page_mapping(
    pml4_phys: u64,
    virt_addr: u64,
    phys_addr: u64,
    flags: u64,
) -> Result<(), ()> {
    let pml4_idx = ((virt_addr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((virt_addr >> 30) & 0x1FF) as usize;
    let pd_idx = ((virt_addr >> 21) & 0x1FF) as usize;
    let pt_idx = ((virt_addr >> 12) & 0x1FF) as usize;

    unsafe {
        let pml4 = phys_to_mut_ptr::<u64>(pml4_phys);
        let pdpt_phys = ensure_table_entry(pml4, pml4_idx, flags | PTE_PRESENT)?;

        let pdpt = phys_to_mut_ptr::<u64>(pdpt_phys);
        let pd_phys = ensure_table_entry(pdpt, pdpt_idx, flags | PTE_PRESENT)?;

        let pd = phys_to_mut_ptr::<u64>(pd_phys);
        let pt_phys = ensure_table_entry(pd, pd_idx, flags | PTE_PRESENT)?;

        let pt = phys_to_mut_ptr::<u64>(pt_phys);
        core::ptr::write_volatile(
            pt.add(pt_idx),
            (phys_addr & 0x000F_FFFF_FFFF_F000) | flags,
        );
    }

    Ok(())
}

/// Map a single 4KB page in an agent's address space.
/// Creates intermediate page table levels as needed.
///
/// Prefer `map_data_page` / `map_code_page` over this function to ensure
/// the correct NX policy is applied automatically.
pub fn map_page(pml4_phys: u64, virt_addr: u64, phys_addr: u64, flags: u64) -> Result<(), ()> {
    set_page_mapping(pml4_phys, virt_addr, phys_addr, flags | PTE_PRESENT)
}

/// Ensure a page table entry exists at the given index.
/// If not present, allocate a new frame for the next-level table.
/// Returns the physical address of the next-level table.
unsafe fn ensure_table_entry(table: *mut u64, index: usize, flags: u64) -> Result<u64, ()> {
    let entry = core::ptr::read_volatile(table.add(index));
    if entry & PTE_PRESENT != 0 {
        if entry & PTE_HUGE != 0 {
            // Do not treat an existing 1 GiB / 2 MiB huge mapping as a
            // next-level page table. Callers that want to map inside such a
            // range must split the huge page first.
            return Err(());
        }
        // Entry exists, return the physical address of the next table
        // Update flags (e.g., add USER bit if needed)
        let phys = entry & 0x000F_FFFF_FFFF_F000;
        let new_entry = phys | (entry & 0xFFF) | (flags & (PTE_USER | PTE_WRITABLE));
        core::ptr::write_volatile(table.add(index), new_entry);
        Ok(phys)
    } else {
        // Allocate a new frame for the next-level table
        let new_frame = alloc_frame_with_kind(FrameKind::PageTable).ok_or(())?;
        // Zero the new frame
        core::ptr::write_bytes(phys_to_mut_ptr::<u8>(new_frame), 0, PAGE_SIZE);
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
        let pml4 = phys_to_const_ptr::<u64>(pml4_phys);
        let pml4e = core::ptr::read_volatile(pml4.add(pml4_idx));
        if pml4e & PTE_PRESENT == 0 {
            return;
        }

        let pdpt = phys_to_const_ptr::<u64>(pml4e & 0x000F_FFFF_FFFF_F000);
        let pdpte = core::ptr::read_volatile(pdpt.add(pdpt_idx));
        if pdpte & PTE_PRESENT == 0 {
            return;
        }

        let pd = phys_to_const_ptr::<u64>(pdpte & 0x000F_FFFF_FFFF_F000);
        let pde = core::ptr::read_volatile(pd.add(pd_idx));
        if pde & PTE_PRESENT == 0 {
            return;
        }

        let pt = phys_to_mut_ptr::<u64>(pde & 0x000F_FFFF_FFFF_F000);
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
