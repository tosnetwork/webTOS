//! AOS Kernel Heap Allocator
//!
//! A simple linked-list free-list allocator that obtains 4KB pages from the
//! frame allocator and manages sub-page allocations for kernel data structures.
//!
//! Registered as Rust's `#[global_allocator]` so the `alloc` crate (`Vec`,
//! `Box`, `String`, etc.) works in the kernel.
//!
//! Design: single-core only (Stage-1/2). Interrupt-safe via CLI/STI around
//! critical sections.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

use crate::arch::x86_64::paging;

/// Page size obtained from the frame allocator.
const PAGE_SIZE: usize = 4096;

/// Minimum allocation alignment (8 bytes for u64 / pointer alignment).
const MIN_ALIGN: usize = 8;

/// Minimum block size: must be large enough to hold a `FreeBlock` header.
const MIN_BLOCK_SIZE: usize = core::mem::size_of::<FreeBlock>();

/// Header stored at the start of every free block in the free list.
#[repr(C)]
struct FreeBlock {
    /// Usable size of this block (not including this header — the header
    /// *overlaps* the free space since we only need it while the block is free).
    /// Actually, we store the *total* size of the region (header + payload)
    /// so we can coalesce and split correctly.
    size: usize,
    next: *mut FreeBlock,
}

/// A simple linked-list heap allocator.
///
/// The free list is an intrusive singly-linked list threaded through free
/// blocks. When the list cannot satisfy a request we ask the frame allocator
/// for a fresh 4KB page (or multiple pages for large allocations).
pub struct KernelAllocator {
    /// Head of the free list. We use `UnsafeCell` because `GlobalAlloc`
    /// takes `&self` but we need interior mutability. Safety is ensured
    /// by disabling interrupts (single-core).
    head: core::cell::UnsafeCell<*mut FreeBlock>,
}

// Safety: single-core kernel — no concurrent access.
unsafe impl Sync for KernelAllocator {}

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator::new();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Align `value` up to the next multiple of `align` (must be a power of two).
#[inline]
const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

/// Disable interrupts and return whether they were previously enabled.
#[inline]
unsafe fn cli() -> bool {
    let flags: u64;
    core::arch::asm!("pushfq; pop {}; cli", out(reg) flags, options(nomem, preserves_flags));
    flags & (1 << 9) != 0
}

/// Re-enable interrupts if `was_enabled` is true.
#[inline]
unsafe fn restore_interrupts(was_enabled: bool) {
    if was_enabled {
        core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
    }
}

impl KernelAllocator {
    pub const fn new() -> Self {
        KernelAllocator {
            head: core::cell::UnsafeCell::new(ptr::null_mut()),
        }
    }

    /// Add a region of memory `[addr, addr+size)` to the free list.
    ///
    /// # Safety
    /// The region must be valid, writable, and not overlap with any existing
    /// allocation or free block.
    unsafe fn add_free_region(&self, addr: usize, size: usize) {
        debug_assert!(size >= MIN_BLOCK_SIZE);
        debug_assert!(addr % MIN_ALIGN == 0);

        let block = addr as *mut FreeBlock;
        let head = self.head.get();

        (*block).size = size;
        (*block).next = *head;
        *head = block;
    }

    /// Try to obtain new pages from the frame allocator and add them to the
    /// free list. Returns `true` on success.
    unsafe fn grow(&self, required: usize) -> bool {
        // Number of pages we need to satisfy `required` bytes.
        let pages_needed = align_up(required, PAGE_SIZE) / PAGE_SIZE;

        // Try to allocate contiguous pages. Because the bitmap allocator
        // hands out frames in roughly ascending order, consecutive calls
        // often return adjacent frames. We attempt to get `pages_needed`
        // frames and merge them if contiguous; otherwise we add each page
        // individually.

        let mut base: usize = 0;
        let mut contiguous_len: usize = 0;

        for _ in 0..pages_needed {
            match paging::alloc_frame() {
                Some(phys) => {
                    let addr = phys as usize;
                    if contiguous_len > 0 && addr == base + contiguous_len {
                        // Extends current contiguous run.
                        contiguous_len += PAGE_SIZE;
                    } else {
                        // Flush previous contiguous run (if any).
                        if contiguous_len > 0 {
                            self.add_free_region(base, contiguous_len);
                        }
                        base = addr;
                        contiguous_len = PAGE_SIZE;
                    }
                }
                None => {
                    // Flush whatever we managed to collect.
                    if contiguous_len > 0 {
                        self.add_free_region(base, contiguous_len);
                    }
                    return contiguous_len > 0;
                }
            }
        }

        if contiguous_len > 0 {
            self.add_free_region(base, contiguous_len);
        }

        true
    }
}

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let was_enabled = cli();

        let align = layout.align().max(MIN_ALIGN);
        let size = align_up(layout.size().max(MIN_BLOCK_SIZE), MIN_ALIGN);

        // Search for a suitable block (first-fit).
        let result = self.find_and_remove(size, align);

        if let Some(ptr) = result {
            restore_interrupts(was_enabled);
            return ptr;
        }

        // Free list couldn't satisfy — grow the heap.
        // We need at least `size + align` to guarantee we can align within
        // the allocated region (worst case alignment waste).
        let grow_size = (size + align).max(PAGE_SIZE);
        if !self.grow(grow_size) {
            restore_interrupts(was_enabled);
            return ptr::null_mut();
        }

        // Retry after growing.
        let result = self.find_and_remove(size, align);
        restore_interrupts(was_enabled);
        result.unwrap_or(ptr::null_mut())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let was_enabled = cli();

        let size = align_up(layout.size().max(MIN_BLOCK_SIZE), MIN_ALIGN);
        self.add_free_region(ptr as usize, size);

        restore_interrupts(was_enabled);
    }
}

impl KernelAllocator {
    /// Search the free list for a block that can satisfy `size` bytes with
    /// `align` alignment. If found, remove (or split) it and return the
    /// aligned pointer.
    unsafe fn find_and_remove(&self, size: usize, align: usize) -> Option<*mut u8> {
        let head = self.head.get();
        let mut prev: *mut *mut FreeBlock = head;
        let mut current = *head;

        while !current.is_null() {
            let block_start = current as usize;
            let block_size = (*current).size;
            let block_end = block_start + block_size;

            // Where the allocation would start within this block, respecting
            // alignment.
            let alloc_start = align_up(block_start, align);
            let alloc_end = alloc_start + size;

            if alloc_end <= block_end {
                // This block fits. Remove it from the list first.
                *prev = (*current).next;

                // Front padding: if `alloc_start > block_start`, we have
                // unused space at the front that we can return to the free list.
                let front_pad = alloc_start - block_start;
                if front_pad >= MIN_BLOCK_SIZE {
                    self.add_free_region(block_start, front_pad);
                }

                // Back padding: unused space after the allocation.
                let back_pad = block_end - alloc_end;
                if back_pad >= MIN_BLOCK_SIZE {
                    self.add_free_region(alloc_end, back_pad);
                }

                return Some(alloc_start as *mut u8);
            }

            prev = &mut (*current).next;
            current = (*current).next;
        }

        None
    }
}

// ---------------------------------------------------------------------------
// Alloc error handler
// ---------------------------------------------------------------------------

#[alloc_error_handler]
fn alloc_error_handler(layout: Layout) -> ! {
    panic!("kernel heap allocation failed: size={}, align={}", layout.size(), layout.align());
}
