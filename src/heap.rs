//! ATOS kernel heap allocator.
//!
//! Small allocations use page-backed slab caches. Larger allocations fall back
//! to contiguous frame allocation. This keeps the external `#[global_allocator]`
//! entry point unchanged while reducing fragmentation and linear free-list
//! scans in the hot path.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr;

use crate::arch::x86_64::paging;

const PAGE_SIZE: usize = 4096;
const MIN_ALIGN: usize = 8;
const SLAB_MAGIC: u32 = 0x534C_4142;
const LARGE_MAGIC: u32 = 0x4C41_5247;
const SLAB_CLASSES: [usize; 9] = [8, 16, 32, 64, 128, 256, 512, 1024, 2048];
const NUM_SLAB_CLASSES: usize = SLAB_CLASSES.len();

#[repr(C)]
struct FreeSlot {
    next: *mut FreeSlot,
}

#[repr(C)]
struct SlabPage {
    magic: u32,
    class_index: u16,
    in_partial: u8,
    _reserved: u8,
    slot_size: u16,
    slot_offset: u16,
    capacity: u16,
    free_count: u16,
    next_partial: *mut SlabPage,
    free_head: *mut FreeSlot,
}

#[repr(C)]
struct LargeAllocHeader {
    magic: u32,
    pages: u32,
    base: u64,
}

#[derive(Clone, Copy)]
struct SlabClass {
    partial: *mut SlabPage,
}

impl SlabClass {
    const fn new() -> Self {
        Self {
            partial: ptr::null_mut(),
        }
    }
}

pub struct KernelAllocator {
    classes: UnsafeCell<[SlabClass; NUM_SLAB_CLASSES]>,
}

unsafe impl Sync for KernelAllocator {}

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator::new();

#[inline]
const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

#[inline]
unsafe fn cli() -> bool {
    let flags: u64;
    core::arch::asm!("pushfq; pop {}; cli", out(reg) flags, options(nomem, preserves_flags));
    flags & (1 << 9) != 0
}

#[inline]
unsafe fn restore_interrupts(was_enabled: bool) {
    if was_enabled {
        core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
    }
}

impl KernelAllocator {
    pub const fn new() -> Self {
        Self {
            classes: UnsafeCell::new([const { SlabClass::new() }; NUM_SLAB_CLASSES]),
        }
    }

    #[inline]
    fn slab_class_index(layout: Layout) -> Option<usize> {
        let size = layout.size().max(1);
        let need = size.max(layout.align()).max(MIN_ALIGN);
        SLAB_CLASSES.iter().position(|&slot_size| slot_size >= need)
    }

    #[inline]
    unsafe fn classes_mut(&self) -> &mut [SlabClass; NUM_SLAB_CLASSES] {
        &mut *self.classes.get()
    }

    unsafe fn insert_partial(
        &self,
        classes: &mut [SlabClass; NUM_SLAB_CLASSES],
        class_index: usize,
        slab: *mut SlabPage,
    ) {
        debug_assert!((*slab).in_partial == 0);
        (*slab).next_partial = classes[class_index].partial;
        (*slab).in_partial = 1;
        classes[class_index].partial = slab;
    }

    unsafe fn remove_partial(
        &self,
        classes: &mut [SlabClass; NUM_SLAB_CLASSES],
        class_index: usize,
        slab: *mut SlabPage,
    ) -> bool {
        let mut prev: *mut SlabPage = ptr::null_mut();
        let mut current = classes[class_index].partial;

        while !current.is_null() {
            if current == slab {
                let next = (*current).next_partial;
                if prev.is_null() {
                    classes[class_index].partial = next;
                } else {
                    (*prev).next_partial = next;
                }
                (*current).next_partial = ptr::null_mut();
                (*current).in_partial = 0;
                return true;
            }
            prev = current;
            current = (*current).next_partial;
        }

        false
    }

    unsafe fn allocate_slab(
        &self,
        classes: &mut [SlabClass; NUM_SLAB_CLASSES],
        class_index: usize,
    ) -> Option<*mut SlabPage> {
        let slot_size = SLAB_CLASSES[class_index];
        let base = paging::alloc_frame_with_kind(paging::FrameKind::KernelHeap)? as usize;
        let slab = base as *mut SlabPage;
        let slot_offset = align_up(core::mem::size_of::<SlabPage>(), slot_size);

        if slot_offset >= PAGE_SIZE {
            let _ = paging::release_frame(base as u64);
            return None;
        }

        let capacity = (PAGE_SIZE - slot_offset) / slot_size;
        if capacity == 0 || capacity > u16::MAX as usize {
            let _ = paging::release_frame(base as u64);
            return None;
        }

        (*slab).magic = SLAB_MAGIC;
        (*slab).class_index = class_index as u16;
        (*slab).in_partial = 0;
        (*slab)._reserved = 0;
        (*slab).slot_size = slot_size as u16;
        (*slab).slot_offset = slot_offset as u16;
        (*slab).capacity = capacity as u16;
        (*slab).free_count = capacity as u16;
        (*slab).next_partial = ptr::null_mut();
        (*slab).free_head = ptr::null_mut();

        for slot_index in (0..capacity).rev() {
            let slot_addr = base + slot_offset + slot_index * slot_size;
            let slot = slot_addr as *mut FreeSlot;
            (*slot).next = (*slab).free_head;
            (*slab).free_head = slot;
        }

        self.insert_partial(classes, class_index, slab);
        Some(slab)
    }

    unsafe fn alloc_small(&self, class_index: usize) -> *mut u8 {
        let classes = self.classes_mut();
        if classes[class_index].partial.is_null() && self.allocate_slab(classes, class_index).is_none()
        {
            return ptr::null_mut();
        }

        let slab = classes[class_index].partial;
        if slab.is_null() || (*slab).free_head.is_null() {
            return ptr::null_mut();
        }

        let slot = (*slab).free_head;
        (*slab).free_head = (*slot).next;
        (*slab).free_count -= 1;

        if (*slab).free_count == 0 {
            classes[class_index].partial = (*slab).next_partial;
            (*slab).next_partial = ptr::null_mut();
            (*slab).in_partial = 0;
        }

        slot as *mut u8
    }

    unsafe fn dealloc_small(&self, ptr: *mut u8, class_index: usize) {
        let classes = self.classes_mut();
        let slab_base = (ptr as usize) & !(PAGE_SIZE - 1);
        let slab = slab_base as *mut SlabPage;

        debug_assert_eq!((*slab).magic, SLAB_MAGIC);
        debug_assert_eq!((*slab).class_index as usize, class_index);

        let was_full = (*slab).free_count == 0;
        let slot = ptr as *mut FreeSlot;
        (*slot).next = (*slab).free_head;
        (*slab).free_head = slot;
        (*slab).free_count += 1;

        if (*slab).free_count == (*slab).capacity {
            if (*slab).in_partial != 0 {
                let _ = self.remove_partial(classes, class_index, slab);
            }
            (*slab).magic = 0;
            let _ = paging::release_frame(slab_base as u64);
            return;
        }

        if was_full && (*slab).in_partial == 0 {
            self.insert_partial(classes, class_index, slab);
        }
    }

    unsafe fn alloc_large(&self, layout: Layout) -> *mut u8 {
        let size = layout.size().max(1);
        let header_size = core::mem::size_of::<LargeAllocHeader>();
        let align = layout
            .align()
            .max(MIN_ALIGN)
            .max(core::mem::align_of::<LargeAllocHeader>());

        let total = match size
            .checked_add(header_size)
            .and_then(|value| value.checked_add(align - 1))
        {
            Some(total) => total,
            None => return ptr::null_mut(),
        };

        let pages = align_up(total, PAGE_SIZE) / PAGE_SIZE;
        let base = match paging::alloc_contiguous_frames_with_kind(pages, paging::FrameKind::KernelHeap)
        {
            Some(base) => base,
            None => return ptr::null_mut(),
        };

        let payload = align_up(base as usize + header_size, align);
        let header = (payload - header_size) as *mut LargeAllocHeader;
        (*header).magic = LARGE_MAGIC;
        (*header).pages = pages as u32;
        (*header).base = base;
        payload as *mut u8
    }

    unsafe fn dealloc_large(&self, ptr: *mut u8) {
        let header_size = core::mem::size_of::<LargeAllocHeader>();
        let header = (ptr as usize - header_size) as *mut LargeAllocHeader;

        debug_assert_eq!((*header).magic, LARGE_MAGIC);
        let _ = paging::release_contiguous_frames((*header).base, (*header).pages as usize);
    }
}

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let was_enabled = cli();
        let ptr = match Self::slab_class_index(layout) {
            Some(class_index) => self.alloc_small(class_index),
            None => self.alloc_large(layout),
        };
        restore_interrupts(was_enabled);
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }

        let was_enabled = cli();
        match Self::slab_class_index(layout) {
            Some(class_index) => self.dealloc_small(ptr, class_index),
            None => self.dealloc_large(ptr),
        }
        restore_interrupts(was_enabled);
    }
}

#[alloc_error_handler]
fn alloc_error_handler(layout: Layout) -> ! {
    panic!(
        "kernel heap allocation failed: size={}, align={}",
        layout.size(),
        layout.align()
    );
}
