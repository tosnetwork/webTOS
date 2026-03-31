//! Buddy-based physical frame allocator for x86_64.
//!
//! This module replaces the old linear bitmap scan with buddy free lists while
//! preserving the higher-level paging API exposed by `paging.rs`.

use crate::sync::SpinLock;

/// Page/frame size: 4 KiB.
pub const PAGE_SIZE: usize = 4096;

/// Maximum physical memory managed by the allocator (1 GiB).
pub const MAX_MEMORY: usize = 1024 * 1024 * 1024;

/// Total number of frames in the managed region.
pub const MAX_FRAMES: usize = MAX_MEMORY / PAGE_SIZE;

/// Largest buddy order supported by the managed memory window.
///
/// `2^18 * 4096 = 1 GiB`, so orders range from 0 to 18 inclusive.
pub const MAX_ORDER: usize = 18;
const ORDER_COUNT: usize = MAX_ORDER + 1;
const INVALID_INDEX: u32 = u32::MAX;

#[derive(Clone, Copy)]
struct ChunkMeta {
    next: u32,
    prev: u32,
    order: u8,
    is_free: bool,
}

impl ChunkMeta {
    const fn empty() -> Self {
        Self {
            next: INVALID_INDEX,
            prev: INVALID_INDEX,
            order: 0,
            is_free: false,
        }
    }
}

struct BuddyAllocator {
    heads: [u32; ORDER_COUNT],
    meta: [ChunkMeta; MAX_FRAMES],
    managed_frames: usize,
    free_frames: usize,
}

impl BuddyAllocator {
    const fn new() -> Self {
        Self {
            heads: [INVALID_INDEX; ORDER_COUNT],
            meta: [const { ChunkMeta::empty() }; MAX_FRAMES],
            managed_frames: 0,
            free_frames: 0,
        }
    }

    fn reset(&mut self, managed_frames: usize) {
        self.managed_frames = managed_frames.min(MAX_FRAMES);
        self.free_frames = 0;

        for head in self.heads.iter_mut() {
            *head = INVALID_INDEX;
        }

        for meta in self.meta.iter_mut() {
            *meta = ChunkMeta::empty();
        }
    }

    fn size_of_order(order: usize) -> usize {
        1usize << order
    }

    fn max_alignment_order(frame: usize) -> usize {
        if frame == 0 {
            MAX_ORDER
        } else {
            usize::min(frame.trailing_zeros() as usize, MAX_ORDER)
        }
    }

    fn push_chunk(&mut self, frame: usize, order: usize) {
        debug_assert!(frame < self.managed_frames);
        debug_assert!(order <= MAX_ORDER);
        debug_assert_eq!(frame & (Self::size_of_order(order) - 1), 0);

        let old_head = self.heads[order];
        let meta = &mut self.meta[frame];
        meta.next = old_head;
        meta.prev = INVALID_INDEX;
        meta.order = order as u8;
        meta.is_free = true;

        if old_head != INVALID_INDEX {
            self.meta[old_head as usize].prev = frame as u32;
        }

        self.heads[order] = frame as u32;
        self.free_frames += Self::size_of_order(order);
    }

    fn remove_chunk(&mut self, frame: usize, order: usize) {
        debug_assert!(frame < self.managed_frames);
        debug_assert!(order <= MAX_ORDER);

        let meta = self.meta[frame];
        let next = meta.next;
        let prev = meta.prev;

        if prev == INVALID_INDEX {
            self.heads[order] = next;
        } else {
            self.meta[prev as usize].next = next;
        }

        if next != INVALID_INDEX {
            self.meta[next as usize].prev = prev;
        }

        self.meta[frame] = ChunkMeta::empty();
        self.free_frames = self.free_frames.saturating_sub(Self::size_of_order(order));
    }

    fn pop_chunk(&mut self, order: usize) -> Option<usize> {
        let head = self.heads[order];
        if head == INVALID_INDEX {
            return None;
        }

        let frame = head as usize;
        self.remove_chunk(frame, order);
        Some(frame)
    }

    fn add_free_range(&mut self, mut start_frame: usize, mut end_frame: usize) {
        start_frame = start_frame.min(self.managed_frames);
        end_frame = end_frame.min(self.managed_frames);

        while start_frame < end_frame {
            let mut order = Self::max_alignment_order(start_frame);
            while Self::size_of_order(order) > end_frame - start_frame {
                order -= 1;
            }

            self.push_chunk(start_frame, order);
            start_frame += Self::size_of_order(order);
        }
    }

    fn alloc_order(&mut self, requested_order: usize) -> Option<usize> {
        if requested_order > MAX_ORDER {
            return None;
        }

        let mut order = requested_order;
        while order <= MAX_ORDER && self.heads[order] == INVALID_INDEX {
            order += 1;
        }

        if order > MAX_ORDER {
            return None;
        }

        let frame = self.pop_chunk(order)?;
        while order > requested_order {
            order -= 1;
            let buddy = frame + Self::size_of_order(order);
            self.push_chunk(buddy, order);
        }

        let meta = &mut self.meta[frame];
        meta.order = requested_order as u8;
        meta.is_free = false;
        meta.next = INVALID_INDEX;
        meta.prev = INVALID_INDEX;
        Some(frame)
    }

    fn min_order_covering(size: usize) -> usize {
        let mut order = 0usize;
        let mut covered = 1usize;
        while covered < size && order < MAX_ORDER {
            order += 1;
            covered <<= 1;
        }
        order
    }

    fn dealloc_order(&mut self, addr: usize, mut order: usize) {
        if order > MAX_ORDER || addr >= self.managed_frames {
            return;
        }

        let mut frame = addr;

        while order < MAX_ORDER {
            let buddy = frame ^ Self::size_of_order(order);
            if buddy >= self.managed_frames {
                break;
            }

            let buddy_meta = self.meta[buddy];
            if !buddy_meta.is_free || buddy_meta.order as usize != order {
                break;
            }

            self.remove_chunk(buddy, order);
            frame = usize::min(frame, buddy);
            order += 1;
        }

        self.push_chunk(frame, order);
    }

    fn alloc_contiguous(&mut self, nr_frames: usize) -> Option<usize> {
        if nr_frames == 0 || nr_frames > self.managed_frames {
            return None;
        }

        let order = Self::min_order_covering(nr_frames);
        let frame = self.alloc_order(order)?;
        let allocated_frames = Self::size_of_order(order);

        if nr_frames < allocated_frames {
            self.add_free_range(frame + nr_frames, frame + allocated_frames);
        }

        Some(frame)
    }

    fn dealloc_contiguous(&mut self, mut frame: usize, mut nr_frames: usize) {
        if nr_frames == 0 || frame >= self.managed_frames {
            return;
        }

        let end = frame.saturating_add(nr_frames).min(self.managed_frames);
        nr_frames = end.saturating_sub(frame);

        while nr_frames > 0 {
            let mut order = Self::max_alignment_order(frame);
            while Self::size_of_order(order) > nr_frames {
                order -= 1;
            }
            self.dealloc_order(frame, order);
            let chunk = Self::size_of_order(order);
            frame += chunk;
            nr_frames -= chunk;
        }
    }
}

static ALLOCATOR: SpinLock<BuddyAllocator> = SpinLock::new(BuddyAllocator::new());

/// Reset the allocator state for a managed memory window.
pub fn init_empty(managed_frames: usize) {
    ALLOCATOR.lock().reset(managed_frames);
}

/// Add a free frame range `[start_frame, end_frame)` to the allocator.
pub fn add_free_range(start_frame: usize, end_frame: usize) {
    ALLOCATOR.lock().add_free_range(start_frame, end_frame);
}

/// Allocate a single 4 KiB frame.
pub fn alloc_frame() -> Option<u64> {
    ALLOCATOR
        .lock()
        .alloc_order(0)
        .map(|frame| (frame * PAGE_SIZE) as u64)
}

/// Allocate an exact contiguous range of frames.
pub fn alloc_contiguous(nr_frames: usize) -> Option<u64> {
    ALLOCATOR
        .lock()
        .alloc_contiguous(nr_frames)
        .map(|frame| (frame * PAGE_SIZE) as u64)
}

/// Free a single previously allocated 4 KiB frame.
pub fn dealloc_frame(addr: u64) {
    let frame = addr as usize / PAGE_SIZE;
    ALLOCATOR.lock().dealloc_order(frame, 0);
}

/// Free an exact contiguous frame range previously returned by
/// `alloc_contiguous`.
pub fn dealloc_contiguous(addr: u64, nr_frames: usize) {
    let frame = addr as usize / PAGE_SIZE;
    ALLOCATOR.lock().dealloc_contiguous(frame, nr_frames);
}

/// Return the number of managed frames in the allocator.
pub fn managed_frames() -> usize {
    ALLOCATOR.lock().managed_frames
}

/// Return the number of currently free frames in the allocator.
pub fn free_frames() -> usize {
    ALLOCATOR.lock().free_frames
}
