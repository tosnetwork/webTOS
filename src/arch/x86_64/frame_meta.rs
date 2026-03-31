//! Per-frame metadata and reference counting.
//!
//! The buddy allocator tracks free extents. This module tracks per-frame
//! ownership metadata for allocated frames so higher-level subsystems can
//! safely share and release pages.

use crate::sync::SpinLock;

use super::frame_alloc::MAX_FRAMES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    Reserved = 0,
    Free = 1,
    Unknown = 2,
    Anon = 3,
    File = 4,
    PageTable = 5,
    KernelHeap = 6,
    Device = 7,
}

#[derive(Clone, Copy)]
struct FrameMeta {
    refcount: u16,
    kind: FrameKind,
}

impl FrameMeta {
    const fn new() -> Self {
        Self {
            refcount: 0,
            kind: FrameKind::Reserved,
        }
    }
}

struct FrameMetaTable {
    managed_frames: usize,
    frames: [FrameMeta; MAX_FRAMES],
}

impl FrameMetaTable {
    const fn new() -> Self {
        Self {
            managed_frames: 0,
            frames: [const { FrameMeta::new() }; MAX_FRAMES],
        }
    }

    fn init(&mut self, managed_frames: usize) {
        self.managed_frames = managed_frames.min(MAX_FRAMES);
        for i in 0..self.managed_frames {
            self.frames[i] = FrameMeta::new();
        }
    }

    fn frame_index(&self, paddr: u64) -> Option<usize> {
        let frame = (paddr as usize) / super::frame_alloc::PAGE_SIZE;
        if frame < self.managed_frames {
            Some(frame)
        } else {
            None
        }
    }

    fn mark_free_range(&mut self, start_frame: usize, end_frame: usize) {
        let start = start_frame.min(self.managed_frames);
        let end = end_frame.min(self.managed_frames);
        for frame in start..end {
            self.frames[frame] = FrameMeta {
                refcount: 0,
                kind: FrameKind::Free,
            };
        }
    }

    fn on_alloc(&mut self, paddr: u64, kind: FrameKind) -> bool {
        let Some(frame) = self.frame_index(paddr) else {
            return false;
        };
        self.frames[frame] = FrameMeta { refcount: 1, kind };
        true
    }

    fn on_alloc_range(&mut self, start_paddr: u64, nr_frames: usize, kind: FrameKind) -> bool {
        let Some(start_frame) = self.frame_index(start_paddr) else {
            return false;
        };
        let end = start_frame.saturating_add(nr_frames).min(self.managed_frames);
        if start_frame >= end {
            return false;
        }
        for frame in start_frame..end {
            self.frames[frame] = FrameMeta { refcount: 1, kind };
        }
        true
    }

    fn retain(&mut self, paddr: u64) -> bool {
        let Some(frame) = self.frame_index(paddr) else {
            return false;
        };
        let meta = &mut self.frames[frame];
        if meta.refcount == 0 {
            return false;
        }
        meta.refcount = meta.refcount.saturating_add(1);
        true
    }

    fn release(&mut self, paddr: u64) -> ReleaseResult {
        let Some(frame) = self.frame_index(paddr) else {
            return ReleaseResult::Unmanaged;
        };
        let meta = &mut self.frames[frame];
        if meta.refcount == 0 {
            return ReleaseResult::AlreadyFree;
        }
        meta.refcount -= 1;
        if meta.refcount == 0 {
            meta.kind = FrameKind::Free;
            ReleaseResult::FreeNow
        } else {
            ReleaseResult::StillReferenced(meta.refcount)
        }
    }

    fn set_kind(&mut self, paddr: u64, kind: FrameKind) -> bool {
        let Some(frame) = self.frame_index(paddr) else {
            return false;
        };
        self.frames[frame].kind = kind;
        true
    }

    fn refcount(&self, paddr: u64) -> u16 {
        self.frame_index(paddr)
            .map(|frame| self.frames[frame].refcount)
            .unwrap_or(0)
    }
}

static FRAME_META: SpinLock<FrameMetaTable> = SpinLock::new(FrameMetaTable::new());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseResult {
    Unmanaged,
    AlreadyFree,
    StillReferenced(u16),
    FreeNow,
}

/// Initialize per-frame metadata for the managed memory window.
pub fn init(managed_frames: usize) {
    FRAME_META.lock().init(managed_frames);
}

/// Mark the given frame range `[start_frame, end_frame)` as allocator-owned
/// free memory.
pub fn mark_free_range(start_frame: usize, end_frame: usize) {
    FRAME_META.lock().mark_free_range(start_frame, end_frame);
}

/// Record a newly allocated frame with refcount 1.
pub fn on_alloc(paddr: u64, kind: FrameKind) -> bool {
    FRAME_META.lock().on_alloc(paddr, kind)
}

/// Record a newly allocated contiguous frame range with refcount 1.
pub fn on_alloc_range(start_paddr: u64, nr_frames: usize, kind: FrameKind) -> bool {
    FRAME_META.lock().on_alloc_range(start_paddr, nr_frames, kind)
}

/// Increase the reference count on an allocated frame.
pub fn retain(paddr: u64) -> bool {
    FRAME_META.lock().retain(paddr)
}

/// Decrease the reference count on an allocated frame.
pub fn release(paddr: u64) -> ReleaseResult {
    FRAME_META.lock().release(paddr)
}

/// Update the classification for a frame.
pub fn set_kind(paddr: u64, kind: FrameKind) -> bool {
    FRAME_META.lock().set_kind(paddr, kind)
}

/// Return the current frame reference count.
pub fn refcount(paddr: u64) -> u16 {
    FRAME_META.lock().refcount(paddr)
}
