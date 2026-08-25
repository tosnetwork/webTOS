# Memory Subsystem Migration Plan

This document tracks the staged migration of TOS memory management toward a
more scalable design while preserving TOS-specific determinism and syscall
structure.

## Goals

- Keep TOS architecture ownership and deterministic policies.
- Replace the current bitmap frame allocator with a buddy allocator.
- Add per-frame metadata and reference counting.
- Replace the current linked-list kernel heap allocator with slab-based
  allocation for small objects.
- Cleanly separate Linux VMA policy from low-level page table operations.

## Status Summary

- Phase 0: completed
- Phase 1: completed
- Phase 2: completed
- Phase 3: completed
- Phase 4: completed

## Phase 0: Lock External Interfaces

Status: completed

Keep the current public paging API stable while swapping internal
implementations:

- `paging::alloc_frame()`
- `paging::dealloc_frame()`
- `paging::map_page()`
- `paging::unmap_page()`
- `paging::retain_address_space()`
- `paging::release_address_space()`

## Phase 1: Replace Bitmap Frame Allocation

Status: completed

Target:

- Introduce a buddy-based physical frame allocator.
- Preserve the existing `paging::*` allocation entry points.
- Keep UEFI memory map parsing and current boot flow working.

Expected work:

- Add `src/arch/x86_64/frame_alloc.rs`.
- Route `paging::init_from_uefi_mmap()`, `paging::init_with_memory_limit()`,
  `paging::alloc_frame()`, and `paging::dealloc_frame()` through the new
  allocator.
- Keep current page table code unchanged above the allocation layer.

Validation:

- Kernel builds successfully.
- Syscall regression still passes.
- Dynamic musl hello still boots.
- Java smoke remains functional.

## Phase 2: Add Per-Frame Metadata and Refcounts

Status: completed

Target:

- Track each physical frame with side metadata.
- Add frame reference counting independent from address-space reference
  tracking.

Expected work:

- Add `src/arch/x86_64/frame_meta.rs`.
- Track at least:
  - `refcount`
  - `kind` (`Free`, `Anon`, `File`, `PageTable`, `KernelHeap`, `Device`)
- Convert direct frame frees in Linux VM and page-table code into
  `retain/release` style operations.

Validation:

- Shared address spaces do not free backing pages early.
- Lazy file-backed mappings do not double free pages.

## Phase 3: Replace Kernel Heap with Slab Allocation

Status: completed

Target:

- Keep the global allocator entry point.
- Use slab caches for small objects and page-backed allocation for larger
  objects.

Expected work:

- Rewrite `src/heap.rs` behind the same `#[global_allocator]` entry point.
- Introduce size classes:
  - `8`, `16`, `32`, `64`, `128`, `256`, `512`, `1024`, `2048`
- Route larger allocations directly to the page allocator.

Current progress:

- Replaced the old linked-list free-list allocator with page-backed slab
  caches for the configured size classes.
- Large allocations now use contiguous frame allocation with allocator-local
  headers for aligned deallocation.
- Added allocator-native `alloc_zeroed` and `realloc` handling so common
  collection growth patterns can stay in-place when they remain within the
  same slab class or large allocation span.
- Added a boot-time kernel heap smoke that exercises `Box`, `Vec`, `String`,
  and `BTreeMap` allocation patterns.
- Short QEMU boot and Java smoke still advance with the slab allocator enabled.

Validation:

- Frequent `Vec`, `Box`, `String`, and `BTreeMap` allocations remain stable.
- Kernel heap fragmentation is reduced.

## Phase 4: Split VMA Policy from Page Table Operations

Status: completed

Target:

- Separate Linux VMA bookkeeping from low-level PTE mutation.

Expected work:

- Add `src/arch/x86_64/page_table.rs`.
- Keep Linux VMA policy in `src/linux_compat/memory.rs`.
- Move low-level page walking, map/unmap, and protect logic into a dedicated
  page-table backend.

Current progress:

- Added `src/arch/x86_64/page_table.rs` as the low-level x86_64 page-table
  backend for raw leaf walking, address translation, and leaf remap/unmap
  operations.
- Removed Linux-specific page-table walk helpers from
  `src/linux_compat/memory.rs` so that file/anon VMA policy stays separate
  from raw PTE traversal.
- Routed page fault fill, `munmap`, `mprotect`, `brk`, and `madvise` through
  the page-table backend while keeping VMA ownership and protection policy in
  `src/linux_compat/memory.rs`.
- Reused the same page-table backend in `src/agent_loader.rs` and
  `src/linux_compat/process.rs` so user-memory copies and loader stack setup no
  longer maintain their own ad-hoc page-table walkers.

Validation:

- `mmap`, `munmap`, `mprotect`, and page fault handling all flow through VMA
  policy first.
- Python, Node, and Java runtime smoke tests continue to advance.

## Source References

Reference implementations to study during migration:

- A mature buddy allocator layout.
- A mature slab allocator layout.
- A mature VMA and `mmap` flow.
