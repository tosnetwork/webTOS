//! Memory management syscalls for the Linux compatibility layer.
//!
//! Implements mmap, munmap, mprotect, brk, and madvise with fully
//! deterministic addressing. All mmap allocations are assigned sequentially
//! from a fixed base (no ASLR) so that execution is reproducible.

#![allow(dead_code)]

use crate::agent;
use crate::arch::x86_64::paging::{
    self, alloc_frame, dealloc_frame, map_page, unmap_page, invlpg,
    PTE_PRESENT, PTE_WRITABLE, PTE_USER, PTE_NX, PAGE_SIZE,
};
use super::state::get_state_mut;
use super::constants::{ENOMEM, EINVAL};

// ── mmap flag constants ────────────────────────────────────────────────────

const MAP_SHARED: u32 = 0x01;
const MAP_PRIVATE: u32 = 0x02;
const MAP_FIXED: u32 = 0x10;
const MAP_ANONYMOUS: u32 = 0x20;

// ── mprotect / mmap prot constants ─────────────────────────────────────────

const PROT_NONE: u32 = 0x0;
const PROT_READ: u32 = 0x1;
const PROT_WRITE: u32 = 0x2;
const PROT_EXEC: u32 = 0x4;

// ── madvise advice constants ───────────────────────────────────────────────

const MADV_NORMAL: u32 = 0;
const MADV_DONTNEED: u32 = 4;

// ── Deterministic mmap base ────────────────────────────────────────────────

/// Fixed base address for deterministic mmap allocation (4 GB).
/// Well above typical user code, below the canonical hole.
pub const MMAP_BASE: u64 = 0x1_0000_0000;

// ── Helpers ────────────────────────────────────────────────────────────────

/// Align a length up to the nearest page boundary.
#[inline]
fn page_align_up(len: u64) -> u64 {
    (len + (PAGE_SIZE as u64 - 1)) & !(PAGE_SIZE as u64 - 1)
}

/// Convert Linux prot flags to x86_64 page table entry flags.
///
/// Mapping:
///   PROT_READ  -> PTE_PRESENT | PTE_USER | PTE_NX
///   PROT_WRITE -> adds PTE_WRITABLE
///   PROT_EXEC  -> removes PTE_NX
///   PROT_NONE  -> PTE_USER only (not present, will fault)
fn prot_to_pte_flags(prot: u32) -> u64 {
    if prot == PROT_NONE {
        // Not present - any access will fault
        return PTE_USER;
    }

    let mut flags = PTE_PRESENT | PTE_USER | PTE_NX;

    if prot & PROT_WRITE != 0 {
        flags |= PTE_WRITABLE;
    }

    if prot & PROT_EXEC != 0 {
        // Remove NX to allow execution
        flags &= !PTE_NX;
    }

    flags
}

/// Get the CR3 (page table root) for an agent.
fn get_agent_cr3(agent_id: u16) -> Option<u64> {
    let a = agent::get_agent(agent_id)?;
    if a.context.cr3 == 0 {
        return None;
    }
    Some(a.context.cr3)
}

/// Zero a physical frame via its identity-mapped address.
///
/// Safety: the frame must be a valid allocated physical page accessible
/// through the identity mapping.
unsafe fn zero_frame(phys: u64) {
    let ptr = phys as *mut u8;
    core::ptr::write_bytes(ptr, 0, PAGE_SIZE);
}

// ── sys_mmap ───────────────────────────────────────────────────────────────

/// Map pages into an agent's address space.
///
/// Deterministic: if no fixed address is requested, the next sequential
/// address from `state.mmap_next` is used and the pointer is advanced.
///
/// Returns the virtual address of the mapping on success, or a negative
/// errno on failure.
pub fn sys_mmap(
    agent_id: u16,
    addr: u64,
    length: u64,
    prot: u32,
    flags: u32,
    fd: i32,
    offset: u64,
) -> i64 {
    if length == 0 {
        return -EINVAL;
    }

    let cr3 = match get_agent_cr3(agent_id) {
        Some(c) => c,
        None => return -EINVAL,
    };

    let state = match get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EINVAL,
    };

    let aligned_len = page_align_up(length);
    let num_pages = (aligned_len / PAGE_SIZE as u64) as usize;

    // Determine the virtual address for the mapping
    let vaddr = if addr != 0 && (flags & MAP_FIXED != 0) {
        // MAP_FIXED: use the exact requested address (must be page-aligned)
        if addr & (PAGE_SIZE as u64 - 1) != 0 {
            return -EINVAL;
        }
        addr
    } else {
        // Deterministic: use next sequential address and advance
        let base = state.mmap_next;
        state.mmap_next = base + aligned_len;
        base
    };

    let pte_flags = prot_to_pte_flags(prot);

    // Allocate and map each page
    for i in 0..num_pages {
        let page_vaddr = vaddr + (i as u64) * (PAGE_SIZE as u64);
        let frame = match alloc_frame() {
            Some(f) => f,
            None => {
                // Out of memory: unmap and free pages allocated so far
                for j in 0..i {
                    let prev_vaddr = vaddr + (j as u64) * (PAGE_SIZE as u64);
                    if let Some(phys) = read_pte_phys(cr3, prev_vaddr) {
                        unmap_page(cr3, prev_vaddr);
                        dealloc_frame(phys);
                    }
                }
                return -ENOMEM;
            }
        };

        // Zero the frame (anonymous pages, or placeholder for file-backed)
        unsafe { zero_frame(frame); }

        if map_page(cr3, page_vaddr, frame, pte_flags).is_err() {
            dealloc_frame(frame);
            return -ENOMEM;
        }
    }

    // Suppress unused warnings for file-backed mapping parameters.
    // These will be used once the fs layer supports read-into-physical.
    let _ = (fd, offset);

    // File-backed mapping: read content from the agent's keyspace
    if fd >= 0 && (flags & MAP_ANONYMOUS == 0) {
        // TODO: copy file content from keyspace into the mapped pages
        // once the fs layer exposes a read-into-physical interface.
        // For now, file-backed mappings are zeroed (pages already zeroed above).
    }

    vaddr as i64
}

// ── sys_munmap ─────────────────────────────────────────────────────────────

/// Unmap pages from an agent's address space and free the backing frames.
///
/// Returns 0 on success, or a negative errno on failure.
pub fn sys_munmap(agent_id: u16, addr: u64, length: u64) -> i64 {
    if length == 0 || addr & (PAGE_SIZE as u64 - 1) != 0 {
        return -EINVAL;
    }

    let cr3 = match get_agent_cr3(agent_id) {
        Some(c) => c,
        None => return -EINVAL,
    };

    let aligned_len = page_align_up(length);
    let num_pages = (aligned_len / PAGE_SIZE as u64) as usize;

    for i in 0..num_pages {
        let page_vaddr = addr + (i as u64) * (PAGE_SIZE as u64);

        // Read the PTE to get the physical address before unmapping
        if let Some(phys) = read_pte_phys(cr3, page_vaddr) {
            unmap_page(cr3, page_vaddr);
            dealloc_frame(phys);
        } else {
            // Page was not mapped - silently skip (matches Linux behavior)
        }
    }

    0
}

// ── sys_mprotect ───────────────────────────────────────────────────────────

/// Change protection flags on a range of pages.
///
/// Returns 0 on success, or a negative errno on failure.
pub fn sys_mprotect(agent_id: u16, addr: u64, length: u64, prot: u32) -> i64 {
    if length == 0 || addr & (PAGE_SIZE as u64 - 1) != 0 {
        return -EINVAL;
    }

    let cr3 = match get_agent_cr3(agent_id) {
        Some(c) => c,
        None => return -EINVAL,
    };

    let aligned_len = page_align_up(length);
    let num_pages = (aligned_len / PAGE_SIZE as u64) as usize;
    let new_flags = prot_to_pte_flags(prot);

    for i in 0..num_pages {
        let page_vaddr = addr + (i as u64) * (PAGE_SIZE as u64);

        // Walk the page table to find the leaf PTE and update its flags
        if let Some(phys) = read_pte_phys(cr3, page_vaddr) {
            // Re-map the page with new flags (overwrites the existing PTE)
            let _ = map_page(cr3, page_vaddr, phys, new_flags);
            invlpg(page_vaddr);
        }
        // If the page is not mapped, silently skip (matches Linux behavior)
    }

    0
}

// ── sys_brk ────────────────────────────────────────────────────────────────

/// Adjust the program break (heap end).
///
/// - `new_brk == 0`: return the current brk value
/// - `new_brk > current`: expand heap by allocating and mapping new pages
/// - `new_brk < current`: shrink heap by unmapping and freeing pages
///
/// Returns the new brk value on success, or the current brk on failure.
pub fn sys_brk(agent_id: u16, new_brk: u64) -> i64 {
    let cr3 = match get_agent_cr3(agent_id) {
        Some(c) => c,
        None => {
            // No address space: return a plausible default
            return 0x0060_0000;
        }
    };

    let state = match get_state_mut(agent_id) {
        Some(s) => s,
        None => return 0x0060_0000,
    };

    // Query only: return current brk
    if new_brk == 0 {
        return state.brk_current as i64;
    }

    let current = state.brk_current;

    if new_brk > current {
        // Expand: allocate pages from current (page-aligned up) to new_brk
        let start_page = page_align_up(current);
        let end_page = page_align_up(new_brk);
        let pte_flags = PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NX;

        let mut page = start_page;
        while page < end_page {
            let frame = match alloc_frame() {
                Some(f) => f,
                None => {
                    // OOM: return current brk (failure indication)
                    return state.brk_current as i64;
                }
            };

            unsafe { zero_frame(frame); }

            if map_page(cr3, page, frame, pte_flags).is_err() {
                dealloc_frame(frame);
                return state.brk_current as i64;
            }

            page += PAGE_SIZE as u64;
        }

        state.brk_current = new_brk;
    } else if new_brk < current {
        // Shrink: unmap pages from new_brk (page-aligned up) to current
        let start_page = page_align_up(new_brk);
        let end_page = page_align_up(current);

        let mut page = start_page;
        while page < end_page {
            if let Some(phys) = read_pte_phys(cr3, page) {
                unmap_page(cr3, page);
                dealloc_frame(phys);
            }
            page += PAGE_SIZE as u64;
        }

        state.brk_current = new_brk;
    }
    // new_brk == current: no-op

    state.brk_current as i64
}

// ── sys_madvise ────────────────────────────────────────────────────────────

/// Provide advice about use of memory.
///
/// Only `MADV_DONTNEED` is handled: zeros the pages but does not unmap them.
/// All other advice values are silently accepted as no-ops.
///
/// Returns 0 on success, or a negative errno on failure.
pub fn sys_madvise(agent_id: u16, addr: u64, length: u64, advice: u32) -> i64 {
    if addr & (PAGE_SIZE as u64 - 1) != 0 {
        return -EINVAL;
    }

    if advice == MADV_DONTNEED {
        let cr3 = match get_agent_cr3(agent_id) {
            Some(c) => c,
            None => return -EINVAL,
        };

        let aligned_len = page_align_up(length);
        let num_pages = (aligned_len / PAGE_SIZE as u64) as usize;

        for i in 0..num_pages {
            let page_vaddr = addr + (i as u64) * (PAGE_SIZE as u64);

            if let Some(phys) = read_pte_phys(cr3, page_vaddr) {
                // Zero the physical frame but leave the mapping in place
                unsafe { zero_frame(phys); }
                invlpg(page_vaddr);
            }
        }
    }
    // All other advice values: no-op, return success

    0
}

// ── Page table walk helper ─────────────────────────────────────────────────

/// Walk the four-level page table to extract the physical address from
/// a leaf PTE for a given virtual address.
///
/// Returns `Some(physical_address)` if the page is mapped, `None` otherwise.
fn read_pte_phys(pml4_phys: u64, vaddr: u64) -> Option<u64> {
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;

    unsafe {
        let pml4 = pml4_phys as *const u64;
        let pml4e = core::ptr::read_volatile(pml4.add(pml4_idx));
        if pml4e & PTE_PRESENT == 0 {
            return None;
        }

        let pdpt = (pml4e & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pdpte = core::ptr::read_volatile(pdpt.add(pdpt_idx));
        if pdpte & PTE_PRESENT == 0 {
            return None;
        }

        let pd = (pdpte & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pde = core::ptr::read_volatile(pd.add(pd_idx));
        if pde & PTE_PRESENT == 0 {
            return None;
        }

        // Check for 2MB huge page
        if pde & paging::PTE_HUGE != 0 {
            let base = pde & 0x000F_FFFF_FFE0_0000; // 2MB aligned
            let page_offset = vaddr & 0x1F_FFFF;
            return Some(base + page_offset);
        }

        let pt = (pde & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pte = core::ptr::read_volatile(pt.add(pt_idx));
        if pte & PTE_PRESENT == 0 {
            return None;
        }

        Some(pte & 0x000F_FFFF_FFFF_F000)
    }
}
