//! Memory management syscalls for the Linux compatibility layer.
//!
//! Implements mmap, munmap, mprotect, brk, and madvise with fully
//! deterministic addressing. All mmap allocations are assigned sequentially
//! from a fixed base (no ASLR) so that execution is reproducible.

#![allow(dead_code)]

extern crate alloc;

use super::constants::{EFAULT, EINVAL, ENOMEM};
use super::state::{self, get_state, get_state_mut, LinuxAgentState, VmaEntry, VmaKind};
use crate::agent;
use crate::arch::x86_64::paging::{
    self, alloc_frame_with_kind, invlpg, release_frame, set_page_mapping, unmap_page, FrameKind,
    PAGE_SIZE, PTE_NX, PTE_PRESENT, PTE_USER, PTE_WRITABLE,
};
// ── mmap flag constants ────────────────────────────────────────────────────

const MAP_SHARED: u32 = 0x01;
const MAP_PRIVATE: u32 = 0x02;
const MAP_FIXED: u32 = 0x10;
const MAP_ANONYMOUS: u32 = 0x20;

/// Software-only PTE bit used to mark a reserved anonymous PROT_NONE VMA.
///
/// x86_64 leaves bits 9-11 available to software in leaf PTEs.
const PTE_SOFT_RESERVED: u64 = 1 << 9;

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
///   PROT_READ  -> PTE_PRESENT | PTE_USER | optional PTE_NX
///   PROT_WRITE -> adds PTE_WRITABLE
///   PROT_EXEC  -> removes PTE_NX
///   PROT_NONE  -> PTE_USER only (not present, will fault)
fn prot_to_pte_flags(prot: u32) -> u64 {
    if prot == PROT_NONE {
        // Not present - any access will fault
        return PTE_USER;
    }

    let mut flags = PTE_PRESENT | PTE_USER;
    if crate::arch::x86_64::security::nx_active() {
        flags |= PTE_NX;
    }

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

#[inline]
fn vm_owner_agent_id(agent_id: u16) -> u16 {
    match super::state::get_state(agent_id) {
        Some(st) => {
            let owner = st.vm_space_owner;
            if owner != 0 && super::state::get_state(owner).is_some() {
                owner
            } else {
                agent_id
            }
        }
        None => agent_id,
    }
}

fn insert_vma(state: &mut LinuxAgentState, mut vma: VmaEntry) -> Result<(), i64> {
    if vma.len == 0 {
        return Err(-EINVAL);
    }
    if try_merge_vma(state, &vma) {
        return Ok(());
    }
    vma.active = true;
    let Some(slot) = state.alloc_vma_slot() else {
        return Err(-ENOMEM);
    };
    state.vmas[slot] = vma;
    Ok(())
}

fn free_vma_slots(state: &LinuxAgentState) -> usize {
    state.vmas.iter().filter(|vma| !vma.active).count()
}

fn same_vma_shape(a: &VmaEntry, b: &VmaEntry) -> bool {
    a.active
        && b.active
        && a.prot == b.prot
        && a.flags == b.flags
        && a.kind == b.kind
        && a.keyspace_id == b.keyspace_id
        && a.keyspace_key == b.keyspace_key
}

fn file_offsets_are_contiguous(left: &VmaEntry, right: &VmaEntry) -> bool {
    left.kind != VmaKind::File || left.file_offset.saturating_add(left.len) == right.file_offset
}

fn try_merge_vma(state: &mut LinuxAgentState, vma: &VmaEntry) -> bool {
    for existing in state.vmas.iter_mut() {
        if !same_vma_shape(existing, vma) {
            continue;
        }

        if existing.end() == vma.start && file_offsets_are_contiguous(existing, vma) {
            existing.len = existing.len.saturating_add(vma.len);
            return true;
        }

        if vma.end() == existing.start && file_offsets_are_contiguous(vma, existing) {
            existing.start = vma.start;
            existing.len = existing.len.saturating_add(vma.len);
            if existing.kind == VmaKind::File {
                existing.file_offset = vma.file_offset;
            }
            return true;
        }
    }

    false
}

fn merge_adjacent_vmas(state: &mut LinuxAgentState) {
    loop {
        let mut merged = false;
        for i in 0..state::MAX_VMAS {
            if !state.vmas[i].active {
                continue;
            }
            for j in (i + 1)..state::MAX_VMAS {
                if !state.vmas[j].active {
                    continue;
                }

                let right = state.vmas[j];
                if try_merge_vma(state, &right) {
                    state.vmas[j] = VmaEntry::empty();
                    merged = true;
                    break;
                }
            }
            if merged {
                break;
            }
        }
        if !merged {
            break;
        }
    }
}

fn clone_vma_piece(src: &VmaEntry, start: u64, end: u64, prot: u32) -> VmaEntry {
    let mut piece = *src;
    piece.active = true;
    piece.start = start;
    piece.len = end.saturating_sub(start);
    piece.prot = prot;
    if piece.kind == VmaKind::File {
        piece.file_offset = src.file_offset.saturating_add(start.saturating_sub(src.start));
    }
    piece
}

fn remove_vma_range(state: &mut LinuxAgentState, start: u64, len: u64) -> Result<(), i64> {
    let end = start.checked_add(len).ok_or(-EINVAL)?;
    for i in 0..state::MAX_VMAS {
        let vma = state.vmas[i];
        if !vma.active {
            continue;
        }
        let overlap_start = core::cmp::max(vma.start, start);
        let overlap_end = core::cmp::min(vma.end(), end);
        if overlap_start >= overlap_end {
            continue;
        }

        let has_left = vma.start < overlap_start;
        let has_right = overlap_end < vma.end();
        let needed_extra = usize::from(has_left && has_right);
        if free_vma_slots(state) < needed_extra {
            return Err(-ENOMEM);
        }

        match (has_left, has_right) {
            (false, false) => state.vmas[i] = VmaEntry::empty(),
            (true, false) => {
                state.vmas[i] = clone_vma_piece(&vma, vma.start, overlap_start, vma.prot);
            }
            (false, true) => {
                state.vmas[i] = clone_vma_piece(&vma, overlap_end, vma.end(), vma.prot);
            }
            (true, true) => {
                state.vmas[i] = clone_vma_piece(&vma, vma.start, overlap_start, vma.prot);
                insert_vma(state, clone_vma_piece(&vma, overlap_end, vma.end(), vma.prot))?;
            }
        }
    }
    merge_adjacent_vmas(state);
    Ok(())
}

fn protect_vma_range(state: &mut LinuxAgentState, start: u64, len: u64, prot: u32) -> Result<(), i64> {
    let end = start.checked_add(len).ok_or(-EINVAL)?;
    for i in 0..state::MAX_VMAS {
        let vma = state.vmas[i];
        if !vma.active {
            continue;
        }
        let overlap_start = core::cmp::max(vma.start, start);
        let overlap_end = core::cmp::min(vma.end(), end);
        if overlap_start >= overlap_end {
            continue;
        }

        let has_left = vma.start < overlap_start;
        let has_right = overlap_end < vma.end();
        let needed_extra = usize::from(has_left) + usize::from(has_right);
        if free_vma_slots(state) < needed_extra {
            return Err(-ENOMEM);
        }

        state.vmas[i] = clone_vma_piece(&vma, overlap_start, overlap_end, prot);
        if has_left {
            insert_vma(state, clone_vma_piece(&vma, vma.start, overlap_start, vma.prot))?;
        }
        if has_right {
            insert_vma(state, clone_vma_piece(&vma, overlap_end, vma.end(), vma.prot))?;
        }
    }
    merge_adjacent_vmas(state);
    Ok(())
}

fn read_file_slice(keyspace: u16, key: u64, offset: usize, dst: &mut [u8]) -> usize {
    crate::state::load_file_range(keyspace, key, offset, dst)
}

fn fault_access_allowed(vma: &VmaEntry, error_code: u64) -> bool {
    let is_write = error_code & 0x2 != 0;
    let is_exec = error_code & 0x10 != 0;
    if is_exec {
        vma.prot & PROT_EXEC != 0
    } else if is_write {
        vma.prot & PROT_WRITE != 0
    } else {
        vma.prot & (PROT_READ | PROT_WRITE | PROT_EXEC) != 0
    }
}

pub fn handle_user_page_fault(agent_id: u16, fault_addr: u64, error_code: u64) -> bool {
    let trace_python = super::state::trace_runtime_agent(agent_id);
    let cr3 = match get_agent_cr3(agent_id) {
        Some(c) => c,
        None => {
            if trace_python {
                crate::serial_println!(
                    "[PYDBG] page-fault-miss agent={} addr={:#x} err={:#x} reason=no-cr3",
                    agent_id,
                    fault_addr,
                    error_code
                );
            }
            return false;
        }
    };
    let vm_owner = vm_owner_agent_id(agent_id);
    let state = match get_state_mut(vm_owner) {
        Some(s) => s,
        None => {
            if trace_python {
                crate::serial_println!(
                    "[PYDBG] page-fault-miss agent={} addr={:#x} err={:#x} reason=no-state owner={}",
                    agent_id,
                    fault_addr,
                    error_code,
                    vm_owner
                );
            }
            return false;
        }
    };
    let Some(idx) = state.find_vma_index(fault_addr) else {
        if trace_python {
            crate::serial_println!(
                "[PYDBG] page-fault-miss agent={} addr={:#x} err={:#x} reason=no-vma owner={} vma_slots={} mmap_next={:#x}",
                agent_id,
                fault_addr,
                error_code,
                vm_owner,
                state.vmas.iter().filter(|vma| vma.active).count(),
                state.mmap_next
            );
        }
        return false;
    };
    let vma = state.vmas[idx];
    if !fault_access_allowed(&vma, error_code) {
        if trace_python {
            crate::serial_println!(
                "[PYDBG] page-fault-miss agent={} addr={:#x} err={:#x} reason=prot idx={} vma=[{:#x},{:#x}) prot={:#x}",
                agent_id,
                fault_addr,
                error_code,
                idx,
                vma.start,
                vma.end(),
                vma.prot
            );
        }
        return false;
    }

    let page_vaddr = fault_addr & !(PAGE_SIZE as u64 - 1);
    if read_pte_phys(cr3, page_vaddr).is_some() {
        if trace_python {
            crate::serial_println!(
                "[PYDBG] page-fault-miss agent={} addr={:#x} err={:#x} reason=already-mapped page={:#x}",
                agent_id,
                fault_addr,
                error_code,
                page_vaddr
            );
        }
        return false;
    }

    let frame_kind = if vma.kind == VmaKind::File {
        FrameKind::File
    } else {
        FrameKind::Anon
    };
    let frame = match alloc_frame_with_kind(frame_kind) {
        Some(f) => f,
        None => {
            if trace_python {
                crate::serial_println!(
                    "[PYDBG] page-fault-miss agent={} addr={:#x} err={:#x} reason=oom page={:#x}",
                    agent_id,
                    fault_addr,
                    error_code,
                    page_vaddr
                );
            }
            return false;
        }
    };
    unsafe {
        zero_frame(frame);
    }

    if vma.kind == VmaKind::File {
        let page_offset = page_vaddr.saturating_sub(vma.start) as usize;
        let file_offset = vma.file_offset as usize + page_offset;
        let page =
            unsafe { core::slice::from_raw_parts_mut(paging::phys_to_virt(frame) as *mut u8, PAGE_SIZE) };
        let _ = read_file_slice(vma.keyspace_id, vma.keyspace_key, file_offset, page);
    }

    if set_page_mapping(cr3, page_vaddr, frame, prot_to_pte_flags(vma.prot)).is_err() {
        let _ = release_frame(frame);
        if trace_python {
            crate::serial_println!(
                "[PYDBG] page-fault-miss agent={} addr={:#x} err={:#x} reason=map-fail page={:#x}",
                agent_id,
                fault_addr,
                error_code,
                page_vaddr
            );
        }
        return false;
    }
    invlpg(page_vaddr);
    if trace_python {
        crate::serial_println!(
            "[PYDBG] page-fault-fill agent={} addr={:#x} err={:#x} page={:#x} prot={:#x} kind={:?}",
            agent_id,
            fault_addr,
            error_code,
            page_vaddr,
            vma.prot,
            vma.kind
        );
    }
    true
}

/// Zero a physical frame via its identity-mapped address.
///
/// Safety: the frame must be a valid allocated physical page accessible
/// through the identity mapping.
unsafe fn zero_frame(phys: u64) {
    let ptr = paging::phys_to_virt(phys) as *mut u8;
    core::ptr::write_bytes(ptr, 0, PAGE_SIZE);
}

fn translate_user_vaddr(agent_cr3: u64, vaddr: u64) -> Option<u64> {
    let page_off = vaddr & (PAGE_SIZE as u64 - 1);
    let page_base = read_pte_phys(agent_cr3, vaddr)?;
    Some(page_base + page_off)
}

fn write_mapped_bytes(cr3: u64, user_vaddr: u64, data: &[u8]) -> Result<(), i64> {
    let mut written = 0usize;

    while written < data.len() {
        let vaddr = user_vaddr.checked_add(written as u64).ok_or(-EINVAL)?;
        let phys = translate_user_vaddr(cr3, vaddr).ok_or(-EINVAL)?;
        let page_off = (vaddr as usize) & (PAGE_SIZE - 1);
        let chunk_len = (data.len() - written).min(PAGE_SIZE - page_off);

        unsafe {
            let src = data.as_ptr().add(written);
            let dst = paging::phys_to_virt(phys) as *mut u8;
            for i in 0..chunk_len {
                core::ptr::write(dst.add(i), core::ptr::read(src.add(i)));
            }
        }

        written += chunk_len;
    }

    Ok(())
}

fn read_mapped_u64(cr3: u64, vaddr: u64) -> Option<u64> {
    let phys = translate_user_vaddr(cr3, vaddr)?;
    Some(unsafe { core::ptr::read_unaligned(paging::phys_to_virt(phys) as *const u64) })
}

fn file_vaddr_to_offset(elf: &crate::loader::ElfInfo, vaddr: u64, size: u64) -> Option<usize> {
    let end = vaddr.checked_add(size)?;
    for seg in elf.segments[..elf.segment_count].iter().filter_map(|seg| seg.as_ref()) {
        let seg_start = seg.vaddr;
        let seg_end = seg.vaddr.checked_add(seg.file_size)?;
        if vaddr >= seg_start && end <= seg_end {
            let rel = vaddr.checked_sub(seg_start)?;
            let file_off = seg.file_offset.checked_add(rel)?;
            return usize::try_from(file_off).ok();
        }
    }
    None
}

fn find_dynamic_tag(elf: &crate::loader::ElfInfo, image: &[u8], wanted_tag: u64) -> Option<u64> {
    if elf.dynamic_vaddr == 0 || elf.dynamic_size < 16 {
        return None;
    }
    let dyn_off = file_vaddr_to_offset(elf, elf.dynamic_vaddr, elf.dynamic_size)?;
    let dyn_size = usize::try_from(elf.dynamic_size).ok()?;
    if dyn_off.checked_add(dyn_size)? > image.len() {
        return None;
    }

    let mut off = dyn_off;
    let end = dyn_off + dyn_size;
    while off + 16 <= end {
        let tag = u64::from_le_bytes(image[off..off + 8].try_into().ok()?);
        let val = u64::from_le_bytes(image[off + 8..off + 16].try_into().ok()?);
        if tag == wanted_tag {
            return Some(val);
        }
        if tag == 0 {
            break;
        }
        off += 16;
    }
    None
}

fn dynamic_segment_runtime_base(
    elf: &crate::loader::ElfInfo,
    map_addr: u64,
    file_offset: u64,
) -> Option<u64> {
    if elf.dynamic_vaddr == 0 {
        return None;
    }
    let page_mask = PAGE_SIZE as u64 - 1;
    for seg in elf.segments[..elf.segment_count].iter().filter_map(|seg| seg.as_ref()) {
        let seg_end = seg.vaddr.checked_add(seg.mem_size)?;
        if elf.dynamic_vaddr >= seg.vaddr && elf.dynamic_vaddr < seg_end {
            let aligned_off = seg.file_offset & !page_mask;
            let aligned_vaddr = seg.vaddr & !page_mask;
            if file_offset == aligned_off {
                return map_addr.checked_sub(aligned_vaddr);
            }
        }
    }
    None
}

fn debug_dump_mapped_dynamic(agent_id: u16, cr3: u64, key: u64, base: u64, image: &[u8]) {
    let Ok(elf) = crate::loader::parse_elf64(image) else {
        return;
    };
    if !elf.is_dynamic || elf.dynamic_vaddr == 0 || elf.dynamic_size < 16 {
        return;
    }

    let runtime_dyn = base + elf.dynamic_vaddr;
    crate::serial_println!(
        "[PYDBG] elf-dynamic agent={} key={:#x} base={:#x} runtime_dyn={:#x} dynsz={:#x}",
        agent_id,
        key,
        base,
        runtime_dyn,
        elf.dynamic_size
    );
    let dump_count = (elf.dynamic_size / 16).min(32);
    for i in 0..dump_count {
        let entry = runtime_dyn + i * 16;
        let tag = read_mapped_u64(cr3, entry).unwrap_or(u64::MAX);
        let val = read_mapped_u64(cr3, entry + 8).unwrap_or(u64::MAX);
        crate::serial_println!(
            "[PYDBG] elf-dynamic[{}] key={:#x} tag={:#x} val={:#x}",
            i,
            key,
            tag,
            val
        );
        if tag == 0 {
            break;
        }
    }
}

fn debug_dump_runtime_dynamic(agent_id: u16, cr3: u64, key: u64, base: u64, image: &[u8]) {
    let Ok(elf) = crate::loader::parse_elf64(image) else {
        return;
    };
    if elf.dynamic_vaddr == 0 || elf.dynamic_size < 16 {
        return;
    }

    let runtime_dyn = base + elf.dynamic_vaddr;
    crate::serial_println!(
        "[PYDBG] runtime-dynamic agent={} key={:#x} base={:#x} dyn={:#x} dynsz={:#x}",
        agent_id,
        key,
        base,
        runtime_dyn,
        elf.dynamic_size
    );
    let dump_count = (elf.dynamic_size / 16).min(32);
    for i in 0..dump_count {
        let entry = runtime_dyn + i * 16;
        let tag = read_mapped_u64(cr3, entry).unwrap_or(u64::MAX);
        let val = read_mapped_u64(cr3, entry + 8).unwrap_or(u64::MAX);
        crate::serial_println!(
            "[PYDBG] runtime-dynamic[{}] agent={} key={:#x} tag={:#x} val={:#x}",
            i,
            agent_id,
            key,
            tag,
            val
        );
        if tag == 0 {
            break;
        }
    }
}

fn debug_dump_file_dynamic(agent_id: u16, key: u64, image: &[u8]) {
    let Ok(elf) = crate::loader::parse_elf64(image) else {
        return;
    };
    if elf.dynamic_vaddr == 0 || elf.dynamic_size < 16 {
        return;
    }

    let Some(dyn_off) = file_vaddr_to_offset(&elf, elf.dynamic_vaddr, elf.dynamic_size) else {
        crate::serial_println!(
            "[PYDBG] file-dynamic agent={} key={:#x} unresolved-vaddr={:#x} dynsz={:#x}",
            agent_id,
            key,
            elf.dynamic_vaddr,
            elf.dynamic_size
        );
        return;
    };

    let dyn_size = elf.dynamic_size as usize;
    if dyn_off + dyn_size > image.len() {
        crate::serial_println!(
            "[PYDBG] file-dynamic agent={} key={:#x} truncated off={:#x} dynsz={:#x} image_len={:#x}",
            agent_id,
            key,
            dyn_off,
            elf.dynamic_size,
            image.len()
        );
        return;
    }

    crate::serial_println!(
        "[PYDBG] file-dynamic agent={} key={:#x} off={:#x} dynsz={:#x}",
        agent_id,
        key,
        dyn_off,
        elf.dynamic_size
    );
    let dump_count = (elf.dynamic_size / 16).min(8);
    for i in 0..dump_count {
        let entry = dyn_off + (i as usize) * 16;
        let tag = u64::from_le_bytes(image[entry..entry + 8].try_into().unwrap());
        let val = u64::from_le_bytes(image[entry + 8..entry + 16].try_into().unwrap());
        crate::serial_println!(
            "[PYDBG] file-dynamic[{}] agent={} key={:#x} tag={:#x} val={:#x}",
            i,
            agent_id,
            key,
            tag,
            val
        );
        if tag == 0 {
            break;
        }
    }
}

fn debug_dump_page_bytes(agent_id: u16, cr3: u64, label: &str, vaddr: u64) {
    let mut words = [0u64; 4];
    for (idx, slot) in words.iter_mut().enumerate() {
        *slot = read_mapped_u64(cr3, vaddr + (idx as u64) * 8).unwrap_or(u64::MAX);
    }
    crate::serial_println!(
        "[PYDBG] {} agent={} vaddr={:#x} qwords={:#x} {:#x} {:#x} {:#x}",
        label,
        agent_id,
        vaddr,
        words[0],
        words[1],
        words[2],
        words[3]
    );
}

fn debug_dump_mapped_rela(agent_id: u16, cr3: u64, key: u64, base: u64, image: &[u8]) {
    let Ok(elf) = crate::loader::parse_elf64(image) else {
        return;
    };

    let Some(rela_vaddr) = find_dynamic_tag(&elf, image, 7) else {
        return;
    };
    let Some(relaent) = find_dynamic_tag(&elf, image, 9) else {
        return;
    };
    if relaent < 24 {
        return;
    }
    let relacount = find_dynamic_tag(&elf, image, 0x6fff_fff9).unwrap_or(0);
    let runtime_rela = base + rela_vaddr;

    crate::serial_println!(
        "[PYDBG] elf-rela agent={} key={:#x} base={:#x} rela={:#x} relaent={} relacount={}",
        agent_id,
        key,
        base,
        runtime_rela,
        relaent,
        relacount
    );

    let mut slots = [0u64; 5];
    let mut slot_count = 0usize;
    for idx in [0u64, 1, 2] {
        slots[slot_count] = idx;
        slot_count += 1;
    }
    if relacount > 0 {
        let before_last = relacount - 1;
        if !slots[..slot_count].contains(&before_last) {
            slots[slot_count] = before_last;
            slot_count += 1;
        }
        if !slots[..slot_count].contains(&relacount) {
            slots[slot_count] = relacount;
            slot_count += 1;
        }
    }

    for idx in slots[..slot_count].iter().copied() {
        let entry = runtime_rela + idx * relaent;
        let a = read_mapped_u64(cr3, entry).unwrap_or(u64::MAX);
        let b = read_mapped_u64(cr3, entry + 8).unwrap_or(u64::MAX);
        let c = read_mapped_u64(cr3, entry + 16).unwrap_or(u64::MAX);
        crate::serial_println!(
            "[PYDBG] elf-rela[{}] agent={} key={:#x} off={:#x} val0={:#x} val1={:#x} val2={:#x}",
            idx,
            agent_id,
            key,
            entry,
            a,
            b,
            c
        );
    }
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
    let trace_python = super::state::trace_runtime_agent(agent_id);
    if length == 0 {
        return -EINVAL;
    }

    let file_backing = if fd >= 0 && (flags & MAP_ANONYMOUS == 0) {
        let st = match get_state(agent_id) {
            Some(s) => s,
            None => return -EINVAL,
        };
        let entry = match st.get_fd(fd) {
            Some(e) => *e,
            None => return -EFAULT,
        };
        Some((entry.keyspace_id, entry.keyspace_key))
    } else {
        None
    };

    let vm_owner = vm_owner_agent_id(agent_id);
    let state = match get_state_mut(vm_owner) {
        Some(s) => s,
        None => return -EINVAL,
    };

    let aligned_len = page_align_up(length);

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

    if trace_python {
        crate::serial_println!(
            "[PYDBG] mmap-enter agent={} fd={} addr={:#x} len={:#x} prot={:#x} flags={:#x} off={:#x} chosen={:#x}",
            agent_id,
            fd,
            addr,
            aligned_len,
            prot,
            flags,
            offset,
            vaddr
        );
    }

    let mut vma = VmaEntry {
        active: true,
        start: vaddr,
        len: aligned_len,
        prot,
        flags,
        kind: VmaKind::Anonymous,
        keyspace_id: 0,
        keyspace_key: 0,
        file_offset: offset,
    };

    if flags & MAP_FIXED != 0 {
        let _ = sys_munmap(agent_id, vaddr, aligned_len);
    }

    if let Some((ks, key)) = file_backing {
        vma.kind = VmaKind::File;
        vma.keyspace_id = ks;
        vma.keyspace_key = key;
        if trace_python {
            crate::serial_println!(
                "[PYDBG] mmap-lazy-file agent={} fd={} addr={:#x} len={:#x} prot={:#x} flags={:#x} off={:#x} ks={} key={:#x}",
                agent_id,
                fd,
                vaddr,
                aligned_len,
                prot,
                flags,
                offset,
                ks,
                key
            );
        }
    } else if trace_python {
        crate::serial_println!(
            "[PYDBG] mmap-lazy-anon agent={} addr={:#x} len={:#x} prot={:#x} flags={:#x}",
            agent_id,
            vaddr,
            aligned_len,
            prot,
            flags
        );
    }

    if insert_vma(state, vma).is_err() {
        return -ENOMEM;
    }

    if trace_python {
        crate::serial_println!("[PYDBG] mmap-exit agent={} ret={:#x}", agent_id, vaddr);
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

    let vm_owner = vm_owner_agent_id(agent_id);
    if let Some(state) = get_state_mut(vm_owner) {
        if let Err(err) = remove_vma_range(state, addr, aligned_len) {
            return err;
        }
    }

    for i in 0..num_pages {
        let page_vaddr = addr + (i as u64) * (PAGE_SIZE as u64);

        // Recover the backing frame even for PROT_NONE mappings where the
        // leaf PTE is intentionally non-present.
        if let Some(pte) = read_leaf_pte(cr3, page_vaddr) {
            let phys = pte & 0x000F_FFFF_FFFF_F000;
            unmap_page(cr3, page_vaddr);
            if phys != 0 {
                let _ = release_frame(phys);
            }
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
    let trace_python = super::state::trace_runtime_agent(agent_id);
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

    let vm_owner = vm_owner_agent_id(agent_id);
    if let Some(state) = get_state_mut(vm_owner) {
        if let Err(err) = protect_vma_range(state, addr, aligned_len, prot) {
            return err;
        }
    }

    for i in 0..num_pages {
        let page_vaddr = addr + (i as u64) * (PAGE_SIZE as u64);

        // Walk the page table to find the leaf PTE and update its flags.
        // PROT_NONE leaves are intentionally non-present, so we must recover
        // the frame pointer from the raw PTE instead of requiring PTE_PRESENT.
        if let Some(pte) = read_leaf_pte(cr3, page_vaddr) {
            let phys = pte & 0x000F_FFFF_FFFF_F000;
            if phys == 0 && (pte & PTE_SOFT_RESERVED != 0) {
                if prot == PROT_NONE {
                    let _ = set_page_mapping(cr3, page_vaddr, 0, PTE_USER | PTE_SOFT_RESERVED);
                } else {
                    let frame = match alloc_frame_with_kind(FrameKind::Anon) {
                        Some(f) => f,
                        None => return -ENOMEM,
                    };
                    unsafe {
                        zero_frame(frame);
                    }
                    let _ = set_page_mapping(cr3, page_vaddr, frame, new_flags);
                }
            } else {
                // Re-map the page with new flags (overwrites the existing PTE)
                let _ = set_page_mapping(cr3, page_vaddr, phys, new_flags);
            }
            invlpg(page_vaddr);
        }
        // If the page is not mapped, silently skip (matches Linux behavior)
    }

    if trace_python {
        crate::serial_println!(
            "[PYDBG] mprotect-exit agent={} ret=0 addr={:#x} len={:#x} prot={:#x}",
            agent_id,
            addr,
            aligned_len,
            prot
        );
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

    let vm_owner = vm_owner_agent_id(agent_id);
    let state = match get_state_mut(vm_owner) {
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
        let mut pte_flags = PTE_PRESENT | PTE_WRITABLE | PTE_USER;
        if crate::arch::x86_64::security::nx_active() {
            pte_flags |= PTE_NX;
        }

        let mut page = start_page;
        while page < end_page {
            let frame = match alloc_frame_with_kind(FrameKind::Anon) {
                Some(f) => f,
                None => {
                    // OOM: return current brk (failure indication)
                    return state.brk_current as i64;
                }
            };

            unsafe {
                zero_frame(frame);
            }

            if set_page_mapping(cr3, page, frame, pte_flags).is_err() {
                let _ = release_frame(frame);
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
                let _ = release_frame(phys);
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
                unsafe {
                    zero_frame(phys);
                }
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
    let pte = read_leaf_pte(pml4_phys, vaddr)?;
    if pte & PTE_PRESENT == 0 {
        return None;
    }
    Some(pte & 0x000F_FFFF_FFFF_F000)
}

/// Walk the page tables and return the raw leaf PTE value.
///
/// Unlike `read_pte_phys`, this still succeeds for PROT_NONE mappings where
/// the leaf keeps a physical frame pointer but clears PTE_PRESENT, or for
/// anonymous reserve-only mappings marked with `PTE_SOFT_RESERVED`.
fn read_leaf_pte(pml4_phys: u64, vaddr: u64) -> Option<u64> {
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;

    unsafe {
        let pml4 = paging::phys_to_virt(pml4_phys) as *const u64;
        let pml4e = core::ptr::read_volatile(pml4.add(pml4_idx));
        if pml4e & PTE_PRESENT == 0 {
            return None;
        }

        let pdpt = paging::phys_to_virt(pml4e & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pdpte = core::ptr::read_volatile(pdpt.add(pdpt_idx));
        if pdpte & PTE_PRESENT == 0 {
            return None;
        }

        let pd = paging::phys_to_virt(pdpte & 0x000F_FFFF_FFFF_F000) as *const u64;
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

        let pt = paging::phys_to_virt(pde & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pte = core::ptr::read_volatile(pt.add(pt_idx));
        if pte & 0x000F_FFFF_FFFF_F000 == 0 && (pte & PTE_SOFT_RESERVED == 0) {
            return None;
        }

        Some(pte)
    }
}
