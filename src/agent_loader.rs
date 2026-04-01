//! ATOS Agent Loader
//!
//! Loads agent binaries (ELF64 or WASM) from memory or disk and spawns
//! them as running agents. Connects existing components: loader.rs (ELF
//! parser), wasm/decoder.rs (WASM decoder), paging.rs (address spaces),
//! and agent.rs (agent creation).
//!
//! Yellow Paper §24.2.3.1: Runtime Agent Loading from Disk and Memory.

extern crate alloc;

use crate::agent::*;
use crate::arch::x86_64::context::new_user_context;
use crate::arch::x86_64::page_table;
use crate::arch::x86_64::paging;
use crate::linux_compat::state::{VmaEntry, VmaKind};
use crate::mailbox;
use crate::sched;
use crate::serial_println;
use crate::state;
use crate::wasm;

/// Maximum agent image size.
///
/// Modern distro-provided PIE executables such as `/usr/bin/python3` and
/// `/usr/bin/node` are often well above 4 MiB, so the Linux-compat loading
/// path needs a materially larger ceiling than the earlier toy binaries.
const MAX_IMAGE_SIZE: usize = 128 * 1024 * 1024;

/// Maximum number of dynamically loaded WASM modules.
const MAX_WASM_MODULES: usize = MAX_AGENTS;

/// User virtual address for code (must match init.rs).
const USER_CODE_VADDR: u64 = 0x4000_0000;
/// User virtual address for stack (must match init.rs).
const USER_STACK_VADDR: u64 = 0x4000_1000;

/// Table of WASM modules for dynamically loaded agents.
/// Indexed by agent_id. The wasm_runner_entry retrieves its module from here.
static mut WASM_MODULES: [Option<wasm::decoder::WasmModule>; MAX_WASM_MODULES] =
    [const { None }; MAX_WASM_MODULES];

/// Per-agent runtime class for dynamically loaded WASM agents.
static mut WASM_RUNTIME_CLASSES: [wasm::types::RuntimeClass; MAX_WASM_MODULES] =
    [wasm::types::RuntimeClass::ProofGrade; MAX_WASM_MODULES];

pub const fn max_linux_image_size() -> usize {
    MAX_IMAGE_SIZE
}

pub struct PreparedLinuxImage {
    pub cr3: u64,
    pub entry: u64,
    pub initial_rsp: u64,
    pub initial_brk: u64,
    pub argc: usize,
    pub user_stack_base: u64,
    pub user_stack_top: u64,
    pub main_elf: crate::loader::ElfInfo,
    pub interp_elf: Option<crate::loader::ElfInfo>,
    pub main_backing: Option<(u16, u64)>,
    pub interp_backing: Option<(u16, u64)>,
}

const LINUX_PROT_READ: u32 = 0x1;
const LINUX_PROT_WRITE: u32 = 0x2;
const LINUX_PROT_EXEC: u32 = 0x4;
const LINUX_MAP_PRIVATE: u32 = 0x02;

fn linux_prot_from_segment(seg: &crate::loader::LoadSegment) -> u32 {
    let mut prot = 0u32;
    if seg.flags & 0x4 != 0 {
        prot |= LINUX_PROT_READ;
    }
    if seg.flags & 0x2 != 0 {
        prot |= LINUX_PROT_WRITE;
    }
    if seg.flags & 0x1 != 0 {
        prot |= LINUX_PROT_EXEC;
    }
    prot
}

fn resolve_linux_backing(path: &[u8]) -> Option<(u16, u64)> {
    let (ks, key) = crate::linux_compat::vfs::resolve_path(0, path);
    if crate::state::query_file_size(ks, key) > 0 || crate::state::state_get(ks, key).is_some() {
        Some((ks, key))
    } else {
        None
    }
}

fn install_initial_elf_vmas(
    agent_id: AgentId,
    elf_info: &crate::loader::ElfInfo,
    backing: Option<(u16, u64)>,
    min_vaddr: u64,
) -> Result<(), i64> {
    let page_mask = paging::PAGE_SIZE as u64 - 1;
    for seg in elf_info.segments[..elf_info.segment_count]
        .iter()
        .filter_map(|seg| seg.as_ref())
    {
        if seg.vaddr < min_vaddr {
            continue;
        }
        let start = seg.vaddr & !page_mask;
        let page_bias = seg.vaddr & page_mask;
        let len = page_align_up_u64(seg.mem_size.checked_add(page_bias).ok_or(E_INVALID_ARG)?);
        let file_offset = seg.file_offset & !page_mask;
        let (kind, keyspace_id, keyspace_key) = match backing {
            Some((ks, key)) => (VmaKind::File, ks, key),
            None => (VmaKind::Anonymous, 0, 0),
        };
        crate::linux_compat::memory::install_initial_vma(
            agent_id,
            VmaEntry {
                active: true,
                start,
                len,
                prot: linux_prot_from_segment(seg),
                flags: LINUX_MAP_PRIVATE,
                kind,
                keyspace_id,
                keyspace_key,
                file_offset,
            },
        )?;
    }
    Ok(())
}

pub(crate) fn install_initial_linux_vmas(
    agent_id: AgentId,
    prepared: &PreparedLinuxImage,
) -> Result<(), i64> {
    install_initial_elf_vmas(agent_id, &prepared.main_elf, prepared.main_backing, 0)?;
    if let Some(interp_elf) = prepared.interp_elf {
        install_initial_elf_vmas(
            agent_id,
            &interp_elf,
            prepared.interp_backing,
            USER_CODE_VADDR,
        )?;
    }
    crate::linux_compat::memory::install_initial_vma(
        agent_id,
        VmaEntry {
            active: true,
            start: prepared.user_stack_base,
            len: prepared.user_stack_top.saturating_sub(prepared.user_stack_base),
            prot: LINUX_PROT_READ | LINUX_PROT_WRITE,
            flags: LINUX_MAP_PRIVATE,
            kind: VmaKind::Anonymous,
            keyspace_id: 0,
            keyspace_key: 0,
            file_offset: 0,
        },
    )?;
    Ok(())
}

fn write_agent_user_bytes(agent_cr3: u64, user_vaddr: u64, data: &[u8]) -> Result<(), i64> {
    page_table::copy_to_user(agent_cr3, user_vaddr, data)
        .then_some(())
        .ok_or(E_BAD_IMAGE)
}

fn write_agent_user_u64(agent_cr3: u64, user_vaddr: u64, value: u64) -> Result<(), i64> {
    write_agent_user_bytes(agent_cr3, user_vaddr, &value.to_ne_bytes())
}

fn read_agent_user_u64(agent_cr3: u64, user_vaddr: u64) -> Option<u64> {
    page_table::read_user_u64(agent_cr3, user_vaddr)
}

fn read_agent_user_u32(agent_cr3: u64, user_vaddr: u64) -> Option<u32> {
    page_table::read_user_u32(agent_cr3, user_vaddr)
}

fn loaded_file_vaddr(
    elf_info: &crate::loader::ElfInfo,
    file_offset: u64,
    size: u64,
) -> Option<u64> {
    let end = file_offset.checked_add(size)?;

    for seg in elf_info.segments[..elf_info.segment_count]
        .iter()
        .filter_map(|seg| seg.as_ref())
    {
        let seg_file_start = seg.file_offset;
        let seg_file_end = seg.file_offset.checked_add(seg.file_size)?;
        if file_offset >= seg_file_start && end <= seg_file_end {
            return seg
                .vaddr
                .checked_add(file_offset.checked_sub(seg_file_start)?);
        }
    }

    None
}

fn loaded_file_offset(
    elf_info: &crate::loader::ElfInfo,
    vaddr: u64,
    size: u64,
) -> Option<usize> {
    let end = vaddr.checked_add(size)?;

    for seg in elf_info.segments[..elf_info.segment_count]
        .iter()
        .filter_map(|seg| seg.as_ref())
    {
        let seg_vaddr_start = seg.vaddr;
        let seg_vaddr_end = seg.vaddr.checked_add(seg.file_size)?;
        if vaddr >= seg_vaddr_start && end <= seg_vaddr_end {
            let rel = vaddr.checked_sub(seg_vaddr_start)?;
            let file_off = seg.file_offset.checked_add(rel)?;
            return usize::try_from(file_off).ok();
        }
    }

    None
}

fn find_dynamic_tag_in_image(
    elf_info: &crate::loader::ElfInfo,
    image: &[u8],
    wanted_tag: u64,
) -> Option<u64> {
    if elf_info.dynamic_vaddr == 0 || elf_info.dynamic_size < 16 {
        return None;
    }

    let dyn_off = loaded_file_offset(elf_info, elf_info.dynamic_vaddr, elf_info.dynamic_size)?;
    let dyn_size = usize::try_from(elf_info.dynamic_size).ok()?;
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

fn map_user_stack_region(agent_cr3: u64, user_stack_base: u64) -> Result<u64, i64> {
    debug_assert_eq!(USER_STACK_SIZE % paging::PAGE_SIZE, 0);

    for page_idx in 0..(USER_STACK_SIZE / paging::PAGE_SIZE) {
        let phys = paging::alloc_frame_with_kind(paging::FrameKind::Anon)
            .ok_or(E_QUOTA_EXCEEDED)?;
        unsafe {
            page_table::zero_frame(phys);
        }
        paging::map_page(
            agent_cr3,
            user_stack_base + (page_idx * paging::PAGE_SIZE) as u64,
            phys,
            paging::PTE_PRESENT | paging::PTE_WRITABLE | paging::PTE_USER,
        )
        .map_err(|_| E_QUOTA_EXCEEDED)?;
    }

    Ok(user_stack_base + USER_STACK_SIZE as u64)
}

#[inline]
fn page_align_up_u64(value: u64) -> u64 {
    let page_mask = paging::PAGE_SIZE as u64 - 1;
    (value + page_mask) & !page_mask
}

fn initial_linux_brk(elf_info: &crate::loader::ElfInfo) -> u64 {
    let mut brk = 0u64;

    for seg in elf_info.segments[..elf_info.segment_count]
        .iter()
        .filter_map(|seg| seg.as_ref())
    {
        if seg.flags & 0x2 == 0 {
            continue;
        }
        brk = brk.max(seg.vaddr.saturating_add(seg.mem_size));
    }

    if brk == 0 {
        for seg in elf_info.segments[..elf_info.segment_count]
            .iter()
            .filter_map(|seg| seg.as_ref())
        {
            brk = brk.max(seg.vaddr.saturating_add(seg.mem_size));
        }
    }

    page_align_up_u64(brk)
}

fn map_segment_pages(agent_cr3: u64, seg: &crate::loader::LoadSegment) -> Result<(), i64> {
    let page_mask = paging::PAGE_SIZE as u64 - 1;
    let seg_page_base = seg.vaddr & !page_mask;
    let page_bias = seg.vaddr & page_mask;
    let total_map_len = seg.mem_size.checked_add(page_bias).ok_or(E_INVALID_ARG)?;

    let pages_needed = pages_for_bytes(total_map_len).ok_or(E_INVALID_ARG)?;
    let is_write = seg.flags & 0x2 != 0;
    let mut flags = paging::PTE_PRESENT | paging::PTE_USER;
    if is_write {
        flags |= paging::PTE_WRITABLE;
    }

    for page_idx in 0..pages_needed {
        let page_offset = (page_idx as u64)
            .checked_mul(paging::PAGE_SIZE as u64)
            .ok_or(E_INVALID_ARG)?;
        let vaddr = seg_page_base
            .checked_add(page_offset)
            .ok_or(E_INVALID_ARG)?;
        if let Some(mapping) = page_table::mapped_page_base(agent_cr3, vaddr) {
            if !mapping.is_huge {
                paging::map_page(agent_cr3, vaddr, mapping.phys_base, flags)
                    .map_err(|_| E_QUOTA_EXCEEDED)?;
                page_table::invalidate(vaddr);
                continue;
            }
        }
        let frame_kind = if is_write {
            paging::FrameKind::Anon
        } else {
            paging::FrameKind::File
        };
        let phys = paging::alloc_frame_with_kind(frame_kind).ok_or(E_QUOTA_EXCEEDED)?;
        unsafe {
            page_table::zero_frame(phys);
        }
        paging::map_page(agent_cr3, vaddr, phys, flags).map_err(|_| E_QUOTA_EXCEEDED)?;
        page_table::invalidate(vaddr);
    }

    Ok(())
}

fn copy_segment_file_bytes(
    agent_cr3: u64,
    seg: &crate::loader::LoadSegment,
    image: &[u8],
) -> Result<(), i64> {
    if seg.file_size == 0 {
        return Ok(());
    }

    let copy_start = seg.file_offset as usize;
    let copy_len = seg.file_size as usize;
    let copy_end = copy_start.checked_add(copy_len).ok_or(E_INVALID_ARG)?;
    if copy_end > image.len() {
        return Err(E_BAD_IMAGE);
    }

    write_agent_user_bytes(agent_cr3, seg.vaddr, &image[copy_start..copy_end])
}

fn load_segments_into_address_space(
    agent_cr3: u64,
    image: &[u8],
    elf_info: &crate::loader::ElfInfo,
    min_vaddr: u64,
) -> Result<u64, i64> {
    let mut highest_end = 0u64;

    for seg in elf_info.segments[..elf_info.segment_count]
        .iter()
        .filter_map(|s| s.as_ref())
    {
        if seg.vaddr < min_vaddr {
            continue;
        }

        highest_end = highest_end.max(seg.vaddr.saturating_add(seg.mem_size));
        map_segment_pages(agent_cr3, seg)?;
        copy_segment_file_bytes(agent_cr3, seg, image)?;
    }

    Ok(highest_end)
}

fn min_load_vaddr(elf_info: &crate::loader::ElfInfo) -> u64 {
    elf_info.segments[..elf_info.segment_count]
        .iter()
        .filter_map(|s| s.as_ref())
        .map(|s| s.vaddr)
        .min()
        .unwrap_or(0)
}

fn non_relocatable_needs_low_mapping(elf_info: &crate::loader::ElfInfo) -> bool {
    let page_mask = paging::PAGE_SIZE as u64 - 1;

    for seg in elf_info.segments[..elf_info.segment_count]
        .iter()
        .filter_map(|s| s.as_ref())
    {
        if seg.vaddr >= USER_CODE_VADDR {
            continue;
        }

        let page_bias = seg.vaddr & page_mask;
        let total_map_len = match seg.mem_size.checked_add(page_bias) {
            Some(len) => len,
            None => return true,
        };
        let page_footprint = page_align_up_u64(total_map_len);
        let header_stub = seg.flags == 0x4 && page_footprint <= paging::PAGE_SIZE as u64;

        if !header_stub {
            return true;
        }
    }

    false
}

fn validate_non_relocatable_layout(elf_info: &crate::loader::ElfInfo, label: &[u8]) -> Result<(), i64> {
    if !elf_info.is_relocatable && non_relocatable_needs_low_mapping(elf_info) {
        serial_println!(
            "[AGENT_LOADER] FATAL: non-relocatable ELF {:?} needs low vaddr {:#x}, but ATOS currently reserves 0..{:#x} for the identity map",
            core::str::from_utf8(label).unwrap_or("?"),
            min_load_vaddr(elf_info),
            USER_CODE_VADDR
        );
        return Err(E_BAD_IMAGE);
    }
    Ok(())
}

/// Spawn a new agent from an in-memory binary image.
///
/// # Arguments
/// * `caller_id` - the parent agent spawning this agent
/// * `image` - the raw binary data (ELF64 or WASM)
/// * `kind` - runtime kind (Native or Wasm)
/// * `energy` - energy budget (deducted from caller)
/// * `mem_quota` - memory quota in pages
///
/// # Returns
/// The new agent's ID on success, or a negative error code.
pub fn spawn_from_image(
    caller_id: AgentId,
    image: &[u8],
    kind: RuntimeKind,
    energy: u64,
    mem_quota: u32,
) -> Result<AgentId, i64> {
    spawn_from_image_with_class(
        caller_id,
        image,
        kind,
        energy,
        mem_quota,
        wasm::types::DEFAULT_RUNTIME_CLASS,
    )
}

/// Spawn a new agent with a specific RuntimeClass.
pub fn spawn_from_image_with_class(
    caller_id: AgentId,
    image: &[u8],
    kind: RuntimeKind,
    energy: u64,
    mem_quota: u32,
    runtime_class: wasm::types::RuntimeClass,
) -> Result<AgentId, i64> {
    // ── Input validation ────────────────────────────────────────────────
    if image.is_empty() {
        return Err(E_INVALID_ARG);
    }
    if image.len() > MAX_IMAGE_SIZE {
        return Err(E_PAYLOAD_TOO_LARGE);
    }
    if energy == 0 {
        return Err(E_INVALID_ARG);
    }
    if mem_quota == 0 {
        return Err(E_INVALID_ARG);
    }

    match kind {
        RuntimeKind::Native => spawn_native_elf(caller_id, image, energy, mem_quota),
        RuntimeKind::Wasm => {
            spawn_wasm_with_class(caller_id, image, energy, mem_quota, runtime_class)
        }
        RuntimeKind::LinuxCompat => {
            // Linux compat agents use the full Linux stack builder.
            spawn_linux_agent(caller_id, image, energy, mem_quota, &[], &[])
        }
    }
}

// ─── Native ELF64 loading path ──────────────────────────────────────────────

fn spawn_native_elf(
    caller_id: AgentId,
    image: &[u8],
    energy: u64,
    mem_quota: u32,
) -> Result<AgentId, i64> {
    // 1. Parse ELF
    let mut elf_info = crate::loader::parse_elf64(image).map_err(|_| E_BAD_IMAGE)?;
    validate_non_relocatable_layout(&elf_info, b"<native-elf>")?;

    // 1b. Handle dynamically-linked binaries. Only ET_DYN images receive a
    // deterministic load bias; ET_EXEC binaries with PT_INTERP must stay at
    // their link-time virtual addresses.
    if elf_info.is_dynamic {
        // Extract interpreter path for diagnostics
        if elf_info.interp_len > 0 && elf_info.interp_offset + elf_info.interp_len <= image.len() {
            let interp_bytes =
                &image[elf_info.interp_offset..elf_info.interp_offset + elf_info.interp_len];
            // Trim trailing NUL
            let interp_end = interp_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(interp_bytes.len());
            if interp_end > 0 {
                // Log the interpreter path (up to 64 bytes to avoid overflow)
                let display_len = interp_end.min(64);
                serial_println!(
                    "[AGENT_LOADER] Dynamic ELF requests interpreter ({} bytes): {:?}",
                    interp_end,
                    core::str::from_utf8(&interp_bytes[..display_len]).unwrap_or("<non-utf8>")
                );
            }
        }

        if elf_info.is_relocatable {
            // For ET_DYN, segment vaddrs are relative offsets. Apply a load bias
            // so the binary is placed at a deterministic user-space address.
            if elf_info.load_bias == 0 {
                // Use USER_CODE_VADDR as the base for PIE binaries whose
                // segments start near vaddr 0.
                let min_vaddr = min_load_vaddr(&elf_info);
                if min_vaddr < USER_CODE_VADDR {
                    elf_info.load_bias =
                        USER_CODE_VADDR - (min_vaddr & !(paging::PAGE_SIZE as u64 - 1));
                }
            }

            // Apply load bias to entry point and all segment vaddrs
            elf_info.entry_point = elf_info.entry_point.wrapping_add(elf_info.load_bias);
            for i in 0..elf_info.segment_count {
                if let Some(ref mut seg) = elf_info.segments[i] {
                    seg.vaddr = seg.vaddr.wrapping_add(elf_info.load_bias);
                }
            }

            serial_println!(
                "[AGENT_LOADER] Dynamic ELF: load_bias={:#x}, entry={:#x}",
                elf_info.load_bias,
                elf_info.entry_point
            );
        }
    }

    // 2. Create isolated address space
    let agent_cr3 = paging::create_address_space().ok_or(E_QUOTA_EXCEEDED)?;

    // 3. Load each segment into the new address space.
    //    Skip segments below USER_CODE_VADDR (e.g., 0x400000 ELF header
    //    metadata segment) since they conflict with identity-mapped pages.
    let _ = load_segments_into_address_space(agent_cr3, image, &elf_info, USER_CODE_VADDR as u64)?;

    // 3b. If dynamic: load the interpreter (ld-linux) and adjust entry point.
    //     The interpreter is loaded at INTERP_BASE_VADDR, well above the main
    //     binary, so address spaces don't collide.
    const INTERP_BASE_VADDR: u64 = 0x7F00_0000;
    let main_entry = elf_info.entry_point;
    let main_phdr_vaddr = (elf_info.phdr_entry_size as u64)
        .checked_mul(elf_info.phdr_count as u64)
        .and_then(|size| loaded_file_vaddr(&elf_info, elf_info.phdr_offset, size));
    let mut interp_base: u64 = 0;
    let mut interp_highest_end: u64 = 0;

    let final_entry = if elf_info.is_dynamic && elf_info.interp_len > 0 {
        // Extract interpreter path
        let interp_bytes =
            &image[elf_info.interp_offset..elf_info.interp_offset + elf_info.interp_len];
        let interp_end = interp_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(interp_bytes.len());
        let interp_path = &interp_bytes[..interp_end];

        // Resolve interpreter path via VFS → base image keyspace
        let (interp_ks, interp_key) = crate::linux_compat::vfs::resolve_path(0, interp_path);

        let mut interp_owned = None;
        let interp_image: &[u8] = if interp_ks == crate::state::BASE_IMAGE_KEYSPACE {
            match crate::base_image::find_by_key(interp_key) {
                Some(entry) => entry.data,
                None => &[],
            }
        } else {
            let interp_size = crate::state::query_file_size(interp_ks, interp_key);
            if interp_size == 0 {
                &[]
            } else {
                let mut buf = alloc::vec![0u8; interp_size];
                let loaded = crate::state::load_multi_segment(interp_ks, interp_key, &mut buf);
                buf.truncate(loaded);
                interp_owned = Some(buf);
                interp_owned.as_ref().unwrap().as_slice()
            }
        };

        if interp_image.is_empty() {
            // Interpreter not found in base image — fall back to main entry
            serial_println!(
                "[AGENT_LOADER] Interpreter not in base image, using main entry {:#x}",
                main_entry
            );
            main_entry
        } else {
            serial_println!(
                "[AGENT_LOADER] Loaded interpreter ({} bytes) from keyspace",
                interp_image.len()
            );

            // Parse interpreter ELF
            match crate::loader::parse_elf64(interp_image) {
                Ok(mut interp_elf) => {
                    // Apply load bias: place interpreter at INTERP_BASE_VADDR
                    let interp_min_vaddr = interp_elf.segments[..interp_elf.segment_count]
                        .iter()
                        .filter_map(|s| s.as_ref())
                        .map(|s| s.vaddr)
                        .min()
                        .unwrap_or(0);
                    let bias =
                        INTERP_BASE_VADDR - (interp_min_vaddr & !(paging::PAGE_SIZE as u64 - 1));
                    interp_base = bias;

                    interp_elf.entry_point = interp_elf.entry_point.wrapping_add(bias);
                    for i in 0..interp_elf.segment_count {
                        if let Some(ref mut seg) = interp_elf.segments[i] {
                            seg.vaddr = seg.vaddr.wrapping_add(bias);
                        }
                    }

                    interp_highest_end = load_segments_into_address_space(
                        agent_cr3,
                        interp_image,
                        &interp_elf,
                        USER_CODE_VADDR as u64,
                    )?;

                    serial_println!(
                        "[AGENT_LOADER] Interpreter loaded at base={:#x}, entry={:#x}",
                        interp_base,
                        interp_elf.entry_point
                    );

                    // Entry point is the interpreter's entry, not the main binary's
                    interp_elf.entry_point
                }
                Err(e) => {
                    serial_println!("[AGENT_LOADER] Interpreter ELF parse failed: {:?}", e);
                    main_entry
                }
            }
        }
    } else {
        main_entry
    };

    // 4. Allocate a 128 KiB user stack region ABOVE the highest loaded
    //    segment to avoid overwriting code/data.
    let mut highest_seg_end: u64 = USER_STACK_VADDR; // fallback
    for i in 0..elf_info.segment_count {
        if let Some(s) = &elf_info.segments[i] {
            if s.vaddr >= USER_CODE_VADDR as u64 {
                let end = s.vaddr + s.mem_size;
                if end > highest_seg_end {
                    highest_seg_end = end;
                }
            }
        }
    }
    // Also account for interpreter segments
    if interp_highest_end > highest_seg_end {
        highest_seg_end = interp_highest_end;
    }
    // Align to page boundary and add a guard gap
    let user_stack_base =
        (highest_seg_end + paging::PAGE_SIZE as u64) & !(paging::PAGE_SIZE as u64 - 1);
    let user_stack_top = map_user_stack_region(agent_cr3, user_stack_base)?;

    // 4b. Build auxiliary vector (auxv) on the user stack for ld-linux.
    //     The stack layout expected by the dynamic linker:
    //       [stack top]
    //       auxv: AT_NULL terminator
    //       auxv: AT_ENTRY = main binary entry point
    //       auxv: AT_BASE  = interpreter load base
    //       auxv: AT_PHDR  = main binary program header address
    //       auxv: AT_PHENT = size of each program header entry
    //       auxv: AT_PHNUM = number of program header entries
    //       auxv: AT_PAGESZ = page size
    //       auxv: AT_RANDOM = pointer to 16 random bytes
    //       envp: NULL
    //       argv: NULL
    //       argc: 0
    //     Each auxv entry is { type: u64, value: u64 } = 16 bytes.
    let auxv_base = user_stack_top - 256;
    if elf_info.is_dynamic && interp_base > 0 {
        // Write auxv below the stack top
        let phdr_addr = main_phdr_vaddr.ok_or(E_BAD_IMAGE)?;

        let auxv: [(u64, u64); 8] = [
            (9, main_entry),                      // AT_ENTRY: main program entry
            (7, interp_base),                     // AT_BASE: interpreter base address
            (3, phdr_addr),                       // AT_PHDR: program header table address
            (4, elf_info.phdr_entry_size as u64), // AT_PHENT: size of phdr entry
            (5, elf_info.phdr_count as u64),      // AT_PHNUM: number of phdr entries
            (6, paging::PAGE_SIZE as u64),        // AT_PAGESZ
            (25, auxv_base + 128),                // AT_RANDOM: pointer to 16 "random" bytes
            (0, 0),                               // AT_NULL: terminator
        ];

        write_agent_user_u64(agent_cr3, auxv_base, 0)?;
        write_agent_user_u64(agent_cr3, auxv_base + 8, 0)?;
        write_agent_user_u64(agent_cr3, auxv_base + 16, 0)?;

        let auxv_ptr = auxv_base + 24;
        for (i, (atype, aval)) in auxv.iter().enumerate() {
            let entry_base = auxv_ptr + (i as u64) * 16;
            write_agent_user_u64(agent_cr3, entry_base, *atype)?;
            write_agent_user_u64(agent_cr3, entry_base + 8, *aval)?;
        }

        let mut random = [0u8; 16];
        for (i, byte) in random.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_add(0x42);
        }
        write_agent_user_bytes(agent_cr3, auxv_base + 128, &random)?;
    }

    // 5. Allocate kernel stack for syscall handling
    let k_stack_top = sched::allocate_agent_stack();
    if k_stack_top == 0 {
        return Err(E_QUOTA_EXCEEDED);
    }

    // 6. Create the agent with the FINAL entry point
    //    (interpreter entry for dynamic, main entry for static)
    let entry = final_entry;
    let agent_id = create_agent(Some(caller_id), entry, user_stack_top, energy, mem_quota)?;

    // 7. Configure user-mode context
    //    For dynamic binaries, RSP points to the auxv area so ld-linux can find it.
    let initial_rsp = if elf_info.is_dynamic && interp_base > 0 {
        auxv_base // RSP points to argc at auxv_base
    } else {
        user_stack_top
    };
    if let Some(agent) = get_agent_mut(agent_id) {
        agent.mode = AgentMode::User;
        agent.kernel_stack_top = k_stack_top;
        agent.stack_bottom = sched::stack_bottom_from_top(k_stack_top);
        agent.context = new_user_context(entry, initial_rsp, k_stack_top);
        agent.context.cr3 = agent_cr3;
    }

    // 8. Create mailbox, keyspace, enqueue
    finish_agent_setup(agent_id, caller_id)?;

    serial_println!(
        "[AGENT_LOADER] Spawned native ELF agent {} (entry={:#x}, parent={})",
        agent_id,
        entry,
        caller_id
    );

    Ok(agent_id)
}

// ─── Linux-compat ELF loading path ─────────────────────────────────────────

/// Spawn a Linux-compat agent with a real Linux initial stack.
///
/// Builds the standard Linux user stack layout:
///   [low address]
///   argc                   ← RSP points here
///   argv[0] ptr
///   argv[1] ptr
///   ...
///   NULL                   (argv terminator)
///   envp[0] ptr
///   ...
///   NULL                   (envp terminator)
///   auxv[0].type, auxv[0].value
///   ...
///   AT_NULL, 0             (auxv terminator)
///   padding (16-byte align)
///   string data: argv strings, envp strings, AT_RANDOM bytes
///   [high address = stack top]
///
/// `exe_path`: the executable path (e.g., b"/app/hello"). Used for AT_EXECFN
///   and stored in LinuxAgentState. If empty, defaults to b"/app/unknown".
/// `argv`: argument strings. If empty, a single argv[0] = exe_path is used.
pub fn spawn_linux_agent(
    caller_id: AgentId,
    image: &[u8],
    energy: u64,
    mem_quota: u32,
    exe_path: &[u8],
    argv: &[&[u8]],
) -> Result<AgentId, i64> {
    spawn_linux_agent_with_env(caller_id, image, energy, mem_quota, exe_path, argv, &[])
}

pub fn prepare_linux_agent_image(
    image: &[u8],
    exe_path: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
) -> Result<PreparedLinuxImage, i64> {
    // ── Input validation ────────────────────────────────────────────────
    if image.is_empty() {
        return Err(E_INVALID_ARG);
    }
    if image.len() > MAX_IMAGE_SIZE {
        return Err(E_PAYLOAD_TOO_LARGE);
    }

    // Default exe_path
    let exe = if exe_path.is_empty() {
        b"/app/unknown" as &[u8]
    } else {
        exe_path
    };
    let main_backing = resolve_linux_backing(exe);

    // 1. Parse ELF
    let mut elf_info = crate::loader::parse_elf64(image).map_err(|_| E_BAD_IMAGE)?;
    // 1b. Only ET_DYN main images receive a deterministic load bias.
    // ET_EXEC binaries with PT_INTERP must stay at their link-time vaddrs.
    if elf_info.is_relocatable {
        if elf_info.load_bias == 0 {
            let min_vaddr = min_load_vaddr(&elf_info);
            if min_vaddr < USER_CODE_VADDR {
                elf_info.load_bias =
                    USER_CODE_VADDR - (min_vaddr & !(paging::PAGE_SIZE as u64 - 1));
            }
        }
        elf_info.entry_point = elf_info.entry_point.wrapping_add(elf_info.load_bias);
        for i in 0..elf_info.segment_count {
            if let Some(ref mut seg) = elf_info.segments[i] {
                seg.vaddr = seg.vaddr.wrapping_add(elf_info.load_bias);
            }
        }
        if elf_info.dynamic_vaddr != 0 {
            elf_info.dynamic_vaddr = elf_info.dynamic_vaddr.wrapping_add(elf_info.load_bias);
        }
        serial_println!(
            "[AGENT_LOADER] Linux dynamic ELF: load_bias={:#x}, entry={:#x}",
            elf_info.load_bias,
            elf_info.entry_point
        );
    }

    // 2. Create isolated address space
    let agent_cr3 = paging::create_linux_address_space().ok_or(E_QUOTA_EXCEEDED)?;
    let prepared = (|| {
        // 3. Load each segment. Linux-compat binaries may legally occupy low
        // user virtual addresses (for example ET_EXEC at 0x400000).
        let _ = load_segments_into_address_space(agent_cr3, image, &elf_info, 0)?;
        let initial_brk = initial_linux_brk(&elf_info);

        if exe_path == b"/usr/bin/python3" && elf_info.load_bias == USER_CODE_VADDR {
            for off in [
                0x1b060_u64,
                0x1b078,
                0x1b090,
                0x4fc20,
                0x69108,
                0x69120,
                0x69138,
                0x69150,
                0x515d0,
                0x515e8,
                0x51600,
            ] {
                let a = read_agent_user_u64(agent_cr3, USER_CODE_VADDR + off).unwrap_or(u64::MAX);
                let b =
                    read_agent_user_u64(agent_cr3, USER_CODE_VADDR + off + 8).unwrap_or(u64::MAX);
                let c = read_agent_user_u64(agent_cr3, USER_CODE_VADDR + off + 16)
                    .unwrap_or(u64::MAX);
                serial_println!(
                    "[PYDBG] main-rela off={:#x} val0={:#x} val1={:#x} val2={:#x}",
                    off,
                    a,
                    b,
                    c
                );
            }
        }

        // 3b. Load interpreter if dynamic
        const INTERP_BASE_VADDR: u64 = 0x7F00_0000;
        let main_entry = elf_info.entry_point;
        let main_phdr_vaddr = (elf_info.phdr_entry_size as u64)
            .checked_mul(elf_info.phdr_count as u64)
            .and_then(|size| loaded_file_vaddr(&elf_info, elf_info.phdr_offset, size));
        let mut interp_base: u64 = 0;
        let mut interp_highest_end: u64 = 0;
        let mut interp_loaded_elf: Option<crate::loader::ElfInfo> = None;
        let mut interp_backing: Option<(u16, u64)> = None;

        let final_entry = if elf_info.is_dynamic && elf_info.interp_len > 0 {
            let interp_bytes =
                &image[elf_info.interp_offset..elf_info.interp_offset + elf_info.interp_len];
            let interp_end = interp_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(interp_bytes.len());
            let interp_path = &interp_bytes[..interp_end];

            serial_println!(
                "[AGENT_LOADER] PT_INTERP: {:?}",
                core::str::from_utf8(interp_path).unwrap_or("<non-utf8>")
            );

            let (interp_ks, interp_key) = crate::linux_compat::vfs::resolve_path(0, interp_path);
            interp_backing = resolve_linux_backing(interp_path);
            let mut interp_owned = None;
            let interp_image: &[u8] = if interp_ks == crate::state::BASE_IMAGE_KEYSPACE {
                match crate::base_image::find_by_key(interp_key) {
                    Some(entry) => entry.data,
                    None => &[],
                }
            } else {
                let interp_size = crate::state::query_file_size(interp_ks, interp_key);
                if interp_size == 0 {
                    &[]
                } else {
                    let mut buf = alloc::vec![0u8; interp_size];
                    let loaded = crate::state::load_multi_segment(interp_ks, interp_key, &mut buf);
                    buf.truncate(loaded);
                    interp_owned = Some(buf);
                    interp_owned.as_ref().unwrap().as_slice()
                }
            };

            if interp_image.is_empty() {
                serial_println!(
                    "[AGENT_LOADER] FATAL: interpreter {:?} not found in base image — cannot start dynamic ELF",
                    core::str::from_utf8(interp_path).unwrap_or("?")
                );
                return Err(E_NOT_FOUND);
            }

            serial_println!(
                "[AGENT_LOADER] Loaded interpreter ({} bytes), first 16: [{:#04x},{:#04x},{:#04x},{:#04x},{:#04x},{:#04x},{:#04x},{:#04x},{:#04x},{:#04x},{:#04x},{:#04x},{:#04x},{:#04x},{:#04x},{:#04x}]",
                interp_image.len(),
                interp_image[0], interp_image[1], interp_image[2], interp_image[3],
                interp_image[4], interp_image[5], interp_image[6], interp_image[7],
                interp_image[8], interp_image[9], interp_image[10], interp_image[11],
                interp_image[12], interp_image[13], interp_image[14], interp_image[15]
            );

            let (_iks, ikey) = crate::linux_compat::vfs::resolve_path(0, interp_path);
            if let Some((raw, raw_len)) = crate::state::state_get(interp_ks, ikey) {
                serial_println!(
                    "[AGENT_LOADER] Direct state_get: len={}, first 6: [{:#04x},{:#04x},{:#04x},{:#04x},{:#04x},{:#04x}]",
                    raw_len, raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]
                );
            }

            let mut interp_elf = crate::loader::parse_elf64(interp_image).map_err(|e| {
                serial_println!(
                    "[AGENT_LOADER] FATAL: interpreter ELF parse failed: {:?}",
                    e
                );
                E_BAD_IMAGE
            })?;

            let interp_min_vaddr = interp_elf.segments[..interp_elf.segment_count]
                .iter()
                .filter_map(|s| s.as_ref())
                .map(|s| s.vaddr)
                .min()
                .unwrap_or(0);
            let bias = INTERP_BASE_VADDR - (interp_min_vaddr & !(paging::PAGE_SIZE as u64 - 1));
            interp_base = bias;

            interp_elf.entry_point = interp_elf.entry_point.wrapping_add(bias);
            if interp_elf.dynamic_vaddr != 0 {
                interp_elf.dynamic_vaddr = interp_elf.dynamic_vaddr.wrapping_add(bias);
            }
            for i in 0..interp_elf.segment_count {
                if let Some(ref mut seg) = interp_elf.segments[i] {
                    seg.vaddr = seg.vaddr.wrapping_add(bias);
                }
            }

            interp_highest_end = load_segments_into_address_space(
                agent_cr3,
                interp_image,
                &interp_elf,
                USER_CODE_VADDR as u64,
            )?;
            interp_loaded_elf = Some(interp_elf);

            serial_println!(
                "[AGENT_LOADER] Interpreter at base={:#x}, entry={:#x}",
                interp_base,
                interp_elf.entry_point
            );
            if exe == b"/usr/bin/python3"
                && interp_elf.dynamic_vaddr != 0
                && interp_elf.dynamic_size >= 16
            {
                serial_println!(
                    "[AGENT_LOADER] interp dynamic={:#x} dynsz={:#x}",
                    interp_elf.dynamic_vaddr,
                    interp_elf.dynamic_size
                );
                let dump_count = interp_elf.dynamic_size / 16;
                for i in 0..dump_count.min(32) {
                    let entry_addr = interp_elf.dynamic_vaddr + i * 16;
                    let tag = read_agent_user_u64(agent_cr3, entry_addr).unwrap_or(u64::MAX);
                    let val =
                        read_agent_user_u64(agent_cr3, entry_addr + 8).unwrap_or(u64::MAX);
                    serial_println!(
                        "[AGENT_LOADER] interp dynamic[{}]: tag={:#x} val={:#x}",
                        i,
                        tag,
                        val
                    );
                    if tag == 0 {
                        break;
                    }
                }

                let rela_vaddr =
                    find_dynamic_tag_in_image(&interp_elf, interp_image, 7).unwrap_or(0);
                let relaent =
                    find_dynamic_tag_in_image(&interp_elf, interp_image, 9).unwrap_or(0);
                let relacount = find_dynamic_tag_in_image(&interp_elf, interp_image, 0x6fff_fff9)
                    .unwrap_or(0);
                if rela_vaddr != 0 && relaent >= 24 {
                    serial_println!(
                        "[AGENT_LOADER] interp rela={:#x} relaent={} relacount={}",
                        interp_base + rela_vaddr,
                        relaent,
                        relacount
                    );
                    for idx in [0u64, 1, 2, relacount.saturating_sub(1), relacount] {
                        let entry = interp_base + rela_vaddr + idx * relaent;
                        let a = read_agent_user_u64(agent_cr3, entry).unwrap_or(u64::MAX);
                        let b =
                            read_agent_user_u64(agent_cr3, entry + 8).unwrap_or(u64::MAX);
                        let c =
                            read_agent_user_u64(agent_cr3, entry + 16).unwrap_or(u64::MAX);
                        serial_println!(
                            "[AGENT_LOADER] interp rela[{}]: off={:#x} val0={:#x} val1={:#x} val2={:#x}",
                            idx,
                            entry,
                            a,
                            b,
                            c
                        );
                    }
                }
            }
            interp_elf.entry_point
        } else if elf_info.is_dynamic && elf_info.interp_len == 0 {
            main_entry
        } else {
            main_entry
        };

        if exe == b"/usr/bin/python3" && elf_info.dynamic_vaddr != 0 && elf_info.dynamic_size >= 16
        {
            serial_println!(
                "[AGENT_LOADER] python auxv main_entry={:#x} at_base={:#x} at_phdr={:#x} phnum={} phent={} dynamic={:#x} dynsz={:#x}",
                main_entry,
                interp_base,
                main_phdr_vaddr.unwrap_or(0),
                elf_info.phdr_count,
                elf_info.phdr_entry_size,
                elf_info.dynamic_vaddr,
                elf_info.dynamic_size
            );
            let dump_count = elf_info.dynamic_size / 16;
            for i in 0..dump_count {
                let entry_addr = elf_info.dynamic_vaddr + i * 16;
                let tag = read_agent_user_u64(agent_cr3, entry_addr).unwrap_or(u64::MAX);
                let val = read_agent_user_u64(agent_cr3, entry_addr + 8).unwrap_or(u64::MAX);
                serial_println!(
                    "[AGENT_LOADER] python dynamic[{}]: tag={:#x} val={:#x}",
                    i,
                    tag,
                    val
                );
                if tag == 0 {
                    break;
                }
            }
            if let Some(phdr_addr) = main_phdr_vaddr {
                for i in 0..elf_info.phdr_count as u64 {
                    let entry = phdr_addr + i * elf_info.phdr_entry_size as u64;
                    let p_type = read_agent_user_u32(agent_cr3, entry).unwrap_or(u32::MAX);
                    let p_flags = read_agent_user_u32(agent_cr3, entry + 4).unwrap_or(u32::MAX);
                    let p_offset = read_agent_user_u64(agent_cr3, entry + 8).unwrap_or(u64::MAX);
                    let p_vaddr = read_agent_user_u64(agent_cr3, entry + 16).unwrap_or(u64::MAX);
                    let p_filesz =
                        read_agent_user_u64(agent_cr3, entry + 32).unwrap_or(u64::MAX);
                    let p_memsz =
                        read_agent_user_u64(agent_cr3, entry + 40).unwrap_or(u64::MAX);
                    serial_println!(
                        "[AGENT_LOADER] python phdr[{}]: type={:#x} flags={:#x} off={:#x} vaddr={:#x} filesz={:#x} memsz={:#x}",
                        i,
                        p_type,
                        p_flags,
                        p_offset,
                        p_vaddr,
                        p_filesz,
                        p_memsz
                    );
                }
            }
        }

        // 4. Allocate user stack above the highest loaded segment
        let mut highest_seg_end: u64 = USER_STACK_VADDR;
        for i in 0..elf_info.segment_count {
            if let Some(s) = &elf_info.segments[i] {
                highest_seg_end = highest_seg_end.max(s.vaddr + s.mem_size);
            }
        }
        if interp_highest_end > highest_seg_end {
            highest_seg_end = interp_highest_end;
        }
        let user_stack_base =
            (highest_seg_end + paging::PAGE_SIZE as u64) & !(paging::PAGE_SIZE as u64 - 1);
        let user_stack_top = map_user_stack_region(agent_cr3, user_stack_base)?;

        // 5. Build the Linux initial stack layout
        let default_env_vars: [&[u8]; 3] = [b"LANG=C", b"HOME=/", b"PATH=/usr/bin:/bin"];
        let default_argv: [&[u8]; 1] = [exe];
        let effective_argv: &[&[u8]] = if argv.is_empty() { &default_argv } else { argv };
        let effective_envp: &[&[u8]] = if envp.is_empty() { &default_env_vars } else { envp };

        let phdr_addr = main_phdr_vaddr.unwrap_or(0);
        let mut auxv_entries = [(0u64, 0u64); 24];
        let mut auxv_count = 0usize;
        let push_auxv = |entries: &mut [(u64, u64); 24], count: &mut usize, atype: u64, aval: u64| {
            entries[*count] = (atype, aval);
            *count += 1;
        };
        if phdr_addr != 0 {
            push_auxv(&mut auxv_entries, &mut auxv_count, 3, phdr_addr);
            push_auxv(
                &mut auxv_entries,
                &mut auxv_count,
                4,
                elf_info.phdr_entry_size as u64,
            );
            push_auxv(
                &mut auxv_entries,
                &mut auxv_count,
                5,
                elf_info.phdr_count as u64,
            );
        }
        push_auxv(&mut auxv_entries, &mut auxv_count, 6, paging::PAGE_SIZE as u64);
        push_auxv(&mut auxv_entries, &mut auxv_count, 15, 0); // AT_PLATFORM
        push_auxv(&mut auxv_entries, &mut auxv_count, 16, 0); // AT_HWCAP
        push_auxv(&mut auxv_entries, &mut auxv_count, 17, 100); // AT_CLKTCK
        if interp_base > 0 {
            push_auxv(&mut auxv_entries, &mut auxv_count, 7, interp_base);
        }
        push_auxv(&mut auxv_entries, &mut auxv_count, 9, main_entry);
        push_auxv(&mut auxv_entries, &mut auxv_count, 11, 1000);
        push_auxv(&mut auxv_entries, &mut auxv_count, 12, 1000);
        push_auxv(&mut auxv_entries, &mut auxv_count, 13, 1000);
        push_auxv(&mut auxv_entries, &mut auxv_count, 14, 1000);
        push_auxv(&mut auxv_entries, &mut auxv_count, 23, 0);
        push_auxv(&mut auxv_entries, &mut auxv_count, 25, 0);
        push_auxv(&mut auxv_entries, &mut auxv_count, 26, 0); // AT_HWCAP2
        push_auxv(&mut auxv_entries, &mut auxv_count, 31, 0);
        push_auxv(&mut auxv_entries, &mut auxv_count, 0, 0);

        let mut string_area_size: usize = 16;
        string_area_size += b"x86_64".len() + 1;
        string_area_size += exe.len() + 1;
        for arg in effective_argv {
            string_area_size += arg.len() + 1;
        }
        for env in effective_envp {
            string_area_size += env.len() + 1;
        }

        let argc = effective_argv.len();
        let envc = effective_envp.len();
        let pointer_area_size: usize =
            8 + (argc + 1) * 8 + (envc + 1) * 8 + auxv_count * 16;

        let string_base = user_stack_top - string_area_size as u64;
        let ptr_base = string_base - pointer_area_size as u64;
        let initial_rsp = ptr_base & !0xF;

        let mut sptr = string_base;

        let at_random_addr = sptr;
        let mut random_bytes = [0u8; 16];
        for (i, b) in random_bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(0x37).wrapping_add(0x42);
        }
        write_agent_user_bytes(agent_cr3, sptr, &random_bytes)?;
        sptr += 16;

        let platform_addr = sptr;
        write_agent_user_bytes(agent_cr3, sptr, b"x86_64")?;
        write_agent_user_bytes(agent_cr3, sptr + 6, &[0])?;
        sptr += 7;

        let execfn_addr = sptr;
        write_agent_user_bytes(agent_cr3, sptr, exe)?;
        write_agent_user_bytes(agent_cr3, sptr + exe.len() as u64, &[0])?;
        sptr += exe.len() as u64 + 1;

        let mut argv_addrs = [0u64; 64];
        for (i, arg) in effective_argv.iter().enumerate() {
            argv_addrs[i] = sptr;
            write_agent_user_bytes(agent_cr3, sptr, arg)?;
            write_agent_user_bytes(agent_cr3, sptr + arg.len() as u64, &[0])?;
            sptr += arg.len() as u64 + 1;
        }

        let mut envp_addrs = [0u64; 16];
        for (i, env) in effective_envp.iter().enumerate() {
            envp_addrs[i] = sptr;
            write_agent_user_bytes(agent_cr3, sptr, env)?;
            write_agent_user_bytes(agent_cr3, sptr + env.len() as u64, &[0])?;
            sptr += env.len() as u64 + 1;
        }

        let mut wptr = initial_rsp;
        write_agent_user_u64(agent_cr3, wptr, argc as u64)?;
        wptr += 8;

        for i in 0..argc {
            write_agent_user_u64(agent_cr3, wptr, argv_addrs[i])?;
            wptr += 8;
        }
        write_agent_user_u64(agent_cr3, wptr, 0)?;
        wptr += 8;

        for i in 0..envc {
            write_agent_user_u64(agent_cr3, wptr, envp_addrs[i])?;
            wptr += 8;
        }
        write_agent_user_u64(agent_cr3, wptr, 0)?;
        wptr += 8;

        let write_auxv =
            |wptr: &mut u64, cr3: u64, atype: u64, aval: u64| -> Result<(), i64> {
                write_agent_user_u64(cr3, *wptr, atype)?;
                write_agent_user_u64(cr3, *wptr + 8, aval)?;
                *wptr += 16;
                Ok(())
            };

        for (atype, aval) in auxv_entries[..auxv_count].iter_mut() {
            match *atype {
                15 => *aval = platform_addr,
                25 => *aval = at_random_addr,
                31 => *aval = execfn_addr,
                _ => {}
            }
        }

        for (atype, aval) in auxv_entries[..auxv_count].iter() {
            write_auxv(&mut wptr, agent_cr3, *atype, *aval)?;
        }

        Ok(PreparedLinuxImage {
            cr3: agent_cr3,
            entry: final_entry,
            initial_rsp,
            initial_brk,
            argc,
            user_stack_base,
            user_stack_top,
            main_elf: elf_info,
            interp_elf: interp_loaded_elf,
            main_backing,
            interp_backing,
        })
    })();

    if prepared.is_err() {
        let _ = paging::release_address_space(agent_cr3);
    }
    prepared
}

/// Spawn a Linux-compatible agent with an explicit environment block.
///
/// If `envp` is empty, a minimal deterministic default environment is used.
pub fn spawn_linux_agent_with_env(
    caller_id: AgentId,
    image: &[u8],
    energy: u64,
    mem_quota: u32,
    exe_path: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
) -> Result<AgentId, i64> {
    let exe = if exe_path.is_empty() {
        b"/app/unknown" as &[u8]
    } else {
        exe_path
    };
    let prepared = prepare_linux_agent_image(image, exe_path, argv, envp)?;

    // 6. Allocate kernel stack
    let k_stack_top = sched::allocate_agent_stack();
    if k_stack_top == 0 {
        let _ = paging::release_address_space(prepared.cr3);
        return Err(E_QUOTA_EXCEEDED);
    }

    // 7. Create the agent
    let entry = prepared.entry;
    let agent_id = match create_agent(Some(caller_id), entry, k_stack_top, energy, mem_quota) {
        Ok(id) => id,
        Err(e) => {
            let _ = paging::release_address_space(prepared.cr3);
            return Err(e);
        }
    };

    // 8. Configure user-mode context — RSP always points to argc
    if let Some(agent) = get_agent_mut(agent_id) {
        agent.mode = AgentMode::User;
        agent.kernel_stack_top = k_stack_top;
        agent.stack_bottom = sched::stack_bottom_from_top(k_stack_top);
        agent.context = new_user_context(entry, prepared.initial_rsp, k_stack_top);
        agent.context.cr3 = prepared.cr3;
    }

    // 9. Initialize Linux-compat state and store exe_path
    finish_agent_setup(agent_id, caller_id)?;
    crate::linux_compat::state::init_state(agent_id);
    crate::linux_compat::state::set_exe_path(agent_id, exe);
    if let Some(st) = crate::linux_compat::state::get_state_mut(agent_id) {
        st.brk_current = prepared.initial_brk;
    }
    install_initial_linux_vmas(agent_id, &prepared)?;

    serial_println!(
        "[AGENT_LOADER] Spawned Linux agent {} (entry={:#x}, argc={}, brk={:#x}, exe={:?})",
        agent_id,
        entry,
        prepared.argc,
        prepared.initial_brk,
        core::str::from_utf8(exe).unwrap_or("?")
    );

    Ok(agent_id)
}

// ─── WASM loading path ──────────────────────────────────────────────────────

fn spawn_wasm_with_class(
    caller_id: AgentId,
    image: &[u8],
    energy: u64,
    mem_quota: u32,
    runtime_class: wasm::types::RuntimeClass,
) -> Result<AgentId, i64> {
    // 1. Decode and validate the WASM module
    let module = wasm::decoder::decode(image).map_err(|_| E_BAD_IMAGE)?;

    // 2. Validate: must have an entry point (run, _start, or main)
    if module.find_export_func(b"run").is_none()
        && module.find_export_func(b"_start").is_none()
        && module.find_export_func(b"main").is_none()
    {
        serial_println!("[AGENT_LOADER] WASM module missing entry point (run/_start/main)");
        return Err(E_BAD_IMAGE);
    }

    // 3. Allocate a kernel stack for the WASM runner (needs 64 KiB for WasmInstance)
    let stack_top = sched::allocate_agent_stack();
    if stack_top == 0 {
        return Err(E_QUOTA_EXCEEDED);
    }

    // 4. Create a kernel-mode agent with the generic WASM runner as entry point
    let agent_id = create_agent(
        Some(caller_id),
        wasm_runner_entry as *const () as u64,
        stack_top,
        energy,
        mem_quota,
    )?;

    // 5. Store the module in the WASM_MODULES table (indexed by agent_id)
    let slot = agent_id as usize;
    if slot >= MAX_WASM_MODULES {
        return Err(E_QUOTA_EXCEEDED);
    }
    unsafe {
        WASM_MODULES[slot] = Some(module);
        WASM_RUNTIME_CLASSES[slot] = runtime_class;
    }

    // 6. Set cr3 to current kernel page table (WASM agents run in kernel mode)
    if let Some(agent) = get_agent_mut(agent_id) {
        let cr3: u64;
        unsafe {
            core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
        }
        agent.stack_bottom = sched::stack_bottom_from_top(stack_top);
        agent.context.cr3 = cr3;
    }

    // 7. Create mailbox, keyspace, enqueue
    finish_agent_setup(agent_id, caller_id)?;

    serial_println!(
        "[AGENT_LOADER] Spawned WASM agent {} (parent={})",
        agent_id,
        caller_id
    );

    Ok(agent_id)
}

// ─── Generic WASM runner ────────────────────────────────────────────────────

/// Generic entry point for dynamically loaded WASM agents.
///
/// Retrieves the WasmModule from the WASM_MODULES table using the current
/// agent's ID, then runs the same host-call interpreter loop as wasm_agent.rs.
pub extern "C" fn wasm_runner_entry() -> ! {
    let agent_id = sched::current();

    serial_println!(
        "[WASM_RUNNER] Agent {} starting dynamic WASM execution",
        agent_id
    );

    // Take ownership of the module from the table
    let module = unsafe {
        let slot = agent_id as usize;
        if slot >= MAX_WASM_MODULES {
            serial_println!(
                "[WASM_RUNNER] Agent {} has no WASM module (slot out of range)",
                agent_id
            );
            loop {
                crate::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
            }
        }
        match WASM_MODULES[slot].take() {
            Some(m) => m,
            None => {
                serial_println!("[WASM_RUNNER] Agent {} has no WASM module", agent_id);
                loop {
                    crate::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
                }
            }
        }
    };

    // Find entry point: try "run", "_start", "main" in order
    let run_idx = match module
        .find_export_func(b"run")
        .or_else(|| module.find_export_func(b"_start"))
        .or_else(|| module.find_export_func(b"main"))
    {
        Some(idx) => idx,
        None => {
            serial_println!("[WASM_RUNNER] Agent {} missing entry point", agent_id);
            loop {
                crate::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
            }
        }
    };

    // Create instance with fuel from agent's energy budget
    let fuel = match get_agent(agent_id) {
        Some(a) => a.energy_budget.min(1_000_000) as u64,
        None => 50_000,
    };
    let rc = unsafe { WASM_RUNTIME_CLASSES[agent_id as usize] };
    let mut instance = match wasm::runtime::WasmInstance::with_class(module, fuel, rc) {
        Ok(inst) => inst,
        Err(e) => {
            serial_println!(
                "[WASM_RUNNER] Agent {} instantiation trapped: {:?}",
                agent_id,
                e
            );
            crate::syscall::syscall(SYS_EXIT, 1, 0, 0, 0, 0);
            loop {} // unreachable
        }
    };

    // Run start function if present (WASM spec requirement)
    match instance.run_start() {
        wasm::runtime::ExecResult::Ok | wasm::runtime::ExecResult::Returned(_) => {}
        wasm::runtime::ExecResult::Trap(e) => {
            serial_println!(
                "[WASM_RUNNER] Agent {} start function trapped: {:?}",
                agent_id,
                e
            );
            crate::syscall::syscall(SYS_EXIT, 1, 0, 0, 0, 0);
        }
        _ => {}
    }

    // Run the host-call interpreter loop (same pattern as wasm_agent.rs)
    let mut result = instance.call_func(run_idx, &[]);
    let mut host_calls = 0u64;

    loop {
        match result {
            wasm::runtime::ExecResult::HostCall(import_idx, ref args, arg_count) => {
                host_calls = host_calls.saturating_add(1);
                if host_calls % 5000 == 1 {
                    serial_println!(
                        "[WASM_RUNNER] Agent {} host call #{} (import {})",
                        agent_id,
                        host_calls,
                        import_idx
                    );
                }

                let ret_val = match wasm::host::handle_host_call(
                    &mut instance,
                    import_idx,
                    &args[..arg_count as usize],
                    arg_count,
                ) {
                    Ok(val) => val,
                    Err(_) => break,
                };

                result = instance.resume(ret_val);
            }

            wasm::runtime::ExecResult::Ok | wasm::runtime::ExecResult::Returned(_) => {
                serial_println!(
                    "[WASM_RUNNER] Agent {} completed after {} host calls",
                    agent_id,
                    host_calls
                );
                break;
            }

            wasm::runtime::ExecResult::OutOfFuel => {
                serial_println!(
                    "[WASM_RUNNER] Agent {} out of fuel after {} host calls",
                    agent_id,
                    host_calls
                );
                break;
            }

            wasm::runtime::ExecResult::Trap(ref e) => {
                serial_println!("[WASM_RUNNER] Agent {} trap: {:?}", agent_id, e);
                break;
            }

            wasm::runtime::ExecResult::Exception(tag, _) => {
                serial_println!(
                    "[WASM_RUNNER] Agent {} uncaught exception (tag {})",
                    agent_id,
                    tag
                );
                break;
            }
        }
    }

    // Exit the agent
    crate::syscall::syscall(SYS_EXIT, 0, 0, 0, 0, 0);
    // Unreachable, but satisfy -> !
    loop {
        crate::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
    }
}

// ─── Disk loading (reads from Agent Storage Region) ─────────────────────────

/// Agent Storage Region start sector (Yellow Paper §24.6.1).
const AGENT_STORAGE_START: u64 = 4_198_408;
/// Agent Storage Region end sector.
const AGENT_STORAGE_END: u64 = 268_435_455;

/// Load an agent binary from the Agent Storage Region on disk and spawn it.
///
/// # Arguments
/// * `caller_id` - parent agent
/// * `disk_offset_sectors` - starting sector within the Agent Storage Region
/// * `size_sectors` - number of 512-byte sectors to read
/// * `kind` - runtime kind
/// * `energy` - energy budget
/// * `mem_quota` - memory quota in pages
pub fn load_from_disk(
    caller_id: AgentId,
    disk_offset_sectors: u64,
    size_sectors: u32,
    kind: RuntimeKind,
    energy: u64,
    mem_quota: u32,
) -> Result<AgentId, i64> {
    // Validate sector range is within Agent Storage Region
    let abs_start = AGENT_STORAGE_START
        .checked_add(disk_offset_sectors)
        .ok_or(E_INVALID_ARG)?;
    let abs_end = abs_start
        .checked_add(size_sectors as u64)
        .ok_or(E_INVALID_ARG)?;
    if abs_end > AGENT_STORAGE_END {
        return Err(E_INVALID_ARG);
    }

    // Validate size is reasonable (max 4 MB = 8192 sectors)
    if size_sectors == 0 || size_sectors > 8192 {
        return Err(E_INVALID_ARG);
    }

    // Calculate buffer size
    let buf_size = (size_sectors as usize)
        .checked_mul(512)
        .ok_or(E_INVALID_ARG)?;

    // Allocate temporary buffer via kernel heap
    let mut buf = alloc::vec![0u8; buf_size];

    // Read from disk via unified StorageDevice
    let dev = crate::block::StorageDevice::detect().ok_or(E_NOT_FOUND)?;

    // Read in batches of up to 128 sectors (ATA PIO limit)
    let batch_size: u32 = 128;
    let mut sectors_read: u32 = 0;
    while sectors_read < size_sectors {
        let remaining = size_sectors.saturating_sub(sectors_read);
        let count = remaining.min(batch_size);
        let lba = abs_start
            .checked_add(sectors_read as u64)
            .ok_or(E_INVALID_ARG)?;
        let offset = (sectors_read as usize)
            .checked_mul(512)
            .ok_or(E_INVALID_ARG)?;
        let end = offset
            .checked_add((count as usize).checked_mul(512).ok_or(E_INVALID_ARG)?)
            .ok_or(E_INVALID_ARG)?;
        dev.read(lba, count, &mut buf[offset..end])
            .map_err(|_| E_NOT_FOUND)?;
        sectors_read = sectors_read.checked_add(count).ok_or(E_INVALID_ARG)?;
    }

    serial_println!(
        "[AGENT_LOADER] Read {} sectors from disk at LBA {}",
        size_sectors,
        abs_start
    );

    // Spawn from the loaded bytes
    spawn_from_image(caller_id, &buf, kind, energy, mem_quota)
}

// ─── Helper functions ───────────────────────────────────────────────────────

/// Common post-creation setup: create mailbox, keyspace, enqueue, emit event.
fn finish_agent_setup(agent_id: AgentId, parent_id: AgentId) -> Result<(), i64> {
    mailbox::create_mailbox(agent_id as MailboxId, agent_id).map_err(|_| E_QUOTA_EXCEEDED)?;
    state::create_keyspace(agent_id as u16).map_err(|_| E_QUOTA_EXCEEDED)?;
    // Snapshot initial state root and creation tick for receipts
    if let Some(agent) = crate::agent::get_agent_mut(agent_id) {
        let root32 = state::get_root(agent_id as u16).unwrap_or([0u8; 32]);
        agent.initial_state_root = root32;
        agent.tick_created = crate::arch::x86_64::timer::get_ticks();
    }
    sched::enqueue(agent_id);
    crate::event::agent_created(agent_id, parent_id);
    Ok(())
}

/// Calculate the number of 4 KiB pages needed for a given byte count.
fn pages_for_bytes(bytes: u64) -> Option<usize> {
    let page_size = paging::PAGE_SIZE as u64;
    bytes
        .checked_add(page_size.saturating_sub(1))
        .and_then(|v| v.checked_div(page_size))
        .map(|v| v as usize)
}
