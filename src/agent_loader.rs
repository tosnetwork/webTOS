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
use crate::arch::x86_64::paging;
use crate::mailbox;
use crate::sched;
use crate::serial_println;
use crate::state;
use crate::wasm;

/// Maximum agent image size: 4 MB (1024 pages).
const MAX_IMAGE_SIZE: usize = 4 * 1024 * 1024;

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

fn translate_agent_vaddr(agent_cr3: u64, vaddr: u64) -> Option<u64> {
    let pml4_idx = ((vaddr >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((vaddr >> 30) & 0x1FF) as usize;
    let pd_idx = ((vaddr >> 21) & 0x1FF) as usize;
    let pt_idx = ((vaddr >> 12) & 0x1FF) as usize;

    unsafe {
        let pml4 = agent_cr3 as *const u64;
        let pml4e = core::ptr::read_volatile(pml4.add(pml4_idx));
        if pml4e & paging::PTE_PRESENT == 0 {
            return None;
        }

        let pdpt = (pml4e & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pdpte = core::ptr::read_volatile(pdpt.add(pdpt_idx));
        if pdpte & paging::PTE_PRESENT == 0 {
            return None;
        }

        let pd = (pdpte & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pde = core::ptr::read_volatile(pd.add(pd_idx));
        if pde & paging::PTE_PRESENT == 0 {
            return None;
        }

        if pde & paging::PTE_HUGE != 0 {
            let base = pde & 0x000F_FFFF_FFE0_0000;
            return Some(base + (vaddr & 0x1F_FFFF));
        }

        let pt = (pde & 0x000F_FFFF_FFFF_F000) as *const u64;
        let pte = core::ptr::read_volatile(pt.add(pt_idx));
        if pte & paging::PTE_PRESENT == 0 {
            return None;
        }

        Some((pte & 0x000F_FFFF_FFFF_F000) + (vaddr & (paging::PAGE_SIZE as u64 - 1)))
    }
}

fn write_agent_user_bytes(agent_cr3: u64, user_vaddr: u64, data: &[u8]) -> Result<(), i64> {
    let mut written = 0usize;

    while written < data.len() {
        let vaddr = user_vaddr
            .checked_add(written as u64)
            .ok_or(E_INVALID_ARG)?;
        let phys = translate_agent_vaddr(agent_cr3, vaddr).ok_or(E_BAD_IMAGE)?;
        let page_off = (vaddr as usize) & (paging::PAGE_SIZE - 1);
        let chunk_len = (data.len() - written).min(paging::PAGE_SIZE - page_off);

        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr().add(written),
                phys as *mut u8,
                chunk_len,
            );
        }

        written += chunk_len;
    }

    Ok(())
}

fn write_agent_user_u64(agent_cr3: u64, user_vaddr: u64, value: u64) -> Result<(), i64> {
    write_agent_user_bytes(agent_cr3, user_vaddr, &value.to_ne_bytes())
}

fn loaded_file_vaddr(elf_info: &crate::loader::ElfInfo, file_offset: u64, size: u64) -> Option<u64> {
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

fn map_user_stack_region(agent_cr3: u64, user_stack_base: u64) -> Result<u64, i64> {
    debug_assert_eq!(USER_STACK_SIZE % paging::PAGE_SIZE, 0);

    for page_idx in 0..(USER_STACK_SIZE / paging::PAGE_SIZE) {
        let phys = paging::alloc_frame().ok_or(E_QUOTA_EXCEEDED)?;
        unsafe {
            core::ptr::write_bytes(phys as *mut u8, 0, paging::PAGE_SIZE);
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
            // Linux compat agents are loaded as native ELF binaries
            // with the Linux syscall translation layer enabled.
            let agent_id = spawn_native_elf(caller_id, image, energy, mem_quota)?;
            // Initialize per-agent Linux virtual OS state (fd table, cwd, PRNG, etc.)
            // The presence of LinuxAgentState signals the syscall dispatcher to route
            // through linux_compat::dispatch() instead of the ATOS native path.
            crate::linux_compat::state::init_state(agent_id);
            Ok(agent_id)
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

    // 1b. Handle dynamically-linked binaries (ET_DYN / PT_INTERP)
    if elf_info.is_dynamic {
        // Extract interpreter path for diagnostics
        if elf_info.interp_len > 0 && elf_info.interp_offset + elf_info.interp_len <= image.len() {
            let interp_bytes = &image[elf_info.interp_offset..elf_info.interp_offset + elf_info.interp_len];
            // Trim trailing NUL
            let interp_end = interp_bytes.iter().position(|&b| b == 0).unwrap_or(interp_bytes.len());
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

        // For ET_DYN, segment vaddrs are relative offsets. Apply a load bias
        // so the binary is placed at a deterministic user-space address.
        if elf_info.load_bias == 0 {
            // Use USER_CODE_VADDR as the base for PIE binaries whose
            // segments start near vaddr 0.
            let min_vaddr = elf_info.segments[..elf_info.segment_count]
                .iter()
                .filter_map(|s| s.as_ref())
                .map(|s| s.vaddr)
                .min()
                .unwrap_or(0);
            if min_vaddr < USER_CODE_VADDR {
                elf_info.load_bias = USER_CODE_VADDR - (min_vaddr & !(paging::PAGE_SIZE as u64 - 1));
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

    // 2. Create isolated address space
    let agent_cr3 = paging::create_address_space().ok_or(E_QUOTA_EXCEEDED)?;

    // 3. Load each segment into the new address space.
    //    Skip segments below USER_CODE_VADDR (e.g., 0x400000 ELF header
    //    metadata segment) since they conflict with identity-mapped pages.
    for i in 0..elf_info.segment_count {
        let seg = match &elf_info.segments[i] {
            Some(s) => s,
            None => continue,
        };

        // Skip segments below user space (ELF metadata at 0x400000 etc.)
        if seg.vaddr < USER_CODE_VADDR as u64 {
            continue;
        }

        // Calculate number of pages needed for this segment
        let pages_needed = pages_for_bytes(seg.mem_size).ok_or(E_INVALID_ARG)?;

        for page_idx in 0..pages_needed {
            let page_offset = (page_idx as u64)
                .checked_mul(paging::PAGE_SIZE as u64)
                .ok_or(E_INVALID_ARG)?;
            let vaddr = seg.vaddr.checked_add(page_offset).ok_or(E_INVALID_ARG)?;

            // Allocate a physical frame
            let phys = paging::alloc_frame().ok_or(E_QUOTA_EXCEEDED)?;

            // Zero the frame first
            unsafe {
                core::ptr::write_bytes(phys as *mut u8, 0, paging::PAGE_SIZE);
            }

            // Copy data from the ELF image for this page
            let seg_page_start = page_offset as usize;
            let file_data_start = seg.file_offset as usize;
            if seg_page_start < seg.file_size as usize {
                let copy_start = file_data_start
                    .checked_add(seg_page_start)
                    .ok_or(E_INVALID_ARG)?;
                let remaining_file = (seg.file_size as usize).saturating_sub(seg_page_start);
                let copy_len = remaining_file.min(paging::PAGE_SIZE);
                if copy_start.checked_add(copy_len).ok_or(E_INVALID_ARG)? <= image.len() {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            image.as_ptr().add(copy_start),
                            phys as *mut u8,
                            copy_len,
                        );
                    }
                }
            }

            // Determine page flags
            let is_exec = seg.flags & 0x1 != 0; // PF_X
            let is_write = seg.flags & 0x2 != 0; // PF_W
            let mut flags = paging::PTE_PRESENT | paging::PTE_USER;
            if is_write {
                flags |= paging::PTE_WRITABLE;
            }
            let _ = is_exec; // NX bit handling deferred

            paging::map_page(agent_cr3, vaddr, phys, flags).map_err(|_| E_QUOTA_EXCEEDED)?;
        }
    }

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
        let interp_bytes = &image[elf_info.interp_offset..elf_info.interp_offset + elf_info.interp_len];
        let interp_end = interp_bytes.iter().position(|&b| b == 0).unwrap_or(interp_bytes.len());
        let interp_path = &interp_bytes[..interp_end];

        // Resolve interpreter path via VFS → base image keyspace
        let (interp_ks, interp_key) = crate::linux_compat::vfs::resolve_path(0, interp_path);

        // Load interpreter bytes from keyspace
        let mut interp_buf = alloc::vec![0u8; 2 * 1024 * 1024]; // 2MB max for ld-linux
        let interp_len = crate::state::load_multi_segment(interp_ks, interp_key, &mut interp_buf);

        if interp_len == 0 {
            // Interpreter not found in base image — fall back to main entry
            serial_println!(
                "[AGENT_LOADER] Interpreter not in base image, using main entry {:#x}",
                main_entry
            );
            main_entry
        } else {
            serial_println!(
                "[AGENT_LOADER] Loaded interpreter ({} bytes) from keyspace",
                interp_len
            );

            // Parse interpreter ELF
            match crate::loader::parse_elf64(&interp_buf[..interp_len]) {
                Ok(mut interp_elf) => {
                    // Apply load bias: place interpreter at INTERP_BASE_VADDR
                    let interp_min_vaddr = interp_elf.segments[..interp_elf.segment_count]
                        .iter()
                        .filter_map(|s| s.as_ref())
                        .map(|s| s.vaddr)
                        .min()
                        .unwrap_or(0);
                    let bias = INTERP_BASE_VADDR - (interp_min_vaddr & !(paging::PAGE_SIZE as u64 - 1));
                    interp_base = bias;

                    interp_elf.entry_point = interp_elf.entry_point.wrapping_add(bias);
                    for i in 0..interp_elf.segment_count {
                        if let Some(ref mut seg) = interp_elf.segments[i] {
                            seg.vaddr = seg.vaddr.wrapping_add(bias);
                        }
                    }

                    // Load interpreter segments into agent address space
                    for i in 0..interp_elf.segment_count {
                        let seg = match &interp_elf.segments[i] {
                            Some(s) => s,
                            None => continue,
                        };

                        interp_highest_end = interp_highest_end.max(seg.vaddr.saturating_add(seg.mem_size));

                        let pages_needed = pages_for_bytes(seg.mem_size).ok_or(E_INVALID_ARG)?;
                        for page_idx in 0..pages_needed {
                            let page_offset = (page_idx as u64)
                                .checked_mul(paging::PAGE_SIZE as u64)
                                .ok_or(E_INVALID_ARG)?;
                            let vaddr = seg.vaddr.checked_add(page_offset).ok_or(E_INVALID_ARG)?;

                            let phys = paging::alloc_frame().ok_or(E_QUOTA_EXCEEDED)?;
                            unsafe {
                                core::ptr::write_bytes(phys as *mut u8, 0, paging::PAGE_SIZE);
                            }

                            let seg_page_start = page_offset as usize;
                            let file_data_start = seg.file_offset as usize;
                            if seg_page_start < seg.file_size as usize {
                                let copy_start = file_data_start + seg_page_start;
                                let remaining_file = (seg.file_size as usize).saturating_sub(seg_page_start);
                                let copy_len = remaining_file.min(paging::PAGE_SIZE);
                                if copy_start + copy_len <= interp_len {
                                    unsafe {
                                        core::ptr::copy_nonoverlapping(
                                            interp_buf.as_ptr().add(copy_start),
                                            phys as *mut u8,
                                            copy_len,
                                        );
                                    }
                                }
                            }

                            let is_write = seg.flags & 0x2 != 0;
                            let mut flags = paging::PTE_PRESENT | paging::PTE_USER;
                            if is_write { flags |= paging::PTE_WRITABLE; }
                            paging::map_page(agent_cr3, vaddr, phys, flags)
                                .map_err(|_| E_QUOTA_EXCEEDED)?;
                        }
                    }

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
            (9,  main_entry),          // AT_ENTRY: main program entry
            (7,  interp_base),         // AT_BASE: interpreter base address
            (3,  phdr_addr),           // AT_PHDR: program header table address
            (4,  elf_info.phdr_entry_size as u64), // AT_PHENT: size of phdr entry
            (5,  elf_info.phdr_count as u64), // AT_PHNUM: number of phdr entries
            (6,  paging::PAGE_SIZE as u64), // AT_PAGESZ
            (25, auxv_base + 128),     // AT_RANDOM: pointer to 16 "random" bytes
            (0,  0),                   // AT_NULL: terminator
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
