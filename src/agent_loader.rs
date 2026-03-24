//! ATOS Agent Loader
//!
//! Loads agent binaries (ELF64 or WASM) from memory or disk and spawns
//! them as running agents. Connects existing components: loader.rs (ELF
//! parser), wasm/decoder.rs (WASM decoder), paging.rs (address spaces),
//! and agent.rs (agent creation).
//!
//! Yellow Paper §24.2.3.1: Runtime Agent Loading from Disk and Memory.

extern crate alloc;

use crate::serial_println;
use crate::agent::*;
use crate::arch::x86_64::paging;
use crate::arch::x86_64::context::new_user_context;
use crate::sched;
use crate::mailbox;
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
    spawn_from_image_with_class(caller_id, image, kind, energy, mem_quota, wasm::types::DEFAULT_RUNTIME_CLASS)
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
        RuntimeKind::Wasm => spawn_wasm_with_class(caller_id, image, energy, mem_quota, runtime_class),
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
    let elf_info = crate::loader::parse_elf64(image).map_err(|_| E_BAD_IMAGE)?;

    // 2. Create isolated address space
    let agent_cr3 = paging::create_address_space().ok_or(E_QUOTA_EXCEEDED)?;

    // 3. Load each segment into the new address space
    for i in 0..elf_info.segment_count {
        let seg = match &elf_info.segments[i] {
            Some(s) => s,
            None => continue,
        };

        // Calculate number of pages needed for this segment
        let pages_needed = pages_for_bytes(seg.mem_size).ok_or(E_INVALID_ARG)?;

        for page_idx in 0..pages_needed {
            let page_offset = (page_idx as u64).checked_mul(paging::PAGE_SIZE as u64)
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
                let copy_start = file_data_start.checked_add(seg_page_start)
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

            paging::map_page(agent_cr3, vaddr, phys, flags)
                .map_err(|_| E_QUOTA_EXCEEDED)?;
        }
    }

    // 4. Allocate user stack page
    let stack_phys = paging::alloc_frame().ok_or(E_QUOTA_EXCEEDED)?;
    unsafe {
        core::ptr::write_bytes(stack_phys as *mut u8, 0, paging::PAGE_SIZE);
    }
    paging::map_page(
        agent_cr3, USER_STACK_VADDR, stack_phys,
        paging::PTE_PRESENT | paging::PTE_WRITABLE | paging::PTE_USER,
    ).map_err(|_| E_QUOTA_EXCEEDED)?;
    let user_stack_top = USER_STACK_VADDR.checked_add(paging::PAGE_SIZE as u64)
        .ok_or(E_INVALID_ARG)?;

    // 5. Allocate kernel stack for syscall handling
    let k_stack_top = sched::allocate_agent_stack();
    if k_stack_top == 0 {
        return Err(E_QUOTA_EXCEEDED);
    }

    // 6. Create the agent with the ELF entry point
    let entry = elf_info.entry_point;
    let agent_id = create_agent(Some(caller_id), entry, user_stack_top, energy, mem_quota)?;

    // 7. Configure user-mode context
    if let Some(agent) = get_agent_mut(agent_id) {
        agent.mode = AgentMode::User;
        agent.kernel_stack_top = k_stack_top;
        agent.context = new_user_context(entry, user_stack_top, k_stack_top);
        agent.context.cr3 = agent_cr3;
    }

    // 8. Create mailbox, keyspace, enqueue
    finish_agent_setup(agent_id, caller_id)?;

    serial_println!(
        "[AGENT_LOADER] Spawned native ELF agent {} (entry={:#x}, parent={})",
        agent_id, entry, caller_id
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
        unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack)); }
        agent.context.cr3 = cr3;
    }

    // 7. Create mailbox, keyspace, enqueue
    finish_agent_setup(agent_id, caller_id)?;

    serial_println!(
        "[AGENT_LOADER] Spawned WASM agent {} (parent={})",
        agent_id, caller_id
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

    serial_println!("[WASM_RUNNER] Agent {} starting dynamic WASM execution", agent_id);

    // Take ownership of the module from the table
    let module = unsafe {
        let slot = agent_id as usize;
        if slot >= MAX_WASM_MODULES {
            serial_println!("[WASM_RUNNER] Agent {} has no WASM module (slot out of range)", agent_id);
            loop { crate::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0); }
        }
        match WASM_MODULES[slot].take() {
            Some(m) => m,
            None => {
                serial_println!("[WASM_RUNNER] Agent {} has no WASM module", agent_id);
                loop { crate::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0); }
            }
        }
    };

    // Find entry point: try "run", "_start", "main" in order
    let run_idx = match module.find_export_func(b"run")
        .or_else(|| module.find_export_func(b"_start"))
        .or_else(|| module.find_export_func(b"main"))
    {
        Some(idx) => idx,
        None => {
            serial_println!("[WASM_RUNNER] Agent {} missing entry point", agent_id);
            loop { crate::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0); }
        }
    };

    // Create instance with fuel from agent's energy budget
    let fuel = match get_agent(agent_id) {
        Some(a) => a.energy_budget.min(1_000_000) as u64,
        None => 50_000,
    };
    let rc = unsafe { WASM_RUNTIME_CLASSES[agent_id as usize] };
    let mut instance = wasm::runtime::WasmInstance::with_class(module, fuel, rc);

    // Run start function if present (WASM spec requirement)
    match instance.run_start() {
        wasm::runtime::ExecResult::Ok | wasm::runtime::ExecResult::Returned(_) => {}
        wasm::runtime::ExecResult::Trap(e) => {
            serial_println!("[WASM_RUNNER] Agent {} start function trapped: {:?}", agent_id, e);
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
                        agent_id, host_calls, import_idx
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

            wasm::runtime::ExecResult::Ok
            | wasm::runtime::ExecResult::Returned(_) => {
                serial_println!(
                    "[WASM_RUNNER] Agent {} completed after {} host calls",
                    agent_id, host_calls
                );
                break;
            }

            wasm::runtime::ExecResult::OutOfFuel => {
                serial_println!(
                    "[WASM_RUNNER] Agent {} out of fuel after {} host calls",
                    agent_id, host_calls
                );
                break;
            }

            wasm::runtime::ExecResult::Trap(ref e) => {
                serial_println!("[WASM_RUNNER] Agent {} trap: {:?}", agent_id, e);
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
    let abs_start = AGENT_STORAGE_START.checked_add(disk_offset_sectors)
        .ok_or(E_INVALID_ARG)?;
    let abs_end = abs_start.checked_add(size_sectors as u64)
        .ok_or(E_INVALID_ARG)?;
    if abs_end > AGENT_STORAGE_END {
        return Err(E_INVALID_ARG);
    }

    // Validate size is reasonable (max 4 MB = 8192 sectors)
    if size_sectors == 0 || size_sectors > 8192 {
        return Err(E_INVALID_ARG);
    }

    // Calculate buffer size
    let buf_size = (size_sectors as usize).checked_mul(512).ok_or(E_INVALID_ARG)?;

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
        let lba = abs_start.checked_add(sectors_read as u64).ok_or(E_INVALID_ARG)?;
        let offset = (sectors_read as usize).checked_mul(512).ok_or(E_INVALID_ARG)?;
        let end = offset.checked_add((count as usize).checked_mul(512).ok_or(E_INVALID_ARG)?)
            .ok_or(E_INVALID_ARG)?;
        dev.read(lba, count, &mut buf[offset..end]).map_err(|_| E_NOT_FOUND)?;
        sectors_read = sectors_read.checked_add(count).ok_or(E_INVALID_ARG)?;
    }

    serial_println!(
        "[AGENT_LOADER] Read {} sectors from disk at LBA {}",
        size_sectors, abs_start
    );

    // Spawn from the loaded bytes
    spawn_from_image(caller_id, &buf, kind, energy, mem_quota)
}

// ─── Helper functions ───────────────────────────────────────────────────────

/// Common post-creation setup: create mailbox, keyspace, enqueue, emit event.
fn finish_agent_setup(agent_id: AgentId, parent_id: AgentId) -> Result<(), i64> {
    mailbox::create_mailbox(agent_id as MailboxId, agent_id)
        .map_err(|_| E_QUOTA_EXCEEDED)?;
    state::create_keyspace(agent_id as u16)
        .map_err(|_| E_QUOTA_EXCEEDED)?;
    sched::enqueue(agent_id);
    crate::event::agent_created(agent_id, parent_id);
    Ok(())
}

/// Calculate the number of 4 KiB pages needed for a given byte count.
fn pages_for_bytes(bytes: u64) -> Option<usize> {
    let page_size = paging::PAGE_SIZE as u64;
    bytes.checked_add(page_size.saturating_sub(1))
        .and_then(|v| v.checked_div(page_size))
        .map(|v| v as usize)
}
