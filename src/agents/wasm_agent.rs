//! ATOS WASM Contract Execution Agent
//!
//! A kernel-mode agent that loads deployed WASM bytecode from keyspace storage
//! and processes incoming contract call requests via mailbox IPC. Falls back to
//! a hardcoded test binary for backward compatibility with legacy test agents.

extern crate alloc;

use crate::serial_println;
use crate::agent::*;
use crate::syscall;
use crate::wasm;
use crate::contract_call;
use crate::mailbox;

/// Maximum size of a deployed WASM contract binary (64 KB).
const MAX_WASM_CODE_SIZE: usize = 65536;

/// Default fuel budget for contract execution per call.
const DEFAULT_FUEL: u64 = 100_000;

/// Hardcoded WASM binary for backward-compatible test agents.
///
/// Module structure:
///   - Type section:   1 func type `() -> ()`
///   - Import section: 1 import `"atos"."sys_yield"` as func (type 0)
///   - Function section: 1 local function (type 0)
///   - Export section:   export `"run"` as function index 1
///   - Code section:     function body = `loop { call 0; br 0; } end`
///
/// Function index 0 = imported sys_yield
/// Function index 1 = local "run" function (exported)
static WASM_BINARY: &[u8] = &[
    // ── WASM header ──────────────────────────────────────────────
    0x00, 0x61, 0x73, 0x6D, // magic: \0asm
    0x01, 0x00, 0x00, 0x00, // version: 1

    // ── Type section (id=1, size=4) ──────────────────────────────
    0x01, 0x04, 0x01, 0x60, 0x00, 0x00,

    // ── Import section (id=2, size=17) ───────────────────────────
    0x02, 0x11, 0x01,
    0x03, 0x61, 0x6F, 0x73, // module: "atos" (note: 3 bytes = "aos")
    0x09, 0x73, 0x79, 0x73, 0x5F, 0x79, 0x69, 0x65, 0x6C, 0x64, // field: "sys_yield"
    0x00, 0x00,

    // ── Function section (id=3, size=2) ──────────────────────────
    0x03, 0x02, 0x01, 0x00,

    // ── Export section (id=7, size=7) ─────────────────────────────
    0x07, 0x07, 0x01,
    0x03, 0x72, 0x75, 0x6E, // name: "run"
    0x00, 0x01,

    // ── Code section (id=10, size=11) ────────────────────────────
    0x0A, 0x0B, 0x01,
    0x09, 0x00,
    0x03, 0x40,             // loop (void)
    0x10, 0x00,             // call 0 (sys_yield)
    0x0C, 0x00,             // br 0
    0x0B, 0x0B,             // end loop, end func
];

// ─── Response serialisation ─────────────────────────────────────────────────

/// Serialise a ContractCallResponse into a byte buffer in the wire format
/// expected by `contract_call::parse_response()`.
///
/// Wire format: status(1) + energy_used(8 LE) + output_len(2 LE) + output data.
/// Returns the number of bytes written.
fn serialise_response(resp: &contract_call::ContractCallResponse, buf: &mut [u8]) -> usize {
    let out_len = resp.output_len as usize;
    let total = 11 + out_len;
    if buf.len() < total {
        return 0;
    }

    buf[0] = resp.status;
    buf[1..9].copy_from_slice(&resp.energy_used.to_le_bytes());
    buf[9..11].copy_from_slice(&resp.output_len.to_le_bytes());
    buf[11..11 + out_len].copy_from_slice(&resp.output[..out_len]);

    total
}

// ─── WASM execution helper ──────────────────────────────────────────────────

/// Run a WASM function through the host-call interpreter loop.
///
/// Returns `(fuel_consumed, status_code)` where status_code distinguishes
/// between success, revert (trap), out-of-energy, and host-call errors.
fn run_wasm_function(
    instance: &mut wasm::runtime::WasmInstance,
    func_idx: u32,
    args: &[wasm::types::Value],
    initial_fuel: u64,
) -> (u64, u8) {
    let mut result = instance.call_func(func_idx, args);

    loop {
        match result {
            wasm::runtime::ExecResult::HostCall(import_idx, ref host_args, arg_count) => {
                let ret_val = match wasm::host::handle_host_call(
                    instance,
                    import_idx,
                    &host_args[..arg_count as usize],
                    arg_count,
                ) {
                    Ok(val) => val,
                    Err(e) => {
                        serial_println!("[WASM_AGENT] Host call error: {:?}", e);
                        let consumed = initial_fuel.saturating_sub(instance.get_fuel());
                        return (consumed, contract_call::STATUS_ERROR);
                    }
                };
                result = instance.resume(ret_val);
            }

            wasm::runtime::ExecResult::Ok
            | wasm::runtime::ExecResult::Returned(_) => {
                let consumed = initial_fuel.saturating_sub(instance.get_fuel());
                return (consumed, contract_call::STATUS_SUCCESS);
            }

            wasm::runtime::ExecResult::OutOfFuel => {
                let consumed = initial_fuel;
                return (consumed, contract_call::STATUS_OUT_OF_ENERGY);
            }

            wasm::runtime::ExecResult::Trap(ref e) => {
                serial_println!("[WASM_AGENT] Trap: {:?}", e);
                let consumed = initial_fuel.saturating_sub(instance.get_fuel());
                return (consumed, contract_call::STATUS_REVERT);
            }

            wasm::runtime::ExecResult::Exception(tag, _) => {
                serial_println!("[WASM_AGENT] Uncaught exception (tag {})", tag);
                let consumed = initial_fuel.saturating_sub(instance.get_fuel());
                return (consumed, contract_call::STATUS_REVERT);
            }
        }
    }
}

// ─── Export function resolution ─────────────────────────────────────────────

/// Try to find an exported function suitable for handling a contract call.
///
/// Lookup order:
///   1. An export whose name matches the selector (checked via FNV-1a hash
///      of the export name against the 4-byte selector).
///   2. Well-known names: "call", "handle", "main", "run".
fn find_call_export(module: &wasm::decoder::WasmModule, selector: u32) -> Option<u32> {
    // 1. Try to match the selector against all exported functions by computing
    //    FNV-1a of each export name and comparing the first 4 bytes.
    for exp in module.get_exports() {
        if let wasm::decoder::ExportKind::Func(idx) = exp.kind {
            let name = module.get_name(exp.name_offset, exp.name_len);
            let hash = contract_call::compute_selector(name);
            if hash == selector {
                return Some(idx);
            }
        }
    }

    // 2. Fall back to well-known entry points in priority order.
    static NAMES: &[&[u8]] = &[b"call", b"handle", b"main", b"run"];

    for name in NAMES {
        if let Some(idx) = module.find_export_func(name) {
            return Some(idx);
        }
    }

    None
}

// ─── Entry point ────────────────────────────────────────────────────────────

/// WASM agent entry point.
///
/// Phase 1: Load WASM code from keyspace or fall back to hardcoded binary.
/// Phase 2: Run start function if present.
/// Phase 3: Enter message processing loop — receive contract call requests
///          from the mailbox, execute the WASM function, and send responses.
pub extern "C" fn wasm_agent_entry() -> ! {
    let agent_id = crate::sched::current();
    serial_println!("[WASM_AGENT] Agent {} started", agent_id);

    // ── Phase 1: Load WASM code ─────────────────────────────────────────

    // Try to read deployed WASM bytecode from this agent's keyspace using
    // chunked large value storage.  We heap-allocate the buffer because 64 KB
    // is too large for a kernel stack frame.
    let mut wasm_code_buf = alloc::vec![0u8; MAX_WASM_CODE_SIZE];
    let wasm_code_len = crate::state::load_large_value(agent_id, &mut wasm_code_buf);

    let is_fallback = wasm_code_len == 0;
    if wasm_code_len > 0 {
        serial_println!(
            "[WASM_AGENT] Agent {} loaded {} bytes of WASM from keyspace (chunked)",
            agent_id, wasm_code_len
        );
    } else {
        serial_println!(
            "[WASM_AGENT] Agent {} has no deployed WASM, using fallback binary",
            agent_id
        );
    }

    let wasm_bytes: &[u8] = if !is_fallback {
        &wasm_code_buf[..wasm_code_len]
    } else {
        WASM_BINARY
    };

    // Decode the WASM binary.
    let module = match wasm::decoder::decode(wasm_bytes) {
        Ok(m) => {
            serial_println!(
                "[WASM_AGENT] Module decoded: {} functions, {} imports, {} exports",
                m.get_functions().len(),
                m.get_imports().len(),
                m.get_exports().len()
            );
            m
        }
        Err(e) => {
            serial_println!("[WASM_AGENT] Failed to decode WASM: {:?}", e);
            syscall::syscall(SYS_EXIT, 1, 0, 0, 0, 0);
            loop {} // unreachable
        }
    };

    // If using the fallback binary, run the old test-agent logic (no mailbox loop).
    if is_fallback {
        run_fallback_agent(module, agent_id);
    }

    // ── For deployed contracts: instantiate and enter message loop ───────

    // Create the WASM instance. We reuse it across calls.
    let mut instance = match wasm::runtime::WasmInstance::new(module, DEFAULT_FUEL) {
        Ok(inst) => inst,
        Err(e) => {
            serial_println!("[WASM_AGENT] Agent {} instantiation failed: {:?}", agent_id, e);
            loop { syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0); }
        }
    };
    serial_println!("[WASM_AGENT] Agent {} instance created with {} fuel", agent_id, DEFAULT_FUEL);

    // ── Phase 2: Run start function if present ──────────────────────────

    match instance.run_start() {
        wasm::runtime::ExecResult::Ok | wasm::runtime::ExecResult::Returned(_) => {}
        wasm::runtime::ExecResult::Trap(e) => {
            serial_println!("[WASM_AGENT] Agent {} start function trapped: {:?}", agent_id, e);
            loop { syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0); }
        }
        _ => {}
    }

    // ── Phase 3: Message processing loop ────────────────────────────────

    serial_println!("[WASM_AGENT] Agent {} entering message loop", agent_id);
    let mailbox_id = agent_id; // Stage-1: mailbox_id == agent_id

    loop {
        // 1. Try to receive a message from own mailbox (non-blocking).
        let msg = match mailbox::recv_message(agent_id, mailbox_id) {
            Ok(m) => m,
            Err(_) => {
                // No message available — yield and retry.
                syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
                continue;
            }
        };

        // 2. Try to parse as a ContractCallRequest.
        let payload_len = msg.len as usize;
        let call_req = match contract_call::parse_request(&msg.payload[..payload_len]) {
            Some(req) => req,
            None => {
                // Re-enqueue so message isn't lost.
                serial_println!(
                    "[WASM_AGENT] Agent {} received non-call message ({} bytes), re-enqueuing",
                    agent_id, payload_len
                );
                mailbox::send_message(agent_id, agent_id as u16, &msg.payload[..payload_len]).ok();
                continue;
            }
        };

        serial_println!(
            "[WASM_AGENT] Agent {} received call: selector=0x{:08X}, input_len={}, caller={}",
            agent_id, call_req.selector, call_req.input_len, call_req.caller_agent
        );

        // 2b. Resolve the call export per-request using the selector.
        let call_idx = match find_call_export(instance.module(), call_req.selector) {
            Some(idx) => idx,
            None => {
                serial_println!(
                    "[WASM_AGENT] Agent {} has no export matching selector 0x{:08X}",
                    agent_id, call_req.selector
                );
                // Send an error response back to the caller.
                let response = contract_call::build_response(
                    contract_call::STATUS_ERROR, 0, &[],
                );
                let mut resp_buf = [0u8; 256];
                let resp_len = serialise_response(&response, &mut resp_buf);
                if resp_len > 0 {
                    mailbox::send_message(agent_id, call_req.caller_agent, &resp_buf[..resp_len]).ok();
                }
                continue;
            }
        };

        // 3. Write call input into WASM linear memory at offset 0.
        let input_len = call_req.input_len as usize;
        if let Some(mem) = instance.get_memory_mut(0) {
            let write_len = input_len.min(mem.len());
            mem[..write_len].copy_from_slice(&call_req.input[..write_len]);
        }

        // 4. Reset fuel budget for this call.
        let fuel = if call_req.energy_budget > 0 {
            call_req.energy_budget.min(1_000_000)
        } else {
            DEFAULT_FUEL
        };
        instance.set_fuel(fuel);

        // 5. Execute the WASM function.
        //    Pass input length as an i32 argument so the contract knows the size.
        let (energy_used, status) = run_wasm_function(
            &mut instance,
            call_idx,
            &[wasm::types::Value::I32(input_len as i32)],
            fuel,
        );

        // 6. Read output from WASM linear memory at offset 0.
        //    Convention: the contract writes its output starting at memory offset 0
        //    and returns the output length via the function return value (already
        //    consumed by run_wasm_function). We read up to 243 bytes (MAX_CALL_OUTPUT).
        let mut output = [0u8; 243];
        let mut output_len: usize = 0;

        if status == contract_call::STATUS_SUCCESS {
            if let Some(mem) = instance.get_memory(0) {
                // Read the first 4 bytes as a little-endian u32 output length marker,
                // then the actual output follows at offset 4.
                if mem.len() >= 4 {
                    let declared_len = u32::from_le_bytes([mem[0], mem[1], mem[2], mem[3]]) as usize;
                    output_len = declared_len.min(243).min(mem.len().saturating_sub(4));
                    if output_len > 0 {
                        output[..output_len].copy_from_slice(&mem[4..4 + output_len]);
                    }
                }
            }
        }

        // 7. Build the response.
        let response = contract_call::build_response(status, energy_used, &output[..output_len]);

        // 8. Serialise and send response to the caller's mailbox.
        let mut resp_buf = [0u8; 256];
        let resp_len = serialise_response(&response, &mut resp_buf);

        if resp_len > 0 {
            let caller_mailbox = call_req.caller_agent; // Stage-1: mailbox_id == agent_id
            match mailbox::send_message(agent_id, caller_mailbox, &resp_buf[..resp_len]) {
                Ok(()) => {
                    serial_println!(
                        "[WASM_AGENT] Agent {} sent response to agent {} (status={}, energy={}, output={}B)",
                        agent_id, call_req.caller_agent, status, energy_used, output_len
                    );
                }
                Err(e) => {
                    serial_println!(
                        "[WASM_AGENT] Agent {} failed to send response to {}: err={}",
                        agent_id, call_req.caller_agent, e
                    );
                }
            }
        }

        // Yield to scheduler between calls.
        syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
    }
}

// ─── Fallback: legacy test agent ────────────────────────────────────────────

/// Run the original test-agent logic for agents using the hardcoded WASM binary.
///
/// This preserves backward compatibility: the fallback binary has a "run" export
/// that loops calling sys_yield, which is driven through the host-call loop.
fn run_fallback_agent(module: wasm::decoder::WasmModule, agent_id: AgentId) -> ! {
    serial_println!("[WASM_AGENT] Agent {} running fallback test binary", agent_id);

    // Find the "run" export.
    let run_idx = match module.find_export_func(b"run") {
        Some(idx) => idx,
        None => {
            serial_println!("[WASM_AGENT] Fallback binary missing 'run' export");
            loop { unsafe { core::arch::asm!("hlt"); } }
        }
    };

    // Create instance with fuel budget.
    let mut instance = match wasm::runtime::WasmInstance::new(module, 50_000) {
        Ok(inst) => inst,
        Err(e) => {
            serial_println!("[WASM_AGENT] Fallback instantiation trapped: {:?}", e);
            loop { unsafe { core::arch::asm!("hlt"); } }
        }
    };

    // Run start function if present.
    match instance.run_start() {
        wasm::runtime::ExecResult::Ok | wasm::runtime::ExecResult::Returned(_) => {}
        wasm::runtime::ExecResult::Trap(e) => {
            serial_println!("[WASM_AGENT] Fallback start function trapped: {:?}", e);
            loop { unsafe { core::arch::asm!("hlt"); } }
        }
        _ => {}
    }

    // Run the "run" function through the host-call loop.
    let mut result = instance.call_func(run_idx, &[]);
    let mut host_calls = 0u64;

    loop {
        match result {
            wasm::runtime::ExecResult::HostCall(import_idx, ref args, arg_count) => {
                host_calls += 1;
                if host_calls % 1000 == 1 {
                    serial_println!(
                        "[WASM_AGENT] Agent {} host call #{} (import {})",
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
                    Err(e) => {
                        serial_println!("[WASM_AGENT] Host call error: {:?}", e);
                        break;
                    }
                };

                result = instance.resume(ret_val);
            }

            wasm::runtime::ExecResult::Ok
            | wasm::runtime::ExecResult::Returned(_) => {
                serial_println!(
                    "[WASM_AGENT] Agent {} fallback completed after {} host calls",
                    agent_id, host_calls
                );
                break;
            }

            wasm::runtime::ExecResult::OutOfFuel => {
                serial_println!(
                    "[WASM_AGENT] Agent {} out of fuel after {} host calls",
                    agent_id, host_calls
                );
                break;
            }

            wasm::runtime::ExecResult::Trap(ref e) => {
                serial_println!("[WASM_AGENT] Agent {} trap: {:?}", agent_id, e);
                break;
            }

            wasm::runtime::ExecResult::Exception(tag, _) => {
                serial_println!("[WASM_AGENT] Agent {} uncaught exception (tag {})", agent_id, tag);
                break;
            }
        }
    }

    serial_println!("[WASM_AGENT] Agent {} fallback execution complete, yielding forever", agent_id);
    loop {
        syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
    }
}
