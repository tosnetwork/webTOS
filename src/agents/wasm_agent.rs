//! ATOS WASM Agent
//!
//! A kernel-mode agent that runs a hand-crafted WASM binary through
//! the ATOS WASM interpreter. Demonstrates that WASM and native agents
//! can coexist in the same system.

use crate::serial_println;
use crate::agent::*;
use crate::syscall;
use crate::wasm;
// WasmInstance uses heap-allocated Vec for memory/code — struct itself is small on stack

/// Hand-crafted WASM binary.
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
    // Contains 1 type: () -> ()
    0x01,                   // section id: Type
    0x04,                   // section size: 4 bytes
    0x01,                   // count: 1 type
    0x60,                   // func type marker
    0x00,                   // param count: 0
    0x00,                   // result count: 0

    // ── Import section (id=2, size=17) ───────────────────────────
    // 1 import: "atos"."sys_yield" : func type 0
    0x02,                   // section id: Import
    0x11,                   // section size: 17 bytes
    0x01,                   // count: 1 import
    0x03,                   // module name length: 3
    0x61, 0x6F, 0x73,      // module name: "atos"
    0x09,                   // field name length: 9
    0x73, 0x79, 0x73, 0x5F, // field name: "sys_"
    0x79, 0x69, 0x65, 0x6C, // field name: "yiel"
    0x64,                   // field name: "d"
    0x00,                   // import kind: function
    0x00,                   // type index: 0

    // ── Function section (id=3, size=2) ──────────────────────────
    // 1 local function with type index 0
    0x03,                   // section id: Function
    0x02,                   // section size: 2 bytes
    0x01,                   // count: 1 function
    0x00,                   // type index: 0

    // ── Export section (id=7, size=7) ─────────────────────────────
    // 1 export: "run" -> function index 1
    0x07,                   // section id: Export
    0x07,                   // section size: 7 bytes
    0x01,                   // count: 1 export
    0x03,                   // export name length: 3
    0x72, 0x75, 0x6E,      // export name: "run"
    0x00,                   // export kind: function
    0x01,                   // function index: 1 (0=import, 1=local)

    // ── Code section (id=10, size=11) ────────────────────────────
    // 1 function body:
    //   0 locals
    //   loop (void)
    //     call 0        ;; call sys_yield (import index 0)
    //     br 0          ;; unconditional branch to loop start
    //   end
    //   end
    0x0A,                   // section id: Code
    0x0B,                   // section size: 11 bytes
    0x01,                   // count: 1 function body
    0x09,                   // body size: 9 bytes
    0x00,                   // local declaration count: 0
    0x03,                   // opcode: loop
    0x40,                   // block type: void
    0x10,                   // opcode: call
    0x00,                   // function index: 0 (sys_yield)
    0x0C,                   // opcode: br
    0x00,                   // label index: 0 (innermost = this loop)
    0x0B,                   // end (loop)
    0x0B,                   // end (function)
];

/// WASM agent entry point.
///
/// Decodes the hand-crafted WASM binary, instantiates it, and runs the
/// exported "run" function. Host calls (sys_yield) are handled in a loop
/// until execution completes, traps, or runs out of fuel.
pub extern "C" fn wasm_agent_entry() -> ! {
    serial_println!("[WASM_AGENT] WASM agent started");

    // 1. Decode the WASM binary
    let module = match wasm::decoder::decode(WASM_BINARY) {
        Ok(m) => {
            serial_println!(
                "[WASM_AGENT] Module decoded: {} functions, {} imports, {} exports",
                m.functions.len(),
                m.imports.len(),
                m.exports.len()
            );
            m
        }
        Err(e) => {
            serial_println!("[WASM_AGENT] Failed to decode WASM: {:?}", e);
            loop {
                unsafe { core::arch::asm!("hlt"); }
            }
        }
    };

    // 2. Find the "run" export
    let run_idx = match module.find_export_func(b"run") {
        Some(idx) => {
            serial_println!("[WASM_AGENT] Found export 'run' at function index {}", idx);
            idx
        }
        None => {
            serial_println!("[WASM_AGENT] Export 'run' not found");
            loop {
                unsafe { core::arch::asm!("hlt"); }
            }
        }
    };

    // 3. Create instance with fuel budget
    let mut instance = wasm::runtime::WasmInstance::new(module, 50_000);
    serial_println!("[WASM_AGENT] Instance created with 50000 fuel");

    // 3b. Run start function if present (WASM spec requirement)
    match instance.run_start() {
        wasm::runtime::ExecResult::Ok | wasm::runtime::ExecResult::Returned(_) => {}
        wasm::runtime::ExecResult::Trap(e) => {
            serial_println!("[WASM_AGENT] Start function trapped: {:?}", e);
            loop { unsafe { core::arch::asm!("hlt"); } }
        }
        _ => {}
    }

    // 4. Call the run function and handle host calls in a loop
    let mut result = instance.call_func(run_idx, &[]);
    let mut host_calls = 0u64;

    loop {
        match result {
            wasm::runtime::ExecResult::HostCall(import_idx, ref args, arg_count) => {
                host_calls += 1;
                if host_calls % 1000 == 1 {
                    serial_println!(
                        "[WASM_AGENT] Host call #{} (import {})",
                        host_calls,
                        import_idx
                    );
                }

                // Handle the host call via the host module
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

                // Resume execution with the return value
                result = instance.resume(ret_val);
            }

            wasm::runtime::ExecResult::Ok
            | wasm::runtime::ExecResult::Returned(_) => {
                serial_println!(
                    "[WASM_AGENT] Function returned after {} host calls",
                    host_calls
                );
                break;
            }

            wasm::runtime::ExecResult::OutOfFuel => {
                serial_println!(
                    "[WASM_AGENT] Out of fuel after {} host calls",
                    host_calls
                );
                break;
            }

            wasm::runtime::ExecResult::Trap(ref e) => {
                serial_println!("[WASM_AGENT] Trap: {:?}", e);
                break;
            }
        }
    }

    serial_println!("[WASM_AGENT] WASM execution complete, yielding forever");
    loop {
        syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
    }
}
