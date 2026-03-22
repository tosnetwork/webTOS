//! Host function bindings — bridges WASM imports to AOS syscalls.
//!
//! When a WASM module calls an imported function, the interpreter pauses
//! and returns a `HostCall` result. This module provides the logic to
//! resolve that call based on the import's module/field names.

use crate::wasm::decoder::WasmModule;
use crate::wasm::runtime::WasmInstance;
use crate::wasm::types::*;

// ─── Well-known import names ────────────────────────────────────────────────

const MOD_AOS: &[u8] = b"aos";

const FN_SYS_YIELD: &[u8] = b"sys_yield";
const FN_SYS_SEND: &[u8] = b"sys_send";
const FN_SYS_RECV: &[u8] = b"sys_recv";
const FN_SYS_EXIT: &[u8] = b"sys_exit";
const FN_SYS_ENERGY_GET: &[u8] = b"sys_energy_get";
const FN_LOG: &[u8] = b"log";

// ─── Host call identifiers ─────────────────────────────────────────────────

/// Identifies a resolved host function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostFunc {
    SysYield,
    SysSend,
    SysRecv,
    SysExit,
    SysEnergyGet,
    Log,
    Unknown,
}

/// Resolve an import index to a `HostFunc` by examining the import names.
pub fn resolve_import(module: &WasmModule, import_idx: u32) -> HostFunc {
    let idx = import_idx as usize;
    if idx >= module.import_count {
        return HostFunc::Unknown;
    }

    let imp = match &module.imports[idx] {
        Some(imp) => imp,
        None => return HostFunc::Unknown,
    };

    let mod_name = module.get_name(imp.module_name_offset, imp.module_name_len);
    let field_name = module.get_name(imp.field_name_offset, imp.field_name_len);

    if mod_name != MOD_AOS {
        return HostFunc::Unknown;
    }

    if field_name == FN_SYS_YIELD {
        HostFunc::SysYield
    } else if field_name == FN_SYS_SEND {
        HostFunc::SysSend
    } else if field_name == FN_SYS_RECV {
        HostFunc::SysRecv
    } else if field_name == FN_SYS_EXIT {
        HostFunc::SysExit
    } else if field_name == FN_SYS_ENERGY_GET {
        HostFunc::SysEnergyGet
    } else if field_name == FN_LOG {
        HostFunc::Log
    } else {
        HostFunc::Unknown
    }
}

/// Handle a host function call.
///
/// This is called when the interpreter encounters a `HostCall` result.
/// It resolves the import, executes the host logic, and returns an
/// optional value to push back onto the WASM stack.
///
/// # Arguments
///
/// * `instance` — the running WASM instance (for memory access)
/// * `import_idx` — the import index from the `HostCall`
/// * `args` — the arguments popped from the WASM stack
/// * `arg_count` — number of valid entries in `args`
///
/// # Returns
///
/// `Ok(Some(value))` — push this value onto the WASM stack and resume
/// `Ok(None)` — resume with no return value
/// `Err(e)` — trap the WASM instance
pub fn handle_host_call(
    instance: &mut WasmInstance,
    import_idx: u32,
    args: &[Value],
    _arg_count: u8,
) -> Result<Option<Value>, WasmError> {
    let func = resolve_import(&instance.module, import_idx);

    match func {
        HostFunc::SysYield => {
            // sys_yield() -> i32
            // In a real kernel, this would yield the current agent's timeslice.
            // For now, return 0 (success).
            Ok(Some(Value::I32(0)))
        }

        HostFunc::SysSend => {
            // sys_send(mailbox_id: i32, ptr: i32, len: i32) -> i32
            let _mailbox_id = args[0].as_i32();
            let ptr = args[1].as_i32() as usize;
            let len = args[2].as_i32() as usize;

            // Validate memory bounds
            if ptr + len > instance.memory_size {
                return Err(WasmError::MemoryOutOfBounds);
            }

            // The actual send would go through the kernel mailbox subsystem.
            // For now, just validate and return success.
            let _ = &instance.memory[ptr..ptr + len];
            Ok(Some(Value::I32(0)))
        }

        HostFunc::SysRecv => {
            // sys_recv(mailbox_id: i32, ptr: i32, capacity: i32) -> i32
            let _mailbox_id = args[0].as_i32();
            let ptr = args[1].as_i32() as usize;
            let capacity = args[2].as_i32() as usize;

            // Validate memory bounds
            if ptr + capacity > instance.memory_size {
                return Err(WasmError::MemoryOutOfBounds);
            }

            // The actual recv would read from the kernel mailbox.
            // For now, return 0 (no message available).
            Ok(Some(Value::I32(0)))
        }

        HostFunc::SysExit => {
            // sys_exit(code: i32)
            // Mark the instance as finished. The exit code is on args[0].
            instance.finished = true;
            // Return the exit code — the caller will handle it.
            Ok(Some(Value::I32(args[0].as_i32())))
        }

        HostFunc::SysEnergyGet => {
            // sys_energy_get() -> i64
            // Return remaining fuel as the energy value.
            Ok(Some(Value::I64(instance.fuel as i64)))
        }

        HostFunc::Log => {
            // log(ptr: i32, len: i32)
            // Read a UTF-8 string from WASM memory and print it to serial.
            let ptr = args[0].as_i32() as usize;
            let len = args[1].as_i32() as usize;

            if ptr + len > instance.memory_size {
                return Err(WasmError::MemoryOutOfBounds);
            }

            // In a real kernel, this would write to the serial console.
            // The bytes are at instance.memory[ptr..ptr+len].
            // We can't call println! in no_std without a logger, so this
            // is a no-op stub that validates the memory range.
            let _msg_bytes = &instance.memory[ptr..ptr + len];

            Ok(None) // log returns void
        }

        HostFunc::Unknown => {
            Err(WasmError::ImportNotFound(import_idx))
        }
    }
}
