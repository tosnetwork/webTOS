//! Host function bindings — bridges WASM imports to ATOS syscalls.
//!
//! When a WASM module calls an imported function, the interpreter pauses
//! and returns a `HostCall` result. This module provides the logic to
//! resolve that call based on the import's module/field names.

use crate::wasm::decoder::WasmModule;
use crate::wasm::runtime::WasmInstance;
use crate::wasm::types::*;

// ─── Well-known import names ────────────────────────────────────────────────

const MOD_ATOS: &[u8] = b"atos";

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
pub fn resolve_import(module: &WasmModule, func_idx: u32) -> HostFunc {
    let mut func_count: u32 = 0;
    let mut found_imp = None;
    for imp in module.get_imports() {
        if let crate::wasm::decoder::ImportKind::Func(_) = imp.kind {
            if func_count == func_idx {
                found_imp = Some(imp);
                break;
            }
            func_count = func_count.saturating_add(1);
        }
    }
    let imp = match found_imp {
        Some(i) => i,
        None => return HostFunc::Unknown,
    };

    let mod_name = module.get_name(imp.module_name_offset, imp.module_name_len);
    let field_name = module.get_name(imp.field_name_offset, imp.field_name_len);

    if mod_name != MOD_ATOS {
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
pub fn handle_host_call(
    instance: &mut WasmInstance,
    import_idx: u32,
    args: &[Value],
    _arg_count: u8,
) -> Result<Option<Value>, WasmError> {
    let func = resolve_import(instance.module(), import_idx);

    match func {
        HostFunc::SysYield => {
            Ok(Some(Value::I32(0)))
        }

        HostFunc::SysSend => {
            let _mailbox_id = args[0].as_i32();
            let ptr = args[1].as_i32() as usize;
            let len = args[2].as_i32() as usize;

            let end = ptr.checked_add(len).ok_or(WasmError::MemoryOutOfBounds)?;
            let mem_size = instance.get_memory_size(0).unwrap_or(0);
            if end > mem_size {
                return Err(WasmError::MemoryOutOfBounds);
            }

            let _ = &instance.get_memory(0).unwrap()[ptr..end];
            Ok(Some(Value::I32(0)))
        }

        HostFunc::SysRecv => {
            let _mailbox_id = args[0].as_i32();
            let ptr = args[1].as_i32() as usize;
            let capacity = args[2].as_i32() as usize;

            let end = ptr.checked_add(capacity).ok_or(WasmError::MemoryOutOfBounds)?;
            let mem_size = instance.get_memory_size(0).unwrap_or(0);
            if end > mem_size {
                return Err(WasmError::MemoryOutOfBounds);
            }

            Ok(Some(Value::I32(0)))
        }

        HostFunc::SysExit => {
            instance.set_finished(true);
            Ok(Some(Value::I32(args[0].as_i32())))
        }

        HostFunc::SysEnergyGet => {
            Ok(Some(Value::I64(instance.get_fuel() as i64)))
        }

        HostFunc::Log => {
            let ptr = args[0].as_i32() as usize;
            let len = args[1].as_i32() as usize;

            let end = ptr.checked_add(len).ok_or(WasmError::MemoryOutOfBounds)?;
            let mem_size = instance.get_memory_size(0).unwrap_or(0);
            if end > mem_size {
                return Err(WasmError::MemoryOutOfBounds);
            }

            let _msg_bytes = &instance.get_memory(0).unwrap()[ptr..end];

            Ok(None)
        }

        HostFunc::Unknown => {
            Err(WasmError::ImportNotFound(import_idx))
        }
    }
}
