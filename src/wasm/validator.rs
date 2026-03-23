//! WASM module validator.
//!
//! Performs basic structural validation of a decoded WASM module.
//! This is a minimal validator — it checks that indices are in range,
//! types exist, and code references are valid.

use crate::wasm::decoder::WasmModule;
use crate::wasm::types::WasmError;

/// Validate a decoded WASM module.
///
/// Checks:
/// - All function type indices refer to existing types
/// - All import type indices refer to existing types
/// - All export function indices refer to existing functions (including imports)
/// - Memory pages are within limits
pub fn validate(module: &WasmModule) -> Result<(), WasmError> {
    // Validate function type indices
    for func in &module.functions {
        if func.type_idx as usize >= module.func_types.len() {
            return Err(WasmError::FunctionNotFound(func.type_idx));
        }
    }

    // Validate import type indices
    for imp in &module.imports {
        match imp.kind {
            crate::wasm::decoder::ImportKind::Func(type_idx) => {
                if type_idx as usize >= module.func_types.len() {
                    return Err(WasmError::FunctionNotFound(type_idx));
                }
            }
        }
    }

    // Validate export function indices
    let total_functions = module.imports.len() + module.functions.len();
    for exp in &module.exports {
        match exp.kind {
            crate::wasm::decoder::ExportKind::Func(idx) => {
                if idx as usize >= total_functions {
                    return Err(WasmError::FunctionNotFound(idx));
                }
            }
        }
    }

    // Validate memory limits
    if module.memory_min_pages > crate::wasm::types::MAX_MEMORY_PAGES as u32 {
        return Err(WasmError::MemoryOutOfBounds);
    }

    Ok(())
}
