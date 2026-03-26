//! Utility functions for querying module exports and resolving cross-module
//! function references. These are building blocks used by embedders when
//! linking multi-module WASM programs.

use alloc::string::String;
use alloc::vec::Vec;
use crate::wasm::decoder::{ExportKind, FuncDef, FuncTypeDef, ImportKind, WasmModule};

/// Return the global index of a named export, if it exists.
pub fn exported_global_index(module: &WasmModule, name: &str) -> Option<u32> {
    for export in &module.exports {
        if module.get_name(export.name_offset, export.name_len) == name.as_bytes() {
            if let ExportKind::Global(idx) = export.kind {
                return Some(idx);
            }
        }
    }
    None
}

/// Return the table index of a named export, if it exists.
pub fn exported_table_index(module: &WasmModule, name: &str) -> Option<u32> {
    for export in &module.exports {
        if module.get_name(export.name_offset, export.name_len) == name.as_bytes() {
            if let ExportKind::Table(idx) = export.kind {
                return Some(idx);
            }
        }
    }
    None
}

/// Return the memory index of a named export, if it exists.
pub fn exported_memory_index(module: &WasmModule, name: &str) -> Option<u32> {
    for export in &module.exports {
        if module.get_name(export.name_offset, export.name_len) == name.as_bytes() {
            if let ExportKind::Memory(idx) = export.kind {
                return Some(idx);
            }
        }
    }
    None
}

/// Convert a byte slice (typically from `WasmModule::get_name`) to an owned String.
pub fn bytes_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Look up the n-th function import in a module.
pub fn nth_function_import(module: &WasmModule, func_idx: u32) -> Option<&crate::wasm::decoder::ImportDef> {
    let mut seen = 0u32;
    for import in &module.imports {
        if let ImportKind::Func(_) = import.kind {
            if seen == func_idx {
                return Some(import);
            }
            seen = seen.saturating_add(1);
        }
    }
    None
}

/// Get the type index of a function (import or local).
pub fn function_type_idx(module: &WasmModule, func_idx: u32) -> Option<u32> {
    if (func_idx as usize) < module.func_import_count() {
        return module.func_import_type(func_idx);
    }
    let local_idx = (func_idx as usize).checked_sub(module.func_import_count())?;
    let func = module.functions.get(local_idx)?;
    Some(func.type_idx)
}

/// Get the FuncTypeDef for a function by index (works for both imports and locals).
pub fn function_type(module: &WasmModule, func_idx: u32) -> Option<&FuncTypeDef> {
    let type_idx = function_type_idx(module, func_idx)?;
    module.func_types.get(type_idx as usize)
}

/// Find a matching FuncTypeDef in the module's type list, or add a new one.
/// Returns the type index.
pub fn find_or_add_func_type(module: &mut WasmModule, ft: &FuncTypeDef) -> u32 {
    for (i, existing) in module.func_types.iter().enumerate() {
        if existing.param_count == ft.param_count
            && existing.result_count == ft.result_count
            && existing.params[..existing.param_count as usize] == ft.params[..ft.param_count as usize]
            && existing.results[..existing.result_count as usize] == ft.results[..ft.result_count as usize]
        {
            return i as u32;
        }
    }
    let idx = module.func_types.len() as u32;
    module.func_types.push(ft.clone());
    idx
}

/// Copy a local function body from `src_module` into `host_module`.
/// Returns the new function index in host_module's index space.
/// For imports, returns `func_idx` unchanged (caller must resolve via instances).
pub fn copy_function_from_module(
    host_module: &mut WasmModule,
    src_module: &WasmModule,
    func_idx: u32,
) -> u32 {
    let src_import_count = src_module.func_import_count();
    if (func_idx as usize) >= src_import_count {
        let local_idx = (func_idx as usize) - src_import_count;
        if local_idx < src_module.functions.len() {
            let src_func = &src_module.functions[local_idx];
            let source_ft = if (src_func.type_idx as usize) < src_module.func_types.len() {
                src_module.func_types[src_func.type_idx as usize].clone()
            } else {
                FuncTypeDef::empty()
            };
            let host_type_idx = find_or_add_func_type(host_module, &source_ft);
            let host_code_offset = host_module.code.len();
            let code_start = src_func.code_offset;
            let code_len = src_func.code_len;
            if code_start + code_len <= src_module.code.len() {
                host_module.code.extend_from_slice(&src_module.code[code_start..code_start + code_len]);
            }
            host_module.functions.push(FuncDef {
                type_idx: host_type_idx,
                code_offset: host_code_offset,
                code_len,
                local_count: src_func.local_count,
                locals: src_func.locals,
                non_nullable_locals: Vec::new(),
            });
            return host_module.func_import_count() as u32
                + (host_module.functions.len() as u32 - 1);
        }
    }
    // For imports, we can't reliably resolve without instance info
    func_idx
}

