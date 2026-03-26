//! Import validation and cross-module type comparison for multi-module linking.
//!
//! These functions compare types between modules to determine if import/export
//! pairs are compatible, handling rec groups, GC types, and subtyping.

use crate::wasm::decoder::{FuncTypeDef, GcTypeDef, StorageType, WasmModule};
use crate::wasm::types::{ValType, Value};

/// Check if two FuncTypeDefs are structurally identical.
pub fn func_types_match(a: &FuncTypeDef, b: &FuncTypeDef) -> bool {
    if a.param_count != b.param_count || a.result_count != b.result_count {
        return false;
    }
    for i in 0..a.param_count as usize {
        if a.params[i] != b.params[i] {
            return false;
        }
    }
    for i in 0..a.result_count as usize {
        if a.results[i] != b.results[i] {
            return false;
        }
    }
    true
}

/// Check if two type indices (from potentially different modules) refer to
/// equivalent types, taking rec group structure into account.
/// Two types are equivalent iff:
/// 1. They are at the same position within their respective rec groups
/// 2. Their rec groups have the same size
/// 3. All corresponding types in the rec groups are structurally equivalent
pub fn type_indices_equivalent(
    mod_a: &WasmModule, type_idx_a: u32,
    mod_b: &WasmModule, type_idx_b: u32,
) -> bool {
    let si_a = mod_a.sub_types.get(type_idx_a as usize);
    let si_b = mod_b.sub_types.get(type_idx_b as usize);
    match (si_a, si_b) {
        (Some(a), Some(b)) => {
            // Must be in rec groups of the same size
            if a.rec_group_size != b.rec_group_size {
                return false;
            }
            // Must be at the same position within the rec group
            let pos_a = type_idx_a - a.rec_group_start;
            let pos_b = type_idx_b - b.rec_group_start;
            if pos_a != pos_b {
                return false;
            }
            // All types in the rec group must be structurally equivalent
            for i in 0..a.rec_group_size {
                let idx_a = a.rec_group_start + i;
                let idx_b = b.rec_group_start + i;
                let ft_a = mod_a.func_types.get(idx_a as usize);
                let ft_b = mod_b.func_types.get(idx_b as usize);
                match (ft_a, ft_b) {
                    (Some(fa), Some(fb)) => {
                        if !func_types_match(fa, fb) {
                            return false;
                        }
                    }
                    _ => return false,
                }
                // Check gc_types match (with rec-group-relative type references)
                let gc_a = mod_a.gc_types.get(idx_a as usize);
                let gc_b = mod_b.gc_types.get(idx_b as usize);
                match (gc_a, gc_b) {
                    (Some(GcTypeDef::Struct { field_types: ft_a, field_muts: fm_a }),
                     Some(GcTypeDef::Struct { field_types: ft_b, field_muts: fm_b })) => {
                        if ft_a.len() != ft_b.len() || fm_a != fm_b { return false; }
                        for fi in 0..ft_a.len() {
                            if !cross_module_storage_eq(&ft_a[fi], a.rec_group_start, mod_a,
                                                        &ft_b[fi], b.rec_group_start, mod_b,
                                                        a.rec_group_size) { return false; }
                        }
                    }
                    (Some(GcTypeDef::Array { elem_type: et_a, elem_mutable: em_a }),
                     Some(GcTypeDef::Array { elem_type: et_b, elem_mutable: em_b })) => {
                        if em_a != em_b { return false; }
                        if !cross_module_storage_eq(et_a, a.rec_group_start, mod_a,
                                                    et_b, b.rec_group_start, mod_b,
                                                    a.rec_group_size) { return false; }
                    }
                    (Some(ga), Some(gb)) => {
                        if core::mem::discriminant(ga) != core::mem::discriminant(gb) { return false; }
                    }
                    (None, None) => {}
                    _ => return false,
                }
                // Check subtype info matches
                let si_a_i = mod_a.sub_types.get(idx_a as usize);
                let si_b_i = mod_b.sub_types.get(idx_b as usize);
                match (si_a_i, si_b_i) {
                    (Some(sa), Some(sb)) => {
                        if sa.is_final != sb.is_final { return false; }
                        match (sa.supertype, sb.supertype) {
                            (None, None) => {}
                            (Some(sp_a), Some(sp_b)) => {
                                let in_rg_a = sp_a >= a.rec_group_start && sp_a < a.rec_group_start + a.rec_group_size;
                                let in_rg_b = sp_b >= b.rec_group_start && sp_b < b.rec_group_start + b.rec_group_size;
                                if in_rg_a && in_rg_b {
                                    // Both inside: compare relative positions
                                    if (sp_a - a.rec_group_start) != (sp_b - b.rec_group_start) { return false; }
                                } else if !in_rg_a && !in_rg_b {
                                    // Both outside: recursively check equivalence
                                    if !type_indices_equivalent(mod_a, sp_a, mod_b, sp_b) { return false; }
                                } else {
                                    return false;
                                }
                            }
                            _ => return false,
                        }
                    }
                    _ => {}
                }
            }
            true
        }
        // If no subtype info, fall back to structural comparison
        _ => {
            match (mod_a.func_types.get(type_idx_a as usize), mod_b.func_types.get(type_idx_b as usize)) {
                (Some(fa), Some(fb)) => func_types_match(fa, fb),
                _ => false,
            }
        }
    }
}

/// Check if two storage types are equivalent across modules with rec-group awareness.
pub fn cross_module_storage_eq(
    a: &StorageType, rg_a: u32, mod_a: &WasmModule,
    b: &StorageType, rg_b: u32, mod_b: &WasmModule,
    rg_size: u32,
) -> bool {
    match (a, b) {
        (StorageType::I8, StorageType::I8) | (StorageType::I16, StorageType::I16) => true,
        (StorageType::Val(va), StorageType::Val(vb)) => va == vb,
        (StorageType::RefType(va, ai), StorageType::RefType(vb, bi)) => {
            if va != vb { return false; }
            let in_a = *ai >= rg_a && *ai < rg_a + rg_size;
            let in_b = *bi >= rg_b && *bi < rg_b + rg_size;
            if in_a && in_b { (ai - rg_a) == (bi - rg_b) }
            else if !in_a && !in_b { type_indices_equivalent(mod_a, *ai, mod_b, *bi) }
            else { false }
        }
        _ => false,
    }
}

/// Check if type `src` in `mod_src` is a subtype of type `dst` in `mod_dst`.
/// Handles cross-module rec-group-aware type equivalence and subtype chains.
pub fn cross_module_type_subtype(
    mod_src: &WasmModule, src: u32,
    mod_dst: &WasmModule, dst: u32,
) -> bool {
    // Check equivalence first
    if type_indices_equivalent(mod_src, src, mod_dst, dst) {
        return true;
    }
    // Walk the subtype chain in the source module
    let mut current = src;
    for _ in 0..100 {
        if let Some(info) = mod_src.sub_types.get(current as usize) {
            if let Some(parent) = info.supertype {
                if type_indices_equivalent(mod_src, parent, mod_dst, dst) {
                    return true;
                }
                current = parent;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
    false
}

/// Check if a global import type is compatible with an export type for linking.
/// For immutable globals, subtyping is allowed (import can be supertype of export).
/// For mutable globals, types must match exactly (invariance).
///
/// Heap type values: negative = abstract (-16=func, -17=extern, etc), non-negative = concrete type index.
pub fn global_types_compatible(
    import_val_type: ValType,
    import_byte: u8,
    import_heap_type: Option<i32>,
    export_val_type: ValType,
    export_heap_type: Option<i32>,
    mutable: bool,
) -> bool {
    fn is_funcref_family(t: ValType) -> bool {
        matches!(t, ValType::FuncRef | ValType::TypedFuncRef | ValType::NonNullableFuncRef | ValType::NullableTypedFuncRef)
    }
    fn is_externref_family(t: ValType) -> bool {
        matches!(t, ValType::ExternRef)
    }

    // Classify import
    let imp_is_abstract_func = is_funcref_family(import_val_type)
        || (matches!(import_byte, 0x63 | 0x64) && import_heap_type == Some(-16));
    let imp_is_abstract_extern = is_externref_family(import_val_type)
        || (matches!(import_byte, 0x63 | 0x64) && import_heap_type == Some(-17));
    let imp_is_concrete = matches!(import_byte, 0x63 | 0x64) && matches!(import_heap_type, Some(ht) if ht >= 0);
    let imp_nullable = import_byte != 0x64 && import_val_type != ValType::TypedFuncRef && import_val_type != ValType::NonNullableFuncRef;

    // Classify export
    let exp_is_concrete = matches!(export_heap_type, Some(ht) if ht >= 0);
    let exp_nullable = matches!(export_val_type, ValType::FuncRef | ValType::NullableTypedFuncRef | ValType::ExternRef);

    if mutable {
        // Mutable globals require exact type match (invariance).
        // Both abstract func with same nullability
        if imp_is_abstract_func && is_funcref_family(export_val_type) && !exp_is_concrete {
            return imp_nullable == exp_nullable;
        }
        // Both abstract extern
        if imp_is_abstract_extern && is_externref_family(export_val_type) {
            return true;
        }
        // Both concrete with same type index and nullability
        if imp_is_concrete && exp_is_concrete && import_heap_type == export_heap_type {
            return imp_nullable == exp_nullable;
        }
        return false;
    }

    // Immutable globals: import must be supertype of export.

    // Abstract func import
    if imp_is_abstract_func {
        if !is_funcref_family(export_val_type) {
            return false;
        }
        if imp_nullable {
            return true; // (ref null func) is supertype of all funcref-family
        } else {
            return !exp_nullable; // (ref func) is supertype of non-nullable funcref
        }
    }

    // Abstract extern import
    if imp_is_abstract_extern {
        return is_externref_family(export_val_type);
    }

    // Concrete import (ref null $t) / (ref $t)
    if imp_is_concrete {
        // Can only match concrete exports with same type index
        if exp_is_concrete && import_heap_type == export_heap_type {
            if imp_nullable {
                return true; // (ref null $t) accepts both (ref null $t) and (ref $t)
            } else {
                return !exp_nullable; // (ref $t) only accepts (ref $t)
            }
        }
        return false;
    }

    false
}

/// Decode a value type byte (from the binary format) into a ValType.
pub fn decode_valtype_byte(byte: u8) -> Option<ValType> {
    match byte {
        0x7F => Some(ValType::I32),
        0x7E => Some(ValType::I64),
        0x7D => Some(ValType::F32),
        0x7C => Some(ValType::F64),
        0x7B => Some(ValType::V128),
        0x70 => Some(ValType::FuncRef),
        0x6F => Some(ValType::ExternRef),
        // GC ref types: 0x63=nullable ref, 0x64=non-nullable ref
        // These are multi-byte in binary (followed by heap type), but
        // ImportKind::Global stores only the first byte. Accept as I32 (our ref sentinel).
        0x63 | 0x64 => Some(ValType::I32),
        0x69 => Some(ValType::ExnRef),
        _ => None,
    }
}

/// Check if two ref-like ValTypes are compatible for import linking.
/// In our simplified model (no full subtyping), we consider all funcref-ish types compatible.
pub fn ref_types_compatible(a: ValType, b: ValType) -> bool {
    fn is_funcref_ish(t: ValType) -> bool {
        matches!(t, ValType::FuncRef | ValType::TypedFuncRef | ValType::NonNullableFuncRef | ValType::NullableTypedFuncRef)
    }
    // Both funcref-ish types are compatible
    if is_funcref_ish(a) && is_funcref_ish(b) {
        return true;
    }
    // ExternRef only with ExternRef
    if a == ValType::ExternRef && b == ValType::ExternRef {
        return true;
    }
    false
}

/// Check if a value matches a given ValType (for import validation).
pub fn value_matches_type(value: Value, val_type: ValType) -> bool {
    matches!(
        (value, val_type),
        (Value::I32(_), ValType::I32)
            | (Value::I64(_), ValType::I64)
            | (Value::F32(_), ValType::F32)
            | (Value::F64(_), ValType::F64)
            | (Value::V128(_), ValType::V128)
            | (Value::I32(_), ValType::FuncRef)
            | (Value::I32(_), ValType::ExternRef)
            | (Value::I32(_), ValType::TypedFuncRef)
            | (Value::I32(_), ValType::NonNullableFuncRef)
            | (Value::I32(_), ValType::NullableTypedFuncRef)
            | (Value::NullRef, ValType::I32)
            | (Value::NullRef, ValType::FuncRef)
            | (Value::NullRef, ValType::ExternRef)
            | (Value::NullRef, ValType::TypedFuncRef)
            | (Value::NullRef, ValType::NonNullableFuncRef)
            | (Value::NullRef, ValType::NullableTypedFuncRef)
            | (Value::GcRef(_), ValType::I32)
            | (Value::GcRef(_), ValType::FuncRef)
            | (Value::GcRef(_), ValType::ExternRef)
    )
}
