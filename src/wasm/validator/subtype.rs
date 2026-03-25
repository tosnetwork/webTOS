//! Subtype checking, type equivalence, and reference type compatibility.

use crate::wasm::decoder::{GcTypeDef, StorageType, WasmModule};
use crate::wasm::decoder::ImportKind;
use crate::wasm::types::{ValType, WasmError};

/// Check if two types are ref-compatible (both ref types are interchangeable
/// for the purpose of global init validation when the global type is a ref type).
pub fn is_ref_compatible(a: ValType, b: ValType) -> bool {
    if a == b { return true; }
    // Typed func refs are subtypes of FuncRef
    let a_funcref_family = matches!(a, ValType::FuncRef | ValType::TypedFuncRef | ValType::NonNullableFuncRef | ValType::NullableTypedFuncRef | ValType::NullFuncRef);
    let b_funcref_family = matches!(b, ValType::FuncRef | ValType::TypedFuncRef | ValType::NonNullableFuncRef | ValType::NullableTypedFuncRef | ValType::NullFuncRef);
    if a_funcref_family && b_funcref_family { return true; }
    // externref family
    let a_externref_family = matches!(a, ValType::ExternRef | ValType::NullExternRef);
    let b_externref_family = matches!(b, ValType::ExternRef | ValType::NullExternRef);
    if a_externref_family && b_externref_family { return true; }
    // any hierarchy: NoneRef is compatible with any ref in the any hierarchy
    if (a == ValType::NoneRef || b == ValType::NoneRef) && (is_ref_type(a) && is_ref_type(b)) { return true; }
    false
}

/// Validate subtype declarations: each sub type must be structurally compatible
/// with its declared supertype.
pub fn validate_subtypes(module: &WasmModule) -> Result<(), WasmError> {
    for (idx, sub_info) in module.sub_types.iter().enumerate() {
        if let Some(super_idx) = sub_info.supertype {
            let super_idx = super_idx as usize;
            if super_idx >= module.gc_types.len() {
                return Err(WasmError::TypeMismatch);
            }
            // Supertype must not be final
            if super_idx < module.sub_types.len() && module.sub_types[super_idx].is_final {
                return Err(WasmError::TypeMismatch);
            }
            let sub_gc = &module.gc_types[idx];
            let super_gc = &module.gc_types[super_idx];
            match (sub_gc, super_gc) {
                (GcTypeDef::Struct { field_types: sub_ft, field_muts: sub_fm },
                 GcTypeDef::Struct { field_types: super_ft, field_muts: super_fm }) => {
                    // Subtype must have at least as many fields
                    if sub_ft.len() < super_ft.len() {
                        return Err(WasmError::TypeMismatch);
                    }
                    // Each supertype field must match
                    for i in 0..super_ft.len() {
                        let sub_mut = sub_fm.get(i).copied().unwrap_or(false);
                        let super_mut = super_fm.get(i).copied().unwrap_or(false);
                        // Mutability must match
                        if sub_mut != super_mut {
                            return Err(WasmError::TypeMismatch);
                        }
                        // For mutable fields: types must match exactly (invariant)
                        // For immutable fields: sub field must be subtype of super field (covariant)
                        if sub_mut {
                            // Invariant: must be exact match
                            if !storage_type_eq(&sub_ft[i], &super_ft[i]) {
                                return Err(WasmError::TypeMismatch);
                            }
                        } else {
                            // Covariant: sub field type must be subtype of super field type
                            if !storage_type_subtype(&sub_ft[i], &super_ft[i]) {
                                return Err(WasmError::TypeMismatch);
                            }
                        }
                    }
                }
                (GcTypeDef::Array { elem_type: sub_et, elem_mutable: sub_em },
                 GcTypeDef::Array { elem_type: super_et, elem_mutable: super_em }) => {
                    // Mutability must match
                    if sub_em != super_em {
                        return Err(WasmError::TypeMismatch);
                    }
                    if *sub_em {
                        // Invariant
                        if !storage_type_eq(sub_et, super_et) {
                            return Err(WasmError::TypeMismatch);
                        }
                    } else {
                        // Covariant
                        if !storage_type_subtype(sub_et, super_et) {
                            return Err(WasmError::TypeMismatch);
                        }
                    }
                }
                (GcTypeDef::Func, GcTypeDef::Func) => {
                    // Func subtyping: check param/result types
                    if idx < module.func_types.len() && super_idx < module.func_types.len() {
                        let sub_ft = &module.func_types[idx];
                        let super_ft = &module.func_types[super_idx];
                        // Param/result counts must match (for nominal subtyping in GC)
                        if sub_ft.param_count != super_ft.param_count || sub_ft.result_count != super_ft.result_count {
                            return Err(WasmError::TypeMismatch);
                        }
                        // Params are contravariant, results are covariant
                        for i in 0..sub_ft.param_count as usize {
                            if !val_is_subtype(super_ft.params[i], sub_ft.params[i]) {
                                return Err(WasmError::TypeMismatch);
                            }
                        }
                        for i in 0..sub_ft.result_count as usize {
                            if !val_is_subtype(sub_ft.results[i], super_ft.results[i]) {
                                return Err(WasmError::TypeMismatch);
                            }
                        }
                    }
                }
                _ => {
                    // Mismatched kinds (e.g., struct sub of array)
                    return Err(WasmError::TypeMismatch);
                }
            }
        }
    }
    Ok(())
}

/// Check if two storage types are equal.
pub fn storage_type_eq(a: &StorageType, b: &StorageType) -> bool {
    match (a, b) {
        (StorageType::I8, StorageType::I8) => true,
        (StorageType::I16, StorageType::I16) => true,
        (StorageType::Val(va), StorageType::Val(vb)) => va == vb,
        (StorageType::RefType(va, ai), StorageType::RefType(vb, bi)) => va == vb && ai == bi,
        (StorageType::Val(va), StorageType::RefType(vb, _)) | (StorageType::RefType(va, _), StorageType::Val(vb)) => va == vb,
        _ => false,
    }
}

/// Check if storage type `a` is a subtype of storage type `b`.
pub fn storage_type_subtype(a: &StorageType, b: &StorageType) -> bool {
    match (a, b) {
        (StorageType::I8, StorageType::I8) => true,
        (StorageType::I16, StorageType::I16) => true,
        (StorageType::Val(va), StorageType::Val(vb)) => val_is_subtype(*va, *vb),
        (StorageType::RefType(va, ai), StorageType::RefType(vb, bi)) => {
            if ai == bi { true } else { val_is_subtype(*va, *vb) }
        }
        (StorageType::Val(va), StorageType::RefType(vb, _)) | (StorageType::RefType(va, _), StorageType::Val(vb)) => val_is_subtype(*va, *vb),
        _ => false,
    }
}

/// Validate an init expression used in a data or element segment offset.
pub fn validate_init_expr_for_segment(
    info: &crate::wasm::decoder::InitExprInfo,
    global_import_count: usize,
    _total_globals: usize,
    module: &WasmModule,
    expected_type: ValType,
) -> Result<(), WasmError> {
    // Check global references
    if let Some(ref_idx) = info.global_ref {
        let total_globals = global_import_count + module.globals.len();
        if module.gc_enabled {
            // GC: allow any global
            if ref_idx as usize >= total_globals {
                return Err(WasmError::GlobalIndexOutOfBounds);
            }
        } else {
            // Non-GC: only imported globals allowed
            if ref_idx as usize >= global_import_count {
                return Err(WasmError::GlobalIndexOutOfBounds);
            }
        }
        // Referenced global must be immutable
        if (ref_idx as usize) < global_import_count {
            let mut gi: usize = 0;
            for imp in &module.imports {
                if let ImportKind::Global(_, mutable, _) = imp.kind {
                    if gi == ref_idx as usize {
                        if mutable {
                            return Err(WasmError::ConstExprRequired);
                        }
                        break;
                    }
                    gi += 1;
                }
            }
        } else if module.gc_enabled {
            let local_idx = ref_idx as usize - global_import_count;
            if local_idx < module.globals.len() && module.globals[local_idx].mutable {
                return Err(WasmError::ConstExprRequired);
            }
        }
    }
    // Check for non-constant instructions
    if info.has_non_const {
        return Err(WasmError::ConstExprRequired);
    }
    // Check expression type: must produce exactly 1 value of expected type
    if info.stack_depth != 1 {
        return Err(WasmError::TypeMismatch);
    }
    if let Some(result_type) = info.result_type {
        if result_type != expected_type {
            return Err(WasmError::TypeMismatch);
        }
    }
    // If result_type is None, it came from a global.get - we can't check the type
    // without looking up the global. For now, trust it.
    Ok(())
}

/// Get the element type of a table by index (including imported tables).
pub fn table_elem_type(module: &WasmModule, table_idx: u32, table_import_count: usize) -> ValType {
    if (table_idx as usize) < table_import_count {
        let mut ti = 0usize;
        for imp in &module.imports {
            if let ImportKind::Table(et) = imp.kind {
                if ti == table_idx as usize {
                    return et;
                }
                ti += 1;
            }
        }
        ValType::FuncRef
    } else {
        let local_idx = table_idx as usize - table_import_count;
        if local_idx < module.tables.len() {
            module.tables[local_idx].elem_type
        } else {
            ValType::FuncRef
        }
    }
}

/// Get the index type of a table (I32 for normal, I64 for table64).
pub fn table_index_type(module: &WasmModule, table_idx: u32) -> ValType {
    if (table_idx as usize) < module.tables.len() && module.tables[table_idx as usize].is_table64 {
        ValType::I64
    } else {
        ValType::I32
    }
}

/// Check if source ref type is compatible with destination ref type.
/// Subtyping: non-nullable is subtype of nullable, typed is subtype of abstract.
pub fn ref_types_compatible(src: ValType, dst: ValType) -> bool {
    // Use the comprehensive subtype check
    val_is_subtype(src, dst)
}

/// Check if a type is a non-nullable reference type (requires initialization).
pub fn is_non_nullable_ref(t: ValType) -> bool {
    matches!(t, ValType::TypedFuncRef | ValType::NonNullableFuncRef | ValType::StructRef | ValType::ArrayRef)
}

pub fn val_is_subtype(src: ValType, dst: ValType) -> bool {
    if src == dst { return true; }
    match (src, dst) {
        // FuncRef family: concrete_typed <: non_null_func <: nullable_typed <: funcref
        // (ref $t) <: (ref func) <: (ref null $t) <: (ref null func) = funcref
        (ValType::TypedFuncRef, ValType::NonNullableFuncRef | ValType::NullableTypedFuncRef | ValType::FuncRef) => true,
        (ValType::NonNullableFuncRef, ValType::FuncRef) => true,
        (ValType::NullableTypedFuncRef, ValType::FuncRef) => true,
        // NullFuncRef (nofunc) is bottom of func hierarchy — subtype of all nullable func types
        (ValType::NullFuncRef, ValType::FuncRef | ValType::NullableTypedFuncRef) => true,
        // NullExternRef (noextern) is bottom of extern hierarchy
        (ValType::NullExternRef, ValType::ExternRef) => true,
        // NoneRef (none) is bottom of any hierarchy — subtype of all nullable any-related ref types
        (ValType::NoneRef, d) if is_any_hierarchy(d) => true,
        // GC ref hierarchy: non-nullable subtypes
        // (ref i31) <: (ref eq) <: (ref any)
        (ValType::I31Ref, ValType::EqRef | ValType::AnyRef | ValType::NullableEqRef | ValType::NullableAnyRef) => true,
        // (ref struct) <: (ref eq), (ref struct) <: (ref any), etc.
        (ValType::StructRef, ValType::EqRef | ValType::AnyRef | ValType::NullableStructRef | ValType::NullableEqRef | ValType::NullableAnyRef) => true,
        // (ref null struct) <: (ref null eq) <: (ref null any) — nullable only to nullable
        (ValType::NullableStructRef, ValType::NullableEqRef | ValType::NullableAnyRef) => true,
        // (ref array) <: (ref eq), etc.
        (ValType::ArrayRef, ValType::EqRef | ValType::AnyRef | ValType::NullableArrayRef | ValType::NullableEqRef | ValType::NullableAnyRef) => true,
        // (ref null array) <: (ref null eq) <: (ref null any)
        (ValType::NullableArrayRef, ValType::NullableEqRef | ValType::NullableAnyRef) => true,
        // (ref eq) <: (ref any), (ref eq) <: (ref null eq), (ref eq) <: (ref null any)
        (ValType::EqRef, ValType::AnyRef | ValType::NullableEqRef | ValType::NullableAnyRef) => true,
        // (ref null eq) <: (ref null any)
        (ValType::NullableEqRef, ValType::NullableAnyRef) => true,
        // (ref any) <: (ref null any)
        (ValType::AnyRef, ValType::NullableAnyRef) => true,
        // Concrete GC refs (encoded as TypedFuncRef/NullableTypedFuncRef for non-func types)
        // Non-nullable concrete refs are subtypes of non-nullable and nullable abstract types
        (ValType::TypedFuncRef,
         ValType::AnyRef | ValType::NullableAnyRef | ValType::EqRef | ValType::NullableEqRef |
         ValType::StructRef | ValType::NullableStructRef | ValType::ArrayRef | ValType::NullableArrayRef |
         ValType::I31Ref) => true,
        // Nullable concrete refs are subtypes of only nullable abstract types
        (ValType::NullableTypedFuncRef,
         ValType::NullableAnyRef | ValType::NullableEqRef |
         ValType::NullableStructRef | ValType::NullableArrayRef) => true,
        _ => false,
    }
}

/// Check if a type is in the "any" hierarchy (subtypes of anyref).
pub fn is_any_hierarchy(t: ValType) -> bool {
    matches!(t, ValType::AnyRef | ValType::NullableAnyRef
        | ValType::EqRef | ValType::NullableEqRef
        | ValType::I31Ref
        | ValType::StructRef | ValType::NullableStructRef
        | ValType::ArrayRef | ValType::NullableArrayRef
        | ValType::NoneRef
        | ValType::TypedFuncRef | ValType::NullableTypedFuncRef)
}

/// Check if `src` is a subtype of `dst` (src <: dst).
/// Used for validating try_table catch clause label types.
pub fn is_subtype(src: ValType, dst: ValType) -> bool {
    val_is_subtype(src, dst)
}

/// Check if type index `src` is a declared subtype of type index `dst`
/// by walking the subtype chain in the module's subtype_info.
/// Uses rec-group-aware type equivalence.
pub fn is_type_index_subtype(src: u32, dst: u32, module: &WasmModule) -> bool {
    if src == dst { return true; }
    if types_equivalent_in_module(module, src, dst) { return true; }
    let mut current = src;
    for _ in 0..100 {
        if let Some(info) = module.sub_types.get(current as usize) {
            if let Some(parent) = info.supertype {
                if parent == dst || types_equivalent_in_module(module, parent, dst) {
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

/// Check if two type indices in the same module refer to equivalent types,
/// taking rec group structure into account.
pub fn types_equivalent_in_module(module: &WasmModule, a: u32, b: u32) -> bool {
    if a == b { return true; }
    types_equivalent_in_module_depth(module, a, b, 0)
}

fn types_equivalent_in_module_depth(module: &WasmModule, a: u32, b: u32, depth: u32) -> bool {
    if a == b { return true; }
    if depth > 10 { return false; }
    let si_a = match module.sub_types.get(a as usize) { Some(s) => s, None => return false };
    let si_b = match module.sub_types.get(b as usize) { Some(s) => s, None => return false };
    if si_a.rec_group_size != si_b.rec_group_size { return false; }
    let pos_a = a - si_a.rec_group_start;
    let pos_b = b - si_b.rec_group_start;
    if pos_a != pos_b { return false; }
    if si_a.rec_group_start == si_b.rec_group_start { return false; }
    let rg_a = si_a.rec_group_start;
    let rg_b = si_b.rec_group_start;
    let rg_size = si_a.rec_group_size;
    for i in 0..rg_size {
        if !rec_group_entry_equivalent(module, rg_a + i, rg_a, rg_b + i, rg_b, rg_size, depth) {
            return false;
        }
    }
    true
}

fn rec_group_entry_equivalent(
    module: &WasmModule, idx_a: u32, rg_a: u32, idx_b: u32, rg_b: u32, rg_size: u32, depth: u32,
) -> bool {
    let si_a = module.sub_types.get(idx_a as usize);
    let si_b = module.sub_types.get(idx_b as usize);
    match (si_a, si_b) {
        (Some(sa), Some(sb)) => {
            if sa.is_final != sb.is_final { return false; }
            match (sa.supertype, sb.supertype) {
                (None, None) => {}
                (Some(sp_a), Some(sp_b)) => {
                    let in_a = sp_a >= rg_a && sp_a < rg_a + rg_size;
                    let in_b = sp_b >= rg_b && sp_b < rg_b + rg_size;
                    if in_a && in_b { if (sp_a - rg_a) != (sp_b - rg_b) { return false; } }
                    else if !in_a && !in_b { if sp_a != sp_b && !types_equivalent_in_module_depth(module, sp_a, sp_b, depth + 1) { return false; } }
                    else { return false; }
                }
                _ => return false,
            }
        }
        (None, None) => {}
        _ => return false,
    }
    let gc_a = module.gc_types.get(idx_a as usize);
    let gc_b = module.gc_types.get(idx_b as usize);
    match (gc_a, gc_b) {
        (Some(GcTypeDef::Func), Some(GcTypeDef::Func)) => {
            if let (Some(fa), Some(fb)) = (module.func_types.get(idx_a as usize), module.func_types.get(idx_b as usize)) {
                if fa.param_count != fb.param_count || fa.result_count != fb.result_count { return false; }
                for i in 0..fa.param_count as usize { if fa.params[i] != fb.params[i] { return false; } }
                for i in 0..fa.result_count as usize { if fa.results[i] != fb.results[i] { return false; } }
            }
        }
        (Some(GcTypeDef::Struct { field_types: ft_a, field_muts: fm_a }),
         Some(GcTypeDef::Struct { field_types: ft_b, field_muts: fm_b })) => {
            if ft_a.len() != ft_b.len() || fm_a != fm_b { return false; }
            for i in 0..ft_a.len() {
                if !storage_types_rec_eq(module, &ft_a[i], rg_a, &ft_b[i], rg_b, rg_size, depth) { return false; }
            }
        }
        (Some(GcTypeDef::Array { elem_type: et_a, elem_mutable: em_a }),
         Some(GcTypeDef::Array { elem_type: et_b, elem_mutable: em_b })) => {
            if em_a != em_b { return false; }
            if !storage_types_rec_eq(module, et_a, rg_a, et_b, rg_b, rg_size, depth) { return false; }
        }
        (None, None) => {
            if let (Some(fa), Some(fb)) = (module.func_types.get(idx_a as usize), module.func_types.get(idx_b as usize)) {
                if fa.param_count != fb.param_count || fa.result_count != fb.result_count { return false; }
                for i in 0..fa.param_count as usize { if fa.params[i] != fb.params[i] { return false; } }
                for i in 0..fa.result_count as usize { if fa.results[i] != fb.results[i] { return false; } }
            }
        }
        _ => return false,
    }
    true
}

fn storage_types_rec_eq(
    module: &WasmModule, a: &StorageType, rg_a: u32,
    b: &StorageType, rg_b: u32, rg_size: u32, depth: u32,
) -> bool {
    match (a, b) {
        (StorageType::I8, StorageType::I8) | (StorageType::I16, StorageType::I16) => true,
        (StorageType::Val(va), StorageType::Val(vb)) => va == vb,
        (StorageType::RefType(va, ai), StorageType::RefType(vb, bi)) => {
            if va != vb { return false; }
            let in_a = *ai >= rg_a && *ai < rg_a + rg_size;
            let in_b = *bi >= rg_b && *bi < rg_b + rg_size;
            if in_a && in_b { (ai - rg_a) == (bi - rg_b) }
            else if !in_a && !in_b { ai == bi || types_equivalent_in_module_depth(module, *ai, *bi, depth + 1) }
            else { false }
        }
        _ => false,
    }
}

/// Check if a ValType is a reference type.
pub fn is_ref_type(t: ValType) -> bool {
    matches!(t, ValType::FuncRef | ValType::ExternRef | ValType::TypedFuncRef | ValType::NonNullableFuncRef | ValType::NullableTypedFuncRef
        | ValType::AnyRef | ValType::NullableAnyRef | ValType::EqRef | ValType::NullableEqRef | ValType::I31Ref
        | ValType::StructRef | ValType::NullableStructRef
        | ValType::ArrayRef | ValType::NullableArrayRef
        | ValType::NoneRef | ValType::NullFuncRef | ValType::NullExternRef | ValType::ExnRef)
}
