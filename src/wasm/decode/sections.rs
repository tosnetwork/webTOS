//! Section decoding: parses each WASM binary section into module structures.

use alloc::vec;
use alloc::vec::Vec;
use crate::wasm::types::*;
use super::{
    WasmModule, FuncTypeDef, FuncDef, ImportDef, ImportKind, ExportDef, ExportKind,
    GlobalDef, TableDef, MemoryDef, DataSegment, ElementSegment, ElemMode,
    InitExprInfo, StorageType, GcTypeDef, SubTypeInfo,
};
use super::reader::{read_byte, peek_byte, read_name, decode_leb128_u32, decode_leb128_u64, decode_leb128_i32, decode_leb128_i64};
use super::init_expr::{skip_init_expr, eval_init_expr, scan_init_expr_global_refs, scan_init_expr_info, scan_init_expr_info_gc, eval_init_expr_with_globals};

// Re-export section constants for use in decode()
pub(super) const SECTION_TYPE: u8 = 1;
pub(super) const SECTION_IMPORT: u8 = 2;
pub(super) const SECTION_FUNCTION: u8 = 3;
pub(super) const SECTION_TABLE: u8 = 4;
pub(super) const SECTION_MEMORY: u8 = 5;
pub(super) const SECTION_GLOBAL: u8 = 6;
pub(super) const SECTION_EXPORT: u8 = 7;
pub(super) const SECTION_START: u8 = 8;
pub(super) const SECTION_ELEMENT: u8 = 9;
pub(super) const SECTION_CODE: u8 = 10;
pub(super) const SECTION_DATA: u8 = 11;
pub(super) const SECTION_DATA_COUNT: u8 = 12;
pub(super) const SECTION_TAG: u8 = 13;

/// Map section IDs to canonical ordering positions.
/// DataCount (12) must appear after Element (9) but before Code (10).
pub(super) fn section_order(id: u8) -> u8 {
    match id {
        0 => 0, // Custom sections don't participate in ordering
        SECTION_TYPE => 1,
        SECTION_IMPORT => 2,
        SECTION_FUNCTION => 3,
        SECTION_TABLE => 4,
        SECTION_MEMORY => 5,
        SECTION_TAG => 6,     // Tag section (exception handling) goes between Memory and Global
        SECTION_GLOBAL => 7,
        SECTION_EXPORT => 8,
        SECTION_START => 9,
        SECTION_ELEMENT => 10,
        SECTION_DATA_COUNT => 11,
        SECTION_CODE => 12,
        SECTION_DATA => 13,
        _ => 255,
    }
}

// ─── Section decoders ───────────────────────────────────────────────────────

fn decode_valtype(b: u8) -> Result<ValType, WasmError> {
    match b {
        0x7F => Ok(ValType::I32),
        0x7E => Ok(ValType::I64),
        0x7D => Ok(ValType::F32),
        0x7C => Ok(ValType::F64),
        0x7B => Ok(ValType::V128),
        0x70 => Ok(ValType::FuncRef),
        0x6F => Ok(ValType::ExternRef),
        0x6E => Ok(ValType::NullableAnyRef),
        0x6D => Ok(ValType::NullableEqRef),
        0x6C => Ok(ValType::I31Ref),
        0x6B => Ok(ValType::NullableStructRef),
        0x6A => Ok(ValType::NullableArrayRef),
        0x73 => Ok(ValType::NullFuncRef),    // nullfuncref = (ref null nofunc)
        0x72 => Ok(ValType::NullExternRef),  // nullexternref = (ref null noextern)
        0x71 => Ok(ValType::NoneRef),
        0x69 => Ok(ValType::ExnRef),
        0x74 => Ok(ValType::ExnRef),   // nullexnref = (ref null noexn)
        0x68 => Ok(ValType::AnyRef),   // contref
        _ => Err(WasmError::TypeMismatch),
    }
}

/// Decode a valtype from the bytecode stream, handling multi-byte reference types.
/// In the GC proposal, ref types can be encoded as:
/// - 0x63 <heaptype> (ref null ht)
/// - 0x64 <heaptype> (ref ht)
/// Heap types are encoded as signed LEB128 indices or abstract type bytes.
fn decode_valtype_from_stream(bytes: &[u8], pos: &mut usize) -> Result<ValType, WasmError> {
    let b = read_byte(bytes, pos)?;
    match b {
        0x7F => Ok(ValType::I32),
        0x7E => Ok(ValType::I64),
        0x7D => Ok(ValType::F32),
        0x7C => Ok(ValType::F64),
        0x7B => Ok(ValType::V128),
        0x70 => Ok(ValType::FuncRef),
        0x6F => Ok(ValType::ExternRef),
        // GC proposal shorthand encodings (single-byte, implicitly nullable):
        0x6E => Ok(ValType::NullableAnyRef),      // anyref = (ref null any)
        0x6D => Ok(ValType::NullableEqRef),       // eqref = (ref null eq)
        0x6C => Ok(ValType::I31Ref),              // i31ref = (ref null i31)
        0x6B => Ok(ValType::NullableStructRef),   // structref = (ref null struct)
        0x6A => Ok(ValType::NullableArrayRef),    // arrayref = (ref null array)
        0x73 => Ok(ValType::NullFuncRef),         // nullfuncref = (ref null nofunc)
        0x72 => Ok(ValType::NullExternRef),      // nullexternref = (ref null noextern)
        0x71 => Ok(ValType::NoneRef),             // nullref = (ref null none)
        0x69 => Ok(ValType::ExnRef),              // exnref = (ref null exn)
        0x74 => Ok(ValType::ExnRef),              // nullexnref = (ref null noexn)
        0x68 => Ok(ValType::AnyRef),              // contref = (ref null cont)
        0x63 | 0x64 => {
            let heap_type = decode_leb128_i32(bytes, pos)?;
            let nullable = b == 0x63;
            match heap_type {
                // Heap type constants (signed LEB128): -16=func, -17=extern,
                // -18=any, -19=eq, -20=i31, -21=struct, -22=array,
                // -13=nofunc, -14=noextern, -15=none, -23=exn, -12=noexn
                -17 => Ok(ValType::ExternRef),  // extern
                -16 => { // func
                    if nullable { Ok(ValType::FuncRef) } else { Ok(ValType::NonNullableFuncRef) }
                }
                -18 => if nullable { Ok(ValType::NullableAnyRef) } else { Ok(ValType::AnyRef) },
                -19 => if nullable { Ok(ValType::NullableEqRef) } else { Ok(ValType::EqRef) },
                -20 => Ok(ValType::I31Ref),     // i31
                -21 => if nullable { Ok(ValType::NullableStructRef) } else { Ok(ValType::StructRef) },
                -22 => if nullable { Ok(ValType::NullableArrayRef) } else { Ok(ValType::ArrayRef) },
                -15 => Ok(ValType::NoneRef),    // none
                -14 => Ok(ValType::NullExternRef),  // noextern
                -13 => Ok(ValType::NullFuncRef),    // nofunc
                -23 => Ok(ValType::ExnRef),     // exn
                -12 => Ok(ValType::ExnRef),     // noexn
                _ if heap_type >= 0 => {
                    // Concrete type index reference
                    if nullable { Ok(ValType::NullableTypedFuncRef) } else { Ok(ValType::TypedFuncRef) }
                }
                _ => Err(WasmError::TypeMismatch),
            }
        }
        _ => Err(WasmError::TypeMismatch),
    }
}

/// Returns true if the heap type (signed LEB128 value) indicates a GC-proposal type.
fn is_gc_heap_type(ht: i32) -> bool {
    // any=-18, eq=-19, i31=-20, struct=-21, array=-22,
    // none=-15, noextern=-14, nofunc=-13, exn=-23, noexn=-12
    matches!(ht, -18 | -19 | -20 | -21 | -22 | -15 | -14 | -13 | -23 | -12)
    || ht >= 0 // concrete type index reference is GC
}

/// Decode a valtype and set gc_enabled on the module if a GC heap type is seen.
fn decode_valtype_gc_aware(bytes: &[u8], pos: &mut usize, module: &mut WasmModule) -> Result<ValType, WasmError> {
    decode_valtype_gc_aware_with_limit(bytes, pos, module, u32::MAX)
}

/// Like decode_valtype_gc_aware but also validates that concrete type refs are < max_type_idx.
fn decode_valtype_gc_aware_with_limit(bytes: &[u8], pos: &mut usize, module: &mut WasmModule, max_type_idx: u32) -> Result<ValType, WasmError> {
    let saved = *pos;
    let b = read_byte(bytes, pos)?;
    if b == 0x63 || b == 0x64 {
        let ht = decode_leb128_i32(bytes, pos)?;
        if is_gc_heap_type(ht) {
            module.gc_enabled = true;
        }
        // Validate type reference is in range
        if ht >= 0 && (ht as u32) >= max_type_idx {
            return Err(WasmError::TypeMismatch);
        }
        // Track self-references (type idx == max_type_idx - 1 when max includes self)
        if ht >= 0 {
            let type_idx = ht as u32;
            let current_idx = module.func_types.len() as u32;
            if type_idx == current_idx {
                module.has_self_ref_types = true;
            }
        }
        // Reset and use the normal decoder
        *pos = saved;
        decode_valtype_from_stream(bytes, pos)
    } else {
        // GC shorthand reference types (single-byte) also enable GC:
        // 0x6E=anyref, 0x6D=eqref, 0x6C=i31ref, 0x6B=structref, 0x6A=arrayref,
        // 0x71=nullref, 0x73=nullfuncref, 0x72=nullexternref, 0x69=exnref, 0x68=contref
        if matches!(b, 0x6E | 0x6D | 0x6C | 0x6B | 0x6A | 0x71 | 0x74 | 0x69 | 0x68) {
            module.gc_enabled = true;
        }
        *pos = saved;
        decode_valtype_from_stream(bytes, pos)
    }
}

/// Decode a reference type from the bytecode stream.
/// Only accepts reference types: 0x70 (funcref), 0x6F (externref), 0x63 (ref null ht), 0x64 (ref ht).
/// Returns an error for non-reference types (i32, i64, f32, f64, v128).
fn decode_reftype_from_stream(bytes: &[u8], pos: &mut usize) -> Result<ValType, WasmError> {
    let b = read_byte(bytes, pos)?;
    match b {
        0x70 | 0x6F => Ok(ValType::I32), // funcref, externref -> I32 placeholder
        // GC shorthand encodings — also reference types
        0x6E | 0x6D | 0x6C | 0x6B | 0x6A | 0x73 | 0x72 | 0x71 | 0x74 | 0x69 | 0x68 => Ok(ValType::I32),
        0x63 | 0x64 => {
            let _ = decode_leb128_i32(bytes, pos)?;
            Ok(ValType::I32) // placeholder for typed ref types
        }
        _ => Err(WasmError::TypeMismatch),
    }
}

/// Convert a reftype byte to the actual ValType (FuncRef/ExternRef).
fn reftype_byte_to_valtype(b: u8) -> ValType {
    match b {
        0x70 => ValType::FuncRef,
        0x6F => ValType::ExternRef,
        _ => ValType::FuncRef, // default for typed ref types
    }
}

/// Convert a decoded reftype (which uses I32 placeholder) to the actual ref ValType.
fn reftype_to_valtype(_rt: ValType) -> ValType {
    // This is called after decode_reftype_from_stream which always returns I32.
    // We can't recover the original type from I32, so this is a no-op.
    // Instead, callers should use decode_reftype_real.
    ValType::FuncRef
}

/// Decode a reftype from the byte stream, returning the real ValType.
fn decode_reftype_real(bytes: &[u8], pos: &mut usize) -> Result<ValType, WasmError> {
    decode_reftype_real_with_limit(bytes, pos, u32::MAX)
}

fn decode_reftype_real_with_limit(bytes: &[u8], pos: &mut usize, max_type_idx: u32) -> Result<ValType, WasmError> {
    let b = read_byte(bytes, pos)?;
    match b {
        0x70 => Ok(ValType::FuncRef),
        0x6F => Ok(ValType::ExternRef),
        // GC proposal shorthand encodings (single-byte, implicitly nullable):
        0x6E => Ok(ValType::NullableAnyRef), // anyref = (ref null any)
        0x6D => Ok(ValType::NullableEqRef), // eqref = (ref null eq)
        0x6C => Ok(ValType::I31Ref),       // i31ref = (ref null i31)
        0x6B => Ok(ValType::NullableStructRef), // structref = (ref null struct)
        0x6A => Ok(ValType::NullableArrayRef), // arrayref = (ref null array)
        0x73 => Ok(ValType::NullFuncRef),    // nullfuncref = (ref null nofunc)
        0x72 => Ok(ValType::NullExternRef), // nullexternref = (ref null noextern)
        0x71 => Ok(ValType::NoneRef),      // nullref = (ref null none)
        0x69 => Ok(ValType::ExnRef),       // exnref = (ref null exn)
        0x74 => Ok(ValType::ExnRef),       // nullexnref = (ref null noexn)
        0x68 => Ok(ValType::AnyRef),       // contref = (ref null cont)
        0x63 | 0x64 => {
            let heap_type = decode_leb128_i32(bytes, pos)?;
            if heap_type == -16 { // func
                Ok(if b == 0x63 { ValType::FuncRef } else { ValType::TypedFuncRef })
            } else if heap_type == -17 { // extern
                Ok(ValType::ExternRef)
            } else {
                // Validate concrete type index
                if heap_type >= 0 && (heap_type as u32) >= max_type_idx {
                    return Err(WasmError::TypeMismatch);
                }
                Ok(if b == 0x63 { ValType::NullableTypedFuncRef } else { ValType::TypedFuncRef })
            }
        }
        _ => Err(WasmError::TypeMismatch),
    }
}

/// Decode a storage type (used in struct/array field types).
/// Storage types: 0x78 = i8, 0x77 = i16, or a full valtype.
fn decode_storage_type(bytes: &[u8], pos: &mut usize) -> Result<StorageType, WasmError> {
    let b = peek_byte(bytes, *pos)?;
    match b {
        0x78 => { *pos += 1; Ok(StorageType::I8) }
        0x77 => { *pos += 1; Ok(StorageType::I16) }
        _ => { let vt = decode_valtype_from_stream(bytes, pos)?; Ok(StorageType::Val(vt)) }
    }
}

fn decode_storage_type_with_limit(bytes: &[u8], pos: &mut usize, module: &mut WasmModule, max_type_idx: u32) -> Result<StorageType, WasmError> {
    let b = peek_byte(bytes, *pos)?;
    match b {
        0x78 => { *pos += 1; Ok(StorageType::I8) }
        0x77 => { *pos += 1; Ok(StorageType::I16) }
        0x63 | 0x64 => {
            // Peek ahead to capture the heap type index for concrete ref types
            let saved = *pos;
            let _ = read_byte(bytes, pos)?; // consume 0x63 or 0x64
            let ht = decode_leb128_i32(bytes, pos)?;
            *pos = saved; // reset to let the full decoder handle it
            let vt = decode_valtype_gc_aware_with_limit(bytes, pos, module, max_type_idx)?;
            if ht >= 0 {
                // Concrete type index — store it
                Ok(StorageType::RefType(vt, ht as u32))
            } else {
                Ok(StorageType::Val(vt))
            }
        }
        _ => { let vt = decode_valtype_gc_aware_with_limit(bytes, pos, module, max_type_idx)?; Ok(StorageType::Val(vt)) }
    }
}

/// Skip a storage type (used in struct/array field types).
/// Storage types: 0x78 = i8, 0x77 = i16, or a full valtype.
fn skip_storage_type(bytes: &[u8], pos: &mut usize) -> Result<(), WasmError> {
    decode_storage_type(bytes, pos)?;
    Ok(())
}

/// Decode a composite type (possibly wrapped in sub/sub_final) and push to module.func_types.
/// Handles: func (0x60), struct (0x5F), array (0x5E).
/// max_type_idx: concrete type references in this type must be < max_type_idx.
fn decode_composite_type(
    bytes: &[u8],
    pos: &mut usize,
    module: &mut WasmModule,
) -> Result<(), WasmError> {
    decode_composite_type_with_limit(bytes, pos, module, u32::MAX)
}

fn decode_composite_type_with_limit(
    bytes: &[u8],
    pos: &mut usize,
    module: &mut WasmModule,
    max_type_idx: u32,
) -> Result<(), WasmError> {
    let sub_marker = read_byte(bytes, pos)?;
    let inner_marker;
    let mut sub_info = SubTypeInfo { supertype: None, is_final: true, rec_group_start: 0, rec_group_size: 1 };
    if sub_marker == 0x50 || sub_marker == 0x4F {
        // sub/sub_final: read supertype count + supertypes
        module.gc_enabled = true;
        sub_info.is_final = sub_marker == 0x4F; // 0x4F = sub final
        let super_count = decode_leb128_u32(bytes, pos)? as usize;
        if super_count > 0 {
            sub_info.supertype = Some(decode_leb128_u32(bytes, pos)?);
            // Skip remaining supertypes (we only track the first)
            for _ in 1..super_count {
                let _ = decode_leb128_u32(bytes, pos)?;
            }
        }
        inner_marker = read_byte(bytes, pos)?;
    } else {
        inner_marker = sub_marker;
    }

    match inner_marker {
        0x60 => {
            // func type: parse params and results
            let mut ft = FuncTypeDef::empty();
            let param_count = decode_leb128_u32(bytes, pos)? as u8;
            if param_count as usize > MAX_PARAMS {
                return Err(WasmError::TooManyFunctions);
            }
            ft.param_count = param_count;
            for p in 0..param_count as usize {
                ft.params[p] = decode_valtype_gc_aware_with_limit(bytes, pos, module, max_type_idx)?;
            }
            let result_count = decode_leb128_u32(bytes, pos)? as u8;
            if result_count as usize > MAX_RESULTS {
                return Err(WasmError::TooManyFunctions);
            }
            ft.result_count = result_count;
            for r in 0..result_count as usize {
                ft.results[r] = decode_valtype_gc_aware_with_limit(bytes, pos, module, max_type_idx)?;
            }
            module.func_types.push(ft);
            module.gc_types.push(GcTypeDef::Func);
            module.sub_types.push(sub_info);
        }
        0x5E => {
            // array type (GC proposal): single field (storage_type + mutability)
            module.gc_enabled = true;
            let st = decode_storage_type_with_limit(bytes, pos, module, max_type_idx)?;
            let mt = read_byte(bytes, pos)?; // mutability
            if mt > 1 {
                return Err(WasmError::InvalidSection);
            }
            // Push a placeholder func type so type indices stay aligned
            module.func_types.push(FuncTypeDef::empty());
            module.gc_types.push(GcTypeDef::Array {
                elem_type: st,
                elem_mutable: mt != 0,
            });
            module.sub_types.push(sub_info);
        }
        0x5F => {
            // struct type (GC proposal): count of fields, each is storage_type + mutability
            module.gc_enabled = true;
            let field_count = decode_leb128_u32(bytes, pos)? as usize;
            let mut field_types = Vec::with_capacity(field_count);
            let mut field_muts = Vec::with_capacity(field_count);
            for _ in 0..field_count {
                field_types.push(decode_storage_type_with_limit(bytes, pos, module, max_type_idx)?);
                let mt = read_byte(bytes, pos)?; // mutability
                if mt > 1 {
                    return Err(WasmError::InvalidSection);
                }
                field_muts.push(mt != 0);
            }
            // Push a placeholder func type so type indices stay aligned
            module.func_types.push(FuncTypeDef::empty());
            module.gc_types.push(GcTypeDef::Struct {
                field_types,
                field_muts,
            });
            module.sub_types.push(sub_info);
        }
        _ => return Err(WasmError::InvalidSection),
    }
    Ok(())
}

pub(super) fn decode_type_section(
    bytes: &[u8],
    pos: &mut usize,
    end: usize,
    module: &mut WasmModule,
) -> Result<(), WasmError> {
    let count = decode_leb128_u32(bytes, pos)? as usize;
    if count > MAX_FUNCTIONS {
        return Err(WasmError::TooManyFunctions);
    }

    for _i in 0..count {
        let marker = read_byte(bytes, pos)?;
        // 0x60 = func type, 0x4E = rec type (GC proposal)
        if marker == 0x4E {
            // rec type: count of types, then each is a sub/func type
            module.gc_enabled = true;
            let rec_start = module.func_types.len() as u32;
            let rec_count = decode_leb128_u32(bytes, pos)? as usize;
            let rec_end = rec_start + rec_count as u32;
            for _ in 0..rec_count {
                decode_composite_type_with_limit(bytes, pos, module, rec_end)?;
            }
            // Set rec group info on all types in this group
            for idx in rec_start..rec_end {
                if let Some(si) = module.sub_types.get_mut(idx as usize) {
                    si.rec_group_start = rec_start;
                    si.rec_group_size = rec_count as u32;
                }
            }
            continue;
        }
        // For non-rec types, "unread" the marker by backing up
        *pos -= 1;
        let current_type_idx = module.func_types.len() as u32;
        // Allow self-ref (current_type_idx + 1) so validator can later reject for non-GC.
        decode_composite_type_with_limit(bytes, pos, module, current_type_idx + 1)?;
        // Set rec group info for this singleton type
        if let Some(si) = module.sub_types.get_mut(current_type_idx as usize) {
            si.rec_group_start = current_type_idx;
            si.rec_group_size = 1;
        }
    }

    Ok(())
}

pub(super) fn decode_import_section(
    bytes: &[u8],
    pos: &mut usize,
    _end: usize,
    module: &mut WasmModule,
) -> Result<(), WasmError> {
    let count = decode_leb128_u32(bytes, pos)? as usize;
    if count > MAX_IMPORTS {
        return Err(WasmError::TooManyImports);
    }

    for _i in 0..count {
        let mut imp = ImportDef::empty();

        // Module name
        let mod_name = read_name(bytes, pos)?;
        imp.module_name_offset = module.names.len();
        imp.module_name_len = mod_name.len();
        module.names.extend_from_slice(mod_name);

        // Field name
        let field_name = read_name(bytes, pos)?;
        imp.field_name_offset = module.names.len();
        imp.field_name_len = field_name.len();
        module.names.extend_from_slice(field_name);

        // Import kind
        let kind_byte = read_byte(bytes, pos)?;
        match kind_byte {
            0x00 => {
                // Function import
                let type_idx = decode_leb128_u32(bytes, pos)?;
                imp.kind = ImportKind::Func(type_idx);
            }
            0x01 => {
                // Table import: elemtype + limits
                let elemtype = read_byte(bytes, pos)?;
                let et = match elemtype {
                    0x70 => ValType::FuncRef,
                    0x6F => ValType::ExternRef,
                    0x6E => ValType::NullableAnyRef,
                    0x6D => ValType::NullableEqRef,
                    0x6C => ValType::I31Ref,
                    0x6B => ValType::NullableStructRef,
                    0x6A => ValType::NullableArrayRef,
                    0x73 => ValType::NullFuncRef,
                    0x72 => ValType::NullExternRef,
                    0x71 => ValType::NoneRef,
                    0x69 => ValType::ExnRef,
                    0x74 => ValType::ExnRef,    // nullexnref
                    0x68 => ValType::NullableAnyRef,
                    0x63 | 0x64 => {
                        let ht = decode_leb128_i32(bytes, pos)?;
                        let nullable = elemtype == 0x63;
                        match ht {
                            -16 => if nullable { ValType::FuncRef } else { ValType::TypedFuncRef },
                            -17 => ValType::ExternRef,
                            -18 => if nullable { ValType::NullableAnyRef } else { ValType::AnyRef },
                            -19 => if nullable { ValType::NullableEqRef } else { ValType::EqRef },
                            -20 => ValType::I31Ref,
                            -21 => if nullable { ValType::NullableStructRef } else { ValType::StructRef },
                            -22 => if nullable { ValType::NullableArrayRef } else { ValType::ArrayRef },
                            -23 => ValType::ExnRef,
                            -15 => ValType::NoneRef,
                            -13 => ValType::NullFuncRef,
                            -14 => ValType::NullExternRef,
                            -12 => ValType::ExnRef,
                            _ => if nullable { ValType::NullableTypedFuncRef } else { ValType::TypedFuncRef },
                        }
                    }
                    _ => ValType::FuncRef,
                };
                let flags = read_byte(bytes, pos)?;
                if flags != 0 && flags != 1 && flags != 4 && flags != 5 {
                    return Err(WasmError::InvalidSection);
                }
                let is_table64 = (flags & 0b100) != 0;
                let min = if is_table64 { decode_leb128_u64(bytes, pos)? as u32 } else { decode_leb128_u32(bytes, pos)? };
                let max = if flags & 1 != 0 {
                    if is_table64 { Some(decode_leb128_u64(bytes, pos)? as u32) } else { Some(decode_leb128_u32(bytes, pos)?) }
                } else { None };
                // Add imported table to module tables so runtime can create it
                let is_non_nullable = elemtype == 0x64;
                module.tables.push(TableDef { min, max, elem_type: et, is_table64, init_expr_bytes: None, is_non_nullable });
                imp.kind = ImportKind::Table(et);
            }
            0x02 => {
                // Memory import: limits
                module.has_memory = true;
                module.memory_count += 1;
                let flags = read_byte(bytes, pos)?;
                // Valid flags: 0 (min), 1 (min+max), 3 (shared min+max),
                // 4 (memory64 min), 5 (memory64 min+max), 7 (memory64 shared min+max)
                // Also allow custom-page-sizes flag (bit 3 = 0x08)
                if (flags & !0b1111) != 0 || (flags & 0b0010 != 0 && flags & 0b0001 == 0) {
                    return Err(WasmError::InvalidSection);
                }
                let is_memory64 = (flags & 0b100) != 0;
                let min_raw = if is_memory64 { decode_leb128_u64(bytes, pos)? } else { decode_leb128_u32(bytes, pos)? as u64 };
                let has_max = flags & 1 != 0;
                let max_raw = if has_max {
                    if is_memory64 { decode_leb128_u64(bytes, pos)? } else { decode_leb128_u32(bytes, pos)? as u64 }
                } else { u32::MAX as u64 };
                // If custom-page-sizes flag (bit 3), read and discard the page size
                let mem_page_size_log2 = if flags & 0b1000 != 0 {
                    let page_size_log2 = decode_leb128_u32(bytes, pos)?;
                    if page_size_log2 >= 64 {
                        return Err(WasmError::InvalidSection);
                    }
                    Some(page_size_log2)
                } else {
                    None
                };
                // Validate memory64 limits against maximum before truncating
                if is_memory64 {
                    let page_size_log2 = mem_page_size_log2.unwrap_or(16);
                    // Max pages for memory64 = 2^64 / page_size = 2^(64 - page_size_log2)
                    let max_pages_for_mem64: u64 = if page_size_log2 == 0 {
                        u64::MAX
                    } else if page_size_log2 >= 64 {
                        1
                    } else {
                        1u64 << (64u32 - page_size_log2)
                    };
                    if min_raw > max_pages_for_mem64 {
                        return Err(WasmError::MemoryOutOfBounds);
                    }
                    if has_max && max_raw > max_pages_for_mem64 {
                        return Err(WasmError::MemoryOutOfBounds);
                    }
                }
                let min = min_raw as u32;
                let max = if has_max { max_raw as u32 } else { u32::MAX };
                module.memory_min_pages = min;
                module.is_memory64 = is_memory64;
                module.page_size_log2 = mem_page_size_log2;
                if has_max {
                    module.has_memory_max = true;
                    module.memory_max_pages = max;
                } else {
                    module.memory_max_pages = u32::MAX;
                }
                module.memories.push(MemoryDef {
                    min_pages: min,
                    max_pages: if has_max { max } else { u32::MAX },
                    has_max,
                    is_memory64,
                    is_shared: (flags & 0b0010) != 0,
                    page_size_log2: mem_page_size_log2,
                });
                imp.kind = ImportKind::Memory;
            }
            0x03 => {
                // Global import: valtype + mutability
                let vt = read_byte(bytes, pos)?;
                // Handle multi-byte ref types (0x63, 0x64)
                let heap_type = if vt == 0x63 || vt == 0x64 {
                    Some(decode_leb128_i32(bytes, pos)?)
                } else {
                    None
                };
                let mt = read_byte(bytes, pos)?;
                if mt > 1 {
                    return Err(WasmError::InvalidSection);
                }
                imp.kind = ImportKind::Global(vt, mt != 0, heap_type);
            }
            0x04 => {
                // Tag import (exception handling proposal): attribute byte + type index
                let _attribute = read_byte(bytes, pos)?;
                let type_idx = decode_leb128_u32(bytes, pos)?;
                imp.kind = ImportKind::Tag(type_idx);
            }
            _ => {
                return Err(WasmError::InvalidSection);
            }
        }

        module.imports.push(imp);
    }

    Ok(())
}

pub(super) fn decode_function_section(
    bytes: &[u8],
    pos: &mut usize,
    _end: usize,
    module: &mut WasmModule,
) -> Result<(), WasmError> {
    let count = decode_leb128_u32(bytes, pos)? as usize;
    if count + module.imports.len() > MAX_FUNCTIONS {
        return Err(WasmError::TooManyFunctions);
    }

    for _i in 0..count {
        let type_idx = decode_leb128_u32(bytes, pos)?;
        let mut fd = FuncDef::empty();
        fd.type_idx = type_idx;
        // code_offset and locals will be filled in by the Code section
        module.functions.push(fd);
    }

    Ok(())
}

pub(super) fn decode_memory_section(
    bytes: &[u8],
    pos: &mut usize,
    _end: usize,
    module: &mut WasmModule,
) -> Result<(), WasmError> {
    let count = decode_leb128_u32(bytes, pos)?;
    module.memory_count += count;
    if count < 1 {
        return Ok(());
    }
    module.has_memory = true;
    for mem_idx in 0..count {
        let flags = read_byte(bytes, pos)?;
        // Valid flags: 0 (min), 1 (min+max), 3 (shared min+max),
        // 4 (memory64 min), 5 (memory64 min+max), 7 (memory64 shared min+max)
        // Also allow custom-page-sizes flag (bit 3 = 0x08)
        if (flags & !0b1111) != 0 || (flags & 0b0010 != 0 && flags & 0b0001 == 0) {
            return Err(WasmError::InvalidSection);
        }
        let is_memory64 = (flags & 0b100) != 0;
        let min_raw = if is_memory64 { decode_leb128_u64(bytes, pos)? } else { decode_leb128_u32(bytes, pos)? as u64 };
        let has_max = flags & 1 != 0;
        let max_raw = if has_max {
            if is_memory64 { decode_leb128_u64(bytes, pos)? } else { decode_leb128_u32(bytes, pos)? as u64 }
        } else {
            u64::MAX
        };
        // If custom-page-sizes flag (bit 3), read and validate page_size_log2
        let mem_page_size_log2 = if flags & 0b1000 != 0 {
            let page_size_log2 = decode_leb128_u32(bytes, pos)?;
            // Decode-time check: must be < 64
            if page_size_log2 >= 64 {
                return Err(WasmError::InvalidSection);
            }
            Some(page_size_log2)
        } else {
            None
        };
        // Validate memory64 limits against maximum before truncating
        if is_memory64 {
            let page_size_log2 = mem_page_size_log2.unwrap_or(16);
            // Max pages for memory64 = 2^64 / page_size = 2^(64 - page_size_log2)
            let max_pages_for_mem64: u64 = if page_size_log2 == 0 {
                u64::MAX
            } else if page_size_log2 >= 64 {
                1
            } else {
                1u64 << (64u32 - page_size_log2)
            };
            if min_raw > max_pages_for_mem64 {
                return Err(WasmError::MemoryOutOfBounds);
            }
            if has_max && max_raw > max_pages_for_mem64 {
                return Err(WasmError::MemoryOutOfBounds);
            }
        }
        let min = min_raw as u32;
        let max = if has_max { max_raw as u32 } else { u32::MAX };
        module.memories.push(MemoryDef {
            min_pages: min,
            max_pages: max,
            has_max,
            is_memory64,
            is_shared: (flags & 0b0010) != 0,
            page_size_log2: mem_page_size_log2,
        });
        if mem_idx == 0 {
            module.memory_min_pages = min;
            module.is_memory64 = is_memory64;
            module.page_size_log2 = mem_page_size_log2;
            if has_max {
                module.has_memory_max = true;
                module.memory_max_pages = max;
            } else {
                module.has_memory_max = false;
                module.memory_max_pages = u32::MAX;
            }
        }
    }

    Ok(())
}

pub(super) fn decode_export_section(
    bytes: &[u8],
    pos: &mut usize,
    _end: usize,
    module: &mut WasmModule,
) -> Result<(), WasmError> {
    let count = decode_leb128_u32(bytes, pos)? as usize;
    if count > MAX_EXPORTS {
        return Err(WasmError::TooManyFunctions);
    }

    for _i in 0..count {
        let mut exp = ExportDef::empty();

        // Name
        let name = read_name(bytes, pos)?;
        exp.name_offset = module.names.len();
        exp.name_len = name.len();
        module.names.extend_from_slice(name);

        // Kind
        let kind_byte = read_byte(bytes, pos)?;
        let idx = decode_leb128_u32(bytes, pos)?;
        match kind_byte {
            0x00 => exp.kind = ExportKind::Func(idx),
            0x01 => exp.kind = ExportKind::Table(idx),
            0x02 => exp.kind = ExportKind::Memory(idx),
            0x03 => exp.kind = ExportKind::Global(idx),
            0x04 => exp.kind = ExportKind::Tag(idx),
            _ => exp.kind = ExportKind::Func(idx), // fallback
        }

        module.exports.push(exp);
    }

    Ok(())
}

pub(super) fn decode_code_section(
    bytes: &[u8],
    pos: &mut usize,
    end: usize,
    module: &mut WasmModule,
) -> Result<(), WasmError> {
    let count = decode_leb128_u32(bytes, pos)? as usize;

    for i in 0..count {
        let body_size = decode_leb128_u32(bytes, pos)? as usize;
        let body_end = *pos + body_size;

        if body_end > bytes.len() {
            return Err(WasmError::UnexpectedEnd);
        }

        // Decode locals
        let local_decl_count = decode_leb128_u32(bytes, pos)? as usize;
        // Use u64 to detect overflow beyond u32::MAX
        let mut total_locals: u64 = 0;

        if i >= module.functions.len() {
            return Err(WasmError::FunctionNotFound(i as u32));
        }
        let max_type_idx = module.func_types.len() as u32;

        let mut nn_locals = Vec::new();
        let mut local_types = Vec::new();
        for _ in 0..local_decl_count {
            let n = decode_leb128_u32(bytes, pos)? as u64;
            // Peek at the type byte to detect non-nullable refs (0x64 prefix)
            let type_byte = if *pos < bytes.len() { bytes[*pos] } else { 0 };
            let is_non_nullable = type_byte == 0x64;
            let ty = decode_valtype_gc_aware_with_limit(bytes, pos, module, max_type_idx)?;
            total_locals = total_locals.saturating_add(n);
            // WASM spec: no more than 2^32 - 1 locals total (including params)
            if total_locals > u32::MAX as u64 {
                return Err(WasmError::InvalidSection);
            }
            local_types.push((n, ty, is_non_nullable));
        }

        let func = &mut module.functions[i];
        for (n, ty, is_non_nullable) in &local_types {
            let start = nn_locals.len();
            let end = (start + *n as usize).min(MAX_LOCALS);
            for j in start..end {
                func.locals[j] = *ty;
                if nn_locals.len() <= j {
                    nn_locals.resize(j + 1, false);
                }
                nn_locals[j] = *is_non_nullable;
            }
        }
        func.non_nullable_locals = nn_locals;

        // Also check including params from the function type
        let type_idx = func.type_idx as usize;
        func.local_count = total_locals.min(MAX_LOCALS as u64) as u16;

        if type_idx < module.func_types.len() {
            let param_count = module.func_types[type_idx].param_count as u64;
            if total_locals.saturating_add(param_count) > u32::MAX as u64 {
                return Err(WasmError::InvalidSection);
            }
        }

        // Validate END opcode at end of function body
        if body_end > 0 && bytes[body_end - 1] != 0x0B {
            return Err(WasmError::InvalidSection);
        }

        // Scan for bulk-memory instructions (memory.init=0xFC 0x08, data.drop=0xFC 0x09)
        // that require a data count section.
        if !module.code_uses_data_count {
            let code_start = *pos;
            let code_end_pos = body_end;
            for j in code_start..code_end_pos.saturating_sub(1) {
                if bytes[j] == 0xFC && (bytes[j + 1] == 0x08 || bytes[j + 1] == 0x09) {
                    module.code_uses_data_count = true;
                    break;
                }
            }
        }

        // Copy the remaining bytecode (instructions) into module.code
        let code_bytes = body_end - *pos;
        if module.code.len() + code_bytes > MAX_CODE_SIZE {
            return Err(WasmError::CodeTooLarge);
        }
        func.code_offset = module.code.len();
        func.code_len = code_bytes;
        module.code.extend_from_slice(&bytes[*pos..*pos + code_bytes]);

        *pos = body_end;
    }

    // Section size mismatch: ensure we consumed exactly to section end
    if *pos != end {
        return Err(WasmError::InvalidSection);
    }

    Ok(())
}

// ─── New section decoders (Batch 3) ─────────────────────────────────────────

pub(super) fn decode_table_section(
    bytes: &[u8],
    pos: &mut usize,
    _end: usize,
    module: &mut WasmModule,
) -> Result<(), WasmError> {
    let count = decode_leb128_u32(bytes, pos)? as usize;
    for _ in 0..count {
        // Per wasmparser: tables may have a 0x40 0x00 prefix for the new encoding
        let has_init_expr = if peek_byte(bytes, *pos)? == 0x40 {
            read_byte(bytes, pos)?; // consume 0x40
            if read_byte(bytes, pos)? != 0x00 {
                return Err(WasmError::InvalidSection);
            }
            true
        } else {
            false
        };

        // elemtype: 0x70 = funcref, 0x6F = externref, 0x63/0x64 = ref types,
        // 0x6E-0x6A, 0x73-0x69 = GC shorthand ref types
        let elemtype = read_byte(bytes, pos)?;
        let mut elem_heap_type: i32 = 0;
        if elemtype == 0x63 || elemtype == 0x64 {
            // Nullable/non-nullable ref type: read heap type
            elem_heap_type = decode_leb128_i32(bytes, pos)?;
            // Validate concrete type references
            if elem_heap_type >= 0 && (elem_heap_type as u32) >= module.func_types.len() as u32 {
                return Err(WasmError::TypeMismatch);
            }
        } else if matches!(elemtype, 0x6E | 0x6D | 0x6C | 0x6B | 0x6A | 0x73 | 0x72 | 0x71 | 0x74 | 0x69 | 0x68) {
            // GC shorthand reference types — single byte, no additional data
            // Map to corresponding heap type for later processing
            elem_heap_type = match elemtype {
                0x6E => -0x12, // any
                0x6D => -0x16, // eq
                0x6C => -0x19, // i31
                0x6B => -0x17, // struct
                0x6A => -0x18, // array
                0x73 => -0x15, // nofunc
                0x72 => -0x14, // noextern
                0x71 => -0x13, // none
                0x69 => -0x1A, // exn
                0x68 => -0x12, // cont -> any
                _ => 0,
            };
        } else if elemtype != 0x70 && elemtype != 0x6F {
            return Err(WasmError::InvalidSection);
        }
        let flags = read_byte(bytes, pos)?;
        // Valid limit flags for tables: 0x00 (no max), 0x01 (has max),
        // 0x04 (table64, no max), 0x05 (table64, has max).
        // Flags with shared bit (0x02) are invalid for tables.
        if flags != 0 && flags != 1 && flags != 4 && flags != 5 {
            return Err(WasmError::InvalidSection);
        }
        let has_max = (flags & 0b001) != 0;
        let is_table64 = (flags & 0b100) != 0;
        let min = if is_table64 {
            decode_leb128_u64(bytes, pos)? as u32
        } else {
            decode_leb128_u32(bytes, pos)?
        };
        let max = if has_max {
            if is_table64 {
                Some(decode_leb128_u64(bytes, pos)? as u32)
            } else {
                Some(decode_leb128_u32(bytes, pos)?)
            }
        } else {
            None
        };

        // If has_init_expr, store init expression bytes
        let init_expr_bytes = if has_init_expr {
            let start = *pos;
            let _ = eval_init_expr(bytes, pos)?;
            let end = *pos;
            Some(bytes[start..end].to_vec())
        } else {
            None
        };

        let et = match elemtype {
            0x70 => ValType::FuncRef,
            0x6F => ValType::ExternRef,
            0x6E => ValType::NullableAnyRef,
            0x6D => ValType::NullableEqRef,
            0x6C => ValType::I31Ref,
            0x6B => ValType::NullableStructRef,
            0x6A => ValType::NullableArrayRef,
            0x73 => ValType::NullFuncRef,    // nullfuncref
            0x72 => ValType::NullExternRef,  // nullexternref
            0x71 => ValType::NoneRef,      // nullref
            0x69 => ValType::ExnRef,       // exnref
            0x74 => ValType::ExnRef,       // nullexnref
            0x68 => ValType::NullableAnyRef, // contref
            0x64 => {
                // (ref ht) = non-nullable
                if elem_heap_type == -16 { ValType::TypedFuncRef }
                else if elem_heap_type == -17 { ValType::ExternRef }
                else if elem_heap_type == -18 { ValType::AnyRef }
                else if elem_heap_type == -19 { ValType::EqRef }
                else if elem_heap_type == -20 { ValType::I31Ref }
                else if elem_heap_type == -21 { ValType::StructRef }
                else if elem_heap_type == -22 { ValType::ArrayRef }
                else if elem_heap_type == -23 { ValType::ExnRef }
                else if elem_heap_type == -15 { ValType::NoneRef }
                else if elem_heap_type == -13 { ValType::NullFuncRef }
                else if elem_heap_type == -14 { ValType::NullExternRef }
                else if elem_heap_type == -12 { ValType::ExnRef }
                else { ValType::TypedFuncRef }
            }
            _ => {
                // 0x63 = (ref null ht) = nullable
                if elem_heap_type == -16 { ValType::FuncRef }
                else if elem_heap_type == -17 { ValType::ExternRef }
                else if elem_heap_type == -18 { ValType::NullableAnyRef }
                else if elem_heap_type == -19 { ValType::NullableEqRef }
                else if elem_heap_type == -20 { ValType::I31Ref }
                else if elem_heap_type == -21 { ValType::NullableStructRef }
                else if elem_heap_type == -22 { ValType::NullableArrayRef }
                else if elem_heap_type == -23 { ValType::ExnRef }
                else if elem_heap_type == -15 { ValType::NoneRef }
                else if elem_heap_type == -13 { ValType::NullFuncRef }
                else if elem_heap_type == -14 { ValType::NullExternRef }
                else if elem_heap_type == -12 { ValType::ExnRef }
                else { ValType::NullableTypedFuncRef }
            }
        };
        let is_non_nullable = elemtype == 0x64;
        module.tables.push(TableDef { min, max, elem_type: et, is_table64, init_expr_bytes, is_non_nullable });
    }
    Ok(())
}

pub(super) fn decode_global_section(
    bytes: &[u8],
    pos: &mut usize,
    _end: usize,
    module: &mut WasmModule,
) -> Result<(), WasmError> {
    let count = decode_leb128_u32(bytes, pos)? as usize;
    if count > MAX_GLOBALS {
        return Err(WasmError::TooManyFunctions);
    }
    for _ in 0..count {
        // Peek at bytes to extract heap type for ref types
        let saved_pos = *pos;
        let first_byte = if saved_pos < bytes.len() { bytes[saved_pos] } else { 0 };
        let global_heap_type = if first_byte == 0x63 || first_byte == 0x64 {
            let mut peek_pos = saved_pos + 1;
            decode_leb128_i32(bytes, &mut peek_pos).ok()
        } else {
            None
        };
        // Use stream decoder to handle multi-byte ref types, validating type refs
        let val_type = decode_valtype_gc_aware_with_limit(bytes, pos, module, module.func_types.len() as u32)?;
        let mt = read_byte(bytes, pos)?;
        if mt > 1 {
            return Err(WasmError::InvalidSection);
        }
        let mutable = mt != 0;
        // Scan init expr bytes to find global.get references and type info before consuming them.
        let expr_start = *pos;
        let expr_info = scan_init_expr_info_gc(bytes, *pos, &module.gc_types);
        let init_global_ref = expr_info.global_ref;
        let init_expr_type = expr_info.result_type;
        let init_expr_stack_depth = expr_info.stack_depth;
        let init_func_ref = expr_info.func_ref;
        let init_value = eval_init_expr(bytes, pos)?;
        let init_expr_bytes = bytes[expr_start..*pos].to_vec();
        let has_non_const = expr_info.has_non_const;
        module.globals.push(GlobalDef { val_type, mutable, init_value, init_global_ref, init_expr_type, init_expr_stack_depth, init_func_ref, init_expr_bytes, heap_type: global_heap_type, has_non_const });
    }
    Ok(())
}

pub(super) fn decode_start_section(
    bytes: &[u8],
    pos: &mut usize,
    _end: usize,
    module: &mut WasmModule,
) -> Result<(), WasmError> {
    let func_idx = decode_leb128_u32(bytes, pos)?;
    module.start_func = Some(func_idx);
    Ok(())
}

pub(super) fn decode_element_section(
    bytes: &[u8],
    pos: &mut usize,
    _end: usize,
    module: &mut WasmModule,
) -> Result<(), WasmError> {
    // Collect global init values so element item expressions using global.get
    // can resolve local globals (e.g., funcref globals initialized with ref.func).
    // Global indices include imports first, then defined globals.
    let num_global_imports = module.imports.iter()
        .filter(|i| matches!(i.kind, ImportKind::Global(_, _, _)))
        .count();
    let mut global_init_values: Vec<Value> = vec![Value::I32(0); num_global_imports];
    for g in &module.globals {
        global_init_values.push(g.init_value);
    }

    let count = decode_leb128_u32(bytes, pos)? as usize;
    if count > MAX_ELEMENT_SEGMENTS {
        return Err(WasmError::InvalidSection);
    }
    for _ in 0..count {
        if *pos >= bytes.len() { return Err(WasmError::UnexpectedEnd); }
        let flags = decode_leb128_u32(bytes, pos)?;

        match flags {
            0 => {
                // Active segment: table_idx=0 (implicit), offset expr, func indices
                let expr_start = *pos;
                let expr_info = scan_init_expr_info(bytes, *pos);
                let offset_val = eval_init_expr(bytes, pos)?;
                let expr_end = *pos;
                let offset = match offset_val {
                    Value::I32(v) => v as u32,
                    Value::I64(v) => v as u32,
                    _ => 0,
                };
                let num_elems = decode_leb128_u32(bytes, pos)? as usize;
                let mut func_indices = alloc::vec::Vec::with_capacity(num_elems);
                for _ in 0..num_elems {
                    func_indices.push(decode_leb128_u32(bytes, pos)?);
                }
                module.element_segments.push(ElementSegment {
                    table_idx: 0,
                    offset,
                    func_indices,
                    mode: ElemMode::Active,
                    elem_type: ValType::FuncRef,
                    offset_expr_info: expr_info,
                    item_expr_infos: alloc::vec::Vec::new(),
                    offset_expr_range: (expr_start, expr_end),
                    item_expr_bytes: alloc::vec::Vec::new(),
                });
            }
            1 => {
                // Passive segment: kind byte + func indices (no table, no offset)
                let kind = read_byte(bytes, pos)?; // elemkind (0x00 = funcref)
                if kind != 0x00 {
                    return Err(WasmError::InvalidSection);
                }
                let num_elems = decode_leb128_u32(bytes, pos)? as usize;
                let mut func_indices = alloc::vec::Vec::with_capacity(num_elems);
                for _ in 0..num_elems {
                    func_indices.push(decode_leb128_u32(bytes, pos)?);
                }
                module.element_segments.push(ElementSegment {
                    table_idx: 0,
                    offset: 0,
                    func_indices,
                    mode: ElemMode::Passive,
                    elem_type: ValType::FuncRef,
                    offset_expr_info: Default::default(),
                    item_expr_infos: alloc::vec::Vec::new(),
                    offset_expr_range: (0, 0),
                    item_expr_bytes: alloc::vec::Vec::new(),
                });
            }
            2 => {
                // Active segment with explicit table_idx
                let table_idx = decode_leb128_u32(bytes, pos)?;
                let expr_start = *pos;
                let expr_info = scan_init_expr_info(bytes, *pos);
                let offset_val = eval_init_expr(bytes, pos)?;
                let expr_end = *pos;
                let offset = match offset_val {
                    Value::I32(v) => v as u32,
                    Value::I64(v) => v as u32,
                    _ => 0,
                };
                let kind = read_byte(bytes, pos)?;
                if kind != 0x00 {
                    return Err(WasmError::InvalidSection);
                }
                let num_elems = decode_leb128_u32(bytes, pos)? as usize;
                let mut func_indices = alloc::vec::Vec::with_capacity(num_elems);
                for _ in 0..num_elems {
                    func_indices.push(decode_leb128_u32(bytes, pos)?);
                }
                module.element_segments.push(ElementSegment {
                    table_idx,
                    offset,
                    func_indices,
                    mode: ElemMode::Active,
                    elem_type: ValType::FuncRef,
                    offset_expr_info: expr_info,
                    item_expr_infos: alloc::vec::Vec::new(),
                    offset_expr_range: (expr_start, expr_end),
                    item_expr_bytes: alloc::vec::Vec::new(),
                });
            }
            3 => {
                // Declarative segment: kind + func indices (dropped immediately)
                let kind = read_byte(bytes, pos)?;
                if kind != 0x00 {
                    return Err(WasmError::InvalidSection);
                }
                let num_elems = decode_leb128_u32(bytes, pos)? as usize;
                let mut func_indices = alloc::vec::Vec::with_capacity(num_elems);
                for _ in 0..num_elems {
                    func_indices.push(decode_leb128_u32(bytes, pos)?);
                }
                module.element_segments.push(ElementSegment {
                    table_idx: 0,
                    offset: 0,
                    func_indices,
                    mode: ElemMode::Declarative,
                    elem_type: ValType::FuncRef,
                    offset_expr_info: Default::default(),
                    item_expr_infos: alloc::vec::Vec::new(),
                    offset_expr_range: (0, 0),
                    item_expr_bytes: alloc::vec::Vec::new(),
                });
            }
            4 => {
                // Active, table 0 implicit, offset expr, expression elements
                let expr_start = *pos;
                let expr_info = scan_init_expr_info(bytes, *pos);
                let offset_val = eval_init_expr(bytes, pos)?;
                let expr_end = *pos;
                let offset = match offset_val { Value::I32(v) => v as u32, _ => 0 };
                let num_elems = decode_leb128_u32(bytes, pos)? as usize;
                let mut func_indices = alloc::vec::Vec::with_capacity(num_elems);
                let mut item_expr_infos = alloc::vec::Vec::with_capacity(num_elems);
                let mut item_expr_bytes_vec = alloc::vec::Vec::with_capacity(num_elems);
                for _ in 0..num_elems {
                    let item_start = *pos;
                    let item_info = scan_init_expr_info(bytes, *pos);
                    let val = eval_init_expr_with_globals(bytes, pos, &global_init_values)?;
                    let item_end = *pos;
                    func_indices.push(match val { Value::I32(v) => v as u32, _ => u32::MAX });
                    item_expr_infos.push(item_info);
                    item_expr_bytes_vec.push(bytes[item_start..item_end].to_vec());
                }
                module.element_segments.push(ElementSegment { table_idx: 0, offset, func_indices, mode: ElemMode::Active, elem_type: ValType::FuncRef, offset_expr_info: expr_info, item_expr_infos, offset_expr_range: (expr_start, expr_end), item_expr_bytes: item_expr_bytes_vec });
            }
            5 => {
                // Passive, reftype, expression elements
                let elem_type = decode_reftype_real_with_limit(bytes, pos, module.func_types.len() as u32)?;
                let num_elems = decode_leb128_u32(bytes, pos)? as usize;
                let mut func_indices = alloc::vec::Vec::with_capacity(num_elems);
                let mut item_expr_infos = alloc::vec::Vec::with_capacity(num_elems);
                let mut item_expr_bytes_vec = alloc::vec::Vec::with_capacity(num_elems);
                for _ in 0..num_elems {
                    let item_start = *pos;
                    let item_info = scan_init_expr_info(bytes, *pos);
                    let val = eval_init_expr_with_globals(bytes, pos, &global_init_values)?;
                    let item_end = *pos;
                    func_indices.push(match val { Value::I32(v) => v as u32, _ => u32::MAX });
                    item_expr_infos.push(item_info);
                    item_expr_bytes_vec.push(bytes[item_start..item_end].to_vec());
                }
                module.element_segments.push(ElementSegment {
                    table_idx: 0,
                    offset: 0,
                    func_indices,
                    mode: ElemMode::Passive,
                    elem_type,
                    offset_expr_info: Default::default(),
                    item_expr_infos,
                    offset_expr_range: (0, 0),
                    item_expr_bytes: item_expr_bytes_vec,
                });
            }
            6 => {
                // Active, explicit table_idx, offset expr, reftype, expression elements
                let table_idx = decode_leb128_u32(bytes, pos)?;
                let expr_start = *pos;
                let expr_info = scan_init_expr_info(bytes, *pos);
                let offset_val = eval_init_expr(bytes, pos)?;
                let expr_end = *pos;
                let offset = match offset_val { Value::I32(v) => v as u32, _ => 0 };
                let elem_type = decode_reftype_real_with_limit(bytes, pos, module.func_types.len() as u32)?;
                let num_elems = decode_leb128_u32(bytes, pos)? as usize;
                let mut func_indices = alloc::vec::Vec::with_capacity(num_elems);
                let mut item_expr_infos = alloc::vec::Vec::with_capacity(num_elems);
                let mut item_expr_bytes_vec = alloc::vec::Vec::with_capacity(num_elems);
                for _ in 0..num_elems {
                    let item_start = *pos;
                    let item_info = scan_init_expr_info(bytes, *pos);
                    let val = eval_init_expr_with_globals(bytes, pos, &global_init_values)?;
                    let item_end = *pos;
                    func_indices.push(match val { Value::I32(v) => v as u32, _ => u32::MAX });
                    item_expr_infos.push(item_info);
                    item_expr_bytes_vec.push(bytes[item_start..item_end].to_vec());
                }
                module.element_segments.push(ElementSegment { table_idx, offset, func_indices, mode: ElemMode::Active, elem_type, offset_expr_info: expr_info, item_expr_infos, offset_expr_range: (expr_start, expr_end), item_expr_bytes: item_expr_bytes_vec });
            }
            7 => {
                // Declarative, reftype, expression elements (dropped immediately)
                let elem_type = decode_reftype_real_with_limit(bytes, pos, module.func_types.len() as u32)?;
                let num_elems = decode_leb128_u32(bytes, pos)? as usize;
                let mut func_indices = alloc::vec::Vec::with_capacity(num_elems);
                let mut item_expr_infos = alloc::vec::Vec::with_capacity(num_elems);
                let mut item_expr_bytes_vec = alloc::vec::Vec::with_capacity(num_elems);
                for _ in 0..num_elems {
                    let item_start = *pos;
                    let item_info = scan_init_expr_info(bytes, *pos);
                    let val = eval_init_expr_with_globals(bytes, pos, &global_init_values)?;
                    let item_end = *pos;
                    func_indices.push(match val { Value::I32(v) => v as u32, _ => u32::MAX });
                    item_expr_infos.push(item_info);
                    item_expr_bytes_vec.push(bytes[item_start..item_end].to_vec());
                }
                module.element_segments.push(ElementSegment {
                    table_idx: 0,
                    offset: 0,
                    func_indices,
                    mode: ElemMode::Declarative,
                    elem_type,
                    offset_expr_info: Default::default(),
                    item_expr_infos,
                    offset_expr_range: (0, 0),
                    item_expr_bytes: item_expr_bytes_vec,
                });
            }
            _ => {
                return Err(WasmError::InvalidSection);
            }
        }
    }
    Ok(())
}

pub(super) fn decode_data_section(
    bytes: &[u8],
    pos: &mut usize,
    _end: usize,
    module: &mut WasmModule,
) -> Result<(), WasmError> {
    let count = decode_leb128_u32(bytes, pos)? as usize;
    if count > MAX_DATA_SEGMENTS {
        return Err(WasmError::InvalidSection);
    }
    for _ in 0..count {
        if *pos >= bytes.len() { return Err(WasmError::UnexpectedEnd); }
        let flags = decode_leb128_u32(bytes, pos)?;

        match flags {
            0 => {
                // Active segment: memory_idx=0 (implicit), offset expr, data bytes
                let expr_start = *pos;
                let expr_info = scan_init_expr_info(bytes, *pos);
                let offset_val = eval_init_expr(bytes, pos)?;
                let expr_end = *pos;
                let offset = match offset_val {
                    Value::I32(v) => v as u32,
                    Value::I64(v) => v as u32,
                    _ => 0,
                };
                let data_len = decode_leb128_u32(bytes, pos)? as usize;
                let data_offset = module.code.len();
                if *pos + data_len > bytes.len() {
                    return Err(WasmError::UnexpectedEnd);
                }
                module.code.extend_from_slice(&bytes[*pos..*pos + data_len]);
                *pos += data_len;
                module.data_segments.push(DataSegment {
                    memory_idx: 0,
                    offset,
                    is_active: true,
                    data_offset,
                    data_len,
                    offset_expr_info: expr_info,
                    offset_expr_range: (expr_start, expr_end),
                });
            }
            1 => {
                // Passive segment: just data bytes (no memory, no offset)
                let data_len = decode_leb128_u32(bytes, pos)? as usize;
                if *pos + data_len > bytes.len() {
                    return Err(WasmError::UnexpectedEnd);
                }
                // Store bytes but don't create an active segment
                let data_offset = module.code.len();
                module.code.extend_from_slice(&bytes[*pos..*pos + data_len]);
                *pos += data_len;
                module.data_segments.push(DataSegment {
                    memory_idx: 0,
                    offset: 0,
                    is_active: false,
                    data_offset,
                    data_len,
                    offset_expr_info: Default::default(),
                    offset_expr_range: (0, 0),
                });
            }
            2 => {
                // Active segment with explicit memory_idx
                let memory_idx = decode_leb128_u32(bytes, pos)?;
                let expr_start = *pos;
                let expr_info = scan_init_expr_info(bytes, *pos);
                let offset_val = eval_init_expr(bytes, pos)?;
                let expr_end = *pos;
                let offset = match offset_val {
                    Value::I32(v) => v as u32,
                    Value::I64(v) => v as u32,
                    _ => 0,
                };
                let data_len = decode_leb128_u32(bytes, pos)? as usize;
                let data_offset = module.code.len();
                if *pos + data_len > bytes.len() {
                    return Err(WasmError::UnexpectedEnd);
                }
                module.code.extend_from_slice(&bytes[*pos..*pos + data_len]);
                *pos += data_len;
                module.data_segments.push(DataSegment {
                    memory_idx,
                    offset,
                    is_active: true,
                    data_offset,
                    data_len,
                    offset_expr_info: expr_info,
                    offset_expr_range: (expr_start, expr_end),
                });
            }
            _ => return Err(WasmError::InvalidSection),
        }
    }
    Ok(())
}

pub(super) fn decode_data_count_section(
    bytes: &[u8],
    pos: &mut usize,
    _end: usize,
    module: &mut WasmModule,
) -> Result<(), WasmError> {
    // DataCount section contains a single u32: the number of data segments.
    let count = decode_leb128_u32(bytes, pos)?;
    module.data_count = Some(count);
    Ok(())
}
