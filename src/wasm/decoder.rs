//! WASM binary module decoder.
//!
//! Parses a WASM binary into a `WasmModule`. Large buffers (code, names)
//! are heap-allocated via `Vec`; small tables use fixed-size arrays.
//! Supports sections: Type (1), Import (2), Function (3), Memory (5),
//! Export (7), Code (10).

use alloc::vec::Vec;
use crate::wasm::types::*;

// ─── Module structures ──────────────────────────────────────────────────────

/// A decoded WASM function type (signature).
#[derive(Clone)]
pub struct FuncTypeDef {
    pub param_count: u8,
    pub params: [ValType; MAX_PARAMS],
    pub result_count: u8,
    pub results: [ValType; MAX_RESULTS],
}

impl FuncTypeDef {
    pub const fn empty() -> Self {
        FuncTypeDef {
            param_count: 0,
            params: [ValType::I32; MAX_PARAMS],
            result_count: 0,
            results: [ValType::I32; MAX_RESULTS],
        }
    }
}

/// A decoded WASM function body.
#[derive(Clone)]
pub struct FuncDef {
    pub type_idx: u32,
    pub code_offset: usize,
    pub code_len: usize,
    pub local_count: u16,
    pub locals: [ValType; MAX_LOCALS],
}

impl FuncDef {
    pub const fn empty() -> Self {
        FuncDef {
            type_idx: 0,
            code_offset: 0,
            code_len: 0,
            local_count: 0,
            locals: [ValType::I32; MAX_LOCALS],
        }
    }
}

/// A WASM import definition.
#[derive(Clone)]
pub struct ImportDef {
    pub module_name_offset: usize,
    pub module_name_len: usize,
    pub field_name_offset: usize,
    pub field_name_len: usize,
    pub kind: ImportKind,
}

impl ImportDef {
    pub const fn empty() -> Self {
        ImportDef {
            module_name_offset: 0,
            module_name_len: 0,
            field_name_offset: 0,
            field_name_len: 0,
            kind: ImportKind::Func(0),
        }
    }
}

/// Import kind.
#[derive(Debug, Clone, Copy)]
pub enum ImportKind {
    Func(u32),           // type index
    Table(ValType),      // table import with element type
    Memory,              // memory import
    Global(u8, bool),    // valtype byte, mutable
    Tag(u32),            // tag import: type index (exception handling proposal)
}

/// A WASM export definition.
#[derive(Clone)]
pub struct ExportDef {
    pub name_offset: usize,
    pub name_len: usize,
    pub kind: ExportKind,
}

impl ExportDef {
    pub const fn empty() -> Self {
        ExportDef {
            name_offset: 0,
            name_len: 0,
            kind: ExportKind::Func(0),
        }
    }
}

/// Export kind.
#[derive(Debug, Clone, Copy)]
pub enum ExportKind {
    Func(u32),
    Table(u32),
    Memory(u32),
    Global(u32),
    Tag(u32),
}

/// A global variable definition.
#[derive(Clone)]
pub struct GlobalDef {
    pub val_type: ValType,
    pub mutable: bool,
    pub init_value: Value,
    /// If the init expression uses global.get, this is Some(global_index).
    pub init_global_ref: Option<u32>,
    /// Type produced by the init expression (for validation).
    pub init_expr_type: Option<ValType>,
    /// Stack depth of the init expression (must be 1).
    pub init_expr_stack_depth: u32,
    /// If the init expression uses ref.func, this is the function index.
    pub init_func_ref: Option<u32>,
}

/// A table definition.
#[derive(Clone)]
pub struct TableDef {
    pub min: u32,
    pub max: Option<u32>,
    /// Element type: FuncRef (0x70) or ExternRef (0x6F).
    pub elem_type: ValType,
    /// Whether this table uses 64-bit indices (table64 proposal).
    pub is_table64: bool,
}

/// A memory definition (imported or locally defined).
#[derive(Clone)]
pub struct MemoryDef {
    pub min_pages: u32,
    pub max_pages: u32,
    pub has_max: bool,
    pub is_memory64: bool,
    pub page_size_log2: Option<u32>,
}

/// A data segment for memory initialization.
#[derive(Clone)]
pub struct DataSegment {
    pub memory_idx: u32,
    pub offset: u32,
    /// Whether this is an active segment (true) or passive (false).
    pub is_active: bool,
    pub data_offset: usize, // offset into module.code (reused for data bytes)
    pub data_len: usize,
    /// Info from scanning the offset init expression for validation.
    pub offset_expr_info: InitExprInfo,
    /// Byte range [start, end) of the offset init expression in the original binary.
    pub offset_expr_range: (usize, usize),
}

/// Element segment mode.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ElemMode {
    Active,
    Passive,
    Declarative,
}

/// An element segment for table initialization.
#[derive(Clone)]
pub struct ElementSegment {
    pub table_idx: u32,
    pub offset: u32,
    pub func_indices: alloc::vec::Vec<u32>,
    pub mode: ElemMode,
    /// Element type of this segment (funcref or externref).
    pub elem_type: ValType,
    /// Info from scanning the offset init expression for validation.
    pub offset_expr_info: InitExprInfo,
    /// Per-item expression info for expression-based segments (flags 4-7).
    /// Empty for index-based segments (flags 0-3).
    pub item_expr_infos: alloc::vec::Vec<InitExprInfo>,
    /// Byte range [start, end) of the offset init expression in the original binary.
    pub offset_expr_range: (usize, usize),
}

/// Information extracted from scanning an init expression for validation.
#[derive(Clone, Copy, Default)]
pub struct InitExprInfo {
    /// The highest global.get index found, if any.
    pub global_ref: Option<u32>,
    /// The result type of the expression, if determinable.
    pub result_type: Option<ValType>,
    /// Number of values produced on the type stack.
    pub stack_depth: u32,
    /// Whether the expression uses a non-constant instruction.
    pub has_non_const: bool,
    /// Whether the expression references a mutable global.
    pub has_mutable_global: bool,
    /// If a ref.func is found, the function index (first one only).
    pub func_ref: Option<u32>,
}

/// A fully decoded WASM module.
///
/// All buffers are heap-allocated via `Vec` to avoid large stack frames.
pub struct WasmModule {
    pub func_types: Vec<FuncTypeDef>,
    pub functions: Vec<FuncDef>,
    pub imports: Vec<ImportDef>,
    pub exports: Vec<ExportDef>,
    pub globals: Vec<GlobalDef>,
    pub tables: Vec<TableDef>,
    pub memories: Vec<MemoryDef>,
    pub data_segments: Vec<DataSegment>,
    pub element_segments: Vec<ElementSegment>,
    pub start_func: Option<u32>,

    pub has_memory: bool,
    pub has_memory_max: bool,
    pub memory_count: u32,
    pub memory_min_pages: u32,
    pub memory_max_pages: u32,
    /// Whether the first memory uses 64-bit addressing (memory64 proposal).
    pub is_memory64: bool,
    /// Custom page size log2 for the first memory (None if no custom page size).
    pub page_size_log2: Option<u32>,

    /// Whether GC-proposal features are enabled (allows module-defined globals in const exprs).
    pub gc_enabled: bool,
    /// Whether multi-memory proposal is enabled.
    pub multi_memory_enabled: bool,

    /// DataCount section value (if present); None if no DataCount section.
    pub data_count: Option<u32>,

    /// Whether the code section references data segments (memory.init, data.drop).
    pub code_uses_data_count: bool,

    /// Tag type indices (exception handling proposal).
    /// Each entry is the function type index for that tag.
    pub tag_types: Vec<u32>,

    /// Raw bytecode + data segment bytes storage.
    pub code: Vec<u8>,

    /// Name bytes — import/export names are copied here.
    pub names: Vec<u8>,
}

impl WasmModule {
    pub fn new() -> Self {
        WasmModule {
            func_types: Vec::new(),
            functions: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            globals: Vec::new(),
            tables: Vec::new(),
            memories: Vec::new(),
            data_segments: Vec::new(),
            element_segments: Vec::new(),
            start_func: None,
            has_memory: false,
            has_memory_max: false,
            memory_count: 0,
            memory_min_pages: 0,
            memory_max_pages: 0,
            is_memory64: false,
            page_size_log2: None,
            gc_enabled: false,
            multi_memory_enabled: false,
            data_count: None,
            code_uses_data_count: false,
            tag_types: Vec::new(),
            code: Vec::new(),
            names: Vec::new(),
        }
    }

    /// Look up a name stored in the names buffer.
    pub fn get_name(&self, offset: usize, len: usize) -> &[u8] {
        let end = offset.saturating_add(len).min(self.names.len());
        let start = offset.min(end);
        &self.names[start..end]
    }

    /// Count the number of function imports (not global/table/memory imports).
    /// WASM function index space = func_import_count + local function count.
    pub fn func_import_count(&self) -> usize {
        self.imports.iter().filter(|imp| matches!(imp.kind, ImportKind::Func(_))).count()
    }

    /// Get the type index of the N-th function import.
    pub fn func_import_type(&self, func_idx: u32) -> Option<u32> {
        let mut count: u32 = 0;
        for imp in &self.imports {
            if let ImportKind::Func(ti) = imp.kind {
                if count == func_idx {
                    return Some(ti);
                }
                count = count.saturating_add(1);
            }
        }
        None
    }

    /// Find an exported function index by name.
    pub fn find_export_func(&self, name: &[u8]) -> Option<u32> {
        for exp in &self.exports {
            if let ExportKind::Func(idx) = exp.kind {
                let exp_name = self.get_name(exp.name_offset, exp.name_len);
                if exp_name == name {
                    return Some(idx);
                }
            }
        }
        None
    }
}

// ─── Byte reading helper ────────────────────────────────────────────────────

fn read_byte(bytes: &[u8], pos: &mut usize) -> Result<u8, WasmError> {
    if *pos >= bytes.len() {
        return Err(WasmError::UnexpectedEnd);
    }
    let b = bytes[*pos];
    *pos += 1;
    Ok(b)
}

fn peek_byte(bytes: &[u8], pos: usize) -> Result<u8, WasmError> {
    if pos >= bytes.len() {
        return Err(WasmError::UnexpectedEnd);
    }
    Ok(bytes[pos])
}

// ─── LEB128 helpers ─────────────────────────────────────────────────────────

pub fn decode_leb128_u32(bytes: &[u8], pos: &mut usize) -> Result<u32, WasmError> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= bytes.len() {
            return Err(WasmError::UnexpectedEnd);
        }
        let byte = bytes[*pos];
        *pos += 1;
        if shift == 28 && byte > 0x0F {
            return Err(WasmError::InvalidLEB128);
        }
        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 35 {
            return Err(WasmError::InvalidLEB128);
        }
    }
}

pub fn decode_leb128_u64(bytes: &[u8], pos: &mut usize) -> Result<u64, WasmError> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= bytes.len() {
            return Err(WasmError::UnexpectedEnd);
        }
        let byte = bytes[*pos];
        *pos += 1;
        if shift == 63 && byte > 0x01 {
            return Err(WasmError::InvalidLEB128);
        }
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 70 {
            return Err(WasmError::InvalidLEB128);
        }
    }
}

pub fn decode_leb128_i32(bytes: &[u8], pos: &mut usize) -> Result<i32, WasmError> {
    let mut result: i32 = 0;
    let mut shift: u32 = 0;
    let size = 32;
    loop {
        if *pos >= bytes.len() {
            return Err(WasmError::UnexpectedEnd);
        }
        let byte = bytes[*pos];
        *pos += 1;
        if shift == 28 {
            // 5th byte for i32: only lower 4 bits contribute to the value.
            // Bit 3 is the sign bit. Bits 4-6 must be copies of bit 3.
            // Also, the continuation bit (bit 7) must be 0.
            if byte & 0x80 != 0 {
                return Err(WasmError::InvalidLEB128);
            }
            let sign_bit = (byte >> 3) & 1;
            let upper = (byte >> 4) & 0x07;
            if sign_bit == 0 && upper != 0 {
                return Err(WasmError::InvalidLEB128);
            }
            if sign_bit == 1 && upper != 0x07 {
                return Err(WasmError::InvalidLEB128);
            }
            result |= ((byte & 0x7F) as i32) << shift;
            shift += 7;
            // Sign extend if needed
            if shift < size && (byte & 0x40) != 0 {
                result |= !0 << shift;
            }
            return Ok(result);
        }
        result |= ((byte & 0x7F) as i32) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            // Sign extend if needed
            if shift < size && (byte & 0x40) != 0 {
                result |= !0 << shift;
            }
            return Ok(result);
        }
        if shift >= 35 {
            return Err(WasmError::InvalidLEB128);
        }
    }
}

pub fn decode_leb128_i64(bytes: &[u8], pos: &mut usize) -> Result<i64, WasmError> {
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    let size = 64;
    loop {
        if *pos >= bytes.len() {
            return Err(WasmError::UnexpectedEnd);
        }
        let byte = bytes[*pos];
        *pos += 1;
        if shift == 63 {
            // 10th byte for i64: only bit 0 contributes (bit 63 of the value).
            // Continuation bit (bit 7) must be 0.
            // Bits 1-6 must be copies of bit 0 (sign-consistent).
            if byte & 0x80 != 0 {
                return Err(WasmError::InvalidLEB128);
            }
            // Valid values: 0x00 (positive) or 0x7F (negative)
            if byte != 0x00 && byte != 0x7F {
                return Err(WasmError::InvalidLEB128);
            }
            result |= ((byte & 0x7F) as i64) << shift;
            // Sign extend if needed (bit 6 = 0x40 set means negative)
            if (byte & 0x40) != 0 {
                // No need to sign-extend past 64 bits
            }
            return Ok(result);
        }
        result |= ((byte & 0x7F) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < size && (byte & 0x40) != 0 {
                result |= !0i64 << shift;
            }
            return Ok(result);
        }
        if shift >= 70 {
            return Err(WasmError::InvalidLEB128);
        }
    }
}

// ─── Section IDs ────────────────────────────────────────────────────────────

const SECTION_TYPE: u8 = 1;
const SECTION_IMPORT: u8 = 2;
const SECTION_FUNCTION: u8 = 3;
const SECTION_TABLE: u8 = 4;
const SECTION_MEMORY: u8 = 5;
const SECTION_GLOBAL: u8 = 6;
const SECTION_EXPORT: u8 = 7;
const SECTION_START: u8 = 8;
const SECTION_ELEMENT: u8 = 9;
const SECTION_CODE: u8 = 10;
const SECTION_DATA: u8 = 11;
const SECTION_DATA_COUNT: u8 = 12;
const SECTION_TAG: u8 = 13;

// ─── UTF-8 validation ───────────────────────────────────────────────────────

fn validate_utf8(bytes: &[u8]) -> Result<(), WasmError> {
    core::str::from_utf8(bytes).map_err(|_| WasmError::MalformedUtf8)?;
    Ok(())
}

/// Read a length-prefixed name from the byte stream and validate UTF-8.
fn read_name<'a>(bytes: &'a [u8], pos: &mut usize) -> Result<&'a [u8], WasmError> {
    let len = decode_leb128_u32(bytes, pos)? as usize;
    if *pos + len > bytes.len() {
        return Err(WasmError::UnexpectedEnd);
    }
    let name = &bytes[*pos..*pos + len];
    validate_utf8(name)?;
    *pos += len;
    Ok(name)
}

// ─── WASM magic & version ───────────────────────────────────────────────────

const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D]; // \0asm
const WASM_VERSION: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

// ─── Top-level decode ───────────────────────────────────────────────────────

/// Decode a WASM binary into a `WasmModule`.
pub fn decode(bytes: &[u8]) -> Result<WasmModule, WasmError> {
    if bytes.len() < 8 {
        return Err(WasmError::InvalidMagic);
    }

    // Check magic number
    if bytes[0..4] != WASM_MAGIC {
        return Err(WasmError::InvalidMagic);
    }

    // Check version
    if bytes[4..8] != WASM_VERSION {
        return Err(WasmError::UnsupportedVersion);
    }

    let mut module = WasmModule::new();
    let mut pos: usize = 8;

    // Track the last non-custom section id for ordering validation.
    // Custom sections (id 0) can appear anywhere and don't affect ordering.
    let mut last_non_custom_section_id: u8 = 0;
    let mut has_code_section = false;
    let mut has_data_section = false;

    while pos < bytes.len() {
        let section_id = read_byte(bytes, &mut pos)?;

        // Reject unknown section IDs (valid: 0-13)
        if section_id > SECTION_TAG {
            return Err(WasmError::InvalidSection);
        }

        // Section ordering: non-custom sections must appear in order.
        // Custom sections (id 0) can appear anywhere.
        // Each non-custom section can appear at most once, and must be in
        // ascending id order (except DataCount=12, which appears between
        // Element=9 and Code=10 in canonical order, but the spec allows
        // it after Import and before Code).
        if section_id != 0 {
            if section_id == last_non_custom_section_id {
                // Duplicate section (not custom)
                return Err(WasmError::InvalidSection);
            }
            // DataCount (12) must come after Element (9) but before Code (10).
            // In the binary ordering, DataCount is placed between Element and Code.
            // We map it to a canonical order position between Element and Code.
            let order = section_order(section_id);
            let last_order = section_order(last_non_custom_section_id);
            if order <= last_order {
                return Err(WasmError::InvalidSection);
            }
            last_non_custom_section_id = section_id;
        }

        let section_len = decode_leb128_u32(bytes, &mut pos)? as usize;
        let section_end = pos + section_len;

        if section_end > bytes.len() {
            return Err(WasmError::UnexpectedEnd);
        }

        match section_id {
            SECTION_TYPE => decode_type_section(bytes, &mut pos, section_end, &mut module)?,
            SECTION_IMPORT => decode_import_section(bytes, &mut pos, section_end, &mut module)?,
            SECTION_FUNCTION => decode_function_section(bytes, &mut pos, section_end, &mut module)?,
            SECTION_TABLE => decode_table_section(bytes, &mut pos, section_end, &mut module)?,
            SECTION_MEMORY => decode_memory_section(bytes, &mut pos, section_end, &mut module)?,
            SECTION_GLOBAL => decode_global_section(bytes, &mut pos, section_end, &mut module)?,
            SECTION_EXPORT => decode_export_section(bytes, &mut pos, section_end, &mut module)?,
            SECTION_START => decode_start_section(bytes, &mut pos, section_end, &mut module)?,
            SECTION_ELEMENT => decode_element_section(bytes, &mut pos, section_end, &mut module)?,
            SECTION_CODE => {
                has_code_section = true;
                decode_code_section(bytes, &mut pos, section_end, &mut module)?;
            }
            SECTION_DATA => {
                has_data_section = true;
                decode_data_section(bytes, &mut pos, section_end, &mut module)?;
            }
            SECTION_DATA_COUNT => decode_data_count_section(bytes, &mut pos, section_end, &mut module)?,
            SECTION_TAG => {
                // Tag section (exception handling proposal): decode and validate
                let count = decode_leb128_u32(bytes, &mut pos)? as usize;
                for _ in 0..count {
                    let _attribute = read_byte(bytes, &mut pos)?; // must be 0x00
                    let type_idx = decode_leb128_u32(bytes, &mut pos)?;
                    // Validate: tag type must have no results
                    if (type_idx as usize) < module.func_types.len() {
                        if module.func_types[type_idx as usize].result_count > 0 {
                            return Err(WasmError::TypeMismatch);
                        }
                    }
                    module.tag_types.push(type_idx);
                }
            }
            0 => {
                // Custom section: validate the name (LEB128 + UTF-8), skip payload
                let name_len = decode_leb128_u32(bytes, &mut pos)? as usize;
                if pos + name_len > section_end {
                    return Err(WasmError::UnexpectedEnd);
                }
                // UTF-8 validation of custom section name
                let name_bytes = &bytes[pos..pos + name_len];
                core::str::from_utf8(name_bytes).map_err(|_| WasmError::MalformedUtf8)?;
                pos = section_end;
            }
            _ => unreachable!(), // covered by the > 12 check above
        }

        // Section size mismatch: for non-custom sections, ensure we consumed
        // exactly to section_end. Custom sections are already advanced to section_end above.
        if section_id != 0 {
            if pos != section_end {
                return Err(WasmError::InvalidSection);
            }
        }
    }

    // Validate data count vs data section consistency
    if let Some(data_count) = module.data_count {
        if has_data_section {
            if module.data_segments.len() != data_count as usize {
                return Err(WasmError::InvalidSection);
            }
        } else if data_count != 0 {
            return Err(WasmError::InvalidSection);
        }
    }

    // If code section uses bulk-memory data instructions (memory.init, data.drop),
    // the data count section is required.
    if module.code_uses_data_count && module.data_count.is_none() {
        return Err(WasmError::InvalidSection);
    }

    Ok(module)
}

/// Map section IDs to canonical ordering positions.
/// DataCount (12) must appear after Element (9) but before Code (10).
fn section_order(id: u8) -> u8 {
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
        0x63 | 0x64 => {
            let heap_type = decode_leb128_i32(bytes, pos)?;
            if heap_type == -0x11 {
                Ok(ValType::ExternRef)
            } else if heap_type == -0x10 {
                // (ref null func) = funcref, (ref func) = non-nullable abstract func ref
                if b == 0x63 { Ok(ValType::FuncRef) } else { Ok(ValType::TypedFuncRef) }
            } else if b == 0x63 {
                Ok(ValType::NullableTypedFuncRef) // (ref null $t)
            } else {
                Ok(ValType::TypedFuncRef) // (ref $t)
            }
        }
        _ => Err(WasmError::TypeMismatch),
    }
}

/// Decode a reference type from the bytecode stream.
/// Only accepts reference types: 0x70 (funcref), 0x6F (externref), 0x63 (ref null ht), 0x64 (ref ht).
/// Returns an error for non-reference types (i32, i64, f32, f64, v128).
fn decode_reftype_from_stream(bytes: &[u8], pos: &mut usize) -> Result<ValType, WasmError> {
    let b = read_byte(bytes, pos)?;
    match b {
        0x70 | 0x6F => Ok(ValType::I32), // funcref, externref -> I32 placeholder
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
    let b = read_byte(bytes, pos)?;
    match b {
        0x70 => Ok(ValType::FuncRef),
        0x6F => Ok(ValType::ExternRef),
        0x63 | 0x64 => {
            let heap_type = decode_leb128_i32(bytes, pos)?;
            if heap_type == -0x10 {
                Ok(if b == 0x63 { ValType::FuncRef } else { ValType::TypedFuncRef })
            } else if heap_type == -0x11 {
                Ok(ValType::ExternRef)
            } else {
                Ok(if b == 0x63 { ValType::NullableTypedFuncRef } else { ValType::TypedFuncRef })
            }
        }
        _ => Err(WasmError::TypeMismatch),
    }
}

/// Skip a storage type (used in struct/array field types).
/// Storage types: 0x78 = i8, 0x77 = i16, or a full valtype.
fn skip_storage_type(bytes: &[u8], pos: &mut usize) -> Result<(), WasmError> {
    let b = peek_byte(bytes, *pos)?;
    match b {
        0x78 | 0x77 => { *pos += 1; Ok(()) }
        _ => { decode_valtype_from_stream(bytes, pos)?; Ok(()) }
    }
}

/// Decode a composite type (possibly wrapped in sub/sub_final) and push to module.func_types.
/// Handles: func (0x60), struct (0x5F), array (0x5E).
fn decode_composite_type(
    bytes: &[u8],
    pos: &mut usize,
    module: &mut WasmModule,
) -> Result<(), WasmError> {
    let sub_marker = read_byte(bytes, pos)?;
    let inner_marker;
    if sub_marker == 0x50 || sub_marker == 0x4F {
        // sub/sub_final: read supertype count + supertypes
        let super_count = decode_leb128_u32(bytes, pos)? as usize;
        for _ in 0..super_count {
            let _ = decode_leb128_u32(bytes, pos)?;
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
                ft.params[p] = decode_valtype_from_stream(bytes, pos)?;
            }
            let result_count = decode_leb128_u32(bytes, pos)? as u8;
            if result_count as usize > MAX_RESULTS {
                return Err(WasmError::TooManyFunctions);
            }
            ft.result_count = result_count;
            for r in 0..result_count as usize {
                ft.results[r] = decode_valtype_from_stream(bytes, pos)?;
            }
            module.func_types.push(ft);
        }
        0x5E => {
            // array type (GC proposal): single field (storage_type + mutability)
            skip_storage_type(bytes, pos)?;
            let mt = read_byte(bytes, pos)?; // mutability
            if mt > 1 {
                return Err(WasmError::InvalidSection);
            }
            // Push a placeholder func type so type indices stay aligned
            module.func_types.push(FuncTypeDef::empty());
        }
        0x5F => {
            // struct type (GC proposal): count of fields, each is storage_type + mutability
            let field_count = decode_leb128_u32(bytes, pos)? as usize;
            for _ in 0..field_count {
                skip_storage_type(bytes, pos)?;
                let mt = read_byte(bytes, pos)?; // mutability
                if mt > 1 {
                    return Err(WasmError::InvalidSection);
                }
            }
            // Push a placeholder func type so type indices stay aligned
            module.func_types.push(FuncTypeDef::empty());
        }
        _ => return Err(WasmError::InvalidSection),
    }
    Ok(())
}

fn decode_type_section(
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
            let rec_count = decode_leb128_u32(bytes, pos)? as usize;
            for _ in 0..rec_count {
                decode_composite_type(bytes, pos, module)?;
            }
            continue;
        }
        // For non-rec types, "unread" the marker by backing up
        *pos -= 1;
        decode_composite_type(bytes, pos, module)?;
    }

    Ok(())
}

fn decode_import_section(
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
                    0x63 | 0x64 => {
                        let _ = decode_leb128_i32(bytes, pos)?;
                        if elemtype == 0x63 { ValType::FuncRef } else { ValType::FuncRef }
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
                module.tables.push(TableDef { min, max, elem_type: et, is_table64 });
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
                let min = if is_memory64 { decode_leb128_u64(bytes, pos)? as u32 } else { decode_leb128_u32(bytes, pos)? };
                let has_max = flags & 1 != 0;
                let max = if has_max {
                    if is_memory64 { decode_leb128_u64(bytes, pos)? as u32 } else { decode_leb128_u32(bytes, pos)? }
                } else { u32::MAX };
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
                    page_size_log2: mem_page_size_log2,
                });
                imp.kind = ImportKind::Memory;
            }
            0x03 => {
                // Global import: valtype + mutability
                let vt = read_byte(bytes, pos)?;
                // Handle multi-byte ref types (0x63, 0x64)
                if vt == 0x63 || vt == 0x64 {
                    let _ = decode_leb128_i32(bytes, pos)?;
                }
                let mt = read_byte(bytes, pos)?;
                if mt > 1 {
                    return Err(WasmError::InvalidSection);
                }
                imp.kind = ImportKind::Global(vt, mt != 0);
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

fn decode_function_section(
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

fn decode_memory_section(
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
            let max_pages_for_mem64: u64 = if page_size_log2 == 0 {
                // pagesize 1: max is 2^48 bytes = 2^48
                1u64 << 48
            } else {
                // pagesize 2^n: max is 2^48 / 2^n = 2^(48-n)
                1u64 << (48u32.saturating_sub(page_size_log2))
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

fn decode_export_section(
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

fn decode_code_section(
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
        let func = &mut module.functions[i];

        for _ in 0..local_decl_count {
            let n = decode_leb128_u32(bytes, pos)? as u64;
            let ty = decode_valtype_from_stream(bytes, pos)?;
            total_locals = total_locals.saturating_add(n);
            // WASM spec: no more than 2^32 - 1 locals total (including params)
            if total_locals > u32::MAX as u64 {
                return Err(WasmError::InvalidSection);
            }
            let start = (total_locals - n) as usize;
            for j in start..((total_locals as usize).min(MAX_LOCALS)) {
                func.locals[j] = ty;
            }
        }

        // Also check including params from the function type
        let type_idx = func.type_idx as usize;
        func.local_count = total_locals.min(u16::MAX as u64) as u16;

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

fn decode_table_section(
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

        // elemtype: 0x70 = funcref, 0x6F = externref, 0x63/0x64 = ref types
        let elemtype = read_byte(bytes, pos)?;
        let mut elem_heap_type: i32 = 0;
        if elemtype == 0x63 || elemtype == 0x64 {
            // Nullable/non-nullable ref type: read heap type
            elem_heap_type = decode_leb128_i32(bytes, pos)?;
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

        // If has_init_expr, skip the init expression
        if has_init_expr {
            let _ = eval_init_expr(bytes, pos)?;
        }

        let et = match elemtype {
            0x70 => ValType::FuncRef,
            0x6F => ValType::ExternRef,
            0x64 => {
                // (ref ht) = non-nullable
                if elem_heap_type == -0x10 { ValType::TypedFuncRef }
                else if elem_heap_type == -0x11 { ValType::ExternRef }
                else { ValType::TypedFuncRef }
            }
            _ => {
                // 0x63 = (ref null ht) = nullable
                if elem_heap_type == -0x10 { ValType::FuncRef }
                else if elem_heap_type == -0x11 { ValType::ExternRef }
                else { ValType::NullableTypedFuncRef }
            }
        };
        module.tables.push(TableDef { min, max, elem_type: et, is_table64 });
    }
    Ok(())
}

fn decode_global_section(
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
        // Use stream decoder to handle multi-byte ref types
        let val_type = decode_valtype_from_stream(bytes, pos)?;
        let mt = read_byte(bytes, pos)?;
        if mt > 1 {
            return Err(WasmError::InvalidSection);
        }
        let mutable = mt != 0;
        // Scan init expr bytes to find global.get references and type info before consuming them.
        let expr_info = scan_init_expr_info(bytes, *pos);
        let init_global_ref = expr_info.global_ref;
        let init_expr_type = expr_info.result_type;
        let init_expr_stack_depth = expr_info.stack_depth;
        let init_func_ref = expr_info.func_ref;
        let init_value = eval_init_expr(bytes, pos)?;
        module.globals.push(GlobalDef { val_type, mutable, init_value, init_global_ref, init_expr_type, init_expr_stack_depth, init_func_ref });
    }
    Ok(())
}

fn decode_start_section(
    bytes: &[u8],
    pos: &mut usize,
    _end: usize,
    module: &mut WasmModule,
) -> Result<(), WasmError> {
    let func_idx = decode_leb128_u32(bytes, pos)?;
    module.start_func = Some(func_idx);
    Ok(())
}

fn decode_element_section(
    bytes: &[u8],
    pos: &mut usize,
    _end: usize,
    module: &mut WasmModule,
) -> Result<(), WasmError> {
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
                let expr_info = scan_init_expr_info(bytes, *pos);
                let offset_val = eval_init_expr(bytes, pos)?;
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
                    offset_expr_range: (0, 0),
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
                });
            }
            2 => {
                // Active segment with explicit table_idx
                let table_idx = decode_leb128_u32(bytes, pos)?;
                let expr_info = scan_init_expr_info(bytes, *pos);
                let offset_val = eval_init_expr(bytes, pos)?;
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
                    offset_expr_range: (0, 0),
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
                });
            }
            4 => {
                // Active, table 0 implicit, offset expr, expression elements
                let expr_info = scan_init_expr_info(bytes, *pos);
                let offset_val = eval_init_expr(bytes, pos)?;
                let offset = match offset_val { Value::I32(v) => v as u32, _ => 0 };
                let num_elems = decode_leb128_u32(bytes, pos)? as usize;
                let mut func_indices = alloc::vec::Vec::with_capacity(num_elems);
                let mut item_expr_infos = alloc::vec::Vec::with_capacity(num_elems);
                for _ in 0..num_elems {
                    let item_info = scan_init_expr_info(bytes, *pos);
                    let val = eval_init_expr(bytes, pos)?;
                    func_indices.push(match val { Value::I32(v) => v as u32, _ => u32::MAX });
                    item_expr_infos.push(item_info);
                }
                module.element_segments.push(ElementSegment { table_idx: 0, offset, func_indices, mode: ElemMode::Active, elem_type: ValType::FuncRef, offset_expr_info: expr_info, item_expr_infos, offset_expr_range: (0, 0) });
            }
            5 => {
                // Passive, reftype, expression elements
                let elem_type = decode_reftype_real(bytes, pos)?;
                let num_elems = decode_leb128_u32(bytes, pos)? as usize;
                let mut func_indices = alloc::vec::Vec::with_capacity(num_elems);
                let mut item_expr_infos = alloc::vec::Vec::with_capacity(num_elems);
                for _ in 0..num_elems {
                    let item_info = scan_init_expr_info(bytes, *pos);
                    let val = eval_init_expr(bytes, pos)?;
                    func_indices.push(match val { Value::I32(v) => v as u32, _ => u32::MAX });
                    item_expr_infos.push(item_info);
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
                });
            }
            6 => {
                // Active, explicit table_idx, offset expr, reftype, expression elements
                let table_idx = decode_leb128_u32(bytes, pos)?;
                let expr_info = scan_init_expr_info(bytes, *pos);
                let offset_val = eval_init_expr(bytes, pos)?;
                let offset = match offset_val { Value::I32(v) => v as u32, _ => 0 };
                let elem_type = decode_reftype_real(bytes, pos)?;
                let num_elems = decode_leb128_u32(bytes, pos)? as usize;
                let mut func_indices = alloc::vec::Vec::with_capacity(num_elems);
                let mut item_expr_infos = alloc::vec::Vec::with_capacity(num_elems);
                for _ in 0..num_elems {
                    let item_info = scan_init_expr_info(bytes, *pos);
                    let val = eval_init_expr(bytes, pos)?;
                    func_indices.push(match val { Value::I32(v) => v as u32, _ => u32::MAX });
                    item_expr_infos.push(item_info);
                }
                module.element_segments.push(ElementSegment { table_idx, offset, func_indices, mode: ElemMode::Active, elem_type, offset_expr_info: expr_info, item_expr_infos, offset_expr_range: (0, 0) });
            }
            7 => {
                // Declarative, reftype, expression elements (dropped immediately)
                let elem_type = decode_reftype_real(bytes, pos)?;
                let num_elems = decode_leb128_u32(bytes, pos)? as usize;
                let mut func_indices = alloc::vec::Vec::with_capacity(num_elems);
                let mut item_expr_infos = alloc::vec::Vec::with_capacity(num_elems);
                for _ in 0..num_elems {
                    let item_info = scan_init_expr_info(bytes, *pos);
                    let val = eval_init_expr(bytes, pos)?;
                    func_indices.push(match val { Value::I32(v) => v as u32, _ => u32::MAX });
                    item_expr_infos.push(item_info);
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
                });
            }
            _ => {
                return Err(WasmError::InvalidSection);
            }
        }
    }
    Ok(())
}

fn decode_data_section(
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

fn decode_data_count_section(
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

/// Skip past a constant init expression (read opcodes until 0x0B end marker).
/// Used for table init expressions and other places where we don't need the value.
fn skip_init_expr(bytes: &[u8], pos: &mut usize) -> Result<(), WasmError> {
    loop {
        if *pos >= bytes.len() {
            return Err(WasmError::UnexpectedEnd);
        }
        let opcode = read_byte(bytes, pos)?;
        match opcode {
            0x0B => return Ok(()), // end
            0x41 => { decode_leb128_i32(bytes, pos)?; } // i32.const
            0x42 => { decode_leb128_i64(bytes, pos)?; } // i64.const
            0x43 => { // f32.const
                if *pos + 4 > bytes.len() { return Err(WasmError::UnexpectedEnd); }
                *pos += 4;
            }
            0x44 => { // f64.const
                if *pos + 8 > bytes.len() { return Err(WasmError::UnexpectedEnd); }
                *pos += 8;
            }
            0x23 => { decode_leb128_u32(bytes, pos)?; } // global.get
            0xD0 => { decode_leb128_i32(bytes, pos)?; } // ref.null
            0xD2 => { decode_leb128_u32(bytes, pos)?; } // ref.func
            0xFD => { // SIMD prefix
                let sub = decode_leb128_u32(bytes, pos)?;
                if sub == 12 { // v128.const
                    if *pos + 16 > bytes.len() { return Err(WasmError::UnexpectedEnd); }
                    *pos += 16;
                }
            }
            // Extended-const ops (no immediates): i32.add/sub/mul, i64.add/sub/mul
            0x6A | 0x6B | 0x6C | 0x7C | 0x7D | 0x7E => {}
            _ => return Err(WasmError::InvalidSection),
        }
    }
}

/// Scan init expression bytes to extract validation info.
/// Returns InitExprInfo with global refs, result type, stack depth, etc.
pub fn scan_init_expr_info(bytes: &[u8], start: usize) -> InitExprInfo {
    let mut p = start;
    let mut info = InitExprInfo::default();
    // Track a small type stack
    let mut type_stack: [Option<ValType>; 16] = [None; 16];
    let mut sp: usize = 0;

    while p < bytes.len() {
        let b = bytes[p];
        p += 1;
        match b {
            0x0B => break, // end
            0x23 => {
                // global.get - read the index
                if let Ok(idx) = decode_leb128_u32(bytes, &mut p) {
                    info.global_ref = Some(match info.global_ref {
                        Some(cur) => cur.max(idx),
                        None => idx,
                    });
                    // We don't know the type without looking up the global,
                    // so push None (unknown type)
                    if sp < 16 { type_stack[sp] = None; sp += 1; }
                }
            }
            0x41 => {
                let _ = decode_leb128_i32(bytes, &mut p);
                if sp < 16 { type_stack[sp] = Some(ValType::I32); sp += 1; }
            }
            0x42 => {
                let _ = decode_leb128_i64(bytes, &mut p);
                if sp < 16 { type_stack[sp] = Some(ValType::I64); sp += 1; }
            }
            0x43 => {
                p += 4;
                if sp < 16 { type_stack[sp] = Some(ValType::F32); sp += 1; }
            }
            0x44 => {
                p += 8;
                if sp < 16 { type_stack[sp] = Some(ValType::F64); sp += 1; }
            }
            0xD0 => {
                let ht = decode_leb128_i32(bytes, &mut p);
                let vt = match ht {
                    Ok(-0x10) => Some(ValType::FuncRef),     // (ref null func) = funcref
                    Ok(-0x11) => Some(ValType::ExternRef),   // (ref null extern) = externref
                    Ok(ht_idx) if ht_idx >= 0 => Some(ValType::NullableTypedFuncRef), // (ref null $t)
                    _ => None,
                };
                if sp < 16 { type_stack[sp] = vt; sp += 1; }
            }
            0xD2 => {
                if let Ok(idx) = decode_leb128_u32(bytes, &mut p) {
                    if info.func_ref.is_none() {
                        info.func_ref = Some(idx);
                    }
                }
                // ref.func produces (ref $t) = TypedFuncRef (non-nullable)
                if sp < 16 { type_stack[sp] = Some(ValType::TypedFuncRef); sp += 1; }
            }
            0xFD => {
                let _ = decode_leb128_u32(bytes, &mut p);
                p += 16;
                if sp < 16 { type_stack[sp] = Some(ValType::V128); sp += 1; }
            }
            // i32 arithmetic (extended-const): pop 2, push 1
            0x6A | 0x6B | 0x6C => {
                if sp >= 2 { sp -= 1; type_stack[sp - 1] = Some(ValType::I32); }
            }
            // i64 arithmetic (extended-const): pop 2, push 1
            0x7C | 0x7D | 0x7E => {
                if sp >= 2 { sp -= 1; type_stack[sp - 1] = Some(ValType::I64); }
            }
            _ => {
                info.has_non_const = true;
                break;
            }
        }
    }

    info.stack_depth = sp as u32;
    info.result_type = if sp > 0 { type_stack[sp - 1] } else { None };
    info
}

/// Scan init expression bytes to find the maximum global.get reference index.
/// Wrapper for backward compat.
fn scan_init_expr_global_refs(bytes: &[u8], start: usize) -> Option<u32> {
    scan_init_expr_info(bytes, start).global_ref
}

/// Evaluate a constant init expression (for globals and segment offsets).
/// Supports MVP + extended-const proposal (multi-instruction expressions).
fn eval_init_expr(bytes: &[u8], pos: &mut usize) -> Result<Value, WasmError> {
    if *pos >= bytes.len() {
        return Err(WasmError::UnexpectedEnd);
    }
    // Use a small stack to evaluate extended-const expressions
    let mut stack: [Value; 16] = [Value::I32(0); 16];
    let mut sp: usize = 0;

    loop {
        let opcode = read_byte(bytes, pos)?;
        match opcode {
            0x0B => {
                // end - return top of stack (or I32(0) if empty)
                return if sp > 0 { Ok(stack[sp - 1]) } else { Ok(Value::I32(0)) };
            }
            0x41 => {
                // i32.const
                let v = decode_leb128_i32(bytes, pos)?;
                if sp < 16 { stack[sp] = Value::I32(v); sp += 1; }
            }
            0x42 => {
                // i64.const
                let v = decode_leb128_i64(bytes, pos)?;
                if sp < 16 { stack[sp] = Value::I64(v); sp += 1; }
            }
            0x43 => {
                // f32.const
                if *pos + 4 > bytes.len() { return Err(WasmError::UnexpectedEnd); }
                let b0 = read_byte(bytes, pos)?;
                let b1 = read_byte(bytes, pos)?;
                let b2 = read_byte(bytes, pos)?;
                let b3 = read_byte(bytes, pos)?;
                let v = f32::from_le_bytes([b0, b1, b2, b3]);
                if sp < 16 { stack[sp] = Value::F32(v); sp += 1; }
            }
            0x44 => {
                // f64.const
                if *pos + 8 > bytes.len() { return Err(WasmError::UnexpectedEnd); }
                let mut b8 = [0u8; 8];
                b8.copy_from_slice(&bytes[*pos..*pos+8]);
                *pos += 8;
                if sp < 16 { stack[sp] = Value::F64(f64::from_le_bytes(b8)); sp += 1; }
            }
            0x23 => {
                // global.get (reference to imported or defined global — return placeholder)
                let _idx = decode_leb128_u32(bytes, pos)?;
                if sp < 16 { stack[sp] = Value::I32(0); sp += 1; }
            }
            0xD0 => {
                // ref.null heaptype
                let _ = decode_leb128_i32(bytes, pos)?;
                if sp < 16 { stack[sp] = Value::I32(-1); sp += 1; } // null ref sentinel
            }
            0xD2 => {
                // ref.func funcidx
                let idx = decode_leb128_u32(bytes, pos)?;
                if sp < 16 { stack[sp] = Value::I32(idx as i32); sp += 1; }
            }
            0xFD => {
                // SIMD prefix in init expr: only v128.const (sub-opcode 12) is valid
                let sub = decode_leb128_u32(bytes, pos)?;
                if sub == 12 {
                    if *pos + 16 > bytes.len() { return Err(WasmError::UnexpectedEnd); }
                    let mut v = [0u8; 16];
                    v.copy_from_slice(&bytes[*pos..*pos + 16]);
                    *pos += 16;
                    if sp < 16 { stack[sp] = Value::V128(crate::wasm::types::V128(v)); sp += 1; }
                } else {
                    return Err(WasmError::InvalidSection);
                }
            }
            // Extended-const: i32.add (0x6A), i32.sub (0x6B), i32.mul (0x6C)
            0x6A => {
                if sp >= 2 {
                    let b = match stack[sp-1] { Value::I32(v) => v, _ => 0 };
                    let a = match stack[sp-2] { Value::I32(v) => v, _ => 0 };
                    sp -= 1;
                    stack[sp-1] = Value::I32(a.wrapping_add(b));
                }
            }
            0x6B => {
                if sp >= 2 {
                    let b = match stack[sp-1] { Value::I32(v) => v, _ => 0 };
                    let a = match stack[sp-2] { Value::I32(v) => v, _ => 0 };
                    sp -= 1;
                    stack[sp-1] = Value::I32(a.wrapping_sub(b));
                }
            }
            0x6C => {
                if sp >= 2 {
                    let b = match stack[sp-1] { Value::I32(v) => v, _ => 0 };
                    let a = match stack[sp-2] { Value::I32(v) => v, _ => 0 };
                    sp -= 1;
                    stack[sp-1] = Value::I32(a.wrapping_mul(b));
                }
            }
            // Extended-const: i64.add (0x7C), i64.sub (0x7D), i64.mul (0x7E)
            0x7C => {
                if sp >= 2 {
                    let b = match stack[sp-1] { Value::I64(v) => v, _ => 0 };
                    let a = match stack[sp-2] { Value::I64(v) => v, _ => 0 };
                    sp -= 1;
                    stack[sp-1] = Value::I64(a.wrapping_add(b));
                }
            }
            0x7D => {
                if sp >= 2 {
                    let b = match stack[sp-1] { Value::I64(v) => v, _ => 0 };
                    let a = match stack[sp-2] { Value::I64(v) => v, _ => 0 };
                    sp -= 1;
                    stack[sp-1] = Value::I64(a.wrapping_sub(b));
                }
            }
            0x7E => {
                if sp >= 2 {
                    let b = match stack[sp-1] { Value::I64(v) => v, _ => 0 };
                    let a = match stack[sp-2] { Value::I64(v) => v, _ => 0 };
                    sp -= 1;
                    stack[sp-1] = Value::I64(a.wrapping_mul(b));
                }
            }
            _ => return Err(WasmError::InvalidSection),
        }
    }
}
