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
    Func(u32),        // type index
    Global(u8, bool), // valtype byte, mutable
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
}

/// A global variable definition.
#[derive(Clone)]
pub struct GlobalDef {
    pub val_type: ValType,
    pub mutable: bool,
    pub init_value: Value,
}

/// A table definition.
#[derive(Clone)]
pub struct TableDef {
    pub min: u32,
    pub max: Option<u32>,
}

/// A data segment for memory initialization.
#[derive(Clone)]
pub struct DataSegment {
    pub memory_idx: u32,
    pub offset: u32,
    pub data_offset: usize, // offset into module.code (reused for data bytes)
    pub data_len: usize,
}

/// An element segment for table initialization.
#[derive(Clone)]
pub struct ElementSegment {
    pub table_idx: u32,
    pub offset: u32,
    pub func_indices: alloc::vec::Vec<u32>,
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
    pub data_segments: Vec<DataSegment>,
    pub element_segments: Vec<ElementSegment>,
    pub start_func: Option<u32>,

    pub memory_min_pages: u32,
    pub memory_max_pages: u32,

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
            data_segments: Vec::new(),
            element_segments: Vec::new(),
            start_func: None,
            memory_min_pages: 0,
            memory_max_pages: 0,
            code: Vec::new(),
            names: Vec::new(),
        }
    }

    /// Look up a name stored in the names buffer.
    pub fn get_name(&self, offset: usize, len: usize) -> &[u8] {
        &self.names[offset..offset + len]
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

    while pos < bytes.len() {
        let section_id = bytes[pos];
        pos += 1;

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
            SECTION_CODE => decode_code_section(bytes, &mut pos, section_end, &mut module)?,
            SECTION_DATA => decode_data_section(bytes, &mut pos, section_end, &mut module)?,
            SECTION_DATA_COUNT => decode_data_count_section(bytes, &mut pos, section_end, &mut module)?,
            _ => {
                // Skip unknown sections (pos is reset to section_end below)
            }
        }

        // Make sure we consumed exactly to section_end
        pos = section_end;
    }

    Ok(module)
}

// ─── Section decoders ───────────────────────────────────────────────────────

fn decode_valtype(b: u8) -> Result<ValType, WasmError> {
    match b {
        0x7F => Ok(ValType::I32),
        0x7E => Ok(ValType::I64),
        0x7D => if !STRICT_DETERMINISM { Ok(ValType::F32) } else { Err(WasmError::FloatsDisabled) },
        0x7C => if !STRICT_DETERMINISM { Ok(ValType::F64) } else { Err(WasmError::FloatsDisabled) },
        _ => Err(WasmError::TypeMismatch),
    }
}

fn decode_type_section(
    bytes: &[u8],
    pos: &mut usize,
    _end: usize,
    module: &mut WasmModule,
) -> Result<(), WasmError> {
    let count = decode_leb128_u32(bytes, pos)? as usize;
    if count > MAX_FUNCTIONS {
        return Err(WasmError::TooManyFunctions);
    }

    for _i in 0..count {
        // Each entry starts with 0x60 (func type marker)
        if *pos >= bytes.len() || bytes[*pos] != 0x60 {
            return Err(WasmError::InvalidSection);
        }
        *pos += 1;

        let mut ft = FuncTypeDef::empty();

        // Params
        let param_count = decode_leb128_u32(bytes, pos)? as u8;
        if param_count as usize > MAX_PARAMS {
            return Err(WasmError::TooManyFunctions);
        }
        ft.param_count = param_count;
        for p in 0..param_count as usize {
            ft.params[p] = decode_valtype(bytes[*pos])?;
            *pos += 1;
        }

        // Results
        let result_count = decode_leb128_u32(bytes, pos)? as u8;
        if result_count as usize > MAX_RESULTS {
            return Err(WasmError::TooManyFunctions);
        }
        ft.result_count = result_count;
        for r in 0..result_count as usize {
            ft.results[r] = decode_valtype(bytes[*pos])?;
            *pos += 1;
        }

        module.func_types.push(ft);
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
        let mod_name_len = decode_leb128_u32(bytes, pos)? as usize;
        imp.module_name_offset = module.names.len();
        imp.module_name_len = mod_name_len;
        module.names.extend_from_slice(&bytes[*pos..*pos + mod_name_len]);
        *pos += mod_name_len;

        // Field name
        let field_name_len = decode_leb128_u32(bytes, pos)? as usize;
        imp.field_name_offset = module.names.len();
        imp.field_name_len = field_name_len;
        module.names.extend_from_slice(&bytes[*pos..*pos + field_name_len]);
        *pos += field_name_len;

        // Import kind
        let kind_byte = bytes[*pos];
        *pos += 1;
        match kind_byte {
            0x00 => {
                // Function import
                let type_idx = decode_leb128_u32(bytes, pos)?;
                imp.kind = ImportKind::Func(type_idx);
            }
            0x01 => {
                // Table import: elemtype + limits
                let _elemtype = bytes[*pos]; *pos += 1;
                let flags = decode_leb128_u32(bytes, pos)?;
                let _min = decode_leb128_u32(bytes, pos)?;
                if flags & 1 != 0 { let _ = decode_leb128_u32(bytes, pos)?; }
                imp.kind = ImportKind::Func(0); // placeholder
            }
            0x02 => {
                // Memory import: limits
                let flags = decode_leb128_u32(bytes, pos)?;
                let _min = decode_leb128_u32(bytes, pos)?;
                if flags & 1 != 0 { let _ = decode_leb128_u32(bytes, pos)?; }
                imp.kind = ImportKind::Func(0); // placeholder
            }
            0x03 => {
                // Global import: valtype + mutability
                let vt = bytes[*pos]; *pos += 1;
                let mt = bytes[*pos]; *pos += 1;
                imp.kind = ImportKind::Global(vt, mt != 0);
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
    if count < 1 {
        return Ok(());
    }
    // We only support one memory
    let flags = decode_leb128_u32(bytes, pos)?;
    module.memory_min_pages = decode_leb128_u32(bytes, pos)?;
    if flags & 1 != 0 {
        module.memory_max_pages = decode_leb128_u32(bytes, pos)?;
    } else {
        module.memory_max_pages = module.memory_min_pages;
    }

    // Skip any additional memories
    for _ in 1..count {
        let f = decode_leb128_u32(bytes, pos)?;
        let _ = decode_leb128_u32(bytes, pos)?;
        if f & 1 != 0 {
            let _ = decode_leb128_u32(bytes, pos)?;
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
        let name_len = decode_leb128_u32(bytes, pos)? as usize;
        exp.name_offset = module.names.len();
        exp.name_len = name_len;
        module.names.extend_from_slice(&bytes[*pos..*pos + name_len]);
        *pos += name_len;

        // Kind
        let kind_byte = bytes[*pos];
        *pos += 1;
        let idx = decode_leb128_u32(bytes, pos)?;
        match kind_byte {
            0x00 => exp.kind = ExportKind::Func(idx),
            0x01 => exp.kind = ExportKind::Table(idx),
            0x02 => exp.kind = ExportKind::Memory(idx),
            0x03 => exp.kind = ExportKind::Global(idx),
            _ => exp.kind = ExportKind::Func(idx), // fallback
        }

        module.exports.push(exp);
    }

    Ok(())
}

fn decode_code_section(
    bytes: &[u8],
    pos: &mut usize,
    _end: usize,
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
        let mut total_locals: u16 = 0;

        if i >= module.functions.len() {
            return Err(WasmError::FunctionNotFound(i as u32));
        }
        let func = &mut module.functions[i];

        for _ in 0..local_decl_count {
            let n = decode_leb128_u32(bytes, pos)? as u16;
            let ty = decode_valtype(bytes[*pos])?;
            *pos += 1;
            for _ in 0..n {
                if (total_locals as usize) < MAX_LOCALS {
                    func.locals[total_locals as usize] = ty;
                }
                total_locals += 1;
            }
        }
        func.local_count = total_locals;

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
        // elemtype: 0x70 = funcref (only valid in MVP)
        let elemtype = bytes[*pos]; *pos += 1;
        if elemtype != 0x70 {
            return Err(WasmError::InvalidSection);
        }
        let flags = decode_leb128_u32(bytes, pos)?;
        let min = decode_leb128_u32(bytes, pos)?;
        let max = if flags & 1 != 0 {
            Some(decode_leb128_u32(bytes, pos)?)
        } else {
            None
        };
        module.tables.push(TableDef { min, max });
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
        let vt_byte = bytes[*pos]; *pos += 1;
        let val_type = decode_valtype(vt_byte)?;
        let mutable = bytes[*pos] != 0; *pos += 1;
        let init_value = eval_init_expr(bytes, pos)?;
        module.globals.push(GlobalDef { val_type, mutable, init_value });
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
        let table_idx = decode_leb128_u32(bytes, pos)?;
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
            table_idx,
            offset,
            func_indices,
        });
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
        let memory_idx = decode_leb128_u32(bytes, pos)?;
        let offset_val = eval_init_expr(bytes, pos)?;
        let offset = match offset_val {
            Value::I32(v) => v as u32,
            Value::I64(v) => v as u32,
            _ => 0,
        };
        let data_len = decode_leb128_u32(bytes, pos)? as usize;
        // Store data bytes in module.code (reused buffer)
        let data_offset = module.code.len();
        if *pos + data_len > bytes.len() {
            return Err(WasmError::UnexpectedEnd);
        }
        module.code.extend_from_slice(&bytes[*pos..*pos + data_len]);
        *pos += data_len;
        module.data_segments.push(DataSegment {
            memory_idx,
            offset,
            data_offset,
            data_len,
        });
    }
    Ok(())
}

fn decode_data_count_section(
    bytes: &[u8],
    pos: &mut usize,
    _end: usize,
    _module: &mut WasmModule,
) -> Result<(), WasmError> {
    // DataCount section contains a single u32: the number of data segments.
    // This is used by bulk-memory proposal for validation; we read and discard
    // it since our data section decoder handles counting independently.
    let _count = decode_leb128_u32(bytes, pos)?;
    Ok(())
}

/// Evaluate a constant init expression (for globals and segment offsets).
/// MVP allows: i32.const, i64.const, global.get (of imported global), end.
fn eval_init_expr(bytes: &[u8], pos: &mut usize) -> Result<Value, WasmError> {
    if *pos >= bytes.len() {
        return Err(WasmError::UnexpectedEnd);
    }
    let opcode = bytes[*pos]; *pos += 1;
    let value = match opcode {
        0x41 => {
            // i32.const
            let v = decode_leb128_i32(bytes, pos)?;
            Value::I32(v)
        }
        0x42 => {
            // i64.const
            let v = decode_leb128_i64(bytes, pos)?;
            Value::I64(v)
        }
        0x23 => {
            // global.get (reference to imported global — return placeholder)
            let _idx = decode_leb128_u32(bytes, pos)?;
            Value::I32(0)
        }
        _ => return Err(WasmError::InvalidSection),
    };
    // Expect 0x0B (end)
    if *pos >= bytes.len() || bytes[*pos] != 0x0B {
        return Err(WasmError::InvalidSection);
    }
    *pos += 1;
    Ok(value)
}
