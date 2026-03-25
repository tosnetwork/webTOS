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
    /// Bitset: which locals are non-nullable ref types (need initialization tracking).
    /// Indexed by local index (not including params).
    pub non_nullable_locals: Vec<bool>,
}

impl FuncDef {
    pub const fn empty() -> Self {
        FuncDef {
            type_idx: 0,
            code_offset: 0,
            code_len: 0,
            local_count: 0,
            locals: [ValType::I32; MAX_LOCALS],
            non_nullable_locals: Vec::new(),
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
    Global(u8, bool, Option<i32>),    // valtype byte, mutable, heap type (for 0x63/0x64)
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
    /// Raw init expression bytes for deferred GC evaluation.
    pub init_expr_bytes: Vec<u8>,
    /// Heap type for GC ref types. Negative = abstract (-16=func, -17=extern, etc).
    /// Non-negative = concrete type index. None for non-ref types.
    pub heap_type: Option<i32>,
    /// Whether the init expression contains non-constant instructions.
    pub has_non_const: bool,
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
    /// Optional init expression bytes for all table slots (GC proposal).
    pub init_expr_bytes: Option<Vec<u8>>,
    /// Whether the element type is non-nullable (from 0x64 encoding).
    pub is_non_nullable: bool,
}

/// A memory definition (imported or locally defined).
#[derive(Clone)]
pub struct MemoryDef {
    pub min_pages: u32,
    pub max_pages: u32,
    pub has_max: bool,
    pub is_memory64: bool,
    pub is_shared: bool,
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
    /// Per-item expression bytes for expression-based segments.
    /// Used for re-evaluation at instantiation time (GC proposal).
    pub item_expr_bytes: alloc::vec::Vec<alloc::vec::Vec<u8>>,
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

/// Storage type for struct fields and array elements (GC proposal).
/// Packed types i8/i16 are narrower than full value types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageType {
    I8,
    I16,
    Val(ValType),
    /// A concrete ref type with a tracked heap type index.
    /// Used to distinguish (ref $a) from (ref $b) in validation.
    RefType(ValType, u32),
}

impl StorageType {
    /// Get the full ValType for this storage type (packed -> I32).
    pub fn unpack(self) -> ValType {
        match self {
            StorageType::I8 | StorageType::I16 => ValType::I32,
            StorageType::Val(vt) => vt,
            StorageType::RefType(vt, _) => vt,
        }
    }
}

/// GC type definition — parallel to func_types, indexed by the same type index.
#[derive(Debug, Clone)]
pub enum GcTypeDef {
    /// Regular function type (delegates to func_types entry).
    Func,
    /// Struct type with field types and mutabilities.
    Struct {
        field_types: Vec<StorageType>,
        field_muts: Vec<bool>,
    },
    /// Array type with element type and mutability.
    Array {
        elem_type: StorageType,
        elem_mutable: bool,
    },
}

/// Subtype info: for each type index, which type index is its supertype (if any).
#[derive(Debug, Clone, Copy, Default)]
pub struct SubTypeInfo {
    pub supertype: Option<u32>,
    pub is_final: bool,
    /// The starting type index of the rec group this type belongs to.
    pub rec_group_start: u32,
    /// The number of types in the rec group this type belongs to.
    pub rec_group_size: u32,
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
    /// Whether implicit rec groups are enabled (GC proposal).
    /// When true, non-rec types are treated as being in a singleton rec group.
    pub implicit_rec_enabled: bool,
    /// Whether multi-memory proposal is enabled.
    pub multi_memory_enabled: bool,
    /// Whether multiple tables should be rejected (pre-reference-types, e.g. threads-only).
    pub reject_multi_table: bool,

    /// DataCount section value (if present); None if no DataCount section.
    pub data_count: Option<u32>,

    /// Whether the code section references data segments (memory.init, data.drop).
    pub code_uses_data_count: bool,

    /// Tag type indices (exception handling proposal).
    /// Each entry is the function type index for that tag.
    pub tag_types: Vec<u32>,

    /// GC type definitions — parallel to func_types, one entry per type index.
    pub gc_types: Vec<GcTypeDef>,
    /// Subtype hierarchy — parallel to func_types; stores supertype info.
    pub sub_types: Vec<SubTypeInfo>,
    /// Whether any type has a self-referential type index (outside rec groups).
    pub has_self_ref_types: bool,

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
            implicit_rec_enabled: false,
            multi_memory_enabled: false,
            reject_multi_table: false,
            data_count: None,
            code_uses_data_count: false,
            tag_types: Vec::new(),
            gc_types: Vec::new(),
            sub_types: Vec::new(),
            has_self_ref_types: false,
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

// ─── Reader sub-module (byte reading, LEB128, UTF-8, name reading) ──────────

pub mod reader;
pub use reader::{decode_leb128_u32, decode_leb128_u64, decode_leb128_i32, decode_leb128_i64};
use reader::read_byte;

// ─── Sections sub-module (type/section parsing) ─────────────────────────────

mod sections;
use sections::*;

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


// ─── Init expression sub-module ──────────────────────────────────────────────

pub mod init_expr;
pub use init_expr::{scan_init_expr_info, scan_init_expr_info_gc, eval_init_expr_with_globals};

