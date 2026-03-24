//! WASM module validator.
//!
//! Performs structural and instruction-level validation of a decoded WASM module,
//! including stack-based type checking per the WebAssembly specification.

use crate::wasm::decoder::{ExportKind, ImportKind, WasmModule};
use crate::wasm::types::{ValType, WasmError, MAX_MEMORY_PAGES, MAX_TABLE_SIZE};
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

/// Validate a decoded WASM module.
pub fn validate(module: &WasmModule) -> Result<(), WasmError> {
    // Count imports by kind
    let func_import_count = module.func_import_count();
    let total_functions = func_import_count + module.functions.len();
    let has_memory = module.has_memory;
    let total_tables = module.tables.len() + count_table_imports(module);
    let total_globals = module.globals.len() + count_global_imports(module);

    // Validate function type indices
    for func in &module.functions {
        if func.type_idx as usize >= module.func_types.len() {
            return Err(WasmError::FunctionNotFound(func.type_idx));
        }
    }

    // Validate import type indices
    for imp in &module.imports {
        if let ImportKind::Func(type_idx) = imp.kind {
            if type_idx as usize >= module.func_types.len() {
                return Err(WasmError::FunctionNotFound(type_idx));
            }
        }
    }

    // Validate export indices and check for duplicate export names
    {
        let mut export_names = BTreeSet::new();
        for exp in &module.exports {
            // Check for duplicate names
            let name_bytes = module.get_name(exp.name_offset, exp.name_len);
            let name = String::from_utf8_lossy(name_bytes).into_owned();
            if !export_names.insert(name) {
                return Err(WasmError::DuplicateExport);
            }

            match exp.kind {
                ExportKind::Func(idx) => {
                    if idx as usize >= total_functions {
                        return Err(WasmError::FunctionNotFound(idx));
                    }
                }
                ExportKind::Table(idx) => {
                    if idx as usize >= total_tables {
                        return Err(WasmError::TableIndexOutOfBounds);
                    }
                }
                ExportKind::Memory(idx) => {
                    if idx > 0 || !has_memory {
                        return Err(WasmError::MemoryOutOfBounds);
                    }
                }
                ExportKind::Global(idx) => {
                    if idx as usize >= total_globals {
                        return Err(WasmError::OutOfBounds);
                    }
                }
            }
        }
    }

    // Validate memory limits
    if module.memory_min_pages > MAX_MEMORY_PAGES as u32 {
        return Err(WasmError::MemoryOutOfBounds);
    }
    if module.memory_max_pages != u32::MAX && module.memory_min_pages > module.memory_max_pages {
        return Err(WasmError::MemoryOutOfBounds);
    }
    if module.memory_max_pages != u32::MAX && module.memory_max_pages as usize > MAX_MEMORY_PAGES {
        return Err(WasmError::MemoryOutOfBounds);
    }

    // Validate table limits
    for table in &module.tables {
        if let Some(max) = table.max {
            if table.min > max {
                return Err(WasmError::TableIndexOutOfBounds);
            }
        }
    }

    // Validate start function
    if let Some(start_idx) = module.start_func {
        if start_idx as usize >= total_functions {
            return Err(WasmError::FunctionNotFound(start_idx));
        }
        // Start function must have no params and no results
        let type_idx = if (start_idx as usize) < func_import_count {
            module.func_import_type(start_idx).unwrap_or(0) as usize
        } else {
            let local_idx = start_idx as usize - func_import_count;
            if local_idx < module.functions.len() {
                module.functions[local_idx].type_idx as usize
            } else {
                return Err(WasmError::FunctionNotFound(start_idx));
            }
        };
        if type_idx < module.func_types.len() {
            let ft = &module.func_types[type_idx];
            if ft.param_count != 0 || ft.result_count != 0 {
                return Err(WasmError::TypeMismatch);
            }
        }
    }

    // Validate elem seg table refs and func indices
    for seg in &module.element_segments {
        for &fi in &seg.func_indices {
            if fi != u32::MAX && fi as usize >= total_functions {
                return Err(WasmError::FunctionNotFound(fi));
            }
        }
        if total_tables == 0 || seg.table_idx as usize >= total_tables {
            return Err(WasmError::TableIndexOutOfBounds);
        }
    }
    for seg in &module.data_segments {
        if seg.offset != u32::MAX && !has_memory {
            return Err(WasmError::MemoryOutOfBounds);
        }
    }

    // Validate instruction sequences for each function
    for (i, func) in module.functions.iter().enumerate() {
        validate_function_body(module, i, func, total_functions, has_memory, total_tables, total_globals)?;
    }

    Ok(())
}

fn count_table_imports(module: &WasmModule) -> usize {
    module.imports.iter().filter(|imp| matches!(imp.kind, ImportKind::Table | ImportKind::TableWithLimits { .. })).count()
}

fn count_global_imports(module: &WasmModule) -> usize {
    module.imports.iter().filter(|imp| matches!(imp.kind, ImportKind::Global(_, _))).count()
}

// ─── Type checking structures ────────────────────────────────────────────────

/// Represents a type on the validation stack. `Unknown` is used for polymorphic
/// (unreachable) stack positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StackType {
    Known(ValType),
    Unknown,
}

/// A control frame on the control stack, tracking block structure.
#[derive(Debug, Clone)]
struct CtrlFrame {
    /// The opcode that opened this frame (0x02=block, 0x03=loop, 0x04=if)
    opcode: u8,
    /// Types expected at the start of the block (parameters)
    start_types: Vec<ValType>,
    /// Types produced at the end of the block (results)
    end_types: Vec<ValType>,
    /// Height of the operand stack when this frame was entered
    height: usize,
    /// Whether we are in unreachable code
    unreachable: bool,
}

/// The validation context for a single function.
struct Validator<'a> {
    module: &'a WasmModule,
    code: &'a [u8],
    pc: usize,
    end: usize,
    /// The operand type stack
    opd_stack: Vec<StackType>,
    /// The control flow stack
    ctrl_stack: Vec<CtrlFrame>,
    /// Local types: params then locals
    local_types: Vec<ValType>,
    /// Function return types
    return_types: Vec<ValType>,
    total_functions: usize,
    has_memory: bool,
    total_tables: usize,
    total_globals: usize,
    func_import_count: usize,
}

impl<'a> Validator<'a> {
    fn push_opd(&mut self, t: StackType) {
        self.opd_stack.push(t);
    }

    fn push_val(&mut self, t: ValType) {
        self.opd_stack.push(StackType::Known(t));
    }

    fn pop_opd(&mut self) -> Result<StackType, WasmError> {
        let frame = self.ctrl_stack.last().ok_or(WasmError::StackUnderflow)?;
        if self.opd_stack.len() == frame.height {
            if frame.unreachable {
                return Ok(StackType::Unknown);
            }
            return Err(WasmError::TypeMismatch);
        }
        Ok(self.opd_stack.pop().unwrap())
    }

    fn pop_expect(&mut self, expected: ValType) -> Result<(), WasmError> {
        let actual = self.pop_opd()?;
        match actual {
            StackType::Known(t) if t == expected => Ok(()),
            StackType::Unknown => Ok(()),
            _ => Err(WasmError::TypeMismatch),
        }
    }

    fn pop_expect_st(&mut self, expected: StackType) -> Result<(), WasmError> {
        match expected {
            StackType::Known(t) => self.pop_expect(t),
            StackType::Unknown => { let _ = self.pop_opd()?; Ok(()) }
        }
    }

    fn push_ctrl(&mut self, opcode: u8, start_types: Vec<ValType>, end_types: Vec<ValType>) {
        let height = self.opd_stack.len();
        // Push input types onto the stack
        for &t in &start_types {
            self.push_val(t);
        }
        self.ctrl_stack.push(CtrlFrame {
            opcode,
            start_types,
            end_types,
            height,
            unreachable: false,
        });
    }

    fn pop_ctrl(&mut self) -> Result<CtrlFrame, WasmError> {
        let frame = self.ctrl_stack.last().ok_or(WasmError::StackUnderflow)?;
        let end_types = frame.end_types.clone();
        // Pop the expected result types
        for i in (0..end_types.len()).rev() {
            self.pop_expect(end_types[i])?;
        }
        let frame = self.ctrl_stack.last().ok_or(WasmError::StackUnderflow)?;
        if self.opd_stack.len() != frame.height {
            return Err(WasmError::TypeMismatch);
        }
        let frame = self.ctrl_stack.pop().unwrap();
        Ok(frame)
    }

    fn set_unreachable(&mut self) {
        if let Some(frame) = self.ctrl_stack.last_mut() {
            self.opd_stack.truncate(frame.height);
            frame.unreachable = true;
        }
    }

    /// Get the label types for a branch to depth `n`.
    /// For loop frames, this is the start types; for others, end types.
    fn label_types(&self, n: usize) -> Result<Vec<ValType>, WasmError> {
        if n >= self.ctrl_stack.len() {
            return Err(WasmError::BranchDepthExceeded);
        }
        let idx = self.ctrl_stack.len() - 1 - n;
        let frame = &self.ctrl_stack[idx];
        if frame.opcode == 0x03 {
            // loop: branch goes to start
            Ok(frame.start_types.clone())
        } else {
            Ok(frame.end_types.clone())
        }
    }

    fn read_u8(&mut self) -> Result<u8, WasmError> {
        if self.pc >= self.end {
            return Err(WasmError::UnexpectedEnd);
        }
        let b = self.code[self.pc];
        self.pc += 1;
        Ok(b)
    }

    fn read_u32(&mut self) -> Result<u32, WasmError> {
        read_leb128_u32(self.code, &mut self.pc)
    }

    fn read_i32(&mut self) -> Result<i32, WasmError> {
        crate::wasm::decoder::decode_leb128_i32(self.code, &mut self.pc)
    }

    fn read_i64(&mut self) -> Result<i64, WasmError> {
        crate::wasm::decoder::decode_leb128_i64(self.code, &mut self.pc)
    }

    /// Decode a block type: -0x40 = void, -0x01..-0x04/-0x05 = single valtype, else type index
    fn read_block_type(&mut self) -> Result<(Vec<ValType>, Vec<ValType>), WasmError> {
        let raw = self.read_i32()?;
        if raw == -0x40 {
            // void block
            Ok((Vec::new(), Vec::new()))
        } else if raw < 0 {
            // Single value type encoded as negative
            let vt = match raw {
                -0x01 => ValType::I32,   // 0x7F
                -0x02 => ValType::I64,   // 0x7E
                -0x03 => ValType::F32,   // 0x7D
                -0x04 => ValType::F64,   // 0x7C
                -0x05 => ValType::V128,  // 0x7B
                -0x10 => ValType::I32,   // 0x70 = funcref (mapped to I32)
                -0x11 => ValType::I32,   // 0x6F = externref (mapped to I32)
                _ => return Err(WasmError::InvalidBlockType),
            };
            Ok((Vec::new(), alloc::vec![vt]))
        } else {
            // Type index for multi-value
            let idx = raw as u32 as usize;
            if idx >= self.module.func_types.len() {
                return Err(WasmError::TypeMismatch);
            }
            let ft = &self.module.func_types[idx];
            let params: Vec<ValType> = ft.params[..ft.param_count as usize].to_vec();
            let results: Vec<ValType> = ft.results[..ft.result_count as usize].to_vec();
            Ok((params, results))
        }
    }

    /// Get the type of a local (param or local variable).
    fn local_type(&self, idx: u32) -> Result<ValType, WasmError> {
        if (idx as usize) < self.local_types.len() {
            Ok(self.local_types[idx as usize])
        } else {
            Err(WasmError::OutOfBounds)
        }
    }

    /// Get the type of a global.
    fn global_type(&self, idx: u32) -> Result<(ValType, bool), WasmError> {
        let mut global_import_idx: u32 = 0;
        for imp in &self.module.imports {
            if let ImportKind::Global(vt_byte, mutable) = imp.kind {
                if global_import_idx == idx {
                    let vt = byte_to_valtype(vt_byte)?;
                    return Ok((vt, mutable));
                }
                global_import_idx += 1;
            }
        }
        let local_idx = idx as usize - global_import_idx as usize;
        if local_idx < self.module.globals.len() {
            let g = &self.module.globals[local_idx];
            Ok((g.val_type, g.mutable))
        } else {
            Err(WasmError::OutOfBounds)
        }
    }

    /// Get the function type for a function index (import or local).
    fn func_type(&self, func_idx: u32) -> Result<&'a crate::wasm::decoder::FuncTypeDef, WasmError> {
        let type_idx = if (func_idx as usize) < self.func_import_count {
            self.module.func_import_type(func_idx).ok_or(WasmError::FunctionNotFound(func_idx))? as usize
        } else {
            let local_idx = func_idx as usize - self.func_import_count;
            if local_idx < self.module.functions.len() {
                self.module.functions[local_idx].type_idx as usize
            } else {
                return Err(WasmError::FunctionNotFound(func_idx));
            }
        };
        if type_idx < self.module.func_types.len() {
            Ok(&self.module.func_types[type_idx])
        } else {
            Err(WasmError::TypeMismatch)
        }
    }

    fn validate(&mut self) -> Result<(), WasmError> {
        // Push the function frame: the implicit block wrapping the function body
        let start_types = Vec::new(); // function frame has no start types on stack
        let end_types = self.return_types.clone();
        self.push_ctrl(0x02, start_types, end_types); // treat function body as a block

        while self.pc < self.end {
            let opcode = self.code[self.pc];
            self.pc += 1;

            match opcode {
                // ── unreachable ──
                0x00 => {
                    self.set_unreachable();
                }
                // ── nop ──
                0x01 => {}
                // ── block ──
                0x02 => {
                    let (params, results) = self.read_block_type()?;
                    // Pop params from current stack
                    for i in (0..params.len()).rev() {
                        self.pop_expect(params[i])?;
                    }
                    self.push_ctrl(0x02, params, results);
                }
                // ── loop ──
                0x03 => {
                    let (params, results) = self.read_block_type()?;
                    for i in (0..params.len()).rev() {
                        self.pop_expect(params[i])?;
                    }
                    self.push_ctrl(0x03, params, results);
                }
                // ── if ──
                0x04 => {
                    let (params, results) = self.read_block_type()?;
                    self.pop_expect(ValType::I32)?; // condition
                    for i in (0..params.len()).rev() {
                        self.pop_expect(params[i])?;
                    }
                    self.push_ctrl(0x04, params, results);
                }
                // ── else ──
                0x05 => {
                    let frame = self.pop_ctrl()?;
                    if frame.opcode != 0x04 {
                        return Err(WasmError::TypeMismatch);
                    }
                    self.push_ctrl(0x05, frame.start_types, frame.end_types);
                }
                // ── end ──
                0x0B => {
                    let frame = self.pop_ctrl()?;
                    // If this was an if without else, check that start_types == end_types
                    if frame.opcode == 0x04 {
                        // An if without else must have matching start/end types
                        // (i.e., the block must produce no extra values, or be void)
                        if frame.start_types.len() != frame.end_types.len() {
                            return Err(WasmError::TypeMismatch);
                        }
                        for i in 0..frame.start_types.len() {
                            if frame.start_types[i] != frame.end_types[i] {
                                return Err(WasmError::TypeMismatch);
                            }
                        }
                    }
                    // Push end types onto the stack
                    for &t in &frame.end_types {
                        self.push_val(t);
                    }
                }
                // ── br ──
                0x0C => {
                    let n = self.read_u32()?;
                    let label_types = self.label_types(n as usize)?;
                    for i in (0..label_types.len()).rev() {
                        self.pop_expect(label_types[i])?;
                    }
                    self.set_unreachable();
                }
                // ── br_if ──
                0x0D => {
                    let n = self.read_u32()?;
                    self.pop_expect(ValType::I32)?; // condition
                    let label_types = self.label_types(n as usize)?;
                    for i in (0..label_types.len()).rev() {
                        self.pop_expect(label_types[i])?;
                    }
                    for &t in &label_types {
                        self.push_val(t);
                    }
                }
                // ── br_table ──
                0x0E => {
                    let count = self.read_u32()? as usize;
                    let mut labels = Vec::with_capacity(count + 1);
                    for _ in 0..=count {
                        labels.push(self.read_u32()?);
                    }
                    self.pop_expect(ValType::I32)?; // index
                    // Get the default label's arity
                    let default_label = *labels.last().unwrap();
                    let default_types = self.label_types(default_label as usize)?;
                    let arity = default_types.len();
                    // Check if we're in unreachable/polymorphic context
                    let is_unreachable = self.ctrl_stack.last()
                        .map(|f| f.unreachable && self.opd_stack.len() == f.height)
                        .unwrap_or(false);
                    if is_unreachable {
                        // In unreachable code, types can differ (polymorphic bottom),
                        // but arity must still match across all labels.
                        for &l in &labels {
                            let lt = self.label_types(l as usize)?;
                            if lt.len() != arity {
                                return Err(WasmError::TypeMismatch);
                            }
                        }
                    } else {
                        // Check all labels have same arity and types
                        for &l in &labels {
                            let lt = self.label_types(l as usize)?;
                            if lt.len() != arity {
                                return Err(WasmError::TypeMismatch);
                            }
                        }
                        // Pop the label types
                        for i in (0..default_types.len()).rev() {
                            self.pop_expect(default_types[i])?;
                        }
                        // Check consistency of types across labels
                        for &l in &labels[..labels.len() - 1] {
                            let lt = self.label_types(l as usize)?;
                            for j in 0..arity {
                                if lt[j] != default_types[j] {
                                    return Err(WasmError::TypeMismatch);
                                }
                            }
                        }
                    }
                    self.set_unreachable();
                }
                // ── return ──
                0x0F => {
                    let ret_types = self.return_types.clone();
                    for i in (0..ret_types.len()).rev() {
                        self.pop_expect(ret_types[i])?;
                    }
                    self.set_unreachable();
                }
                // ── call ──
                0x10 => {
                    let func_idx = self.read_u32()?;
                    if func_idx as usize >= self.total_functions {
                        return Err(WasmError::FunctionNotFound(func_idx));
                    }
                    let ft = self.func_type(func_idx)?;
                    let param_count = ft.param_count as usize;
                    let result_count = ft.result_count as usize;
                    let params: Vec<ValType> = ft.params[..param_count].to_vec();
                    let results: Vec<ValType> = ft.results[..result_count].to_vec();
                    for i in (0..params.len()).rev() {
                        self.pop_expect(params[i])?;
                    }
                    for &t in &results {
                        self.push_val(t);
                    }
                }
                // ── call_indirect ──
                0x11 => {
                    let type_idx = self.read_u32()?;
                    let table_idx = self.read_u32()?;
                    if type_idx as usize >= self.module.func_types.len() {
                        return Err(WasmError::TypeMismatch);
                    }
                    if table_idx as usize >= self.total_tables && self.total_tables > 0 {
                        return Err(WasmError::TableIndexOutOfBounds);
                    }
                    self.pop_expect(ValType::I32)?; // table index operand
                    let ft = &self.module.func_types[type_idx as usize];
                    let param_count = ft.param_count as usize;
                    let result_count = ft.result_count as usize;
                    let params: Vec<ValType> = ft.params[..param_count].to_vec();
                    let results: Vec<ValType> = ft.results[..result_count].to_vec();
                    for i in (0..params.len()).rev() {
                        self.pop_expect(params[i])?;
                    }
                    for &t in &results {
                        self.push_val(t);
                    }
                }
                // ── return_call ──
                0x12 => {
                    let func_idx = self.read_u32()?;
                    if func_idx as usize >= self.total_functions {
                        return Err(WasmError::FunctionNotFound(func_idx));
                    }
                    let ft = self.func_type(func_idx)?;
                    let param_count = ft.param_count as usize;
                    let params: Vec<ValType> = ft.params[..param_count].to_vec();
                    for i in (0..params.len()).rev() {
                        self.pop_expect(params[i])?;
                    }
                    self.set_unreachable();
                }
                // ── return_call_indirect ──
                0x13 => {
                    let type_idx = self.read_u32()?;
                    let table_idx = self.read_u32()?;
                    if type_idx as usize >= self.module.func_types.len() {
                        return Err(WasmError::TypeMismatch);
                    }
                    if table_idx as usize >= self.total_tables && self.total_tables > 0 {
                        return Err(WasmError::TableIndexOutOfBounds);
                    }
                    self.pop_expect(ValType::I32)?;
                    let ft = &self.module.func_types[type_idx as usize];
                    let param_count = ft.param_count as usize;
                    let params: Vec<ValType> = ft.params[..param_count].to_vec();
                    for i in (0..params.len()).rev() {
                        self.pop_expect(params[i])?;
                    }
                    self.set_unreachable();
                }
                // ── call_ref (GC proposal, opcode 0x14) ──
                0x14 => {
                    let type_idx = self.read_u32()?;
                    if type_idx as usize >= self.module.func_types.len() {
                        return Err(WasmError::TypeMismatch);
                    }
                    let ft = &self.module.func_types[type_idx as usize];
                    let param_count = ft.param_count as usize;
                    let result_count = ft.result_count as usize;
                    let params: Vec<ValType> = ft.params[..param_count].to_vec();
                    let results: Vec<ValType> = ft.results[..result_count].to_vec();
                    let _ = self.pop_opd()?; // function reference
                    for i in (0..params.len()).rev() {
                        self.pop_expect(params[i])?;
                    }
                    for &t in &results {
                        self.push_val(t);
                    }
                }
                // ── return_call_ref (GC proposal, opcode 0x15) ──
                0x15 => {
                    let type_idx = self.read_u32()?;
                    if type_idx as usize >= self.module.func_types.len() {
                        return Err(WasmError::TypeMismatch);
                    }
                    let ft = &self.module.func_types[type_idx as usize];
                    let param_count = ft.param_count as usize;
                    let params: Vec<ValType> = ft.params[..param_count].to_vec();
                    let _ = self.pop_opd()?; // function reference
                    for i in (0..params.len()).rev() {
                        self.pop_expect(params[i])?;
                    }
                    self.set_unreachable();
                }
                // ── drop ──
                0x1A => {
                    let _ = self.pop_opd()?;
                }
                // ── select (untyped) ──
                0x1B => {
                    self.pop_expect(ValType::I32)?; // condition
                    let t1 = self.pop_opd()?;
                    let t2 = self.pop_opd()?;
                    // Both must be the same numeric type (or unknown)
                    match (t1, t2) {
                        (StackType::Known(a), StackType::Known(b)) => {
                            if a != b {
                                return Err(WasmError::TypeMismatch);
                            }
                            // Untyped select doesn't allow V128 or ref types
                            if a == ValType::V128 {
                                return Err(WasmError::TypeMismatch);
                            }
                            self.push_val(a);
                        }
                        (StackType::Known(a), StackType::Unknown) => {
                            if a == ValType::V128 {
                                return Err(WasmError::TypeMismatch);
                            }
                            self.push_val(a);
                        }
                        (StackType::Unknown, StackType::Known(b)) => {
                            if b == ValType::V128 {
                                return Err(WasmError::TypeMismatch);
                            }
                            self.push_val(b);
                        }
                        (StackType::Unknown, StackType::Unknown) => {
                            self.push_opd(StackType::Unknown);
                        }
                    }
                }
                // ── select (typed) ──
                0x1C => {
                    let count = self.read_u32()?;
                    if count != 1 {
                        return Err(WasmError::TypeMismatch);
                    }
                    let vt_raw = self.read_u32()?;
                    let vt = byte_to_valtype(vt_raw as u8)?;
                    self.pop_expect(ValType::I32)?; // condition
                    self.pop_expect(vt)?;
                    self.pop_expect(vt)?;
                    self.push_val(vt);
                }
                // ── local.get ──
                0x20 => {
                    let idx = self.read_u32()?;
                    let t = self.local_type(idx)?;
                    self.push_val(t);
                }
                // ── local.set ──
                0x21 => {
                    let idx = self.read_u32()?;
                    let t = self.local_type(idx)?;
                    self.pop_expect(t)?;
                }
                // ── local.tee ──
                0x22 => {
                    let idx = self.read_u32()?;
                    let t = self.local_type(idx)?;
                    self.pop_expect(t)?;
                    self.push_val(t);
                }
                // ── global.get ──
                0x23 => {
                    let idx = self.read_u32()?;
                    let (t, _) = self.global_type(idx)?;
                    self.push_val(t);
                }
                // ── global.set ──
                0x24 => {
                    let idx = self.read_u32()?;
                    let (t, mutable) = self.global_type(idx)?;
                    if !mutable {
                        return Err(WasmError::ImmutableGlobal);
                    }
                    self.pop_expect(t)?;
                }
                // ── table.get ──
                0x25 => {
                    let _idx = self.read_u32()?;
                    self.pop_expect(ValType::I32)?;
                    // Table element type - for now push I32 as a placeholder
                    // (funcref/externref are not modeled as ValType)
                    self.push_opd(StackType::Unknown);
                }
                // ── table.set ──
                0x26 => {
                    let _idx = self.read_u32()?;
                    let _ = self.pop_opd()?; // value
                    self.pop_expect(ValType::I32)?; // index
                }
                // ── memory loads ──
                // i32.load, i32.load8_s/u, i32.load16_s/u
                0x28 | 0x2C | 0x2D | 0x2E | 0x2F => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    let _align = self.read_u32()?;
                    let _offset = self.read_u32()?;
                    self.pop_expect(ValType::I32)?; // address
                    self.push_val(ValType::I32);
                }
                // i64.load, i64.load8_s/u, i64.load16_s/u, i64.load32_s/u
                0x29 | 0x30 | 0x31 | 0x32 | 0x33 | 0x34 | 0x35 => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    let _align = self.read_u32()?;
                    let _offset = self.read_u32()?;
                    self.pop_expect(ValType::I32)?;
                    self.push_val(ValType::I64);
                }
                // f32.load
                0x2A => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    let _align = self.read_u32()?;
                    let _offset = self.read_u32()?;
                    self.pop_expect(ValType::I32)?;
                    self.push_val(ValType::F32);
                }
                // f64.load
                0x2B => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    let _align = self.read_u32()?;
                    let _offset = self.read_u32()?;
                    self.pop_expect(ValType::I32)?;
                    self.push_val(ValType::F64);
                }
                // i32.store, i32.store8, i32.store16
                0x36 | 0x3A | 0x3B => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    let _align = self.read_u32()?;
                    let _offset = self.read_u32()?;
                    self.pop_expect(ValType::I32)?; // value
                    self.pop_expect(ValType::I32)?; // address
                }
                // i64.store, i64.store8, i64.store16, i64.store32
                0x37 | 0x3C | 0x3D | 0x3E => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    let _align = self.read_u32()?;
                    let _offset = self.read_u32()?;
                    self.pop_expect(ValType::I64)?; // value
                    self.pop_expect(ValType::I32)?; // address
                }
                // f32.store
                0x38 => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    let _align = self.read_u32()?;
                    let _offset = self.read_u32()?;
                    self.pop_expect(ValType::F32)?;
                    self.pop_expect(ValType::I32)?;
                }
                // f64.store
                0x39 => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    let _align = self.read_u32()?;
                    let _offset = self.read_u32()?;
                    self.pop_expect(ValType::F64)?;
                    self.pop_expect(ValType::I32)?;
                }
                // ── memory.size ──
                0x3F => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    let _ = self.read_u32()?;
                    self.push_val(ValType::I32);
                }
                // ── memory.grow ──
                0x40 => {
                    if !self.has_memory { return Err(WasmError::MemoryOutOfBounds); }
                    let _ = self.read_u32()?;
                    self.pop_expect(ValType::I32)?;
                    self.push_val(ValType::I32);
                }
                // ── i32.const ──
                0x41 => {
                    let _ = self.read_i32()?;
                    self.push_val(ValType::I32);
                }
                // ── i64.const ──
                0x42 => {
                    let _ = self.read_i64()?;
                    self.push_val(ValType::I64);
                }
                // ── f32.const ──
                0x43 => {
                    if self.pc + 4 > self.end { return Err(WasmError::UnexpectedEnd); }
                    self.pc += 4;
                    self.push_val(ValType::F32);
                }
                // ── f64.const ──
                0x44 => {
                    if self.pc + 8 > self.end { return Err(WasmError::UnexpectedEnd); }
                    self.pc += 8;
                    self.push_val(ValType::F64);
                }

                // ── i32 test: i32.eqz ──
                0x45 => {
                    self.pop_expect(ValType::I32)?;
                    self.push_val(ValType::I32);
                }
                // ── i32 comparison: i32.eq..i32.ge_u ──
                0x46..=0x4F => {
                    self.pop_expect(ValType::I32)?;
                    self.pop_expect(ValType::I32)?;
                    self.push_val(ValType::I32);
                }
                // ── i64 test: i64.eqz ──
                0x50 => {
                    self.pop_expect(ValType::I64)?;
                    self.push_val(ValType::I32);
                }
                // ── i64 comparison: i64.eq..i64.ge_u ──
                0x51..=0x5A => {
                    self.pop_expect(ValType::I64)?;
                    self.pop_expect(ValType::I64)?;
                    self.push_val(ValType::I32);
                }
                // ── f32 comparison: f32.eq..f32.ge ──
                0x5B..=0x60 => {
                    self.pop_expect(ValType::F32)?;
                    self.pop_expect(ValType::F32)?;
                    self.push_val(ValType::I32);
                }
                // ── f64 comparison: f64.eq..f64.ge ──
                0x61..=0x66 => {
                    self.pop_expect(ValType::F64)?;
                    self.pop_expect(ValType::F64)?;
                    self.push_val(ValType::I32);
                }

                // ── i32 unary: clz, ctz, popcnt ──
                0x67 | 0x68 | 0x69 => {
                    self.pop_expect(ValType::I32)?;
                    self.push_val(ValType::I32);
                }
                // ── i32 binary: add..rotr ──
                0x6A..=0x78 => {
                    self.pop_expect(ValType::I32)?;
                    self.pop_expect(ValType::I32)?;
                    self.push_val(ValType::I32);
                }
                // ── i64 unary: clz, ctz, popcnt ──
                0x79 | 0x7A | 0x7B => {
                    self.pop_expect(ValType::I64)?;
                    self.push_val(ValType::I64);
                }
                // ── i64 binary: add..rotr ──
                0x7C..=0x8A => {
                    self.pop_expect(ValType::I64)?;
                    self.pop_expect(ValType::I64)?;
                    self.push_val(ValType::I64);
                }
                // ── f32 unary: abs..sqrt ──
                0x8B..=0x91 => {
                    self.pop_expect(ValType::F32)?;
                    self.push_val(ValType::F32);
                }
                // ── f32 binary: add..copysign ──
                0x92..=0x98 => {
                    self.pop_expect(ValType::F32)?;
                    self.pop_expect(ValType::F32)?;
                    self.push_val(ValType::F32);
                }
                // ── f64 unary: abs..sqrt ──
                0x99..=0x9F => {
                    self.pop_expect(ValType::F64)?;
                    self.push_val(ValType::F64);
                }
                // ── f64 binary: add..copysign ──
                0xA0..=0xA6 => {
                    self.pop_expect(ValType::F64)?;
                    self.pop_expect(ValType::F64)?;
                    self.push_val(ValType::F64);
                }

                // ── Conversions ──
                // i32.wrap_i64
                0xA7 => { self.pop_expect(ValType::I64)?; self.push_val(ValType::I32); }
                // i32.trunc_f32_s, i32.trunc_f32_u
                0xA8 | 0xA9 => { self.pop_expect(ValType::F32)?; self.push_val(ValType::I32); }
                // i32.trunc_f64_s, i32.trunc_f64_u
                0xAA | 0xAB => { self.pop_expect(ValType::F64)?; self.push_val(ValType::I32); }
                // i64.extend_i32_s, i64.extend_i32_u
                0xAC | 0xAD => { self.pop_expect(ValType::I32)?; self.push_val(ValType::I64); }
                // i64.trunc_f32_s, i64.trunc_f32_u
                0xAE | 0xAF => { self.pop_expect(ValType::F32)?; self.push_val(ValType::I64); }
                // i64.trunc_f64_s, i64.trunc_f64_u
                0xB0 | 0xB1 => { self.pop_expect(ValType::F64)?; self.push_val(ValType::I64); }
                // f32.convert_i32_s, f32.convert_i32_u
                0xB2 | 0xB3 => { self.pop_expect(ValType::I32)?; self.push_val(ValType::F32); }
                // f32.convert_i64_s, f32.convert_i64_u
                0xB4 | 0xB5 => { self.pop_expect(ValType::I64)?; self.push_val(ValType::F32); }
                // f32.demote_f64
                0xB6 => { self.pop_expect(ValType::F64)?; self.push_val(ValType::F32); }
                // f64.convert_i32_s, f64.convert_i32_u
                0xB7 | 0xB8 => { self.pop_expect(ValType::I32)?; self.push_val(ValType::F64); }
                // f64.convert_i64_s, f64.convert_i64_u
                0xB9 | 0xBA => { self.pop_expect(ValType::I64)?; self.push_val(ValType::F64); }
                // f64.promote_f32
                0xBB => { self.pop_expect(ValType::F32)?; self.push_val(ValType::F64); }
                // i32.reinterpret_f32
                0xBC => { self.pop_expect(ValType::F32)?; self.push_val(ValType::I32); }
                // i64.reinterpret_f64
                0xBD => { self.pop_expect(ValType::F64)?; self.push_val(ValType::I64); }
                // f32.reinterpret_i32
                0xBE => { self.pop_expect(ValType::I32)?; self.push_val(ValType::F32); }
                // f64.reinterpret_i64
                0xBF => { self.pop_expect(ValType::I64)?; self.push_val(ValType::F64); }

                // ── Sign extension ──
                // i32.extend8_s, i32.extend16_s
                0xC0 | 0xC1 => { self.pop_expect(ValType::I32)?; self.push_val(ValType::I32); }
                // i64.extend8_s, i64.extend16_s, i64.extend32_s
                0xC2 | 0xC3 | 0xC4 => { self.pop_expect(ValType::I64)?; self.push_val(ValType::I64); }

                // ── ref.null ──
                0xD0 => {
                    let _ = self.read_i32()?; // heaptype
                    // Push unknown since we don't have ref types in ValType
                    self.push_opd(StackType::Unknown);
                }
                // ── ref.is_null ──
                0xD1 => {
                    let _ = self.pop_opd()?;
                    self.push_val(ValType::I32);
                }
                // ── ref.func ──
                0xD2 => {
                    let idx = self.read_u32()?;
                    if idx as usize >= self.total_functions {
                        return Err(WasmError::FunctionNotFound(idx));
                    }
                    self.push_opd(StackType::Unknown);
                }

                // ── 0xFC prefix: saturating truncation + bulk memory ──
                0xFC => {
                    let sub = self.read_u32()?;
                    match sub {
                        // i32.trunc_sat_f32_s/u
                        0 | 1 => { self.pop_expect(ValType::F32)?; self.push_val(ValType::I32); }
                        // i32.trunc_sat_f64_s/u
                        2 | 3 => { self.pop_expect(ValType::F64)?; self.push_val(ValType::I32); }
                        // i64.trunc_sat_f32_s/u
                        4 | 5 => { self.pop_expect(ValType::F32)?; self.push_val(ValType::I64); }
                        // i64.trunc_sat_f64_s/u
                        6 | 7 => { self.pop_expect(ValType::F64)?; self.push_val(ValType::I64); }
                        // memory.init
                        8 => {
                            let data_idx = self.read_u32()?;
                            let _mem_idx = self.read_u32()?;
                            if data_idx as usize >= self.module.data_segments.len() {
                                return Err(WasmError::OutOfBounds);
                            }
                            self.pop_expect(ValType::I32)?; // size
                            self.pop_expect(ValType::I32)?; // src offset
                            self.pop_expect(ValType::I32)?; // dest offset
                        }
                        // data.drop
                        9 => {
                            let data_idx = self.read_u32()?;
                            if data_idx as usize >= self.module.data_segments.len() {
                                return Err(WasmError::OutOfBounds);
                            }
                        }
                        // memory.copy
                        10 => {
                            let _ = self.read_u32()?;
                            let _ = self.read_u32()?;
                            self.pop_expect(ValType::I32)?; // size
                            self.pop_expect(ValType::I32)?; // src
                            self.pop_expect(ValType::I32)?; // dest
                        }
                        // memory.fill
                        11 => {
                            let _ = self.read_u32()?;
                            self.pop_expect(ValType::I32)?; // size
                            self.pop_expect(ValType::I32)?; // value
                            self.pop_expect(ValType::I32)?; // dest
                        }
                        // table.init
                        12 => {
                            let _ = self.read_u32()?;
                            let _ = self.read_u32()?;
                            self.pop_expect(ValType::I32)?; // n
                            self.pop_expect(ValType::I32)?; // s
                            self.pop_expect(ValType::I32)?; // d
                        }
                        // elem.drop
                        13 => {
                            let _ = self.read_u32()?;
                        }
                        // table.copy
                        14 => {
                            let _ = self.read_u32()?;
                            let _ = self.read_u32()?;
                            self.pop_expect(ValType::I32)?; // n
                            self.pop_expect(ValType::I32)?; // s
                            self.pop_expect(ValType::I32)?; // d
                        }
                        // table.grow
                        15 => {
                            let _ = self.read_u32()?;
                            self.pop_expect(ValType::I32)?; // n
                            let _ = self.pop_opd()?;         // init value
                            self.push_val(ValType::I32);
                        }
                        // table.size
                        16 => {
                            let _ = self.read_u32()?;
                            self.push_val(ValType::I32);
                        }
                        // table.fill
                        17 => {
                            let _ = self.read_u32()?;
                            self.pop_expect(ValType::I32)?; // n
                            let _ = self.pop_opd()?;         // value
                            self.pop_expect(ValType::I32)?; // i
                        }
                        _ => {}
                    }
                }

                // ── 0xFD prefix: SIMD ──
                0xFD => {
                    let sub = self.read_u32()?;
                    self.validate_simd(sub)?;
                }

                // ── 0xFE prefix: threads (unsupported) ──
                0xFE => {
                    return Err(WasmError::UnsupportedProposal);
                }

                _ => {
                    // Unknown opcode - skip
                }
            }
        }

        // After processing all bytecode, the control stack should have exactly 0 frames
        // (the outermost frame was popped by the final 'end')
        if !self.ctrl_stack.is_empty() {
            return Err(WasmError::TypeMismatch);
        }

        Ok(())
    }

    /// Validate SIMD instructions for type-checking purposes.
    /// Handles immediate parsing and stack effects.
    fn validate_simd(&mut self, sub: u32) -> Result<(), WasmError> {
        match sub {
            // v128.load
            0x00 => {
                let _align = self.read_u32()?;
                let _offset = self.read_u32()?;
                self.pop_expect(ValType::I32)?;
                self.push_val(ValType::V128);
            }
            // v128.load8x8_s/u, v128.load16x4_s/u, v128.load32x2_s/u
            0x01..=0x06 => {
                let _align = self.read_u32()?;
                let _offset = self.read_u32()?;
                self.pop_expect(ValType::I32)?;
                self.push_val(ValType::V128);
            }
            // v128.load8_splat, v128.load16_splat, v128.load32_splat, v128.load64_splat
            0x07..=0x0A => {
                let _align = self.read_u32()?;
                let _offset = self.read_u32()?;
                self.pop_expect(ValType::I32)?;
                self.push_val(ValType::V128);
            }
            // v128.store
            0x0B => {
                let _align = self.read_u32()?;
                let _offset = self.read_u32()?;
                self.pop_expect(ValType::V128)?;
                self.pop_expect(ValType::I32)?;
            }
            // v128.const
            0x0C => {
                if self.pc + 16 > self.end { return Err(WasmError::UnexpectedEnd); }
                self.pc += 16;
                self.push_val(ValType::V128);
            }
            // i8x16.shuffle
            0x0D => {
                for _ in 0..16 {
                    if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                    let lane = self.code[self.pc]; self.pc += 1;
                    if lane >= 32 { return Err(WasmError::OutOfBounds); }
                }
                self.pop_expect(ValType::V128)?;
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::V128);
            }
            // i8x16.swizzle
            0x0E => {
                self.pop_expect(ValType::V128)?;
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::V128);
            }
            // v128 splat instructions
            // i8x16.splat, i16x8.splat, i32x4.splat
            0x0F | 0x10 | 0x11 => {
                self.pop_expect(ValType::I32)?;
                self.push_val(ValType::V128);
            }
            // i64x2.splat
            0x12 => {
                self.pop_expect(ValType::I64)?;
                self.push_val(ValType::V128);
            }
            // f32x4.splat
            0x13 => {
                self.pop_expect(ValType::F32)?;
                self.push_val(ValType::V128);
            }
            // f64x2.splat
            0x14 => {
                self.pop_expect(ValType::F64)?;
                self.push_val(ValType::V128);
            }

            // ── extract_lane / replace_lane ──
            // i8x16.extract_lane_s/u
            0x15 | 0x16 => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 16 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::I32);
            }
            // i8x16.replace_lane
            0x17 => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 16 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::I32)?;
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::V128);
            }
            // i16x8.extract_lane_s/u
            0x18 | 0x19 => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 8 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::I32);
            }
            // i16x8.replace_lane
            0x1A => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 8 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::I32)?;
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::V128);
            }
            // i32x4.extract_lane
            0x1B => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 4 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::I32);
            }
            // i32x4.replace_lane
            0x1C => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 4 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::I32)?;
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::V128);
            }
            // i64x2.extract_lane
            0x1D => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 2 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::I64);
            }
            // i64x2.replace_lane
            0x1E => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 2 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::I64)?;
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::V128);
            }
            // f32x4.extract_lane
            0x1F => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 4 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::F32);
            }
            // f32x4.replace_lane
            0x20 => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 4 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::F32)?;
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::V128);
            }
            // f64x2.extract_lane
            0x21 => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 2 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::F64);
            }
            // f64x2.replace_lane
            0x22 => {
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let lane = self.code[self.pc]; self.pc += 1;
                if lane >= 2 { return Err(WasmError::OutOfBounds); }
                self.pop_expect(ValType::F64)?;
                self.pop_expect(ValType::V128)?;
                self.push_val(ValType::V128);
            }

            // v128.load8_lane..v128.load64_lane (0x54..0x57)
            0x54..=0x57 => {
                let _align = self.read_u32()?;
                let _offset = self.read_u32()?;
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let _lane = self.code[self.pc]; self.pc += 1;
                self.pop_expect(ValType::V128)?;
                self.pop_expect(ValType::I32)?;
                self.push_val(ValType::V128);
            }
            // v128.store8_lane..v128.store64_lane (0x58..0x5B)
            0x58..=0x5B => {
                let _align = self.read_u32()?;
                let _offset = self.read_u32()?;
                if self.pc >= self.end { return Err(WasmError::UnexpectedEnd); }
                let _lane = self.code[self.pc]; self.pc += 1;
                self.pop_expect(ValType::V128)?;
                self.pop_expect(ValType::I32)?;
            }
            // v128.load32_zero, v128.load64_zero (0x5C, 0x5D)
            0x5C | 0x5D => {
                let _align = self.read_u32()?;
                let _offset = self.read_u32()?;
                self.pop_expect(ValType::I32)?;
                self.push_val(ValType::V128);
            }

            // All remaining SIMD ops (no immediates) — classified by signature
            _ => {
                let sig = simd_op_signature(sub);
                match sig {
                    SimdSig::UnaryV128 => {
                        self.pop_expect(ValType::V128)?;
                        self.push_val(ValType::V128);
                    }
                    SimdSig::BinaryV128 => {
                        self.pop_expect(ValType::V128)?;
                        self.pop_expect(ValType::V128)?;
                        self.push_val(ValType::V128);
                    }
                    SimdSig::TernaryV128 => {
                        self.pop_expect(ValType::V128)?;
                        self.pop_expect(ValType::V128)?;
                        self.pop_expect(ValType::V128)?;
                        self.push_val(ValType::V128);
                    }
                    SimdSig::ShiftV128 => {
                        self.pop_expect(ValType::I32)?;
                        self.pop_expect(ValType::V128)?;
                        self.push_val(ValType::V128);
                    }
                    SimdSig::V128ToI32 => {
                        self.pop_expect(ValType::V128)?;
                        self.push_val(ValType::I32);
                    }
                }
            }
        }
        Ok(())
    }
}

/// SIMD instruction signature categories
#[derive(Debug, Clone, Copy)]
enum SimdSig {
    UnaryV128,   // v128 -> v128
    BinaryV128,  // v128 x v128 -> v128
    TernaryV128, // v128 x v128 x v128 -> v128
    ShiftV128,   // v128 x i32 -> v128
    V128ToI32,   // v128 -> i32
}

/// Classify a SIMD sub-opcode by its stack signature.
/// Derived from the runtime.rs execution engine's actual pop/push patterns.
fn simd_op_signature(sub: u32) -> SimdSig {
    match sub {
        // ── v128 -> i32 (test/bitmask) ──
        0x53 | 0x63 | 0x64 | 0x83 | 0x84 | 0xA3 | 0xA4 | 0xC3 | 0xC4
        => SimdSig::V128ToI32,

        // ── v128 -> v128 (unary) ──
        0x4D | 0x5E | 0x5F | 0x60 | 0x61 | 0x62 | 0x67 | 0x68 |
        0x69 | 0x6A | 0x74 | 0x75 | 0x7A | 0x7C | 0x7D | 0x7E |
        0x7F | 0x80 | 0x81 | 0x87 | 0x88 | 0x89 | 0x8A | 0x94 |
        0xA0 | 0xA1 | 0xA7 | 0xA8 | 0xA9 | 0xAA | 0xC0 | 0xC1 |
        0xC7 | 0xC8 | 0xC9 | 0xCA | 0xE0 | 0xE1 | 0xE3 | 0xEC |
        0xED | 0xEF | 0xF8 | 0xF9 | 0xFA | 0xFB | 0xFC | 0xFD |
        0xFE | 0xFF |
        // relaxed unary (trunc): 0x100-0x104
        0x100 | 0x101 | 0x102 | 0x103 | 0x104
        => SimdSig::UnaryV128,

        // ── v128 x i32 -> v128 (shift) ──
        0x6B | 0x6C | 0x6D | // i8x16 shl/shr_s/shr_u
        0x8B | 0x8C | 0x8D | // i16x8 shl/shr_s/shr_u
        0xAB | 0xAC | 0xAD | // i32x4 shl/shr_s/shr_u
        0xCB | 0xCC | 0xCD   // i64x2 shl/shr_s/shr_u
        => SimdSig::ShiftV128,

        // ── v128 x v128 x v128 -> v128 (ternary) ──
        0x52 |  // v128.bitselect
        // relaxed SIMD ternary:
        0x105 | 0x106 | 0x107 | 0x108 | // f32x4/f64x2 relaxed_madd/nmadd
        0x109 | 0x10A | 0x10B | 0x10C | // relaxed_laneselect
        0x113   // i32x4.relaxed_dot_i8x16_i7x16_add_s
        => SimdSig::TernaryV128,

        // Everything else is binary (v128 x v128 -> v128)
        _ => SimdSig::BinaryV128,
    }
}

fn byte_to_valtype(b: u8) -> Result<ValType, WasmError> {
    match b {
        0x7F => Ok(ValType::I32),
        0x7E => Ok(ValType::I64),
        0x7D => Ok(ValType::F32),
        0x7C => Ok(ValType::F64),
        0x7B => Ok(ValType::V128),
        // funcref and externref — mapped to I32 like the decoder does
        0x70 | 0x6F => Ok(ValType::I32),
        _ => Err(WasmError::TypeMismatch),
    }
}

/// Validate instructions in a function body using stack-based type checking.
fn validate_function_body(
    module: &WasmModule,
    _func_index: usize,
    func: &crate::wasm::decoder::FuncDef,
    total_functions: usize,
    has_memory: bool,
    total_tables: usize,
    total_globals: usize,
) -> Result<(), WasmError> {
    let code = &module.code;
    let start = func.code_offset;
    let end = func.code_offset + func.code_len;

    if start >= code.len() || end > code.len() {
        return Err(WasmError::CodeTooLarge);
    }

    let type_idx = func.type_idx as usize;
    if type_idx >= module.func_types.len() {
        return Err(WasmError::FunctionNotFound(func.type_idx));
    }

    let ft = &module.func_types[type_idx];
    let func_import_count = module.func_import_count();

    // Build local types: params + locals
    let mut local_types = Vec::new();
    for i in 0..ft.param_count as usize {
        local_types.push(ft.params[i]);
    }
    for i in 0..func.local_count as usize {
        local_types.push(func.locals[i]);
    }

    let return_types: Vec<ValType> = ft.results[..ft.result_count as usize].to_vec();

    let mut validator = Validator {
        module,
        code,
        pc: start,
        end,
        opd_stack: Vec::new(),
        ctrl_stack: Vec::new(),
        local_types,
        return_types,
        total_functions,
        has_memory,
        total_tables,
        total_globals,
        func_import_count,
    };

    validator.validate()
}

// ─── LEB128 helpers for validation ─────────────────────────────────────────

fn read_leb128_u32(code: &[u8], pc: &mut usize) -> Result<u32, WasmError> {
    crate::wasm::decoder::decode_leb128_u32(code, pc)
}
