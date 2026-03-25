//! GC helper methods for WasmInstance.
//! Includes GC const expression evaluation, struct/array field helpers,
//! type testing, and subtype checking.

use super::*;
use alloc::vec::Vec;
use crate::wasm::decoder::{GcTypeDef, StorageType};

impl WasmInstance {
    // ─── GC helpers ──────────────────────────────────────────────────────

    /// Evaluate GC const expressions for globals that need deferred evaluation.
    /// Called after instance creation when gc_heap is available.
    pub(crate) fn eval_gc_globals(&mut self) {
        // Collect init expression bytes to avoid borrow issues
        let global_info: Vec<(Vec<u8>, ValType)> = self.module.globals.iter()
            .map(|g| (g.init_expr_bytes.clone(), g.val_type))
            .collect();

        for (gi, (ref expr_bytes, val_type)) in global_info.iter().enumerate() {
            if expr_bytes.is_empty() { continue; }
            let needs_gc = matches!(val_type,
                ValType::AnyRef | ValType::NullableAnyRef | ValType::EqRef | ValType::NullableEqRef | ValType::I31Ref |
                ValType::StructRef | ValType::NullableStructRef | ValType::ArrayRef | ValType::NullableArrayRef |
                ValType::NoneRef | ValType::NullFuncRef | ValType::NullExternRef |
                ValType::TypedFuncRef | ValType::NonNullableFuncRef | ValType::NullableTypedFuncRef);
            if !needs_gc { continue; }
            if let Some(val) = self.eval_gc_const_expr(expr_bytes, 0) {
                self.globals[gi] = val;
            }
        }
    }

    /// Re-evaluate expression-based element segment items using the GC const expr evaluator.
    /// This is needed because at decode time, GC allocations (struct.new, array.new) can't
    /// be performed since the GC heap doesn't exist yet. We re-evaluate these expressions
    /// now that the instance is set up, and update both func_indices and tables.
    pub(crate) fn eval_gc_elem_exprs(&mut self) {
        use crate::wasm::decoder::ElemMode;
        let seg_count = self.module.element_segments.len();
        for seg_idx in 0..seg_count {
            let seg = &self.module.element_segments[seg_idx];
            if seg.item_expr_bytes.is_empty() { continue; }
            let expr_bytes_list = seg.item_expr_bytes.clone();
            let mode = seg.mode;
            let tbl_idx = seg.table_idx as usize;
            let offset = seg.offset as usize;
            // Re-evaluate each item expression
            let mut new_values: Vec<Value> = Vec::with_capacity(expr_bytes_list.len());
            for expr_bytes in &expr_bytes_list {
                if let Some(val) = self.eval_gc_const_expr(expr_bytes, 0) {
                    new_values.push(val);
                } else {
                    new_values.push(Value::NullRef);
                }
            }
            // Store re-evaluated GcRef values in elem_gc_values for use by gc_array_from_elem
            if self.elem_gc_values.len() <= seg_idx {
                self.elem_gc_values.resize(seg_count, Vec::new());
            }
            self.elem_gc_values[seg_idx] = new_values.clone();
            // Update tables for active segments
            if mode == ElemMode::Active && tbl_idx < self.tables.len() {
                for (i, val) in new_values.iter().enumerate() {
                    let idx = offset + i;
                    if idx < self.tables[self.tbl(tbl_idx)].len() {
                        let entry = match val {
                            Value::NullRef => None,
                            Value::I32(v) => if *v < 0 { None } else { Some(*v as u32) },
                            Value::GcRef(heap_idx) => Some(heap_idx | 0x8000_0000),
                            _ => None,
                        };
                        let rt = resolve_alias(&self.table_aliases, tbl_idx);
                        self.tables[rt][idx] = entry;
                    }
                }
            }
        }
    }

    /// Evaluate a GC-aware const expression, returning the resulting value.
    pub(crate) fn eval_gc_const_expr(&mut self, bytes: &[u8], start: usize) -> Option<Value> {
        use crate::wasm::decoder::{decode_leb128_u32, decode_leb128_i32, decode_leb128_i64};

        let mut pos = start;
        let mut stack: Vec<Value> = Vec::new();

        loop {
            if pos >= bytes.len() { return None; }
            let opcode = bytes[pos];
            pos += 1;
            match opcode {
                0x0B => return stack.pop(),
                0x41 => {
                    if let Ok(v) = decode_leb128_i32(bytes, &mut pos) { stack.push(Value::I32(v)); }
                }
                0x42 => {
                    if let Ok(v) = decode_leb128_i64(bytes, &mut pos) { stack.push(Value::I64(v)); }
                }
                0x43 => {
                    if pos + 4 > bytes.len() { return None; }
                    let v = f32::from_le_bytes([bytes[pos], bytes[pos+1], bytes[pos+2], bytes[pos+3]]);
                    pos += 4;
                    stack.push(Value::F32(v));
                }
                0x44 => {
                    if pos + 8 > bytes.len() { return None; }
                    let mut b8 = [0u8; 8];
                    b8.copy_from_slice(&bytes[pos..pos+8]);
                    pos += 8;
                    stack.push(Value::F64(f64::from_le_bytes(b8)));
                }
                0x23 => {
                    if let Ok(idx) = decode_leb128_u32(bytes, &mut pos) {
                        let val = self.globals.get(idx as usize).copied().unwrap_or(Value::I32(0));
                        stack.push(val);
                    }
                }
                0xD0 => {
                    let _ = decode_leb128_i32(bytes, &mut pos);
                    stack.push(Value::NullRef);
                }
                0xD2 => {
                    if let Ok(idx) = decode_leb128_u32(bytes, &mut pos) {
                        stack.push(Value::I32(idx as i32));
                    }
                }
                0xFB => {
                    if let Ok(sub) = decode_leb128_u32(bytes, &mut pos) {
                        match sub {
                            0 => { // struct.new
                                if let Ok(type_idx) = decode_leb128_u32(bytes, &mut pos) {
                                    let field_count = self.gc_struct_field_count(type_idx);
                                    let start_idx = stack.len().saturating_sub(field_count);
                                    let mut fields: Vec<Value> = stack.drain(start_idx..).collect();
                                    while fields.len() < field_count { fields.push(Value::I32(0)); }
                                    for i in 0..field_count {
                                        fields[i] = self.gc_wrap_field_value(type_idx, i, fields[i]);
                                    }
                                    let heap_idx = self.gc_heap.len() as u32;
                                    self.gc_heap.push(GcObject::Struct { type_idx, fields });
                                    stack.push(Value::GcRef(heap_idx));
                                }
                            }
                            1 => { // struct.new_default
                                if let Ok(type_idx) = decode_leb128_u32(bytes, &mut pos) {
                                    let field_count = self.gc_struct_field_count(type_idx);
                                    let mut fields = Vec::with_capacity(field_count);
                                    for i in 0..field_count {
                                        fields.push(self.gc_struct_field_default(type_idx, i));
                                    }
                                    let heap_idx = self.gc_heap.len() as u32;
                                    self.gc_heap.push(GcObject::Struct { type_idx, fields });
                                    stack.push(Value::GcRef(heap_idx));
                                }
                            }
                            6 => { // array.new
                                if let Ok(type_idx) = decode_leb128_u32(bytes, &mut pos) {
                                    let length = stack.pop().map(|v| v.as_i32() as u32).unwrap_or(0);
                                    let init_val = stack.pop().unwrap_or(Value::I32(0));
                                    let wrapped = self.gc_wrap_array_value(type_idx, init_val);
                                    let elements = vec![wrapped; length as usize];
                                    let heap_idx = self.gc_heap.len() as u32;
                                    self.gc_heap.push(GcObject::Array { type_idx, elements });
                                    stack.push(Value::GcRef(heap_idx));
                                }
                            }
                            7 => { // array.new_default
                                if let Ok(type_idx) = decode_leb128_u32(bytes, &mut pos) {
                                    let length = stack.pop().map(|v| v.as_i32() as u32).unwrap_or(0);
                                    let default_val = self.gc_array_elem_default(type_idx);
                                    let elements = vec![default_val; length as usize];
                                    let heap_idx = self.gc_heap.len() as u32;
                                    self.gc_heap.push(GcObject::Array { type_idx, elements });
                                    stack.push(Value::GcRef(heap_idx));
                                }
                            }
                            8 => { // array.new_fixed
                                if let Ok(type_idx) = decode_leb128_u32(bytes, &mut pos) {
                                    if let Ok(count) = decode_leb128_u32(bytes, &mut pos) {
                                        let count = count as usize;
                                        let start_idx = stack.len().saturating_sub(count);
                                        let mut elements: Vec<Value> = stack.drain(start_idx..).collect();
                                        for e in &mut elements {
                                            *e = self.gc_wrap_array_value(type_idx, *e);
                                        }
                                        let heap_idx = self.gc_heap.len() as u32;
                                        self.gc_heap.push(GcObject::Array { type_idx, elements });
                                        stack.push(Value::GcRef(heap_idx));
                                    }
                                }
                            }
                            28 => {} // ref.i31: value stays as I32
                            29 => { // i31.get_s
                                if let Some(val) = stack.last_mut() {
                                    let v = val.as_i32() & 0x7FFF_FFFF;
                                    *val = Value::I32(if v & 0x4000_0000 != 0 { v | !0x7FFF_FFFFu32 as i32 } else { v });
                                }
                            }
                            30 => { // i31.get_u
                                if let Some(val) = stack.last_mut() {
                                    *val = Value::I32(val.as_i32() & 0x7FFF_FFFF);
                                }
                            }
                            26 | 27 => {} // any.convert_extern, extern.convert_any
                            _ => return None,
                        }
                    }
                }
                0x6A => { if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) { stack.push(Value::I32(a.as_i32().wrapping_add(b.as_i32()))); } }
                0x6B => { if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) { stack.push(Value::I32(a.as_i32().wrapping_sub(b.as_i32()))); } }
                0x6C => { if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) { stack.push(Value::I32(a.as_i32().wrapping_mul(b.as_i32()))); } }
                _ => return None,
            }
        }
    }

    /// Get the number of fields in a struct type.
    pub(crate) fn gc_struct_field_count(&self, type_idx: u32) -> usize {
        if let Some(GcTypeDef::Struct { field_types, .. }) = self.module.gc_types.get(type_idx as usize) {
            field_types.len()
        } else {
            0
        }
    }

    /// Get default value for a struct field.
    pub(crate) fn gc_struct_field_default(&self, type_idx: u32, field_idx: usize) -> Value {
        if let Some(GcTypeDef::Struct { field_types, .. }) = self.module.gc_types.get(type_idx as usize) {
            if let Some(st) = field_types.get(field_idx) {
                return Value::default_for(st.unpack());
            }
        }
        Value::I32(0)
    }

    /// Get default value for an array element.
    pub(crate) fn gc_array_elem_default(&self, type_idx: u32) -> Value {
        if let Some(GcTypeDef::Array { elem_type, .. }) = self.module.gc_types.get(type_idx as usize) {
            return Value::default_for(elem_type.unpack());
        }
        Value::I32(0)
    }

    /// Apply sign/zero extension for struct field packed types.
    pub(crate) fn gc_apply_field_extend(&self, type_idx: u32, field_idx: usize, val: Value, sub_opcode: u32) -> Value {
        if let Some(GcTypeDef::Struct { field_types, .. }) = self.module.gc_types.get(type_idx as usize) {
            if let Some(st) = field_types.get(field_idx) {
                let v = val.as_i32();
                return match st {
                    StorageType::I8 => {
                        if sub_opcode == 3 { Value::I32((v as i8) as i32) }
                        else { Value::I32(v & 0xFF) }
                    }
                    StorageType::I16 => {
                        if sub_opcode == 3 { Value::I32((v as i16) as i32) }
                        else { Value::I32(v & 0xFFFF) }
                    }
                    _ => val,
                };
            }
        }
        val
    }

    /// Apply sign/zero extension for array element packed types.
    pub(crate) fn gc_apply_array_extend(&self, type_idx: u32, val: Value, sub_opcode: u32) -> Value {
        if let Some(GcTypeDef::Array { elem_type, .. }) = self.module.gc_types.get(type_idx as usize) {
            let v = val.as_i32();
            return match elem_type {
                StorageType::I8 => {
                    if sub_opcode == 12 { Value::I32((v as i8) as i32) }
                    else { Value::I32(v & 0xFF) }
                }
                StorageType::I16 => {
                    if sub_opcode == 12 { Value::I32((v as i16) as i32) }
                    else { Value::I32(v & 0xFFFF) }
                }
                _ => val,
            };
        }
        val
    }

    /// Wrap a value for storing into a packed struct field.
    pub(crate) fn gc_wrap_field_value(&self, type_idx: u32, field_idx: usize, val: Value) -> Value {
        if let Some(GcTypeDef::Struct { field_types, .. }) = self.module.gc_types.get(type_idx as usize) {
            if let Some(st) = field_types.get(field_idx) {
                return match st {
                    StorageType::I8 => Value::I32(val.as_i32() & 0xFF),
                    StorageType::I16 => Value::I32(val.as_i32() & 0xFFFF),
                    _ => val,
                };
            }
        }
        val
    }

    /// Wrap a value for storing into a packed array element.
    pub(crate) fn gc_wrap_array_value(&self, type_idx: u32, val: Value) -> Value {
        if let Some(GcTypeDef::Array { elem_type, .. }) = self.module.gc_types.get(type_idx as usize) {
            return match elem_type {
                StorageType::I8 => Value::I32(val.as_i32() & 0xFF),
                StorageType::I16 => Value::I32(val.as_i32() & 0xFFFF),
                _ => val,
            };
        }
        val
    }

    /// Create array elements from a data segment.
    /// For dropped segments, the effective data length is 0 (offset 0 + length 0 succeeds).
    pub(crate) fn gc_array_from_data(&self, type_idx: u32, data_idx: usize, offset: u32, length: u32) -> Result<Vec<Value>, WasmError> {
        if data_idx >= self.module.data_segments.len() {
            return Err(WasmError::MemoryOutOfBounds);
        }
        // Dropped segments are treated as having length 0
        let is_dropped = data_idx < self.dropped_data.len() && self.dropped_data[data_idx];
        let data_len = if is_dropped {
            0usize
        } else {
            self.module.data_segments[data_idx].data_len
        };

        let elem_size = if let Some(GcTypeDef::Array { elem_type, .. }) = self.module.gc_types.get(type_idx as usize) {
            match elem_type {
                StorageType::I8 => 1usize,
                StorageType::I16 => 2,
                StorageType::Val(ValType::I32) | StorageType::Val(ValType::F32) => 4,
                StorageType::Val(ValType::I64) | StorageType::Val(ValType::F64) => 8,
                _ => 4,
            }
        } else { 4 };

        let total_bytes = length as usize * elem_size;
        let start = offset as usize;
        if start + total_bytes > data_len {
            return Err(WasmError::MemoryOutOfBounds);
        }
        if length == 0 {
            return Ok(Vec::new());
        }
        let seg = &self.module.data_segments[data_idx];
        let data = &self.module.code[seg.data_offset..seg.data_offset + seg.data_len];

        let mut elements = Vec::with_capacity(length as usize);
        for i in 0..length as usize {
            let pos = start + i * elem_size;
            let val = match elem_size {
                1 => Value::I32(data[pos] as i32),
                2 => Value::I32(u16::from_le_bytes([data[pos], data[pos+1]]) as i32),
                4 => {
                    let bytes = [data[pos], data[pos+1], data[pos+2], data[pos+3]];
                    if let Some(GcTypeDef::Array { elem_type: StorageType::Val(ValType::F32), .. }) = self.module.gc_types.get(type_idx as usize) {
                        Value::F32(f32::from_le_bytes(bytes))
                    } else {
                        Value::I32(i32::from_le_bytes(bytes))
                    }
                }
                8 => {
                    let mut b8 = [0u8; 8];
                    b8.copy_from_slice(&data[pos..pos+8]);
                    if let Some(GcTypeDef::Array { elem_type: StorageType::Val(ValType::F64), .. }) = self.module.gc_types.get(type_idx as usize) {
                        Value::F64(f64::from_le_bytes(b8))
                    } else {
                        Value::I64(i64::from_le_bytes(b8))
                    }
                }
                _ => Value::I32(0),
            };
            elements.push(val);
        }
        Ok(elements)
    }

    /// Create array elements from an element segment.
    /// For dropped segments, the effective element count is 0 (offset 0 + length 0 succeeds).
    pub(crate) fn gc_array_from_elem(&self, elem_idx: usize, offset: u32, length: u32) -> Result<Vec<Value>, WasmError> {
        if elem_idx >= self.module.element_segments.len() {
            return Err(WasmError::TableIndexOutOfBounds);
        }
        // Dropped segments are treated as having length 0
        let is_dropped = elem_idx < self.dropped_elems.len() && self.dropped_elems[elem_idx];
        let seg_len = if is_dropped {
            0usize
        } else {
            self.module.element_segments[elem_idx].func_indices.len()
        };
        let end = offset as usize + length as usize;
        if end > seg_len {
            return Err(WasmError::TableIndexOutOfBounds);
        }
        if length == 0 {
            return Ok(Vec::new());
        }
        // Use re-evaluated GC values if available (expression-based segments)
        if elem_idx < self.elem_gc_values.len() && !self.elem_gc_values[elem_idx].is_empty() {
            let gc_vals = &self.elem_gc_values[elem_idx];
            let mut elements = Vec::with_capacity(length as usize);
            for i in offset as usize..end {
                if i < gc_vals.len() {
                    elements.push(gc_vals[i]);
                } else {
                    elements.push(Value::NullRef);
                }
            }
            return Ok(elements);
        }
        let seg = &self.module.element_segments[elem_idx];
        let mut elements = Vec::with_capacity(length as usize);
        for i in offset as usize..end {
            let func_idx = seg.func_indices[i];
            if func_idx == u32::MAX {
                elements.push(Value::NullRef);
            } else {
                elements.push(Value::I32(func_idx as i32));
            }
        }
        Ok(elements)
    }

    /// Test if a reference value matches a heap type.
    // Heap type constants (signed LEB128 byte values):
    // -16 (0x70) = func, -17 (0x6F) = extern, -18 (0x6E) = any,
    // -19 (0x6D) = eq, -20 (0x6C) = i31, -21 (0x6B) = struct,
    // -22 (0x6A) = array, -13 (0x73) = nofunc, -14 (0x72) = noextern,
    // -15 (0x71) = none, -23 (0x69) = exn, -12 (0x74) = noexn
    const HT_FUNC: i32 = -16;
    const HT_EXTERN: i32 = -17;
    const HT_ANY: i32 = -18;
    const HT_EQ: i32 = -19;
    const HT_I31: i32 = -20;
    const HT_STRUCT: i32 = -21;
    const HT_ARRAY: i32 = -22;
    const HT_NOFUNC: i32 = -13;
    const HT_NOEXTERN: i32 = -14;
    const HT_NONE: i32 = -15;

    pub(crate) fn gc_ref_test(&self, val: Value, ht: i32, nullable: bool) -> bool {
        match val {
            Value::NullRef | Value::I32(-1) => nullable,
            Value::I32(v) => {
                // I32 values represent i31ref (from ref.i31) or funcref (function index)
                match ht {
                    Self::HT_ANY => true,      // i31 <: any
                    Self::HT_EQ => true,       // i31 <: eq
                    Self::HT_I31 => true,      // i31 <: i31
                    Self::HT_FUNC => true,     // i32 encoding for funcref
                    Self::HT_EXTERN => false,
                    Self::HT_STRUCT => false,
                    Self::HT_ARRAY => false,
                    Self::HT_NONE => false,
                    Self::HT_NOFUNC => false,
                    Self::HT_NOEXTERN => false,
                    _ if ht >= 0 => {
                        // Concrete type: check if this is a funcref and its type is a subtype
                        if v >= 0 {
                            let func_idx = v as u32;
                            let func_type = if (func_idx as usize) < self.module.func_import_count() {
                                self.module.func_import_type(func_idx)
                            } else {
                                let li = (func_idx as usize).wrapping_sub(self.module.func_import_count());
                                self.module.functions.get(li).map(|f| f.type_idx)
                            };
                            if let Some(fti) = func_type {
                                self.gc_is_subtype(fti, ht as u32)
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    }
                    _ => false,
                }
            }
            Value::GcRef(heap_idx) => {
                if heap_idx as usize >= self.gc_heap.len() {
                    return false;
                }
                let obj = &self.gc_heap[heap_idx as usize];
                // Internalized extern values (from any.convert_extern) only match HT_ANY
                if matches!(obj, GcObject::Internalized { .. }) {
                    return ht == Self::HT_ANY;
                }
                // Externalized any values (from extern.convert_any) match HT_EXTERN
                if matches!(obj, GcObject::Externalized { .. }) {
                    return ht == Self::HT_EXTERN;
                }
                let obj_type_idx = obj.type_idx();
                match ht {
                    Self::HT_ANY => true,      // all GC objects <: any
                    Self::HT_EQ => true,       // all GC objects <: eq
                    Self::HT_I31 => false,     // GC objects are not i31
                    Self::HT_STRUCT => matches!(obj, GcObject::Struct { .. }),
                    Self::HT_ARRAY => matches!(obj, GcObject::Array { .. }),
                    Self::HT_FUNC => false,
                    Self::HT_EXTERN => false,
                    Self::HT_NONE => false,
                    Self::HT_NOFUNC => false,
                    Self::HT_NOEXTERN => false,
                    _ if ht >= 0 => self.gc_is_subtype(obj_type_idx, ht as u32),
                    _ => false,
                }
            }
            _ => false,
        }
    }

    /// Check if two types are equivalent using rec-group-aware canonicalization.
    pub(crate) fn gc_types_equivalent(&self, type_a: u32, type_b: u32) -> bool {
        if type_a == type_b { return true; }
        crate::wasm::validator::types_equivalent_in_module(&self.module, type_a, type_b)
    }

    /// Check if type_a is a subtype of type_b (or equal).
    pub(crate) fn gc_is_subtype(&self, type_a: u32, type_b: u32) -> bool {
        if type_a == type_b {
            return true;
        }
        // Check canonical type equivalence
        if self.gc_types_equivalent(type_a, type_b) {
            return true;
        }
        let mut current = type_a;
        for _ in 0..100 {
            if let Some(info) = self.module.sub_types.get(current as usize) {
                if let Some(parent) = info.supertype {
                    if parent == type_b || self.gc_types_equivalent(parent, type_b) {
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


}
