//! GC (0xFB prefix) instruction dispatch for the WASM interpreter.

use alloc::vec;
use alloc::vec::Vec;
use crate::wasm::types::*;
use crate::wasm::decoder::{GcTypeDef, StorageType};
use super::{WasmInstance, ExecResult, GcObject};

impl WasmInstance {
    /// Execute a GC instruction (0xFB prefix). Called with the sub-opcode already read.
    pub(super) fn exec_gc(&mut self, sub: u32) -> Result<(), WasmError> {
                match sub {
                    28 => { // ref.i31: pop i32, push i31ref (represented as i32)
                        // i31ref stores the lower 31 bits
                        // No-op: value stays as-is on the stack, masking done at get time
                    }
                    29 => { // i31.get_s: pop i31ref, sign-extend from 31 bits, push i32
                        let val = self.pop()?;
                        match val {
                            Value::NullRef => {
                                return Err(WasmError::NullI31Reference);
                            }
                            _ => {
                                let v = match val { Value::I32(v) => v, _ => 0 };
                                let masked = v & 0x7FFF_FFFF;
                                let sign_extended = if masked & 0x4000_0000 != 0 {
                                    masked | !0x7FFF_FFFFu32 as i32
                                } else {
                                    masked
                                };
                                self.push(Value::I32(sign_extended))?;
                            }
                        }
                    }
                    30 => { // i31.get_u: pop i31ref, mask to 31 bits, push i32
                        let val = self.pop()?;
                        match val {
                            Value::NullRef => {
                                return Err(WasmError::NullI31Reference);
                            }
                            _ => {
                                let v = match val { Value::I32(v) => v, _ => 0 };
                                self.push(Value::I32(v & 0x7FFF_FFFF))?;
                            }
                        }
                    }
                    0 => { // struct.new: typeidx — pop fields (in reverse), push ref
                        let type_idx = self.read_leb128_u32()?;
                        let field_count = self.gc_struct_field_count(type_idx);
                        let mut fields = vec![Value::I32(0); field_count];
                        for i in (0..field_count).rev() {
                            fields[i] = self.pop()?;
                        }
                        let heap_idx = self.gc_heap.len() as u32;
                        self.gc_heap.push(GcObject::Struct { type_idx, fields });
                        self.push(Value::GcRef(heap_idx))?;
                    }
                    1 => { // struct.new_default: typeidx — push ref with default fields
                        let type_idx = self.read_leb128_u32()?;
                        let field_count = self.gc_struct_field_count(type_idx);
                        let mut fields = Vec::with_capacity(field_count);
                        for i in 0..field_count {
                            fields.push(self.gc_struct_field_default(type_idx, i));
                        }
                        let heap_idx = self.gc_heap.len() as u32;
                        self.gc_heap.push(GcObject::Struct { type_idx, fields });
                        self.push(Value::GcRef(heap_idx))?;
                    }
                    2 | 3 | 4 => { // struct.get / struct.get_s / struct.get_u
                        let type_idx = self.read_leb128_u32()?;
                        let field_idx = self.read_leb128_u32()? as usize;
                        let ref_val = self.pop()?;
                        let heap_idx = match ref_val {
                            Value::GcRef(idx) => idx as usize,
                            Value::NullRef => { return Err(WasmError::NullStructReference); }
                            _ => { return Err(WasmError::NullStructReference); }
                        };
                        if heap_idx >= self.gc_heap.len() {
                            return Err(WasmError::NullStructReference);
                        }
                        let val = match &self.gc_heap[heap_idx] {
                            GcObject::Struct { fields, .. } => {
                                if field_idx >= fields.len() {
                                    return Err(WasmError::OutOfBounds);
                                }
                                fields[field_idx]
                            }
                            _ => { return Err(WasmError::TypeMismatch); }
                        };
                        // Apply sign/zero extension for packed types
                        let result = self.gc_apply_field_extend(type_idx, field_idx, val, sub);
                        self.push(result)?;
                    }
                    5 => { // struct.set: typeidx fieldidx — pop value + ref, set field
                        let type_idx = self.read_leb128_u32()?;
                        let field_idx = self.read_leb128_u32()? as usize;
                        let val = self.pop()?;
                        let ref_val = self.pop()?;
                        let heap_idx = match ref_val {
                            Value::GcRef(idx) => idx as usize,
                            Value::NullRef => { return Err(WasmError::NullStructReference); }
                            _ => { return Err(WasmError::NullStructReference); }
                        };
                        if heap_idx >= self.gc_heap.len() {
                            return Err(WasmError::NullStructReference);
                        }
                        // Wrap value for packed field types
                        let wrapped = self.gc_wrap_field_value(type_idx, field_idx, val);
                        match &mut self.gc_heap[heap_idx] {
                            GcObject::Struct { fields, .. } => {
                                if field_idx >= fields.len() {
                                    return Err(WasmError::OutOfBounds);
                                }
                                fields[field_idx] = wrapped;
                            }
                            _ => { return Err(WasmError::TypeMismatch); }
                        }
                    }
                    6 => { // array.new: typeidx — pop init_value + length, allocate, push ref
                        let type_idx = self.read_leb128_u32()?;
                        let length = self.pop_i32()? as u32;
                        let init_val = self.pop()?;
                        let elements = vec![init_val; length as usize];
                        let heap_idx = self.gc_heap.len() as u32;
                        self.gc_heap.push(GcObject::Array { type_idx, elements });
                        self.push(Value::GcRef(heap_idx))?;
                    }
                    7 => { // array.new_default: typeidx — pop length, allocate with defaults
                        let type_idx = self.read_leb128_u32()?;
                        let length = self.pop_i32()? as u32;
                        let default_val = self.gc_array_elem_default(type_idx);
                        let elements = vec![default_val; length as usize];
                        let heap_idx = self.gc_heap.len() as u32;
                        self.gc_heap.push(GcObject::Array { type_idx, elements });
                        self.push(Value::GcRef(heap_idx))?;
                    }
                    8 => { // array.new_fixed: typeidx + count — pop count values, allocate
                        let type_idx = self.read_leb128_u32()?;
                        let count = self.read_leb128_u32()? as usize;
                        let mut elements = vec![Value::I32(0); count];
                        for i in (0..count).rev() {
                            elements[i] = self.pop()?;
                        }
                        let heap_idx = self.gc_heap.len() as u32;
                        self.gc_heap.push(GcObject::Array { type_idx, elements });
                        self.push(Value::GcRef(heap_idx))?;
                    }
                    9 => { // array.new_data: typeidx + data_idx — pop offset + length
                        let type_idx = self.read_leb128_u32()?;
                        let data_idx = self.read_leb128_u32()? as usize;
                        let length = self.pop_i32()? as u32;
                        let offset = self.pop_i32()? as u32;
                        let elements = self.gc_array_from_data(type_idx, data_idx, offset, length)?;
                        let heap_idx = self.gc_heap.len() as u32;
                        self.gc_heap.push(GcObject::Array { type_idx, elements });
                        self.push(Value::GcRef(heap_idx))?;
                    }
                    10 => { // array.new_elem: typeidx + elem_idx — pop offset + length
                        let type_idx = self.read_leb128_u32()?;
                        let elem_idx = self.read_leb128_u32()? as usize;
                        let length = self.pop_i32()? as u32;
                        let offset = self.pop_i32()? as u32;
                        let elements = self.gc_array_from_elem(elem_idx, offset, length)?;
                        let heap_idx = self.gc_heap.len() as u32;
                        self.gc_heap.push(GcObject::Array { type_idx, elements });
                        self.push(Value::GcRef(heap_idx))?;
                    }
                    11 | 12 | 13 => { // array.get / array.get_s / array.get_u
                        let type_idx = self.read_leb128_u32()?;
                        let index = self.pop_i32()? as u32;
                        let ref_val = self.pop()?;
                        let heap_idx = match ref_val {
                            Value::GcRef(idx) => idx as usize,
                            Value::NullRef => { return Err(WasmError::NullArrayReference); }
                            _ => { return Err(WasmError::NullArrayReference); }
                        };
                        if heap_idx >= self.gc_heap.len() {
                            return Err(WasmError::NullArrayReference);
                        }
                        let val = match &self.gc_heap[heap_idx] {
                            GcObject::Array { elements, .. } => {
                                if index as usize >= elements.len() {
                                    return Err(WasmError::ArrayOutOfBounds);
                                }
                                elements[index as usize]
                            }
                            _ => { return Err(WasmError::TypeMismatch); }
                        };
                        // Apply sign/zero extension for packed array element types
                        let result = self.gc_apply_array_extend(type_idx, val, sub);
                        self.push(result)?;
                    }
                    14 => { // array.set: typeidx — pop value + index + ref, set element
                        let type_idx = self.read_leb128_u32()?;
                        let val = self.pop()?;
                        let index = self.pop_i32()? as u32;
                        let ref_val = self.pop()?;
                        let heap_idx = match ref_val {
                            Value::GcRef(idx) => idx as usize,
                            Value::NullRef => { return Err(WasmError::NullArrayReference); }
                            _ => { return Err(WasmError::NullArrayReference); }
                        };
                        if heap_idx >= self.gc_heap.len() {
                            return Err(WasmError::NullArrayReference);
                        }
                        let wrapped = self.gc_wrap_array_value(type_idx, val);
                        match &mut self.gc_heap[heap_idx] {
                            GcObject::Array { elements, .. } => {
                                if index as usize >= elements.len() {
                                    return Err(WasmError::ArrayOutOfBounds);
                                }
                                elements[index as usize] = wrapped;
                            }
                            _ => { return Err(WasmError::TypeMismatch); }
                        }
                    }
                    15 => { // array.len: pop ref, push length
                        let ref_val = self.pop()?;
                        let heap_idx = match ref_val {
                            Value::GcRef(idx) => idx as usize,
                            Value::NullRef => { return Err(WasmError::NullArrayReference); }
                            _ => { return Err(WasmError::NullArrayReference); }
                        };
                        if heap_idx >= self.gc_heap.len() {
                            return Err(WasmError::NullArrayReference);
                        }
                        let len = match &self.gc_heap[heap_idx] {
                            GcObject::Array { elements, .. } => elements.len() as i32,
                            _ => { return Err(WasmError::TypeMismatch); }
                        };
                        self.push(Value::I32(len))?;
                    }
                    16 => { // array.fill: typeidx — pop length + value + offset + ref
                        let type_idx = self.read_leb128_u32()?;
                        let length = self.pop_i32()? as u32;
                        let val = self.pop()?;
                        let offset = self.pop_i32()? as u32;
                        let ref_val = self.pop()?;
                        let heap_idx = match ref_val {
                            Value::GcRef(idx) => idx as usize,
                            Value::NullRef => { return Err(WasmError::NullArrayReference); }
                            _ => { return Err(WasmError::NullArrayReference); }
                        };
                        if heap_idx >= self.gc_heap.len() {
                            return Err(WasmError::NullArrayReference);
                        }
                        let wrapped = self.gc_wrap_array_value(type_idx, val);
                        match &mut self.gc_heap[heap_idx] {
                            GcObject::Array { elements, .. } => {
                                let end = offset as usize + length as usize;
                                if end > elements.len() {
                                    return Err(WasmError::ArrayOutOfBounds);
                                }
                                for i in offset as usize..end {
                                    elements[i] = wrapped;
                                }
                            }
                            _ => { return Err(WasmError::TypeMismatch); }
                        }
                    }
                    17 => { // array.copy: dst_type + src_type
                        let _dst_type = self.read_leb128_u32()?;
                        let _src_type = self.read_leb128_u32()?;
                        let length = self.pop_i32()? as u32;
                        let src_offset = self.pop_i32()? as u32;
                        let src_ref = self.pop()?;
                        let dst_offset = self.pop_i32()? as u32;
                        let dst_ref = self.pop()?;
                        let src_idx = match src_ref {
                            Value::GcRef(idx) => idx as usize,
                            Value::NullRef => { return Err(WasmError::NullArrayReference); }
                            _ => { return Err(WasmError::NullArrayReference); }
                        };
                        let dst_idx = match dst_ref {
                            Value::GcRef(idx) => idx as usize,
                            Value::NullRef => { return Err(WasmError::NullArrayReference); }
                            _ => { return Err(WasmError::NullArrayReference); }
                        };
                        {
                            // Check bounds even for zero-length copies per spec
                            let src_end = src_offset as usize + length as usize;
                            let dst_end = dst_offset as usize + length as usize;
                            // Check destination bounds first
                            match &self.gc_heap[dst_idx] {
                                GcObject::Array { elements, .. } => {
                                    if dst_end > elements.len() {
                                        return Err(WasmError::ArrayOutOfBounds);
                                    }
                                }
                                _ => { return Err(WasmError::TypeMismatch); }
                            }
                            // Check source bounds
                            match &self.gc_heap[src_idx] {
                                GcObject::Array { elements, .. } => {
                                    if src_end > elements.len() {
                                        return Err(WasmError::ArrayOutOfBounds);
                                    }
                                }
                                _ => { return Err(WasmError::TypeMismatch); }
                            }
                            if length > 0 {
                            // Copy elements, handling overlap
                            let src_elems = {
                                match &self.gc_heap[src_idx] {
                                    GcObject::Array { elements, .. } => {
                                        elements[src_offset as usize..src_end].to_vec()
                                    }
                                    _ => { return Err(WasmError::TypeMismatch); }
                                }
                            };
                            // Then write to destination
                            match &mut self.gc_heap[dst_idx] {
                                GcObject::Array { elements, .. } => {
                                    for i in 0..length as usize {
                                        elements[dst_offset as usize + i] = src_elems[i];
                                    }
                                }
                                _ => { return Err(WasmError::TypeMismatch); }
                            }
                            } // end if length > 0
                        }
                    }
                    18 => { // array.init_data: typeidx + data_idx
                        let type_idx = self.read_leb128_u32()?;
                        let data_idx = self.read_leb128_u32()? as usize;
                        let length = self.pop_i32()? as u32;
                        let src_offset = self.pop_i32()? as u32;
                        let dst_offset = self.pop_i32()? as u32;
                        let ref_val = self.pop()?;
                        let heap_idx = match ref_val {
                            Value::GcRef(idx) => idx as usize,
                            Value::NullRef => { return Err(WasmError::NullArrayReference); }
                            _ => { return Err(WasmError::NullArrayReference); }
                        };
                        // Check array (destination) bounds first per spec
                        match &self.gc_heap[heap_idx] {
                            GcObject::Array { elements, .. } => {
                                let dst_end = dst_offset as usize + length as usize;
                                if dst_end > elements.len() {
                                    return Err(WasmError::ArrayOutOfBounds);
                                }
                            }
                            _ => { return Err(WasmError::TypeMismatch); }
                        }
                        // Then check data source bounds
                        let src_elems = self.gc_array_from_data(type_idx, data_idx, src_offset, length)?;
                        match &mut self.gc_heap[heap_idx] {
                            GcObject::Array { elements, .. } => {
                                for i in 0..length as usize {
                                    elements[dst_offset as usize + i] = src_elems[i];
                                }
                            }
                            _ => { return Err(WasmError::TypeMismatch); }
                        }
                    }
                    19 => { // array.init_elem: typeidx + elem_idx
                        let _type_idx = self.read_leb128_u32()?;
                        let elem_idx = self.read_leb128_u32()? as usize;
                        let length = self.pop_i32()? as u32;
                        let src_offset = self.pop_i32()? as u32;
                        let dst_offset = self.pop_i32()? as u32;
                        let ref_val = self.pop()?;
                        let heap_idx = match ref_val {
                            Value::GcRef(idx) => idx as usize,
                            Value::NullRef => { return Err(WasmError::NullArrayReference); }
                            _ => { return Err(WasmError::NullArrayReference); }
                        };
                        // Check array (destination) bounds first per spec
                        match &self.gc_heap[heap_idx] {
                            GcObject::Array { elements, .. } => {
                                let dst_end = dst_offset as usize + length as usize;
                                if dst_end > elements.len() {
                                    return Err(WasmError::ArrayOutOfBounds);
                                }
                            }
                            _ => { return Err(WasmError::TypeMismatch); }
                        }
                        // Then check element source bounds
                        let src_elems = self.gc_array_from_elem(elem_idx, src_offset, length)?;
                        match &mut self.gc_heap[heap_idx] {
                            GcObject::Array { elements, .. } => {
                                for i in 0..length as usize {
                                    elements[dst_offset as usize + i] = src_elems[i];
                                }
                            }
                            _ => { return Err(WasmError::TypeMismatch); }
                        }
                    }
                    20 | 21 => { // ref.test / ref.test null: heaptype
                        let ht = self.read_leb128_i32()?;
                        let nullable = sub == 21;
                        let ref_val = self.pop()?;
                        let result = self.gc_ref_test(ref_val, ht, nullable);
                        self.push(Value::I32(if result { 1 } else { 0 }))?;
                    }
                    22 | 23 => { // ref.cast / ref.cast null: heaptype
                        let ht = self.read_leb128_i32()?;
                        let nullable = sub == 23;
                        let ref_val = self.pop()?;
                        let ok = self.gc_ref_test(ref_val, ht, nullable);
                        if !ok {
                            return Err(WasmError::CastFailure);
                        }
                        self.push(ref_val)?;
                    }
                    24 => { // br_on_cast: flags + label + ht1 + ht2
                        let _flags = self.read_byte()?;
                        let label = self.read_leb128_u32()?;
                        let _ht1 = self.read_leb128_i32()?;
                        let ht2 = self.read_leb128_i32()?;
                        let ref_val = self.pop()?;
                        let nullable = (_flags & 2) != 0; // bit 1 = output nullable
                        if self.gc_ref_test(ref_val, ht2, nullable) {
                            self.push(ref_val)?;
                            self.branch(label)?;
                        } else {
                            self.push(ref_val)?;
                        }
                    }
                    25 => { // br_on_cast_fail: flags + label + ht1 + ht2
                        let _flags = self.read_byte()?;
                        let label = self.read_leb128_u32()?;
                        let _ht1 = self.read_leb128_i32()?;
                        let ht2 = self.read_leb128_i32()?;
                        let ref_val = self.pop()?;
                        let nullable = (_flags & 2) != 0; // bit 1 = output nullable
                        if !self.gc_ref_test(ref_val, ht2, nullable) {
                            self.push(ref_val)?;
                            self.branch(label)?;
                        } else {
                            self.push(ref_val)?;
                        }
                    }
                    26 => { // any.convert_extern: pop externref, push anyref
                        let val = self.pop()?;
                        match val {
                            Value::NullRef | Value::I32(-1) => { self.push(Value::NullRef)?; }
                            _ => {
                                // Wrap externref into the any hierarchy as Internalized
                                let heap_idx = self.gc_heap.len() as u32;
                                self.gc_heap.push(GcObject::Internalized { value: val });
                                self.push(Value::GcRef(heap_idx))?;
                            }
                        }
                    }
                    27 => { // extern.convert_any: pop anyref, push externref
                        let val = self.pop()?;
                        match val {
                            Value::NullRef | Value::I32(-1) => { self.push(Value::NullRef)?; }
                            _ => {
                                // Wrap anyref into the extern hierarchy as Externalized
                                let heap_idx = self.gc_heap.len() as u32;
                                self.gc_heap.push(GcObject::Externalized { value: val });
                                self.push(Value::GcRef(heap_idx))?;
                            }
                        }
                    }
                    _ => {
                        return Err(WasmError::UnsupportedProposal);
                    }
                }
        Ok(())
    }
}
