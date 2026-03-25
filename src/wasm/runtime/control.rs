//! Control flow helper methods for WasmInstance.
//! Includes scan_legacy_try, skip_to_end, and handle_exception.

use super::*;

impl WasmInstance {
    /// Called right after reading the block type of a `try` instruction.
    /// Returns (legacy_catches, legacy_catch_count, end_pc, delegate_label).
    pub(super) fn scan_legacy_try(&mut self) -> Result<([LegacyCatch; MAX_LEGACY_CATCHES], u8, usize, u32), WasmError> {
        let save_pc = self.pc;
        let mut catches = [LegacyCatch::zero(); MAX_LEGACY_CATCHES];
        let mut catch_count: u8 = 0;
        let mut depth: usize = 1;
        let mut end_pc = 0usize;
        let mut delegate_label: u32 = u32::MAX;

        while depth > 0 {
            let b = self.read_byte()?;
            match b {
                0x02 | 0x03 | 0x04 => {
                    let bt = self.read_leb128_i32()?;
                    if bt == -0x1D || bt == -0x1C { let _ = self.read_leb128_i32()?; }
                    depth += 1;
                }
                0x06 => {
                    let bt = self.read_leb128_i32()?;
                    if bt == -0x1D || bt == -0x1C { let _ = self.read_leb128_i32()?; }
                    depth += 1;
                }
                0x07 => { // catch tag_idx
                    let tag_idx = self.read_leb128_u32()?;
                    if depth == 1 && (catch_count as usize) < MAX_LEGACY_CATCHES {
                        catches[catch_count as usize] = LegacyCatch {
                            handler_pc: self.pc,
                            tag_idx,
                        };
                        catch_count += 1;
                    }
                }
                0x19 => { // catch_all
                    if depth == 1 && (catch_count as usize) < MAX_LEGACY_CATCHES {
                        catches[catch_count as usize] = LegacyCatch {
                            handler_pc: self.pc,
                            tag_idx: u32::MAX,
                        };
                        catch_count += 1;
                    }
                }
                0x18 => { // delegate
                    let label = self.read_leb128_u32()?;
                    depth -= 1;
                    if depth == 0 {
                        end_pc = self.pc;
                        delegate_label = label;
                    }
                }
                0x0B => {
                    depth -= 1;
                    if depth == 0 {
                        end_pc = self.pc;
                    }
                }
                0x05 => {} // else
                0x08 => { let _ = self.read_leb128_u32()?; } // throw
                0x09 => { let _ = self.read_leb128_u32()?; } // rethrow: label
                0x0A => {} // throw_ref
                0x1F => {
                    let bt = self.read_leb128_i32()?;
                    if bt == -0x1D || bt == -0x1C { let _ = self.read_leb128_i32()?; }
                    let cc = self.read_leb128_u32()? as usize;
                    for _ in 0..cc {
                        let ck = self.read_byte()?;
                        match ck {
                            0 | 1 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; }
                            2 | 3 => { let _ = self.read_leb128_u32()?; }
                            _ => {}
                        }
                    }
                    depth += 1;
                }
                0x0C | 0x0D => { let _ = self.read_leb128_u32()?; } // br, br_if
                0x0E => {
                    let count = self.read_leb128_u32()? as usize;
                    for _ in 0..count { let _ = self.read_leb128_u32()?; }
                    let _ = self.read_leb128_u32()?;
                }
                0x10 | 0x12 | 0x14 | 0x15 => { let _ = self.read_leb128_u32()?; }
                0x11 | 0x13 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; }
                0x20 | 0x21 | 0x22 | 0x23 | 0x24 | 0x25 | 0x26 => { let _ = self.read_leb128_u32()?; }
                0xFC => {
                    let sub = self.read_leb128_u32()?;
                    match sub {
                        0..=7 => {}
                        8 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; }
                        9 | 13 => { let _ = self.read_leb128_u32()?; }
                        10 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; }
                        11 | 16 => { let _ = self.read_byte()?; }
                        12 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; }
                        14 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; }
                        15 => { let _ = self.read_leb128_u32()?; }
                        17 => { let _ = self.read_leb128_u32()?; }
                        _ => {}
                    }
                }
                0xFD => {
                    let sub = self.read_leb128_u32()?;
                    match sub {
                        0..=11 | 92..=95 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; }
                        84..=91 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; let _ = self.read_byte()?; }
                        12 => { let mut buf = [0u8; 16]; for b in &mut buf { *b = self.read_byte()?; } }
                        13 => { let _ = self.read_leb128_u32()?; }
                        21..=34 => { let _ = self.read_leb128_u32()?; }
                        _ => {}
                    }
                }
                0xFE => {
                    let sub = self.read_leb128_u32()?;
                    match sub {
                        0x00..=0x4e => {
                            if sub <= 0x03 { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; }
                            else { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; }
                        }
                        _ => {}
                    }
                }
                0x28..=0x3E | 0x3F | 0x40 => {
                    let _ = self.read_leb128_u32()?;
                    let _ = self.read_leb128_u32()?;
                }
                0x41 => { let _ = self.read_leb128_i32()?; }
                0x42 => { let _ = self.read_leb128_i64()?; }
                0x43 => { for _ in 0..4 { let _ = self.read_byte()?; } }
                0x44 => { for _ in 0..8 { let _ = self.read_byte()?; } }
                0xD0 => { let _ = self.read_leb128_i32()?; } // ref.null
                0xD2 => { let _ = self.read_leb128_u32()?; } // ref.func
                0xFB => {
                    let sub = self.read_leb128_u32()?;
                    match sub {
                        0..=7 | 26..=30 => { let _ = self.read_leb128_u32()?; }
                        8 | 12 | 14..=17 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; }
                        _ => {}
                    }
                }
                _ => {} // most opcodes have no immediates
            }
        }
        self.pc = save_pc;
        Ok((catches, catch_count, end_pc, delegate_label))
    }


    /// Skip forward in the bytecode to find the matching End for a block.
    /// This handles nested blocks correctly.
    pub(crate) fn skip_to_end(&mut self) -> Result<usize, WasmError> {
        let mut depth: usize = 1;
        while depth > 0 {
            let b = self.read_byte()?;
            match b {
                0x02 | 0x03 | 0x04 => {
                    // Block, Loop, If — nested
                    // Read and discard the block type (may be multi-byte for ref types)
                    let bt = self.read_leb128_i32()?;
                    if bt == -0x1D || bt == -0x1C {
                        let _ = self.read_leb128_i32()?; // consume heap type
                    }
                    depth += 1;
                }
                0x05 => {
                    // Else — if we're at depth 1, this is our else
                    if depth == 1 {
                        return Ok(self.pc);
                    }
                }
                0x0B => {
                    // End
                    depth -= 1;
                    if depth == 0 {
                        return Ok(self.pc);
                    }
                }
                0x06 => { // try (legacy exception handling) — opens a block
                    let bt = self.read_leb128_i32()?; // block type
                    if bt == -0x1D || bt == -0x1C {
                        let _ = self.read_leb128_i32()?; // consume heap type
                    }
                    depth += 1;
                }
                0x07 => { // catch (legacy): tag_idx
                    let _ = self.read_leb128_u32()?;
                }
                0x08 => { let _ = self.read_leb128_u32()?; } // throw: tag_idx
                0x09 => { let _ = self.read_leb128_u32()?; } // rethrow: label
                0x0A => {} // throw_ref: no immediates
                0x18 => { // delegate (legacy): label — ends the try block
                    let _ = self.read_leb128_u32()?;
                    depth -= 1;
                    if depth == 0 {
                        return Ok(self.pc);
                    }
                }
                0x19 => { // catch_all (legacy): no immediates
                }
                0x1F => {
                    // try_table: block_type + catch_count + catch clauses
                    let bt = self.read_leb128_i32()?;
                    if bt == -0x1D || bt == -0x1C {
                        let _ = self.read_leb128_i32()?; // consume heap type
                    }
                    let catch_count = self.read_leb128_u32()? as usize;
                    for _ in 0..catch_count {
                        let clause_kind = self.read_byte()?;
                        match clause_kind {
                            0 | 1 => { // catch, catch_ref: tag_idx + label
                                let _ = self.read_leb128_u32()?; // tag_idx
                                let _ = self.read_leb128_u32()?; // label
                            }
                            2 | 3 => { // catch_all, catch_all_ref: label
                                let _ = self.read_leb128_u32()?; // label
                            }
                            _ => {} // unknown clause kind
                        }
                    }
                    depth += 1;
                }
                // Instructions with LEB128 immediates that we need to skip
                0x0C | 0x0D => { let _ = self.read_leb128_u32()?; } // br, br_if
                0x0E => {
                    // br_table: count + count labels + default label
                    let count = self.read_leb128_u32()? as usize;
                    for _ in 0..count { let _ = self.read_leb128_u32()?; }
                    let _ = self.read_leb128_u32()?; // default
                }
                0x10 | 0x12 | 0x14 | 0x15 => { let _ = self.read_leb128_u32()?; } // call, return_call, call_ref, return_call_ref
                0x11 | 0x13 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; } // call_indirect, return_call_indirect
                0x20 | 0x21 | 0x22 | 0x23 | 0x24 | 0x25 | 0x26 => { let _ = self.read_leb128_u32()?; } // local/global/table get/set
                0xFC => {
                    // Multi-byte prefix: read sub-opcode, then skip its immediates
                    let sub = self.read_leb128_u32()?;
                    match sub {
                        0..=7 => {} // sat trunc: no immediates
                        8 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; } // memory.init
                        9 | 13 => { let _ = self.read_leb128_u32()?; } // data.drop, elem.drop
                        10 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; } // memory.copy
                        11 => { let _ = self.read_leb128_u32()?; } // memory.fill
                        12 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; } // table.init
                        14 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; } // table.copy
                        15..=17 => { let _ = self.read_leb128_u32()?; } // table.grow/size/fill
                        _ => {}
                    }
                }
                0xFD => {
                    // SIMD prefix: read sub-opcode, then skip its immediates
                    let sub = self.read_leb128_u32()?;
                    match sub {
                        0x00..=0x0b => { // v128 load/store: memarg (flags [+ memidx] + offset)
                            let flags = self.read_leb128_u32()?;
                            if self.module.multi_memory_enabled && (flags & (1 << 6)) != 0 { let _ = self.read_leb128_u32()?; }
                            let _ = self.read_leb128_u32()?;
                        }
                        0x0c => { self.pc += 16; } // v128.const: 16 bytes immediate
                        0x0d => { self.pc += 16; } // i8x16.shuffle: 16 lane bytes
                        0x15..=0x22 => { self.pc += 1; } // extract/replace lane: 1 byte lane index
                        0x54..=0x5b => { // load/store_lane: memarg + lane
                            let flags = self.read_leb128_u32()?;
                            if self.module.multi_memory_enabled && (flags & (1 << 6)) != 0 { let _ = self.read_leb128_u32()?; }
                            let _ = self.read_leb128_u32()?; self.pc += 1;
                        }
                        0x5c..=0x5d => { // load*_zero: memarg
                            let flags = self.read_leb128_u32()?;
                            if self.module.multi_memory_enabled && (flags & (1 << 6)) != 0 { let _ = self.read_leb128_u32()?; }
                            let _ = self.read_leb128_u32()?;
                        }
                        _ => {} // most SIMD ops have no immediates
                    }
                }
                0xFE => {
                    // Threads/Atomics prefix: read sub-opcode, then skip its immediates
                    let sub = self.read_leb128_u32()?;
                    match sub {
                        0x03 => { self.pc += 1; } // atomic.fence: 1 byte (0x00)
                        0x00..=0x02 | 0x10..=0x4e => {
                            // All atomic memory ops have a memarg
                            let flags = self.read_leb128_u32()?;
                            if self.module.multi_memory_enabled && (flags & (1 << 6)) != 0 { let _ = self.read_leb128_u32()?; }
                            let _ = self.read_leb128_u32()?;
                        }
                        _ => {}
                    }
                }
                0x3F | 0x40 => { let _ = self.read_leb128_u32()?; } // memory.size/grow (memory index)
                0x28 | 0x29 | 0x2A | 0x2B | 0x2C | 0x2D | 0x2E | 0x2F
                | 0x30 | 0x31 | 0x32 | 0x33 | 0x34 | 0x35
                | 0x36 | 0x37 | 0x38 | 0x39 | 0x3A | 0x3B | 0x3C | 0x3D | 0x3E => {
                    // memory load/store (all variants): memarg (flags [+ memidx] + offset)
                    let flags = self.read_leb128_u32()?;
                    if self.module.multi_memory_enabled && (flags & (1 << 6)) != 0 {
                        let _ = self.read_leb128_u32()?; // memory index
                    }
                    let _ = self.read_leb128_u32()?; // offset
                }
                0x41 => { let _ = self.read_leb128_i32()?; } // i32.const
                0x42 => { let _ = self.read_leb128_i64()?; } // i64.const
                0x43 => { self.pc += 4; } // f32.const (4 bytes IEEE 754)
                0x44 => { self.pc += 8; } // f64.const (8 bytes IEEE 754)
                0x0F => {} // return
                0x1C => {
                    // select (typed): vector of value types
                    let count = self.read_leb128_u32()? as usize;
                    for _ in 0..count { let _ = self.read_leb128_u32()?; }
                }
                0xD0 => { let _ = self.read_leb128_i32()?; } // ref.null heaptype
                0xD2 => { let _ = self.read_leb128_u32()?; } // ref.func funcidx
                // 0xD3, 0xD4 = ref.as_non_null: no immediates
                0xD5 | 0xD6 => { let _ = self.read_leb128_u32()?; } // br_on_null, br_on_non_null: label
                0xFB => {
                    // GC prefix: read sub-opcode, then skip its immediates
                    let sub = self.read_leb128_u32()?;
                    match sub {
                        0 | 1 => { let _ = self.read_leb128_u32()?; } // struct.new, struct.new_default: typeidx
                        2 | 3 | 4 | 5 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; } // struct.get/get_s/get_u/set: typeidx fieldidx
                        6 | 7 => { let _ = self.read_leb128_u32()?; } // array.new, array.new_default: typeidx
                        8 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; } // array.new_fixed: typeidx + size
                        9 | 10 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; } // array.new_data/elem: typeidx + idx
                        11 | 12 | 13 => { let _ = self.read_leb128_u32()?; } // array.get/get_s/get_u: typeidx
                        14 => { let _ = self.read_leb128_u32()?; } // array.set: typeidx
                        15 => {} // array.len: no immediates
                        16 => { let _ = self.read_leb128_u32()?; } // array.fill: typeidx
                        17 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; } // array.copy: typeidx typeidx
                        18 | 19 => { let _ = self.read_leb128_u32()?; let _ = self.read_leb128_u32()?; } // array.init_data/elem: typeidx + idx
                        20 | 21 => { let _ = self.read_leb128_i32()?; } // ref.test, ref.test (nullable): heaptype
                        22 | 23 => { let _ = self.read_leb128_i32()?; } // ref.cast, ref.cast (nullable): heaptype
                        24 | 25 => { // br_on_cast, br_on_cast_fail
                            let _ = self.read_byte()?; // flags
                            let _ = self.read_leb128_u32()?; // label
                            let _ = self.read_leb128_i32()?; // ht1
                            let _ = self.read_leb128_i32()?; // ht2
                        }
                        26 | 27 => {} // any.convert_extern, extern.convert_any: no immediates
                        28 | 29 | 30 => {} // ref.i31, i31.get_s, i31.get_u: no immediates
                        _ => {} // Unknown GC sub-opcode — assume no immediates
                    }
                }
                _ => {
                    // Most instructions have no immediates — just skip the opcode byte
                }
            }
        }
        Ok(self.pc)
    }


    /// Try to handle an exception by scanning the block stack for matching try_table catch clauses.
    /// If a match is found, sets up the branch and returns Ok(()).
    /// If no match, returns Err(()) so the caller can propagate.
    pub(crate) fn handle_exception(&mut self, tag_idx: u32, values: &[Value]) -> Result<(), ()> {
        // Scan the block stack from top to bottom within the current function,
        // then unwind through call frames if needed.
        loop {
            let base = if self.call_depth > 0 {
                self.call_stack[self.call_depth - 1].block_stack_base
            } else {
                0
            };

            // Scan block stack from top to bottom for try_table or legacy try with matching catch
            let mut found_try_table = None;
            let mut found_legacy = None;
            let mut try_block_idx = self.block_depth;
            while try_block_idx > base {
                try_block_idx -= 1;
                let bf = self.block_stack[try_block_idx];

                // Check legacy try blocks
                if bf.is_legacy_try {
                    // If this is a delegate block (no catches, has delegate label),
                    // skip ahead by delegate_label levels
                    if bf.legacy_delegate_label != u32::MAX {
                        // Pop this block and skip delegate_label more blocks
                        let skip = bf.legacy_delegate_label as usize;
                        if try_block_idx >= skip {
                            try_block_idx -= skip;
                        } else {
                            try_block_idx = base;
                        }
                        continue;
                    }
                    for ci in 0..bf.legacy_catch_count as usize {
                        let lc = bf.legacy_catches[ci];
                        if lc.tag_idx == u32::MAX {
                            // catch_all: matches any exception
                            found_legacy = Some((try_block_idx, ci));
                            break;
                        } else if self.tags_match(lc.tag_idx, tag_idx) {
                            found_legacy = Some((try_block_idx, ci));
                            break;
                        }
                    }
                    if found_legacy.is_some() {
                        break;
                    }
                    continue;
                }

                if !bf.is_try_table {
                    continue;
                }
                // Check try_table catch clauses
                for ci in 0..bf.catch_count as usize {
                    let cc = bf.catches[ci];
                    match cc.kind {
                        0 => {
                            if self.tags_match(cc.tag_idx, tag_idx) {
                                found_try_table = Some((try_block_idx, ci, false));
                                break;
                            }
                        }
                        1 => {
                            if self.tags_match(cc.tag_idx, tag_idx) {
                                found_try_table = Some((try_block_idx, ci, true));
                                break;
                            }
                        }
                        2 => {
                            found_try_table = Some((try_block_idx, ci, false));
                            break;
                        }
                        3 => {
                            found_try_table = Some((try_block_idx, ci, true));
                            break;
                        }
                        _ => {}
                    }
                }
                if found_try_table.is_some() {
                    break;
                }
            }

            // Handle legacy try catch
            if let Some((try_idx, clause_idx)) = found_legacy {
                let lc = self.block_stack[try_idx].legacy_catches[clause_idx];
                let is_catch_all = lc.tag_idx == u32::MAX;
                let try_frame = self.block_stack[try_idx];

                // Reset stack to the try block's stack base
                self.stack_ptr = try_frame.stack_base;
                // Pop all blocks above AND including the try block
                self.truncate_blocks(try_idx);

                // Push a "catch" frame to replace the try frame.
                // This frame represents the catch handler scope.
                // The validator does the same: pop_ctrl() + push_ctrl() for catch.
                let mut catch_frame = BlockFrame::zero();
                catch_frame.start_pc = lc.handler_pc;
                catch_frame.end_pc = try_frame.end_pc;
                catch_frame.stack_base = self.stack_ptr;
                catch_frame.result_count = try_frame.result_count;
                catch_frame.end_result_count = try_frame.end_result_count;
                catch_frame.is_legacy_try = true;
                // Store exception info for rethrow (no truncation)
                catch_frame.legacy_exception_tag = tag_idx;
                let store_idx = self.alloc_legacy_exception_values(values);
                catch_frame.legacy_exception_store_idx = store_idx;
                let _ = self.push_block(catch_frame);

                // Push exception values for catch (not catch_all)
                if !is_catch_all {
                    for v in values {
                        let _ = self.push(*v);
                    }
                }

                // Jump to the handler PC
                self.pc = lc.handler_pc;
                return Ok(());
            }

            if let Some((try_idx, clause_idx, push_exnref)) = found_try_table {
                let cc = self.block_stack[try_idx].catches[clause_idx];
                let label = cc.label;

                // Reset stack to the try_table's stack base
                let try_frame = self.block_stack[try_idx];
                self.stack_ptr = try_frame.stack_base;
                self.truncate_blocks(try_idx);

                // Push the exception values onto the stack for catch/catch_ref
                match cc.kind {
                    0 | 1 => {
                        for v in values {
                            let _ = self.push(*v);
                        }
                    }
                    2 => {}
                    3 => {}
                    _ => {}
                }

                // For catch_ref / catch_all_ref, push exnref
                if push_exnref {
                    let _ = self.push(Value::I32(tag_idx as i32));
                }

                // Branch using the label from the catch clause
                if let Err(_e) = self.branch(label) {
                    return Err(());
                }
                return Ok(());
            }

            // No matching catch in this function's block stack.
            // Unwind the call frame and propagate to the caller.
            if self.call_depth == 0 {
                return Err(());
            }

            let frame = self.call_stack[self.call_depth - 1];
            self.call_depth -= 1;
            self.stack_ptr = frame.stack_base;
            self.pc = frame.return_pc;
            self.truncate_blocks(frame.saved_block_depth);

            if self.call_depth == 0 {
                return Err(());
            }
        }
    }


}
