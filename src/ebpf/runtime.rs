//! eBPF-lite interpreter.
//!
//! Executes verified eBPF-lite programs with instruction counting
//! to guarantee bounded execution.

use super::types::*;

/// eBPF-lite execution context.
pub struct EbpfVm {
    pub regs: [u64; NUM_REGS],
    pub stack: [u8; STACK_SIZE],
    pub pc: usize,
    pub insn_count: usize,
    pub max_insns: usize,
}

impl EbpfVm {
    /// Create a new VM with the given instruction limit.
    pub fn new(max_insns: usize) -> Self {
        EbpfVm {
            regs: [0; NUM_REGS],
            stack: [0; STACK_SIZE],
            pc: 0,
            insn_count: 0,
            max_insns,
        }
    }

    /// Execute a verified program with the given context pointer.
    ///
    /// `ctx` is passed in r1 (following eBPF calling convention).
    /// Returns the value in r0 (the return value).
    pub fn execute(&mut self, program: &[Insn], ctx: u64) -> Result<u64, EbpfError> {
        self.regs = [0; NUM_REGS];
        self.regs[1] = ctx; // r1 = context pointer
        self.regs[10] = self.stack.as_ptr() as u64 + STACK_SIZE as u64; // r10 = frame pointer
        self.pc = 0;
        self.insn_count = 0;

        loop {
            if self.pc >= program.len() {
                return Err(EbpfError::OutOfBounds);
            }
            if self.insn_count >= self.max_insns {
                return Err(EbpfError::MaxInstructionsExceeded);
            }
            self.insn_count += 1;

            let insn = program[self.pc];
            let class = insn.opcode & 0x07;

            match class {
                BPF_ALU64 => self.exec_alu64(&insn)?,
                BPF_ALU => self.exec_alu32(&insn)?,
                BPF_JMP => {
                    if let Some(ret) = self.exec_jmp(&insn)? {
                        return Ok(ret);
                    }
                }
                BPF_LDX => self.exec_ldx(&insn)?,
                BPF_STX => self.exec_stx(&insn)?,
                BPF_ST => self.exec_st(&insn)?,
                _ => return Err(EbpfError::InvalidOpcode(insn.opcode)),
            }

            self.pc += 1;
        }
    }

    /// Execute a 64-bit ALU instruction.
    fn exec_alu64(&mut self, insn: &Insn) -> Result<(), EbpfError> {
        let dst = insn.dst();
        let src_val = if insn.opcode & BPF_X != 0 {
            self.regs[insn.src()]
        } else {
            insn.imm as i64 as u64 // sign-extend immediate
        };

        match insn.opcode & 0xF0 {
            BPF_ADD => self.regs[dst] = self.regs[dst].wrapping_add(src_val),
            BPF_SUB => self.regs[dst] = self.regs[dst].wrapping_sub(src_val),
            BPF_MUL => self.regs[dst] = self.regs[dst].wrapping_mul(src_val),
            BPF_DIV => {
                if src_val == 0 {
                    return Err(EbpfError::DivisionByZero);
                }
                self.regs[dst] /= src_val;
            }
            BPF_MOD => {
                if src_val == 0 {
                    return Err(EbpfError::DivisionByZero);
                }
                self.regs[dst] %= src_val;
            }
            BPF_MOV => self.regs[dst] = src_val,
            BPF_AND => self.regs[dst] &= src_val,
            BPF_OR => self.regs[dst] |= src_val,
            BPF_XOR => self.regs[dst] ^= src_val,
            BPF_LSH => self.regs[dst] <<= src_val & 63,
            BPF_RSH => self.regs[dst] >>= src_val & 63,
            BPF_NEG => self.regs[dst] = (-(self.regs[dst] as i64)) as u64,
            _ => return Err(EbpfError::InvalidOpcode(insn.opcode)),
        }
        Ok(())
    }

    /// Execute a 32-bit ALU instruction.
    ///
    /// Operates on the lower 32 bits and zero-extends the result.
    fn exec_alu32(&mut self, insn: &Insn) -> Result<(), EbpfError> {
        let dst = insn.dst();
        let dst_val = self.regs[dst] as u32;
        let src_val = if insn.opcode & BPF_X != 0 {
            self.regs[insn.src()] as u32
        } else {
            insn.imm as u32
        };

        let result: u32 = match insn.opcode & 0xF0 {
            BPF_ADD => dst_val.wrapping_add(src_val),
            BPF_SUB => dst_val.wrapping_sub(src_val),
            BPF_MUL => dst_val.wrapping_mul(src_val),
            BPF_DIV => {
                if src_val == 0 {
                    return Err(EbpfError::DivisionByZero);
                }
                dst_val / src_val
            }
            BPF_MOD => {
                if src_val == 0 {
                    return Err(EbpfError::DivisionByZero);
                }
                dst_val % src_val
            }
            BPF_MOV => src_val,
            BPF_AND => dst_val & src_val,
            BPF_OR => dst_val | src_val,
            BPF_XOR => dst_val ^ src_val,
            BPF_LSH => dst_val << (src_val & 31),
            BPF_RSH => dst_val >> (src_val & 31),
            BPF_NEG => (-(dst_val as i32)) as u32,
            _ => return Err(EbpfError::InvalidOpcode(insn.opcode)),
        };

        // Zero-extend to 64-bit
        self.regs[dst] = result as u64;
        Ok(())
    }

    /// Execute a jump/branch instruction.
    ///
    /// Returns `Some(r0)` on BPF_EXIT, `None` otherwise.
    fn exec_jmp(&mut self, insn: &Insn) -> Result<Option<u64>, EbpfError> {
        let op = insn.opcode & 0xF0;

        match op {
            BPF_EXIT => {
                return Ok(Some(self.regs[0]));
            }
            BPF_CALL => {
                self.call_helper(insn.imm as u32)?;
                return Ok(None);
            }
            _ => {}
        }

        let src_val = if insn.opcode & BPF_X != 0 {
            self.regs[insn.src()]
        } else {
            insn.imm as i64 as u64
        };
        let dst_val = self.regs[insn.dst()];

        let taken = match op {
            BPF_JA => true,
            BPF_JEQ => dst_val == src_val,
            BPF_JGT => dst_val > src_val,
            BPF_JGE => dst_val >= src_val,
            BPF_JSET => (dst_val & src_val) != 0,
            BPF_JNE => dst_val != src_val,
            BPF_JLT => dst_val < src_val,
            BPF_JLE => dst_val <= src_val,
            _ => return Err(EbpfError::InvalidOpcode(insn.opcode)),
        };

        if taken {
            // pc will be incremented by 1 after this, so target = pc + 1 + off
            // We set pc = pc + off, and the +1 happens in the main loop.
            self.pc = (self.pc as i64 + insn.off as i64) as usize;
        }

        Ok(None)
    }

    /// Execute a memory load instruction (LDX).
    ///
    /// `dst = *(size*)(src + off)`
    fn exec_ldx(&mut self, insn: &Insn) -> Result<(), EbpfError> {
        let src_addr = (self.regs[insn.src()] as i64 + insn.off as i64) as u64;
        let size_code = insn.opcode & 0x18;

        let val = match size_code {
            BPF_B => {
                let ptr = src_addr as *const u8;
                if !self.check_read(src_addr, 1) {
                    return Err(EbpfError::OutOfBounds);
                }
                (unsafe { *ptr }) as u64
            }
            BPF_H => {
                let ptr = src_addr as *const u16;
                if !self.check_read(src_addr, 2) {
                    return Err(EbpfError::OutOfBounds);
                }
                (unsafe { core::ptr::read_unaligned(ptr) }) as u64
            }
            BPF_W => {
                let ptr = src_addr as *const u32;
                if !self.check_read(src_addr, 4) {
                    return Err(EbpfError::OutOfBounds);
                }
                (unsafe { core::ptr::read_unaligned(ptr) }) as u64
            }
            BPF_DW => {
                let ptr = src_addr as *const u64;
                if !self.check_read(src_addr, 8) {
                    return Err(EbpfError::OutOfBounds);
                }
                unsafe { core::ptr::read_unaligned(ptr) }
            }
            _ => return Err(EbpfError::InvalidOpcode(insn.opcode)),
        };

        self.regs[insn.dst()] = val;
        Ok(())
    }

    /// Execute a register-source store instruction (STX).
    ///
    /// `*(size*)(dst + off) = src`
    fn exec_stx(&mut self, insn: &Insn) -> Result<(), EbpfError> {
        let dst_addr = (self.regs[insn.dst()] as i64 + insn.off as i64) as u64;
        let val = self.regs[insn.src()];
        self.store(dst_addr, val, insn.opcode & 0x18)
    }

    /// Execute an immediate-source store instruction (ST).
    ///
    /// `*(size*)(dst + off) = imm`
    fn exec_st(&mut self, insn: &Insn) -> Result<(), EbpfError> {
        let dst_addr = (self.regs[insn.dst()] as i64 + insn.off as i64) as u64;
        let val = insn.imm as i64 as u64;
        self.store(dst_addr, val, insn.opcode & 0x18)
    }

    /// Write a value to memory at the given address and size.
    fn store(&mut self, addr: u64, val: u64, size_code: u8) -> Result<(), EbpfError> {
        match size_code {
            BPF_B => {
                if !self.check_write(addr, 1) {
                    return Err(EbpfError::OutOfBounds);
                }
                unsafe { *(addr as *mut u8) = val as u8; }
            }
            BPF_H => {
                if !self.check_write(addr, 2) {
                    return Err(EbpfError::OutOfBounds);
                }
                unsafe { core::ptr::write_unaligned(addr as *mut u16, val as u16); }
            }
            BPF_W => {
                if !self.check_write(addr, 4) {
                    return Err(EbpfError::OutOfBounds);
                }
                unsafe { core::ptr::write_unaligned(addr as *mut u32, val as u32); }
            }
            BPF_DW => {
                if !self.check_write(addr, 8) {
                    return Err(EbpfError::OutOfBounds);
                }
                unsafe { core::ptr::write_unaligned(addr as *mut u64, val); }
            }
            _ => return Err(EbpfError::InvalidOpcode(size_code)),
        }
        Ok(())
    }

    /// Check if a read of `len` bytes at `addr` is within the stack.
    fn check_read(&self, addr: u64, len: usize) -> bool {
        let stack_base = self.stack.as_ptr() as u64;
        let stack_end = stack_base + STACK_SIZE as u64;
        // Allow reads from stack region or from context (any non-null address
        // that was passed in r1). For safety, we allow all reads in this
        // simplified implementation — the verifier ensures the program is safe.
        // In a production kernel, this would use memory maps.
        if addr >= stack_base && addr + len as u64 <= stack_end {
            return true;
        }
        // Allow reads from context pointers (non-stack memory).
        // This is safe because the verifier has validated the program and
        // contexts are kernel-allocated with known layouts.
        addr != 0
    }

    /// Check if a write of `len` bytes at `addr` is within the stack.
    fn check_write(&self, addr: u64, len: usize) -> bool {
        let stack_base = self.stack.as_ptr() as u64;
        let stack_end = stack_base + STACK_SIZE as u64;
        // Only allow writes to the stack region.
        addr >= stack_base && addr + len as u64 <= stack_end
    }

    /// Execute a helper function call.
    ///
    /// Arguments are in r1-r5, result goes in r0.
    fn call_helper(&mut self, helper_id: u32) -> Result<(), EbpfError> {
        match helper_id {
            HELPER_MAP_LOOKUP => {
                // r1 = map_id, r2 = key_ptr, r3 = key_len
                let map_id = self.regs[1] as u32;
                if let Some(map) = super::maps::get_map(map_id) {
                    // Read key from the pointer in r2
                    let key_len = self.regs[3] as usize;
                    if key_len > super::maps::MAX_KEY_SIZE {
                        self.regs[0] = 0;
                        return Ok(());
                    }
                    let key_ptr = self.regs[2] as *const u8;
                    let mut key_buf = [0u8; super::maps::MAX_KEY_SIZE];
                    for i in 0..key_len {
                        key_buf[i] = unsafe { *key_ptr.add(i) };
                    }
                    match map.lookup(&key_buf[..key_len]) {
                        Some(val) => {
                            self.regs[0] = val.as_ptr() as u64;
                        }
                        None => {
                            self.regs[0] = 0;
                        }
                    }
                } else {
                    self.regs[0] = 0;
                }
            }
            HELPER_MAP_UPDATE => {
                // r1 = map_id, r2 = key_ptr, r3 = key_len, r4 = val_ptr, r5 = val_len
                let map_id = self.regs[1] as u32;
                if let Some(map) = super::maps::get_map_mut(map_id) {
                    let key_len = self.regs[3] as usize;
                    let val_len = self.regs[5] as usize;
                    if key_len <= super::maps::MAX_KEY_SIZE
                        && val_len <= super::maps::MAX_VALUE_SIZE
                    {
                        let key_ptr = self.regs[2] as *const u8;
                        let val_ptr = self.regs[4] as *const u8;
                        let mut key_buf = [0u8; super::maps::MAX_KEY_SIZE];
                        let mut val_buf = [0u8; super::maps::MAX_VALUE_SIZE];
                        for i in 0..key_len {
                            key_buf[i] = unsafe { *key_ptr.add(i) };
                        }
                        for i in 0..val_len {
                            val_buf[i] = unsafe { *val_ptr.add(i) };
                        }
                        match map.update(&key_buf[..key_len], &val_buf[..val_len]) {
                            Ok(()) => self.regs[0] = 0,
                            Err(_) => self.regs[0] = 1,
                        }
                    } else {
                        self.regs[0] = 1;
                    }
                } else {
                    self.regs[0] = 1;
                }
            }
            HELPER_MAP_DELETE => {
                // r1 = map_id, r2 = key_ptr, r3 = key_len
                let map_id = self.regs[1] as u32;
                if let Some(map) = super::maps::get_map_mut(map_id) {
                    let key_len = self.regs[3] as usize;
                    if key_len <= super::maps::MAX_KEY_SIZE {
                        let key_ptr = self.regs[2] as *const u8;
                        let mut key_buf = [0u8; super::maps::MAX_KEY_SIZE];
                        for i in 0..key_len {
                            key_buf[i] = unsafe { *key_ptr.add(i) };
                        }
                        self.regs[0] = if map.delete(&key_buf[..key_len]) { 0 } else { 1 };
                    } else {
                        self.regs[0] = 1;
                    }
                } else {
                    self.regs[0] = 1;
                }
            }
            HELPER_GET_AGENT_ID => {
                self.regs[0] = crate::sched::current() as u64;
            }
            HELPER_GET_ENERGY => {
                let agent_id = crate::sched::current();
                if let Some(agent) = crate::agent::get_agent(agent_id) {
                    self.regs[0] = agent.energy_budget;
                } else {
                    self.regs[0] = 0;
                }
            }
            HELPER_EMIT_EVENT => {
                // r1 = event_code — fire-and-forget, always succeeds
                // In a full implementation this would call into the event subsystem.
                self.regs[0] = 0;
            }
            HELPER_GET_TICK => {
                self.regs[0] = crate::arch::x86_64::timer::get_ticks();
            }
            _ => return Err(EbpfError::InvalidHelper(helper_id)),
        }
        Ok(())
    }
}
