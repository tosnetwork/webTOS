//! Float and V128 helper methods for WasmInstance.
//! Float NaN handling, wasm ceil/floor/trunc/nearest/sqrt, min/max,
//! and V128 SIMD memory/pop/read helpers.

use super::*;

impl WasmInstance {
    // ─── Float helpers ────────────────────────────────────────────────

    pub(crate) fn pop_f32(&mut self) -> Result<f32, WasmError> {
        Ok(self.pop()?.as_f32())
    }

    pub(crate) fn pop_f64(&mut self) -> Result<f64, WasmError> {
        Ok(self.pop()?.as_f64())
    }

    pub(crate) fn read_f32(&mut self) -> Result<f32, WasmError> {
        if self.pc.checked_add(4).ok_or(WasmError::UnexpectedEnd)? > self.module.code.len() {
            return Err(WasmError::UnexpectedEnd);
        }
        let bytes = [
            self.module.code[self.pc], self.module.code[self.pc + 1],
            self.module.code[self.pc + 2], self.module.code[self.pc + 3],
        ];
        self.pc += 4;
        Ok(f32::from_le_bytes(bytes))
    }

    pub(crate) fn read_f64(&mut self) -> Result<f64, WasmError> {
        if self.pc.checked_add(8).ok_or(WasmError::UnexpectedEnd)? > self.module.code.len() {
            return Err(WasmError::UnexpectedEnd);
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.module.code[self.pc..self.pc + 8]);
        self.pc += 8;
        Ok(f64::from_le_bytes(bytes))
    }

    pub(crate) fn mem_load_f32(&self, mem_idx: usize, addr: usize) -> Result<f32, WasmError> {
        if addr.checked_add(4).ok_or(WasmError::MemoryOutOfBounds)? > self.mem_size(mem_idx) {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let m = self.mem(mem_idx);
        Ok(f32::from_le_bytes([m[addr], m[addr + 1], m[addr + 2], m[addr + 3]]))
    }

    pub(crate) fn mem_load_f64(&self, mem_idx: usize, addr: usize) -> Result<f64, WasmError> {
        if addr.checked_add(8).ok_or(WasmError::MemoryOutOfBounds)? > self.mem_size(mem_idx) {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let m = self.mem(mem_idx);
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&m[addr..addr + 8]);
        Ok(f64::from_le_bytes(bytes))
    }

    pub(crate) fn mem_store_f32(&mut self, mem_idx: usize, addr: usize, val: f32) -> Result<(), WasmError> {
        if addr.checked_add(4).ok_or(WasmError::MemoryOutOfBounds)? > self.mem_size(mem_idx) {
            return Err(WasmError::MemoryOutOfBounds);
        }
        self.mem_mut(mem_idx)[addr..addr + 4].copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    pub(crate) fn mem_store_f64(&mut self, mem_idx: usize, addr: usize, val: f64) -> Result<(), WasmError> {
        if addr.checked_add(8).ok_or(WasmError::MemoryOutOfBounds)? > self.mem_size(mem_idx) {
            return Err(WasmError::MemoryOutOfBounds);
        }
        self.mem_mut(mem_idx)[addr..addr + 8].copy_from_slice(&val.to_le_bytes());
        Ok(())
    }

    // ─── Float NaN helpers (matching wasmi semantics) ──────────────────

    /// Convert signaling NaN to quiet NaN, preserving payload.
    /// WASM spec requires all NaN outputs to be quiet NaN.
    pub(crate) fn quiet_nan_f32(v: f32) -> f32 {
        if v.is_nan() {
            f32::from_bits(v.to_bits() | 0x0040_0000) // set quiet bit
        } else { v }
    }

    pub(crate) fn quiet_nan_f64(v: f64) -> f64 {
        if v.is_nan() {
            f64::from_bits(v.to_bits() | 0x0008_0000_0000_0000)
        } else { v }
    }

    /// WASM spec: f32.nearest rounds to nearest even.
    pub(crate) fn wasm_nearest_f32(v: f32) -> f32 {
        if v.is_nan() { return Self::quiet_nan_f32(v); }
        libm::rintf(v)
    }

    pub(crate) fn wasm_nearest_f64(v: f64) -> f64 {
        if v.is_nan() { return Self::quiet_nan_f64(v); }
        libm::rint(v)
    }

    /// Unary float ops: quiet NaN passthrough for ceil/floor/trunc/sqrt.
    pub(crate) fn wasm_ceil_f32(v: f32) -> f32 {
        if v.is_nan() { return Self::quiet_nan_f32(v); }
        libm::ceilf(v)
    }
    pub(crate) fn wasm_floor_f32(v: f32) -> f32 {
        if v.is_nan() { return Self::quiet_nan_f32(v); }
        libm::floorf(v)
    }
    pub(crate) fn wasm_trunc_f32(v: f32) -> f32 {
        if v.is_nan() { return Self::quiet_nan_f32(v); }
        libm::truncf(v)
    }
    pub(crate) fn wasm_sqrt_f32(v: f32) -> f32 {
        if v.is_nan() { return Self::quiet_nan_f32(v); }
        libm::sqrtf(v)
    }
    pub(crate) fn wasm_ceil_f64(v: f64) -> f64 {
        if v.is_nan() { return Self::quiet_nan_f64(v); }
        libm::ceil(v)
    }
    pub(crate) fn wasm_floor_f64(v: f64) -> f64 {
        if v.is_nan() { return Self::quiet_nan_f64(v); }
        libm::floor(v)
    }
    pub(crate) fn wasm_trunc_f64(v: f64) -> f64 {
        if v.is_nan() { return Self::quiet_nan_f64(v); }
        libm::trunc(v)
    }
    pub(crate) fn wasm_sqrt_f64(v: f64) -> f64 {
        if v.is_nan() { return Self::quiet_nan_f64(v); }
        libm::sqrt(v)
    }

    /// WASM spec min/max: propagate NaN with quieting (using lhs+rhs),
    /// handle -0.0/+0.0 sign correctly. Matches wasmi semantics.
    pub(crate) fn wasm_min_f32(a: f32, b: f32) -> f32 {
        if a < b { a }
        else if b < a { b }
        else if a == b {
            // Handle -0.0 vs +0.0: min(-0, +0) = -0
            if a.is_sign_negative() && b.is_sign_positive() { a } else { b }
        } else {
            // At least one is NaN — use + to propagate and quiet
            a + b
        }
    }
    pub(crate) fn wasm_max_f32(a: f32, b: f32) -> f32 {
        if a > b { a }
        else if b > a { b }
        else if a == b {
            if a.is_sign_positive() && b.is_sign_negative() { a } else { b }
        } else {
            a + b
        }
    }
    pub(crate) fn wasm_min_f64(a: f64, b: f64) -> f64 {
        if a < b { a }
        else if b < a { b }
        else if a == b {
            if a.is_sign_negative() && b.is_sign_positive() { a } else { b }
        } else {
            a + b
        }
    }
    pub(crate) fn wasm_max_f64(a: f64, b: f64) -> f64 {
        if a > b { a }
        else if b > a { b }
        else if a == b {
            if a.is_sign_positive() && b.is_sign_negative() { a } else { b }
        } else {
            a + b
        }
    }

    // ─── V128 / SIMD helpers ──────────────────────────────────────────

    pub(crate) fn pop_v128(&mut self) -> Result<V128, WasmError> {
        Ok(self.pop()?.as_v128())
    }

    pub(crate) fn read_v128(&mut self) -> Result<V128, WasmError> {
        if self.pc.checked_add(16).ok_or(WasmError::UnexpectedEnd)? > self.module.code.len() {
            return Err(WasmError::UnexpectedEnd);
        }
        let mut b = [0u8; 16];
        b.copy_from_slice(&self.module.code[self.pc..self.pc + 16]);
        self.pc += 16;
        Ok(V128(b))
    }

    pub(crate) fn mem_load_v128(&self, mem_idx: usize, addr: usize) -> Result<V128, WasmError> {
        if addr.checked_add(16).ok_or(WasmError::MemoryOutOfBounds)? > self.mem_size(mem_idx) {
            return Err(WasmError::MemoryOutOfBounds);
        }
        let m = self.mem(mem_idx);
        let mut b = [0u8; 16];
        b.copy_from_slice(&m[addr..addr + 16]);
        Ok(V128(b))
    }

    pub(crate) fn mem_store_v128(&mut self, mem_idx: usize, addr: usize, val: V128) -> Result<(), WasmError> {
        if addr.checked_add(16).ok_or(WasmError::MemoryOutOfBounds)? > self.mem_size(mem_idx) {
            return Err(WasmError::MemoryOutOfBounds);
        }
        self.mem_mut(mem_idx)[addr..addr + 16].copy_from_slice(&val.0);
        Ok(())
    }


}
