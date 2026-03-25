//! Value types, V128 SIMD type, and runtime Value representation.

/// Value types supported by this interpreter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValType {
    I32,
    I64,
    F32,
    F64,
    V128,
    FuncRef,
    ExternRef,
    /// A typed, non-nullable function reference: (ref $t).
    /// This is distinct from FuncRef (which is (ref null func), i.e., general funcref).
    TypedFuncRef,
    /// A typed, nullable function reference: (ref null $t).
    /// This is distinct from FuncRef (which is funcref / (ref null func)).
    NullableTypedFuncRef,
    /// GC proposal: (ref any) / (ref null any) — abstract any type
    AnyRef,
    /// GC proposal: (ref eq) / (ref null eq) — abstract eq type
    EqRef,
    /// GC proposal: (ref i31) / (ref null i31) — i31 reference
    I31Ref,
    /// GC proposal: (ref struct) / (ref null struct) — abstract struct type
    StructRef,
    /// GC proposal: (ref null struct) — abstract nullable struct type
    NullableStructRef,
    /// GC proposal: (ref array) / (ref null array) — abstract array type
    ArrayRef,
    /// GC proposal: (ref null none) — bottom type for any hierarchy
    NoneRef,
    /// GC proposal: (ref null nofunc) — bottom type for func hierarchy
    NullFuncRef,
    /// GC proposal: (ref null noextern) — bottom type for extern hierarchy
    NullExternRef,
    /// Exception handling proposal: exnref (exception reference)
    ExnRef,
    /// Non-nullable abstract func reference: (ref func).
    /// Distinguished from TypedFuncRef which is (ref $t) for a concrete type.
    NonNullableFuncRef,
    /// GC proposal: (ref null any) — nullable
    NullableAnyRef,
    /// GC proposal: (ref null eq) — nullable
    NullableEqRef,
    /// GC proposal: (ref null array) — nullable
    NullableArrayRef,
}

/// A 128-bit SIMD value (v128), stored as little-endian byte array.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(16))]
pub struct V128(pub [u8; 16]);

impl V128 {
    pub const ZERO: V128 = V128([0u8; 16]);

    pub fn from_u128(v: u128) -> Self { V128(v.to_le_bytes()) }
    pub fn to_u128(self) -> u128 { u128::from_le_bytes(self.0) }

    /// Interpret as array of N lanes
    pub fn as_i8x16(self) -> [i8; 16] {
        let mut r = [0i8; 16];
        for i in 0..16 { r[i] = self.0[i] as i8; }
        r
    }
    pub fn as_u8x16(self) -> [u8; 16] { self.0 }
    pub fn as_i16x8(self) -> [i16; 8] {
        let mut r = [0i16; 8];
        for i in 0..8 { r[i] = i16::from_le_bytes([self.0[i*2], self.0[i*2+1]]); }
        r
    }
    pub fn as_u16x8(self) -> [u16; 8] {
        let mut r = [0u16; 8];
        for i in 0..8 { r[i] = u16::from_le_bytes([self.0[i*2], self.0[i*2+1]]); }
        r
    }
    pub fn as_i32x4(self) -> [i32; 4] {
        let mut r = [0i32; 4];
        for i in 0..4 { r[i] = i32::from_le_bytes([self.0[i*4], self.0[i*4+1], self.0[i*4+2], self.0[i*4+3]]); }
        r
    }
    pub fn as_u32x4(self) -> [u32; 4] {
        let mut r = [0u32; 4];
        for i in 0..4 { r[i] = u32::from_le_bytes([self.0[i*4], self.0[i*4+1], self.0[i*4+2], self.0[i*4+3]]); }
        r
    }
    pub fn as_i64x2(self) -> [i64; 2] {
        let mut r = [0i64; 2];
        for i in 0..2 {
            let mut b = [0u8; 8]; b.copy_from_slice(&self.0[i*8..i*8+8]);
            r[i] = i64::from_le_bytes(b);
        }
        r
    }
    pub fn as_u64x2(self) -> [u64; 2] {
        let mut r = [0u64; 2];
        for i in 0..2 {
            let mut b = [0u8; 8]; b.copy_from_slice(&self.0[i*8..i*8+8]);
            r[i] = u64::from_le_bytes(b);
        }
        r
    }
    pub fn as_f32x4(self) -> [f32; 4] {
        let mut r = [0.0f32; 4];
        for i in 0..4 { r[i] = f32::from_le_bytes([self.0[i*4], self.0[i*4+1], self.0[i*4+2], self.0[i*4+3]]); }
        r
    }
    pub fn as_f64x2(self) -> [f64; 2] {
        let mut r = [0.0f64; 2];
        for i in 0..2 {
            let mut b = [0u8; 8]; b.copy_from_slice(&self.0[i*8..i*8+8]);
            r[i] = f64::from_le_bytes(b);
        }
        r
    }

    pub fn from_i8x16(v: [i8; 16]) -> Self { let mut b = [0u8; 16]; for i in 0..16 { b[i] = v[i] as u8; } V128(b) }
    pub fn from_u8x16(v: [u8; 16]) -> Self { V128(v) }
    pub fn from_i16x8(v: [i16; 8]) -> Self { let mut b = [0u8; 16]; for i in 0..8 { let x = v[i].to_le_bytes(); b[i*2] = x[0]; b[i*2+1] = x[1]; } V128(b) }
    pub fn from_i32x4(v: [i32; 4]) -> Self { let mut b = [0u8; 16]; for i in 0..4 { let x = v[i].to_le_bytes(); b[i*4..i*4+4].copy_from_slice(&x); } V128(b) }
    pub fn from_u32x4(v: [u32; 4]) -> Self { let mut b = [0u8; 16]; for i in 0..4 { let x = v[i].to_le_bytes(); b[i*4..i*4+4].copy_from_slice(&x); } V128(b) }
    pub fn from_i64x2(v: [i64; 2]) -> Self { let mut b = [0u8; 16]; for i in 0..2 { let x = v[i].to_le_bytes(); b[i*8..i*8+8].copy_from_slice(&x); } V128(b) }
    pub fn from_f32x4(v: [f32; 4]) -> Self { let mut b = [0u8; 16]; for i in 0..4 { let x = v[i].to_le_bytes(); b[i*4..i*4+4].copy_from_slice(&x); } V128(b) }
    pub fn from_f64x2(v: [f64; 2]) -> Self { let mut b = [0u8; 16]; for i in 0..2 { let x = v[i].to_le_bytes(); b[i*8..i*8+8].copy_from_slice(&x); } V128(b) }
}

#[derive(Debug, Clone, Copy)]
pub enum Value {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    V128(V128),
    /// Null reference — used for ref.null of any heap type.
    NullRef,
    /// GC heap reference: index into WasmInstance::gc_heap.
    /// The heap_type field stores the abstract heap type code for type checking:
    /// -0x12=any, -0x16=eq, -0x19=i31, -0x17=struct, -0x18=array, -0x10=func, -0x11=extern
    /// or >= 0 for a concrete type index.
    GcRef(u32),
}

impl Value {
    /// Return zero/null for the given type.
    pub const fn default_for(ty: ValType) -> Self {
        match ty {
            ValType::I32 => Value::I32(0),
            ValType::I64 => Value::I64(0),
            ValType::F32 => Value::F32(0.0),
            ValType::F64 => Value::F64(0.0),
            ValType::V128 => Value::V128(V128::ZERO),
            ValType::FuncRef | ValType::ExternRef
            | ValType::TypedFuncRef | ValType::NullableTypedFuncRef
            | ValType::NonNullableFuncRef
            | ValType::AnyRef | ValType::NullableAnyRef
            | ValType::EqRef | ValType::NullableEqRef
            | ValType::I31Ref
            | ValType::StructRef | ValType::NullableStructRef
            | ValType::ArrayRef | ValType::NullableArrayRef
            | ValType::NoneRef
            | ValType::NullFuncRef | ValType::NullExternRef
            | ValType::ExnRef => Value::NullRef,
        }
    }

    pub fn as_i32(self) -> i32 {
        match self {
            Value::I32(v) => v,
            Value::I64(v) => v as i32,
            Value::F32(v) => v as i32,
            Value::F64(v) => v as i32,
            Value::V128(_) => 0,
            Value::NullRef => -1,
            Value::GcRef(idx) => idx as i32,
        }
    }

    pub fn as_i64(self) -> i64 {
        match self {
            Value::I32(v) => v as i64,
            Value::I64(v) => v,
            Value::F32(v) => v as i64,
            Value::F64(v) => v as i64,
            Value::V128(_) => 0,
            Value::NullRef => -1,
            Value::GcRef(idx) => idx as i64,
        }
    }

    pub fn as_f32(self) -> f32 {
        match self {
            Value::I32(v) => v as f32,
            Value::I64(v) => v as f32,
            Value::F32(v) => v,
            Value::F64(v) => v as f32,
            Value::V128(_) => 0.0,
            Value::NullRef => 0.0,
            Value::GcRef(_) => 0.0,
        }
    }

    pub fn as_f64(self) -> f64 {
        match self {
            Value::I32(v) => v as f64,
            Value::I64(v) => v as f64,
            Value::F32(v) => v as f64,
            Value::F64(v) => v,
            Value::V128(_) => 0.0,
            Value::NullRef => 0.0,
            Value::GcRef(_) => 0.0,
        }
    }

    pub fn as_v128(self) -> V128 {
        match self {
            Value::V128(v) => v,
            _ => V128::ZERO,
        }
    }
}
