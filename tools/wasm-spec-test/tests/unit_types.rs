//! Unit tests for wasm types: Value::default_for, V128 lane operations.

extern crate wasm_spec_test;
use wasm_spec_test::wasm::types::*;

// ─── Value::default_for ─────────────────────────────────────────────────────

#[test]
fn default_i32_is_zero() {
    match Value::default_for(ValType::I32) {
        Value::I32(0) => {}
        other => panic!("expected I32(0), got {:?}", other),
    }
}

#[test]
fn default_i64_is_zero() {
    match Value::default_for(ValType::I64) {
        Value::I64(0) => {}
        other => panic!("expected I64(0), got {:?}", other),
    }
}

#[test]
fn default_f32_is_zero() {
    match Value::default_for(ValType::F32) {
        Value::F32(v) if v == 0.0 && !v.is_sign_negative() => {}
        other => panic!("expected F32(0.0), got {:?}", other),
    }
}

#[test]
fn default_f64_is_zero() {
    match Value::default_for(ValType::F64) {
        Value::F64(v) if v == 0.0 && !v.is_sign_negative() => {}
        other => panic!("expected F64(0.0), got {:?}", other),
    }
}

#[test]
fn default_v128_is_zero() {
    match Value::default_for(ValType::V128) {
        Value::V128(v) => assert_eq!(v.to_u128(), 0),
        other => panic!("expected V128(ZERO), got {:?}", other),
    }
}

#[test]
fn default_funcref_is_null() {
    match Value::default_for(ValType::FuncRef) {
        Value::NullRef => {}
        other => panic!("expected NullRef, got {:?}", other),
    }
}

#[test]
fn default_externref_is_null() {
    match Value::default_for(ValType::ExternRef) {
        Value::NullRef => {}
        other => panic!("expected NullRef, got {:?}", other),
    }
}

#[test]
fn default_all_ref_types_are_null() {
    let ref_types = [
        ValType::TypedFuncRef,
        ValType::NullableTypedFuncRef,
        ValType::NonNullableFuncRef,
        ValType::AnyRef,
        ValType::NullableAnyRef,
        ValType::EqRef,
        ValType::NullableEqRef,
        ValType::I31Ref,
        ValType::StructRef,
        ValType::NullableStructRef,
        ValType::ArrayRef,
        ValType::NullableArrayRef,
        ValType::NoneRef,
        ValType::NullFuncRef,
        ValType::NullExternRef,
        ValType::ExnRef,
    ];
    for ty in ref_types {
        match Value::default_for(ty) {
            Value::NullRef => {}
            other => panic!("expected NullRef for {:?}, got {:?}", ty, other),
        }
    }
}

// ─── V128 lane operations ───────────────────────────────────────────────────

#[test]
fn v128_i8x16_roundtrip() {
    let input: [i8; 16] = [-128, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 127];
    let v = V128::from_i8x16(input);
    assert_eq!(v.as_i8x16(), input);
}

#[test]
fn v128_u8x16_roundtrip() {
    let input: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 255];
    let v = V128::from_u8x16(input);
    assert_eq!(v.as_u8x16(), input);
}

#[test]
fn v128_i16x8_roundtrip() {
    let input: [i16; 8] = [-32768, -1, 0, 1, 256, 1000, -1000, 32767];
    let v = V128::from_i16x8(input);
    assert_eq!(v.as_i16x8(), input);
}

#[test]
fn v128_i32x4_roundtrip() {
    let input: [i32; 4] = [i32::MIN, -1, 0, i32::MAX];
    let v = V128::from_i32x4(input);
    assert_eq!(v.as_i32x4(), input);
}

#[test]
fn v128_u32x4_roundtrip() {
    let input: [u32; 4] = [0, 1, u32::MAX / 2, u32::MAX];
    let v = V128::from_u32x4(input);
    assert_eq!(v.as_u32x4(), input);
}

#[test]
fn v128_i64x2_roundtrip() {
    let input: [i64; 2] = [i64::MIN, i64::MAX];
    let v = V128::from_i64x2(input);
    assert_eq!(v.as_i64x2(), input);
}

#[test]
fn v128_f32x4_roundtrip() {
    let input: [f32; 4] = [0.0, -1.5, f32::INFINITY, f32::NEG_INFINITY];
    let v = V128::from_f32x4(input);
    let output = v.as_f32x4();
    for i in 0..4 {
        assert_eq!(input[i].to_bits(), output[i].to_bits(), "lane {i}");
    }
}

#[test]
fn v128_f32x4_nan_preserved() {
    let nan = f32::NAN;
    let v = V128::from_f32x4([nan, nan, nan, nan]);
    let output = v.as_f32x4();
    for i in 0..4 {
        assert!(output[i].is_nan(), "lane {i} should be NaN");
    }
}

#[test]
fn v128_f64x2_roundtrip() {
    let input: [f64; 2] = [f64::NEG_INFINITY, 3.141592653589793];
    let v = V128::from_f64x2(input);
    let output = v.as_f64x2();
    for i in 0..2 {
        assert_eq!(input[i].to_bits(), output[i].to_bits(), "lane {i}");
    }
}

#[test]
fn v128_u128_roundtrip() {
    let value: u128 = 0xDEADBEEF_CAFEBABE_12345678_9ABCDEF0;
    let v = V128::from_u128(value);
    assert_eq!(v.to_u128(), value);
}

#[test]
fn v128_zero_constant() {
    assert_eq!(V128::ZERO.to_u128(), 0);
    assert_eq!(V128::ZERO.as_i8x16(), [0i8; 16]);
    assert_eq!(V128::ZERO.as_i32x4(), [0i32; 4]);
    assert_eq!(V128::ZERO.as_i64x2(), [0i64; 2]);
}
