//! Tests for newtype index wrappers.

use wasbi::prelude::*;

#[test]
fn func_idx_basic() {
    let idx = FuncIdx::new(42);
    assert_eq!(idx.raw(), 42);
    assert_eq!(idx.as_usize(), 42);
    assert_eq!(u32::from(idx), 42);
}

#[test]
fn func_idx_from_u32() {
    let idx: FuncIdx = 10u32.into();
    assert_eq!(idx.raw(), 10);
}

#[test]
fn index_equality() {
    assert_eq!(FuncIdx::new(5), FuncIdx::new(5));
    assert_ne!(FuncIdx::new(5), FuncIdx::new(6));
}

#[test]
fn index_ordering() {
    assert!(FuncIdx::new(1) < FuncIdx::new(2));
    assert!(TypeIdx::new(10) > TypeIdx::new(5));
}

#[test]
fn different_index_types_are_distinct() {
    // This test documents that FuncIdx(5) and TypeIdx(5) are different types
    // and cannot be compared or confused at compile time.
    let _func = FuncIdx::new(5);
    let _type = TypeIdx::new(5);
    // If these were the same type, we'd get a compile error for
    // trait conflicts. They compile independently.
}

#[test]
fn index_zero() {
    assert_eq!(FuncIdx::new(0).as_usize(), 0);
    assert_eq!(GlobalIdx::new(0).raw(), 0);
}

#[test]
fn index_max() {
    let idx = FuncIdx::new(u32::MAX);
    assert_eq!(idx.raw(), u32::MAX);
}
