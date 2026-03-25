//! Saturating float-to-int conversions (0xFC 0x00-0x07).
//!
//! Matching wasmi semantics: NaN -> 0, +inf -> MAX, -inf -> MIN (or 0 for unsigned),
//! out-of-range -> saturate.

pub fn sat_trunc_f32_i32(v: f32) -> i32 {
    if v.is_nan() { return 0; }
    if v.is_infinite() { return if v.is_sign_positive() { i32::MAX } else { i32::MIN }; }
    if v >= 2147483648.0_f32 { return i32::MAX; }
    if v <= -2147483904.0_f32 { return i32::MIN; }
    v as i32
}
pub fn sat_trunc_f32_u32(v: f32) -> u32 {
    if v.is_nan() { return 0; }
    if v.is_infinite() { return if v.is_sign_positive() { u32::MAX } else { 0 }; }
    if v >= 4294967296.0_f32 { return u32::MAX; }
    if v <= -1.0_f32 { return 0; }
    v as u32
}
pub fn sat_trunc_f64_i32(v: f64) -> i32 {
    if v.is_nan() { return 0; }
    if v.is_infinite() { return if v.is_sign_positive() { i32::MAX } else { i32::MIN }; }
    if v >= 2147483648.0_f64 { return i32::MAX; }
    if v <= -2147483649.0_f64 { return i32::MIN; }
    v as i32
}
pub fn sat_trunc_f64_u32(v: f64) -> u32 {
    if v.is_nan() { return 0; }
    if v.is_infinite() { return if v.is_sign_positive() { u32::MAX } else { 0 }; }
    if v >= 4294967296.0_f64 { return u32::MAX; }
    if v <= -1.0_f64 { return 0; }
    v as u32
}
pub fn sat_trunc_f32_i64(v: f32) -> i64 {
    if v.is_nan() { return 0; }
    if v.is_infinite() { return if v.is_sign_positive() { i64::MAX } else { i64::MIN }; }
    if v >= 9223372036854775808.0_f32 { return i64::MAX; }
    if v <= -9223373136366403584.0_f32 { return i64::MIN; }
    v as i64
}
pub fn sat_trunc_f32_u64(v: f32) -> u64 {
    if v.is_nan() { return 0; }
    if v.is_infinite() { return if v.is_sign_positive() { u64::MAX } else { 0 }; }
    if v >= 18446744073709551616.0_f32 { return u64::MAX; }
    if v <= -1.0_f32 { return 0; }
    v as u64
}
pub fn sat_trunc_f64_i64(v: f64) -> i64 {
    if v.is_nan() { return 0; }
    if v.is_infinite() { return if v.is_sign_positive() { i64::MAX } else { i64::MIN }; }
    if v >= 9223372036854775808.0_f64 { return i64::MAX; }
    if v <= -9223372036854777856.0_f64 { return i64::MIN; }
    v as i64
}
pub fn sat_trunc_f64_u64(v: f64) -> u64 {
    if v.is_nan() { return 0; }
    if v.is_infinite() { return if v.is_sign_positive() { u64::MAX } else { 0 }; }
    if v >= 18446744073709551616.0_f64 { return u64::MAX; }
    if v <= -1.0_f64 { return 0; }
    v as u64
}
