//! Unit tests for the WASM decoder: LEB128, minimal module, section parsing, UTF-8.

extern crate wasm_spec_test;
use wasm_spec_test::wasm::decode::*;

// ─── LEB128 unsigned 32-bit ─────────────────────────────────────────────────

#[test]
fn leb128_u32_zero() {
    let bytes = [0x00];
    let mut pos = 0;
    assert_eq!(decode_leb128_u32(&bytes, &mut pos).unwrap(), 0);
    assert_eq!(pos, 1);
}

#[test]
fn leb128_u32_one_byte_max() {
    let bytes = [0x7F];
    let mut pos = 0;
    assert_eq!(decode_leb128_u32(&bytes, &mut pos).unwrap(), 127);
}

#[test]
fn leb128_u32_two_bytes() {
    let bytes = [0x80, 0x01];
    let mut pos = 0;
    assert_eq!(decode_leb128_u32(&bytes, &mut pos).unwrap(), 128);
    assert_eq!(pos, 2);
}

#[test]
fn leb128_u32_max_value() {
    let bytes = [0xFF, 0xFF, 0xFF, 0xFF, 0x0F];
    let mut pos = 0;
    assert_eq!(decode_leb128_u32(&bytes, &mut pos).unwrap(), u32::MAX);
    assert_eq!(pos, 5);
}

#[test]
fn leb128_u32_overflow_rejected() {
    let bytes = [0xFF, 0xFF, 0xFF, 0xFF, 0x1F];
    let mut pos = 0;
    assert!(decode_leb128_u32(&bytes, &mut pos).is_err());
}

#[test]
fn leb128_u32_too_many_bytes() {
    let bytes = [0x80, 0x80, 0x80, 0x80, 0x80, 0x00];
    let mut pos = 0;
    assert!(decode_leb128_u32(&bytes, &mut pos).is_err());
}

#[test]
fn leb128_u32_empty_input() {
    let bytes: [u8; 0] = [];
    let mut pos = 0;
    assert!(decode_leb128_u32(&bytes, &mut pos).is_err());
}

#[test]
fn leb128_u32_truncated_multibyte() {
    let bytes = [0x80];
    let mut pos = 0;
    assert!(decode_leb128_u32(&bytes, &mut pos).is_err());
}

// ─── LEB128 signed 32-bit ──────────────────────────────────────────────────

#[test]
fn leb128_i32_zero() {
    let bytes = [0x00];
    let mut pos = 0;
    assert_eq!(decode_leb128_i32(&bytes, &mut pos).unwrap(), 0);
}

#[test]
fn leb128_i32_minus_one() {
    let bytes = [0x7F];
    let mut pos = 0;
    assert_eq!(decode_leb128_i32(&bytes, &mut pos).unwrap(), -1);
}

#[test]
fn leb128_i32_min_value() {
    let bytes = [0x80, 0x80, 0x80, 0x80, 0x78];
    let mut pos = 0;
    assert_eq!(decode_leb128_i32(&bytes, &mut pos).unwrap(), i32::MIN);
}

#[test]
fn leb128_i32_max_value() {
    let bytes = [0xFF, 0xFF, 0xFF, 0xFF, 0x07];
    let mut pos = 0;
    assert_eq!(decode_leb128_i32(&bytes, &mut pos).unwrap(), i32::MAX);
}

#[test]
fn leb128_i32_positive_overflow_rejected() {
    let bytes = [0xFF, 0xFF, 0xFF, 0xFF, 0x17];
    let mut pos = 0;
    assert!(decode_leb128_i32(&bytes, &mut pos).is_err());
}

#[test]
fn leb128_i32_negative_overflow_rejected() {
    let bytes = [0x80, 0x80, 0x80, 0x80, 0x68];
    let mut pos = 0;
    assert!(decode_leb128_i32(&bytes, &mut pos).is_err());
}

// ─── LEB128 signed 64-bit ──────────────────────────────────────────────────

#[test]
fn leb128_i64_zero() {
    let bytes = [0x00];
    let mut pos = 0;
    assert_eq!(decode_leb128_i64(&bytes, &mut pos).unwrap(), 0i64);
}

#[test]
fn leb128_i64_minus_one() {
    let bytes = [0x7F];
    let mut pos = 0;
    assert_eq!(decode_leb128_i64(&bytes, &mut pos).unwrap(), -1i64);
}

#[test]
fn leb128_i64_max_value() {
    let bytes = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];
    let mut pos = 0;
    assert_eq!(decode_leb128_i64(&bytes, &mut pos).unwrap(), i64::MAX);
}

#[test]
fn leb128_i64_min_value() {
    let bytes = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F];
    let mut pos = 0;
    assert_eq!(decode_leb128_i64(&bytes, &mut pos).unwrap(), i64::MIN);
}

// ─── LEB128 unsigned 64-bit ────────────────────────────────────────────────

#[test]
fn leb128_u64_max_value() {
    let bytes = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
    let mut pos = 0;
    assert_eq!(decode_leb128_u64(&bytes, &mut pos).unwrap(), u64::MAX);
}

#[test]
fn leb128_u64_overflow_rejected() {
    let bytes = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02];
    let mut pos = 0;
    assert!(decode_leb128_u64(&bytes, &mut pos).is_err());
}

// ─── Minimal valid module ───────────────────────────────────────────────────

#[test]
fn decode_minimal_module() {
    let bytes = b"\x00asm\x01\x00\x00\x00";
    let module = decode(bytes).expect("minimal module should decode");
    assert_eq!(module.func_types.len(), 0);
    assert_eq!(module.imports.len(), 0);
    assert_eq!(module.exports.len(), 0);
}

#[test]
fn decode_rejects_empty_input() {
    assert!(decode(&[]).is_err());
}

#[test]
fn decode_rejects_truncated_magic() {
    assert!(decode(b"\x00as").is_err());
}

#[test]
fn decode_rejects_wrong_magic() {
    assert!(decode(b"\x01asm\x01\x00\x00\x00").is_err());
}

#[test]
fn decode_rejects_wrong_version() {
    assert!(decode(b"\x00asm\x02\x00\x00\x00").is_err());
}

// ─── Module with type section ───────────────────────────────────────────────

#[test]
fn decode_module_with_empty_type_section() {
    let bytes = b"\x00asm\x01\x00\x00\x00\x01\x01\x00";
    let module = decode(bytes).expect("module with empty type section should decode");
    assert_eq!(module.func_types.len(), 0);
}

#[test]
fn decode_module_with_one_func_type() {
    // Type section: 1 func type () -> ()
    let bytes = b"\x00asm\x01\x00\x00\x00\x01\x04\x01\x60\x00\x00";
    let module = decode(bytes).expect("should decode");
    assert_eq!(module.func_types.len(), 1);
    assert_eq!(module.func_types[0].param_count, 0);
    assert_eq!(module.func_types[0].result_count, 0);
}

// ─── Module with memory section ─────────────────────────────────────────────

#[test]
fn decode_module_with_memory() {
    let bytes = b"\x00asm\x01\x00\x00\x00\x05\x03\x01\x00\x01";
    let module = decode(bytes).expect("should decode");
    assert!(module.has_memory);
    assert_eq!(module.memory_min_pages, 1);
}

// ─── Module with export section ─────────────────────────────────────────────

#[test]
fn decode_module_with_export() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"\x00asm\x01\x00\x00\x00");
    bytes.extend_from_slice(b"\x01\x04\x01\x60\x00\x00"); // type section
    bytes.extend_from_slice(b"\x03\x02\x01\x00");         // function section
    bytes.extend_from_slice(b"\x07\x05\x01\x01f\x00\x00"); // export "f" -> func 0
    bytes.extend_from_slice(b"\x0a\x04\x01\x02\x00\x0b"); // code section
    let module = decode(&bytes).expect("should decode");
    assert_eq!(module.exports.len(), 1);
}

// ─── Invalid section ordering ───────────────────────────────────────────────

#[test]
fn decode_rejects_duplicate_type_section() {
    let bytes = b"\x00asm\x01\x00\x00\x00\x01\x01\x00\x01\x01\x00";
    assert!(decode(bytes).is_err());
}

#[test]
fn decode_rejects_out_of_order_sections() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"\x00asm\x01\x00\x00\x00");
    bytes.extend_from_slice(b"\x07\x01\x00"); // export section
    bytes.extend_from_slice(b"\x03\x01\x00"); // function section (should come before export)
    assert!(decode(&bytes).is_err());
}

// ─── UTF-8 validation ───────────────────────────────────────────────────────

#[test]
fn decode_rejects_invalid_utf8_export_name() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"\x00asm\x01\x00\x00\x00");
    bytes.extend_from_slice(b"\x01\x04\x01\x60\x00\x00"); // type section
    bytes.extend_from_slice(b"\x03\x02\x01\x00");         // function section
    bytes.extend_from_slice(b"\x07\x05\x01\x01\xff\x00\x00"); // export with 0xFF name
    bytes.extend_from_slice(b"\x0a\x04\x01\x02\x00\x0b"); // code section
    assert!(decode(&bytes).is_err(), "invalid UTF-8 in export name should be rejected");
}

#[test]
fn decode_rejects_invalid_utf8_import_module() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"\x00asm\x01\x00\x00\x00");
    bytes.extend_from_slice(b"\x01\x04\x01\x60\x00\x00"); // type section
    bytes.extend_from_slice(b"\x02\x07\x01\x01\xff\x01f\x00\x00"); // import with 0xFF module name
    assert!(decode(&bytes).is_err(), "invalid UTF-8 in import module name should be rejected");
}

// ─── Unknown section ID ─────────────────────────────────────────────────────

#[test]
fn decode_rejects_unknown_section_id() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"\x00asm\x01\x00\x00\x00");
    bytes.push(14); // unknown section id
    bytes.push(0);  // section length 0
    assert!(decode(&bytes).is_err());
}

// ─── Custom section is allowed anywhere ─────────────────────────────────────

#[test]
fn decode_accepts_custom_section() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"\x00asm\x01\x00\x00\x00");
    bytes.extend_from_slice(b"\x00\x05\x04test");
    let module = decode(&bytes).expect("custom section should be accepted");
    assert_eq!(module.functions.len(), 0);
}
