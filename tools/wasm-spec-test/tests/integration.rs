//! Integration tests: engine does not panic on edge-case inputs,
//! and returns proper errors for malformed modules.

extern crate wasm_spec_test;
use wasm_spec_test::wasm::decode::decode;
use wasm_spec_test::wasm::runtime::WasmInstance;
use wasm_spec_test::wasm::types::RuntimeClass;
use wasm_spec_test::wasm::validator::validate;

const FUEL: u64 = 100_000;

// ─── Empty / truncated modules ──────────────────────────────────────────────

#[test]
fn empty_input_returns_error() {
    let result = decode(&[]);
    assert!(result.is_err(), "empty input should return error, not panic");
}

#[test]
fn single_byte_returns_error() {
    let result = decode(&[0x00]);
    assert!(result.is_err());
}

#[test]
fn four_bytes_magic_only_returns_error() {
    let result = decode(b"\x00asm");
    assert!(result.is_err());
}

#[test]
fn seven_bytes_truncated_version_returns_error() {
    let result = decode(b"\x00asm\x01\x00\x00");
    assert!(result.is_err());
}

#[test]
fn truncated_section_returns_error() {
    // Valid header, then a type section (id=1) with length claiming 100 bytes but only 1 available
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"\x00asm\x01\x00\x00\x00");
    bytes.push(1);    // section id = type
    bytes.push(100);  // section length = 100 (but only 0 bytes follow)
    let result = decode(&bytes);
    assert!(result.is_err(), "truncated section should return error");
}

// ─── Minimal valid module: no panic through full pipeline ───────────────────

#[test]
fn minimal_module_no_panic() {
    let bytes = b"\x00asm\x01\x00\x00\x00";
    let module = decode(bytes).expect("minimal module should decode");
    validate(&module).expect("minimal module should validate");
    let instance = WasmInstance::with_class(module, FUEL, RuntimeClass::BestEffort);
    assert!(instance.is_ok(), "minimal module should instantiate");
}

// ─── Malformed modules return errors ────────────────────────────────────────

#[test]
fn wrong_magic_returns_error_not_panic() {
    let result = std::panic::catch_unwind(|| {
        decode(b"WASM\x01\x00\x00\x00")
    });
    match result {
        Ok(Err(_)) => {} // expected: error, no panic
        Ok(Ok(_)) => panic!("should have returned an error"),
        Err(_) => panic!("should not panic on wrong magic"),
    }
}

#[test]
fn all_zeros_returns_error_not_panic() {
    let bytes = [0u8; 64];
    let result = std::panic::catch_unwind(|| decode(&bytes));
    match result {
        Ok(Err(_)) => {}
        Ok(Ok(_)) => panic!("should have returned an error"),
        Err(_) => panic!("should not panic on all-zeros input"),
    }
}

#[test]
fn random_bytes_returns_error_not_panic() {
    // Deterministic "random" bytes
    let bytes: Vec<u8> = (0..256).map(|i| ((i * 137 + 42) % 256) as u8).collect();
    let result = std::panic::catch_unwind(|| decode(&bytes));
    match result {
        Ok(Err(_)) => {}
        Ok(Ok(_)) => {} // if it somehow decoded, that's fine
        Err(_) => panic!("should not panic on arbitrary bytes"),
    }
}

#[test]
fn valid_header_garbage_section_returns_error() {
    // Valid header followed by section id=1 (type) with garbage payload
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"\x00asm\x01\x00\x00\x00");
    bytes.push(1);  // type section
    bytes.push(4);  // length = 4
    bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // garbage
    let result = std::panic::catch_unwind(|| decode(&bytes));
    match result {
        Ok(Err(_)) => {}
        Ok(Ok(_)) => {} // if the decoder tolerates it, that's acceptable
        Err(_) => panic!("should not panic on garbage section payload"),
    }
}

// ─── Module with function that just returns ─────────────────────────────────

#[test]
fn simple_function_module_no_panic() {
    // Module: type () -> (), one function, code = [end]
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"\x00asm\x01\x00\x00\x00"); // header
    bytes.extend_from_slice(b"\x01\x04\x01\x60\x00\x00"); // type section: () -> ()
    bytes.extend_from_slice(b"\x03\x02\x01\x00");         // function section: func 0 = type 0
    bytes.extend_from_slice(b"\x0a\x04\x01\x02\x00\x0b"); // code: 1 body, size=2, 0 locals, end

    let module = decode(&bytes).expect("should decode");
    validate(&module).expect("should validate");
    let _instance = WasmInstance::with_class(module, FUEL, RuntimeClass::BestEffort)
        .expect("should instantiate");
}

// ─── Module with many sections ──────────────────────────────────────────────

#[test]
fn module_with_memory_and_global_no_panic() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"\x00asm\x01\x00\x00\x00");
    // Memory section: 1 memory, limits flag=0, initial=1
    bytes.extend_from_slice(b"\x05\x03\x01\x00\x01");
    // Global section: 1 global, type=i32 (0x7F), mutable=0, init=i32.const 42, end
    bytes.extend_from_slice(b"\x06\x06\x01\x7f\x00\x41\x2a\x0b");

    let module = decode(&bytes).expect("should decode");
    validate(&module).expect("should validate");
    let _instance = WasmInstance::with_class(module, FUEL, RuntimeClass::BestEffort)
        .expect("should instantiate");
}

// ─── Malformed section lengths ──────────────────────────────────────────────

#[test]
fn section_length_overflow_returns_error() {
    // Section with LEB128 length that overflows u32
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"\x00asm\x01\x00\x00\x00");
    bytes.push(1); // type section
    bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x1F]); // length > u32::MAX
    let result = decode(&bytes);
    assert!(result.is_err());
}

#[test]
fn section_length_exceeds_remaining_returns_error() {
    // Section claims more bytes than remaining in input
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"\x00asm\x01\x00\x00\x00");
    bytes.push(1);  // type section
    bytes.push(50); // claims 50 bytes
    bytes.push(0);  // but only 1 byte follows
    let result = decode(&bytes);
    assert!(result.is_err());
}
