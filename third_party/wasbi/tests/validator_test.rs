#![allow(clippy::vec_init_then_push)]
//! Validator rejection tests — modules that should fail validation.

use wasbi::decoder::decode;
use wasbi::prelude::*;
use wasbi::validator::validate;

const HEADER: &[u8] = &[0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];

/// Encode a u32 as LEB128 bytes.
fn leb128(val: u32) -> Vec<u8> {
    let mut v = val;
    let mut out = Vec::new();
    loop {
        let mut byte = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
    out
}

/// Build a module with one function.
fn module_with_typed_body(params: &[u8], results: &[u8], body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::from(HEADER);

    // Type section
    let mut type_payload = Vec::new();
    type_payload.push(0x01); // one type
    type_payload.push(0x60); // func
    type_payload.extend_from_slice(&leb128(params.len() as u32));
    type_payload.extend_from_slice(params);
    type_payload.extend_from_slice(&leb128(results.len() as u32));
    type_payload.extend_from_slice(results);
    buf.push(0x01); // type section id
    buf.extend_from_slice(&leb128(type_payload.len() as u32));
    buf.extend_from_slice(&type_payload);

    // Function section
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);

    // Code section
    let mut func_body = Vec::new();
    func_body.push(0x00); // 0 locals
    func_body.extend_from_slice(body);
    func_body.push(0x0B); // end

    let mut code_payload = Vec::new();
    code_payload.push(0x01); // one body
    code_payload.extend_from_slice(&leb128(func_body.len() as u32));
    code_payload.extend_from_slice(&func_body);

    buf.push(0x0A); // code section id
    buf.extend_from_slice(&leb128(code_payload.len() as u32));
    buf.extend_from_slice(&code_payload);

    buf
}

#[test]
fn validate_empty_module() {
    let module = decode(HEADER).unwrap();
    validate(&module).unwrap();
}

#[test]
fn validate_type_mismatch_return() {
    // Function () -> (i32) but body produces i64
    let wasm = module_with_typed_body(
        &[],
        &[0x7F],
        &[
            0x42, 0x00, // i64.const 0
        ],
    );
    let module = decode(&wasm).unwrap();
    let err = validate(&module).unwrap_err();
    assert!(err.is_validation_error());
}

#[test]
fn validate_stack_underflow() {
    // Function () -> (i32) but body does i32.add with empty stack
    let wasm = module_with_typed_body(
        &[],
        &[0x7F],
        &[
            0x6A, // i32.add (needs 2 operands, has 0)
        ],
    );
    let module = decode(&wasm).unwrap();
    assert!(validate(&module).is_err());
}

#[test]
fn validate_duplicate_export() {
    let mut buf = Vec::from(HEADER);
    // Type section: () -> ()
    buf.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
    // Function section: 2 functions
    buf.extend_from_slice(&[0x03, 0x03, 0x02, 0x00, 0x00]);
    // Export section: both named "f"
    let mut export_payload = Vec::new();
    export_payload.push(0x02); // two exports
    export_payload.push(0x01);
    export_payload.push(b'f');
    export_payload.push(0x00);
    export_payload.push(0x00);
    export_payload.push(0x01);
    export_payload.push(b'f');
    export_payload.push(0x00);
    export_payload.push(0x01);
    buf.push(0x07);
    buf.extend_from_slice(&leb128(export_payload.len() as u32));
    buf.extend_from_slice(&export_payload);
    // Code section: 2 empty bodies
    buf.extend_from_slice(&[0x0A, 0x07, 0x02, 0x02, 0x00, 0x0B, 0x02, 0x00, 0x0B]);

    let module = decode(&buf).unwrap();
    let err = validate(&module).unwrap_err();
    assert_eq!(err, WasmError::DuplicateExport);
}

#[test]
fn validate_valid_function_with_params() {
    // (i32, i32) -> (i32) with i32.add
    let wasm = module_with_typed_body(
        &[0x7F, 0x7F],
        &[0x7F],
        &[
            0x20, 0x00, // local.get 0
            0x20, 0x01, // local.get 1
            0x6A, // i32.add
        ],
    );
    let module = decode(&wasm).unwrap();
    validate(&module).unwrap();
}

#[test]
fn validate_valid_if_else() {
    // (i32) -> (i32) with if/else
    let wasm = module_with_typed_body(
        &[0x7F],
        &[0x7F],
        &[
            0x20, 0x00, // local.get 0
            0x04, 0x7F, // if (result i32)
            0x41, 0x01, // i32.const 1
            0x05, // else
            0x41, 0x00, // i32.const 0
            0x0B, // end if
        ],
    );
    let module = decode(&wasm).unwrap();
    validate(&module).unwrap();
}

#[test]
fn validate_correct_block_result() {
    // () -> (i32) with block producing i32
    let wasm = module_with_typed_body(
        &[],
        &[0x7F],
        &[
            0x02, 0x7F, // block (result i32)
            0x41, 0x2A, // i32.const 42
            0x0B, // end block
        ],
    );
    let module = decode(&wasm).unwrap();
    validate(&module).unwrap();
}

#[test]
fn error_display_messages() {
    assert_eq!(
        format!("{}", WasmError::DivisionByZero),
        "integer divide by zero"
    );
    assert_eq!(
        format!("{}", WasmError::MemoryOutOfBounds),
        "out of bounds memory access"
    );
    assert_eq!(
        format!("{}", WasmError::ImportNotFound(5)),
        "import not found: index 5"
    );
    assert_eq!(
        format!("{}", WasmError::InvalidOpcode(0xFF)),
        "invalid opcode: 0xFF"
    );
}
