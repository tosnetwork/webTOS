#![allow(clippy::field_reassign_with_default)]
//! Runtime behavior tests.

use wasbi::prelude::*;
use wasbi::types::ErrorLayer;

const HEADER: &[u8] = &[0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];

/// Build a module with a single function that has given body bytes.
/// The function type is () -> (i32).
fn module_with_body(body: &[u8]) -> Vec<u8> {
    let body_size = body.len() + 2; // +1 for local count, +1 for end
    let code_size = body_size + 1; // +1 for body count byte (size of body)

    let mut buf = Vec::from(HEADER);
    // Type section: () -> (i32)
    buf.extend_from_slice(&[0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F]);
    // Function section
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    // Export section: "f"
    buf.extend_from_slice(&[0x07, 0x05, 0x01, 0x01, b'f', 0x00, 0x00]);
    // Code section
    buf.push(0x0A);
    buf.push((code_size + 1) as u8); // section size
    buf.push(0x01); // one body
    buf.push(body_size as u8); // body size
    buf.push(0x00); // 0 locals
    buf.extend_from_slice(body);
    buf.push(0x0B); // end

    buf
}

/// Build: () -> () void function
fn module_void_body(body: &[u8]) -> Vec<u8> {
    let body_size = body.len() + 2;
    let code_size = body_size + 1;

    let mut buf = Vec::from(HEADER);
    // Type section: () -> ()
    buf.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
    // Function section
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    // Export section: "f"
    buf.extend_from_slice(&[0x07, 0x05, 0x01, 0x01, b'f', 0x00, 0x00]);
    // Code section
    buf.push(0x0A);
    buf.push((code_size + 1) as u8);
    buf.push(0x01);
    buf.push(body_size as u8);
    buf.push(0x00);
    buf.extend_from_slice(body);
    buf.push(0x0B);

    buf
}

#[test]
fn fuel_exhaustion() {
    // i32.const 1; loop body that burns fuel
    let wasm = module_void_body(&[
        0x03, 0x40, // loop (void)
        0x0C, 0x00, // br 0 (infinite loop)
        0x0B, // end loop
    ]);

    let mut config = Config::default();
    config.fuel = 50;
    let engine = Engine::new(config);
    let module = Module::new(&engine, &wasm).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    match instance.call("f", &[]) {
        ExecResult::OutOfFuel => {} // expected
        other => panic!("expected OutOfFuel, got {:?}", other),
    }
}

#[test]
fn division_by_zero_i32() {
    // i32.const 1; i32.const 0; i32.div_s
    let wasm = module_with_body(&[
        0x41, 0x01, // i32.const 1
        0x41, 0x00, // i32.const 0
        0x6D, // i32.div_s
    ]);

    let engine = Engine::default();
    let module = Module::new(&engine, &wasm).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    match instance.call("f", &[]) {
        ExecResult::Trap(WasmError::DivisionByZero) => {}
        other => panic!("expected DivisionByZero, got {:?}", other),
    }
}

#[test]
fn unreachable_trap() {
    let wasm = module_with_body(&[0x00]); // unreachable

    let engine = Engine::default();
    let module = Module::new(&engine, &wasm).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    match instance.call("f", &[]) {
        ExecResult::Trap(WasmError::UnreachableExecuted) => {}
        other => panic!("expected UnreachableExecuted, got {:?}", other),
    }
}

#[test]
fn i32_arithmetic() {
    // i32.const 10; i32.const 20; i32.add
    let wasm = module_with_body(&[
        0x41, 0x0A, // i32.const 10
        0x41, 0x14, // i32.const 20
        0x6A, // i32.add
    ]);

    let engine = Engine::default();
    let module = Module::new(&engine, &wasm).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    match instance.call("f", &[]) {
        ExecResult::Returned(Value::I32(30)) => {}
        other => panic!("expected 30, got {:?}", other),
    }
}

#[test]
fn i32_subtract() {
    let wasm = module_with_body(&[
        0x41, 0x32, // i32.const 50
        0x41, 0x08, // i32.const 8
        0x6B, // i32.sub
    ]);

    let engine = Engine::default();
    let module = Module::new(&engine, &wasm).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    match instance.call("f", &[]) {
        ExecResult::Returned(Value::I32(42)) => {}
        other => panic!("expected 42, got {:?}", other),
    }
}

#[test]
fn i32_multiply() {
    let wasm = module_with_body(&[
        0x41, 0x06, // i32.const 6
        0x41, 0x07, // i32.const 7
        0x6C, // i32.mul
    ]);

    let engine = Engine::default();
    let module = Module::new(&engine, &wasm).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    match instance.call("f", &[]) {
        ExecResult::Returned(Value::I32(42)) => {}
        other => panic!("expected 42, got {:?}", other),
    }
}

#[test]
fn memory_load_store() {
    // Module with memory, store i32 42 at offset 0, then load it back
    let mut buf = Vec::from(HEADER);
    // Type section: () -> (i32)
    buf.extend_from_slice(&[0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F]);
    // Function section
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    // Memory section: 1 page
    buf.extend_from_slice(&[0x05, 0x03, 0x01, 0x00, 0x01]);
    // Export section: "f"
    buf.extend_from_slice(&[0x07, 0x05, 0x01, 0x01, b'f', 0x00, 0x00]);
    // Code section
    let body: &[u8] = &[
        0x41, 0x00, // i32.const 0 (addr)
        0x41, 0x2A, // i32.const 42 (value)
        0x36, 0x02, 0x00, // i32.store align=2 offset=0
        0x41, 0x00, // i32.const 0 (addr)
        0x28, 0x02, 0x00, // i32.load align=2 offset=0
    ];
    let body_size = body.len() + 2;
    buf.push(0x0A);
    buf.push((body_size + 2) as u8);
    buf.push(0x01);
    buf.push(body_size as u8);
    buf.push(0x00);
    buf.extend_from_slice(body);
    buf.push(0x0B);

    let engine = Engine::default();
    let module = Module::new(&engine, &buf).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    match instance.call("f", &[]) {
        ExecResult::Returned(Value::I32(42)) => {}
        other => panic!("expected 42, got {:?}", other),
    }
}

#[test]
fn instance_memory_accessor() {
    let mut buf = Vec::from(HEADER);
    // Memory section: 1 page min
    buf.extend_from_slice(&[0x05, 0x03, 0x01, 0x00, 0x01]);

    let engine = Engine::default();
    let module = Module::new(&engine, &buf).unwrap();
    let instance = Instance::new(module, &engine).unwrap();

    assert!(instance.memory(0).is_some());
    assert_eq!(instance.memory_size(0), Some(65536));
    assert!(instance.memory(1).is_none());
}

#[test]
fn proofgrade_rejects_floats() {
    // f32.const 1.0 (would need to return f32, but let's use a void body)
    let wasm = module_void_body(&[
        0x43, 0x00, 0x00, 0x80, 0x3F, // f32.const 1.0
        0x1A, // drop
    ]);

    let mut config = Config::default();
    config.runtime_class = RuntimeClass::ProofGrade;
    let engine = Engine::new(config);
    let module = Module::new(&engine, &wasm).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    match instance.call("f", &[]) {
        ExecResult::Trap(WasmError::FloatsDisabled) => {}
        other => panic!("expected FloatsDisabled, got {:?}", other),
    }
}

#[test]
fn error_layer_classification() {
    assert_eq!(WasmError::InvalidMagic.layer(), ErrorLayer::Decode);
    assert_eq!(WasmError::InvalidLEB128.layer(), ErrorLayer::Decode);
    assert_eq!(WasmError::TypeMismatch.layer(), ErrorLayer::Validation);
    assert_eq!(WasmError::DuplicateExport.layer(), ErrorLayer::Validation);
    assert_eq!(
        WasmError::ImportNotFound(0).layer(),
        ErrorLayer::Instantiation
    );
    assert_eq!(
        WasmError::FunctionNotFound(0).layer(),
        ErrorLayer::Instantiation
    );
    assert_eq!(WasmError::DivisionByZero.layer(), ErrorLayer::Trap);
    assert_eq!(WasmError::OutOfFuel.layer(), ErrorLayer::Trap);
    assert_eq!(WasmError::MemoryOutOfBounds.layer(), ErrorLayer::Trap);
    assert_eq!(WasmError::StackOverflow.layer(), ErrorLayer::Trap);
}

#[test]
fn set_fuel_and_read_back() {
    let engine = Engine::default();
    let module = Module::new(&engine, HEADER).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    instance.set_fuel(999);
    assert_eq!(instance.fuel(), 999);
}
