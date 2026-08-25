//! Tests for feature-gated proposal support.

use wasbi::prelude::*;

const HEADER: &[u8] = &[0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];

/// Encode a u32 as LEB128.
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

fn module_void_body(body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::from(HEADER);
    // Type: () -> ()
    buf.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
    // Func
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    // Export "f"
    buf.extend_from_slice(&[0x07, 0x05, 0x01, 0x01, b'f', 0x00, 0x00]);
    // Code
    let mut func_body = Vec::new();
    func_body.push(0x00); // 0 locals
    func_body.extend_from_slice(body);
    func_body.push(0x0B);
    let mut code_payload = Vec::new();
    code_payload.push(0x01);
    code_payload.extend_from_slice(&leb128(func_body.len() as u32));
    code_payload.extend_from_slice(&func_body);
    buf.push(0x0A);
    buf.extend_from_slice(&leb128(code_payload.len() as u32));
    buf.extend_from_slice(&code_payload);
    buf
}

#[test]
fn config_default_has_all_features() {
    let config = Config::default();
    assert_eq!(config.runtime_class, RuntimeClass::BestEffort);
    assert_eq!(config.fuel, 1_000_000);
}

#[test]
fn engine_default_and_clone() {
    let engine = Engine::default();
    let engine2 = engine.clone();
    assert_eq!(engine.config().fuel, engine2.config().fuel);
}

#[test]
fn module_surface_reports_counts() {
    let engine = Engine::default();
    let module = Module::new(&engine, HEADER).unwrap();
    assert_eq!(module.import_count(), 0);
    assert_eq!(module.export_count(), 0);
    assert_eq!(module.function_count(), 0);
}

#[test]
fn instance_global_accessors() {
    // Module with one mutable i32 global initialized to 7
    let mut buf = Vec::from(HEADER);
    buf.extend_from_slice(&[0x06, 0x06, 0x01, 0x7F, 0x01, 0x41, 0x07, 0x0B]);

    let engine = Engine::default();
    let module = Module::new(&engine, &buf).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    assert_eq!(instance.global(0), Some(Value::I32(7)));
    instance.set_global(0, Value::I32(99));
    assert_eq!(instance.global(0), Some(Value::I32(99)));
    assert_eq!(instance.global(999), None);
}

#[test]
fn instance_table_accessor() {
    // Module with one funcref table of size 2
    let mut buf = Vec::from(HEADER);
    // Table section: 1 table, funcref, min=2, no max
    buf.extend_from_slice(&[0x04, 0x04, 0x01, 0x70, 0x00, 0x02]);

    let engine = Engine::default();
    let module = Module::new(&engine, &buf).unwrap();
    let instance = Instance::new(module, &engine).unwrap();

    let table = instance.table(0);
    assert!(table.is_some());
    assert_eq!(table.unwrap().len(), 2);
    assert!(instance.table(1).is_none());
}

#[test]
fn empty_module_no_memory() {
    let engine = Engine::default();
    let module = Module::new(&engine, HEADER).unwrap();
    let instance = Instance::new(module, &engine).unwrap();

    assert!(instance.memory(0).is_none());
    assert_eq!(instance.memory_size(0), None);
}

#[test]
fn multiple_calls_on_same_instance() {
    let wasm = module_void_body(&[0x01]); // nop

    let engine = Engine::default();
    let module = Module::new(&engine, &wasm).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    // Call same function multiple times
    for _ in 0..5 {
        match instance.call("f", &[]) {
            ExecResult::Ok => {}
            other => panic!("expected Ok, got {:?}", other),
        }
    }
}

#[test]
fn wasm_error_display() {
    let err = WasmError::StackOverflow;
    let msg = format!("{err}");
    assert_eq!(msg, "stack overflow");

    let err = WasmError::InvalidOpcode(0xAB);
    let msg = format!("{err}");
    assert!(msg.contains("0xAB"));
}

#[test]
fn wasm_error_layer_trap_variants() {
    use wasbi::types::ErrorLayer;

    let traps = [
        WasmError::StackOverflow,
        WasmError::StackUnderflow,
        WasmError::OutOfBounds,
        WasmError::DivisionByZero,
        WasmError::UnreachableExecuted,
        WasmError::OutOfFuel,
        WasmError::MemoryOutOfBounds,
        WasmError::CallStackOverflow,
        WasmError::NullReference,
        WasmError::CastFailure,
    ];

    for trap in &traps {
        assert_eq!(
            trap.layer(),
            ErrorLayer::Trap,
            "expected Trap for {:?}",
            trap
        );
    }
}

#[test]
fn config_limit_rejects_large_memory_module() {
    let mut buf = Vec::from(HEADER);
    buf.extend_from_slice(&[0x05, 0x03, 0x01, 0x00, 0x01]);

    let engine = Engine::new(Config {
        max_memory_pages: 0,
        ..Config::default()
    });

    match Module::new(&engine, &buf) {
        Err(WasmError::LimitExceeded("max_memory_pages")) => {}
        Err(err) => panic!("expected max_memory_pages limit error, got {err}"),
        Ok(_) => panic!("expected max_memory_pages limit error, got success"),
    }
}

#[cfg(not(feature = "simd"))]
#[test]
fn simd_module_is_rejected_during_module_creation() {
    let wasm = module_void_body(&[
        0xFD, 0x0C, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1A,
    ]);
    let engine = Engine::default();

    match Module::new(&engine, &wasm) {
        Err(WasmError::UnsupportedProposal) => {}
        Err(err) => panic!("expected UnsupportedProposal, got {err}"),
        Ok(_) => panic!("expected UnsupportedProposal, got success"),
    }
}
