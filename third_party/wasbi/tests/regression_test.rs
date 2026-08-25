#![allow(clippy::vec_init_then_push, clippy::nonminimal_bool)]
//! Regression tests for edge cases and previously-fixed bugs.

use wasbi::decoder::decode;
use wasbi::prelude::*;
use wasbi::validator::validate;

const HEADER: &[u8] = &[0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];

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

fn signed_leb128(val: i32) -> Vec<u8> {
    let mut v = val;
    let mut out = Vec::new();
    loop {
        let mut byte = (v & 0x7F) as u8;
        v >>= 7;
        let more = !(v == 0 && (byte & 0x40) == 0) && !(v == -1 && (byte & 0x40) != 0);
        if more {
            byte |= 0x80;
        }
        out.push(byte);
        if !more {
            break;
        }
    }
    out
}

fn module_i32_body(body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::from(HEADER);
    buf.extend_from_slice(&[0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F]);
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    buf.extend_from_slice(&[0x07, 0x05, 0x01, 0x01, b'f', 0x00, 0x00]);
    let mut func_body = Vec::new();
    func_body.push(0x00);
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

// ── Integer edge cases ──────────────────────────────────────────────────

#[test]
fn i32_div_min_by_neg1() {
    // INT32_MIN / -1 = integer overflow
    let mut body = Vec::new();
    body.push(0x41);
    body.extend_from_slice(&signed_leb128(i32::MIN)); // i32.const MIN
    body.push(0x41);
    body.extend_from_slice(&signed_leb128(-1)); // i32.const -1
    body.push(0x6D); // i32.div_s

    let wasm = module_i32_body(&body);
    let engine = Engine::default();
    let module = Module::new(&engine, &wasm).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    match instance.call("f", &[]) {
        ExecResult::Trap(WasmError::IntegerOverflow) => {}
        other => panic!("expected IntegerOverflow, got {:?}", other),
    }
}

#[test]
fn i32_rem_by_zero() {
    let wasm = module_i32_body(&[
        0x41, 0x0A, // i32.const 10
        0x41, 0x00, // i32.const 0
        0x6F, // i32.rem_s
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
fn i32_div_unsigned_by_zero() {
    let wasm = module_i32_body(&[
        0x41, 0x01, // i32.const 1
        0x41, 0x00, // i32.const 0
        0x6E, // i32.div_u
    ]);
    let engine = Engine::default();
    let module = Module::new(&engine, &wasm).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    match instance.call("f", &[]) {
        ExecResult::Trap(WasmError::DivisionByZero) => {}
        other => panic!("expected DivisionByZero, got {:?}", other),
    }
}

// ── Memory edge cases ───────────────────────────────────────────────────

#[test]
fn memory_load_out_of_bounds() {
    let mut buf = Vec::from(HEADER);
    buf.extend_from_slice(&[0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F]); // type
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]); // func
    buf.extend_from_slice(&[0x05, 0x03, 0x01, 0x00, 0x01]); // memory: 1 page
    buf.extend_from_slice(&[0x07, 0x05, 0x01, 0x01, b'f', 0x00, 0x00]); // export

    // Load from address 65536 (out of bounds for 1-page memory)
    let body = &[
        0x41, 0x80, 0x80, 0x04, // i32.const 65536
        0x28, 0x02, 0x00, // i32.load align=2 offset=0
    ];
    let mut func_body = Vec::new();
    func_body.push(0x00);
    func_body.extend_from_slice(body);
    func_body.push(0x0B);
    let mut code_payload = Vec::new();
    code_payload.push(0x01);
    code_payload.extend_from_slice(&leb128(func_body.len() as u32));
    code_payload.extend_from_slice(&func_body);
    buf.push(0x0A);
    buf.extend_from_slice(&leb128(code_payload.len() as u32));
    buf.extend_from_slice(&code_payload);

    let engine = Engine::default();
    let module = Module::new(&engine, &buf).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    match instance.call("f", &[]) {
        ExecResult::Trap(WasmError::MemoryOutOfBounds) => {}
        other => panic!("expected MemoryOutOfBounds, got {:?}", other),
    }
}

// ── Validation edge cases ───────────────────────────────────────────────

#[test]
fn validate_export_func_index_in_bounds() {
    let mut buf = Vec::from(HEADER);
    buf.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]); // type
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]); // func
                                                      // Export with out-of-bounds func index (99)
    buf.extend_from_slice(&[0x07, 0x05, 0x01, 0x01, b'f', 0x00, 0x63]); // func index 99
    buf.extend_from_slice(&[0x0A, 0x04, 0x01, 0x02, 0x00, 0x0B]); // code

    let module = decode(&buf).unwrap();
    assert!(validate(&module).is_err());
}

// ── Linker edge cases ───────────────────────────────────────────────────

#[test]
fn linker_unresolved_import_traps() {
    // Module importing "env"."missing"
    let mut buf = Vec::from(HEADER);
    buf.extend_from_slice(&[0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F]); // type: () -> (i32)
                                                                        // Import
    let mut imp = Vec::new();
    imp.push(0x01); // one import
    imp.push(0x03);
    imp.extend_from_slice(b"env");
    imp.push(0x07);
    imp.extend_from_slice(b"missing");
    imp.push(0x00);
    imp.push(0x00); // func type 0
    buf.push(0x02);
    buf.extend_from_slice(&leb128(imp.len() as u32));
    buf.extend_from_slice(&imp);
    // Func section: one local func
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    // Export "f" = func 1 (local)
    buf.extend_from_slice(&[0x07, 0x05, 0x01, 0x01, b'f', 0x00, 0x01]);
    // Code: call func 0 (the import)
    let body: &[u8] = &[0x10, 0x00]; // call 0
    let mut func_body = Vec::new();
    func_body.push(0x00);
    func_body.extend_from_slice(body);
    func_body.push(0x0B);
    let mut code_payload = Vec::new();
    code_payload.push(0x01);
    code_payload.extend_from_slice(&leb128(func_body.len() as u32));
    code_payload.extend_from_slice(&func_body);
    buf.push(0x0A);
    buf.extend_from_slice(&leb128(code_payload.len() as u32));
    buf.extend_from_slice(&code_payload);

    let engine = Engine::default();
    let module = Module::new(&engine, &buf).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    // Call f, which calls the import — should get HostCall
    match instance.call("f", &[]) {
        ExecResult::HostCall(0, _, _) => {
            // Dispatch with empty linker → ImportNotFound
            let linker = wasbi::linker::Linker::new();
            match linker.dispatch(&mut instance, 0, &[]) {
                Err(WasmError::ImportNotFound(_)) => {}
                other => panic!("expected ImportNotFound, got {:?}", other),
            }
        }
        other => panic!("expected HostCall, got {:?}", other),
    }
}

// ── Module accessor tests ───────────────────────────────────────────────

#[test]
fn module_export_accessors() {
    let engine = Engine::default();

    // Module with memory + global + table + function exports
    let mut buf = Vec::from(HEADER);
    // Type
    buf.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
    // Func
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    // Table: funcref, min=1
    buf.extend_from_slice(&[0x04, 0x04, 0x01, 0x70, 0x00, 0x01]);
    // Memory: 1 page
    buf.extend_from_slice(&[0x05, 0x03, 0x01, 0x00, 0x01]);
    // Global: i32, immutable, 0
    buf.extend_from_slice(&[0x06, 0x06, 0x01, 0x7F, 0x00, 0x41, 0x00, 0x0B]);
    // Exports
    let mut exp = Vec::new();
    exp.push(0x04); // 4 exports
    exp.push(0x01);
    exp.push(b'f');
    exp.push(0x00);
    exp.push(0x00); // func
    exp.push(0x01);
    exp.push(b't');
    exp.push(0x01);
    exp.push(0x00); // table
    exp.push(0x01);
    exp.push(b'm');
    exp.push(0x02);
    exp.push(0x00); // memory
    exp.push(0x01);
    exp.push(b'g');
    exp.push(0x03);
    exp.push(0x00); // global
    buf.push(0x07);
    buf.extend_from_slice(&leb128(exp.len() as u32));
    buf.extend_from_slice(&exp);
    // Code
    buf.extend_from_slice(&[0x0A, 0x04, 0x01, 0x02, 0x00, 0x0B]);

    let module = Module::new(&engine, &buf).unwrap();
    assert_eq!(module.export_func("f"), Some(0));
    assert_eq!(module.export_table("t"), Some(0));
    assert_eq!(module.export_memory("m"), Some(0));
    assert_eq!(module.export_global("g"), Some(0));
    assert!(module.export_func("missing").is_none());
}
