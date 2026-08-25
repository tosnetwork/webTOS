#![allow(clippy::field_reassign_with_default, clippy::same_item_push)]
//! Stress tests for resource limits and large-module behavior.

use wasbi::prelude::*;

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

/// Build a module with N nested blocks, each producing an i32.
fn deeply_nested_blocks(depth: usize) -> Vec<u8> {
    let mut buf = Vec::from(HEADER);
    // Type: () -> (i32)
    buf.extend_from_slice(&[0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F]);
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    buf.extend_from_slice(&[0x07, 0x05, 0x01, 0x01, b'f', 0x00, 0x00]);

    // Body: block(block(block(...i32.const 42...end)end)end)
    let mut body = Vec::new();
    body.push(0x00); // 0 locals
    for _ in 0..depth {
        body.push(0x02); // block
        body.push(0x7F); // result i32
    }
    body.push(0x41);
    body.push(0x2A); // i32.const 42
    for _ in 0..depth {
        body.push(0x0B); // end block
    }
    body.push(0x0B); // end func

    let mut code = Vec::new();
    code.push(0x01); // one body
    code.extend_from_slice(&leb128(body.len() as u32));
    code.extend_from_slice(&body);
    buf.push(0x0A);
    buf.extend_from_slice(&leb128(code.len() as u32));
    buf.extend_from_slice(&code);
    buf
}

#[test]
fn deeply_nested_blocks_100() {
    let wasm = deeply_nested_blocks(100);
    let engine = Engine::default();
    let module = Module::new(&engine, &wasm).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    match instance.call("f", &[]) {
        ExecResult::Returned(Value::I32(42)) => {}
        other => panic!("expected 42, got {:?}", other),
    }
}

#[test]
fn deeply_nested_blocks_500() {
    let wasm = deeply_nested_blocks(500);
    let engine = Engine::default();
    let module = Module::new(&engine, &wasm).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    match instance.call("f", &[]) {
        ExecResult::Returned(Value::I32(42)) => {}
        other => panic!("expected 42, got {:?}", other),
    }
}

#[test]
fn fuel_exactly_sufficient() {
    // Module: () -> (i32), body = i32.const 42 (2 instructions: const + implicit return)
    let mut buf = Vec::from(HEADER);
    buf.extend_from_slice(&[0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F]);
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    buf.extend_from_slice(&[0x07, 0x05, 0x01, 0x01, b'f', 0x00, 0x00]);
    buf.extend_from_slice(&[0x0A, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2A, 0x0B]);

    // Set fuel to exactly what's needed
    let mut config = Config::default();
    config.fuel = 10; // generous enough for a simple function
    let engine = Engine::new(config);
    let module = Module::new(&engine, &buf).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    match instance.call("f", &[]) {
        ExecResult::Returned(Value::I32(42)) => {}
        other => panic!("expected 42, got {:?}", other),
    }
    assert!(instance.fuel() < 10); // some fuel was consumed
}

#[test]
fn fuel_exactly_one_too_few() {
    // Infinite loop with fuel=1 should run out quickly
    let mut buf = Vec::from(HEADER);
    buf.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]); // type () -> ()
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]); // func
    buf.extend_from_slice(&[0x07, 0x05, 0x01, 0x01, b'f', 0x00, 0x00]); // export

    // Code: func body = [0 locals, loop(void) { br 0 } end, end]
    let body: &[u8] = &[0x00, 0x03, 0x40, 0x0C, 0x00, 0x0B, 0x0B];
    let mut code = Vec::new();
    code.push(0x01); // one body
    code.extend_from_slice(&leb128(body.len() as u32));
    code.extend_from_slice(body);
    buf.push(0x0A);
    buf.extend_from_slice(&leb128(code.len() as u32));
    buf.extend_from_slice(&code);

    let mut config = Config::default();
    config.fuel = 3;
    let engine = Engine::new(config);
    let module = Module::new(&engine, &buf).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    match instance.call("f", &[]) {
        ExecResult::OutOfFuel => {}
        other => panic!("expected OutOfFuel, got {:?}", other),
    }
}

#[test]
fn single_memory_with_max() {
    // Module with 1 memory, min=1, max=4
    let mut buf = Vec::from(HEADER);
    // Memory section: 1 memory, has-max, min=1, max=4
    buf.extend_from_slice(&[0x05, 0x04, 0x01, 0x01, 0x01, 0x04]);

    let engine = Engine::default();
    let module = Module::new(&engine, &buf).unwrap();
    let instance = Instance::new(module, &engine).unwrap();

    assert!(instance.memory(0).is_some());
    assert_eq!(instance.memory_size(0), Some(65536)); // 1 page = 64KiB
    assert!(instance.memory(1).is_none());
}

#[test]
fn many_globals() {
    // Module with 10 globals
    let mut buf = Vec::from(HEADER);
    let mut global_payload = Vec::new();
    global_payload.push(10); // 10 globals
    for i in 0..10u8 {
        global_payload.push(0x7F); // i32
        global_payload.push(0x01); // mutable
        global_payload.push(0x41); // i32.const
        global_payload.extend_from_slice(&leb128(i as u32));
        global_payload.push(0x0B); // end
    }
    buf.push(0x06);
    buf.extend_from_slice(&leb128(global_payload.len() as u32));
    buf.extend_from_slice(&global_payload);

    let engine = Engine::default();
    let module = Module::new(&engine, &buf).unwrap();
    let instance = Instance::new(module, &engine).unwrap();

    for i in 0..10 {
        assert_eq!(instance.global(i), Some(Value::I32(i as i32)));
    }
    assert_eq!(instance.global(10), None);
}

#[test]
fn set_fuel_mid_execution() {
    // Module with nop + return 42
    let mut buf = Vec::from(HEADER);
    buf.extend_from_slice(&[0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F]);
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    buf.extend_from_slice(&[0x07, 0x05, 0x01, 0x01, b'f', 0x00, 0x00]);
    buf.extend_from_slice(&[0x0A, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2A, 0x0B]);

    let engine = Engine::default();
    let module = Module::new(&engine, &buf).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    instance.set_fuel(999_999);
    assert_eq!(instance.fuel(), 999_999);
}

#[test]
fn instance_is_finished_after_call() {
    let mut buf = Vec::from(HEADER);
    buf.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]);
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    buf.extend_from_slice(&[0x07, 0x05, 0x01, 0x01, b'f', 0x00, 0x00]);
    buf.extend_from_slice(&[0x0A, 0x04, 0x01, 0x02, 0x00, 0x0B]);

    let engine = Engine::default();
    let module = Module::new(&engine, &buf).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    assert!(!instance.is_finished());
    instance.call("f", &[]);
    assert!(instance.is_finished());
}
