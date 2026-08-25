#![allow(clippy::vec_init_then_push)]
//! Host call integration tests.

use wasbi::linker::Linker;
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

/// Module that imports "env"."add" (i32, i32) -> (i32) and exports "call_add"
fn module_with_add_import() -> Vec<u8> {
    let mut buf = Vec::from(HEADER);
    // Type section: 2 types
    // type 0: (i32, i32) -> (i32)
    // type 1: () -> (i32)
    let mut types = Vec::new();
    types.push(0x02); // 2 types
    types.push(0x60);
    types.push(0x02);
    types.push(0x7F);
    types.push(0x7F);
    types.push(0x01);
    types.push(0x7F);
    types.push(0x60);
    types.push(0x00);
    types.push(0x01);
    types.push(0x7F);
    buf.push(0x01);
    buf.extend_from_slice(&leb128(types.len() as u32));
    buf.extend_from_slice(&types);

    // Import: "env"."add" type 0
    let mut imp = Vec::new();
    imp.push(0x01);
    imp.push(0x03);
    imp.extend_from_slice(b"env");
    imp.push(0x03);
    imp.extend_from_slice(b"add");
    imp.push(0x00);
    imp.push(0x00);
    buf.push(0x02);
    buf.extend_from_slice(&leb128(imp.len() as u32));
    buf.extend_from_slice(&imp);

    // Function section: 1 local func, type 1
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x01]);

    // Export: "call_add" = func 1
    let mut exp = Vec::new();
    exp.push(0x01);
    exp.push(0x08);
    exp.extend_from_slice(b"call_add");
    exp.push(0x00);
    exp.push(0x01);
    buf.push(0x07);
    buf.extend_from_slice(&leb128(exp.len() as u32));
    buf.extend_from_slice(&exp);

    // Code: call_add() = add(10, 32)
    let body: &[u8] = &[
        0x41, 0x0A, // i32.const 10
        0x41, 0x20, // i32.const 32
        0x10, 0x00, // call func 0 (the import)
    ];
    let mut func_body = Vec::new();
    func_body.push(0x00); // 0 locals
    func_body.extend_from_slice(body);
    func_body.push(0x0B);
    let mut code = Vec::new();
    code.push(0x01);
    code.extend_from_slice(&leb128(func_body.len() as u32));
    code.extend_from_slice(&func_body);
    buf.push(0x0A);
    buf.extend_from_slice(&leb128(code.len() as u32));
    buf.extend_from_slice(&code);

    buf
}

#[test]
fn host_call_add_via_linker() {
    let wasm = module_with_add_import();
    let engine = Engine::default();
    let module = Module::new(&engine, &wasm).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    let mut linker = Linker::new();
    linker.func_wrap("env", "add", |_inst: Caller<'_, ()>, args| {
        let a = args[0].as_i32();
        let b = args[1].as_i32();
        Ok(Some(Value::I32(a + b)))
    });

    match instance.call("call_add", &[]) {
        ExecResult::HostCall(idx, ref args, count) => {
            let ret = linker
                .dispatch(&mut instance, idx, &args[..count as usize])
                .unwrap();
            match instance.resume(ret) {
                ExecResult::Returned(Value::I32(42)) => {}
                other => panic!("expected 42, got {:?}", other),
            }
        }
        other => panic!("expected HostCall, got {:?}", other),
    }
}

#[test]
fn host_call_with_memory_access() {
    // Module with memory + import that reads memory
    let mut buf = Vec::from(HEADER);
    // Types: type 0 = (i32, i32) -> (i32), type 1 = () -> (i32)
    buf.extend_from_slice(&[
        0x01, 0x0B, 0x02, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F, 0x60, 0x00, 0x01, 0x7F,
    ]);
    // Import: "env"."read_mem" type 0
    let mut imp = Vec::new();
    imp.push(0x01);
    imp.push(0x03);
    imp.extend_from_slice(b"env");
    imp.push(0x08);
    imp.extend_from_slice(b"read_mem");
    imp.push(0x00);
    imp.push(0x00);
    buf.push(0x02);
    buf.extend_from_slice(&leb128(imp.len() as u32));
    buf.extend_from_slice(&imp);
    // Func
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x01]);
    // Memory
    buf.extend_from_slice(&[0x05, 0x03, 0x01, 0x00, 0x01]);
    // Export "f"
    buf.extend_from_slice(&[0x07, 0x05, 0x01, 0x01, b'f', 0x00, 0x01]);
    // Code: store 42 at addr 0, then call read_mem(0, 4)
    let body: &[u8] = &[
        0x41, 0x00, 0x41, 0x2A, 0x36, 0x02, 0x00, // i32.store(0, 42)
        0x41, 0x00, 0x41, 0x04, 0x10, 0x00, // call read_mem(0, 4)
    ];
    let mut func_body = Vec::new();
    func_body.push(0x00);
    func_body.extend_from_slice(body);
    func_body.push(0x0B);
    let mut code = Vec::new();
    code.push(0x01);
    code.extend_from_slice(&leb128(func_body.len() as u32));
    code.extend_from_slice(&func_body);
    buf.push(0x0A);
    buf.extend_from_slice(&leb128(code.len() as u32));
    buf.extend_from_slice(&code);

    let engine = Engine::default();
    let module = Module::new(&engine, &buf).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    let mut linker = Linker::new();
    linker.func_wrap("env", "read_mem", |caller: Caller<'_, ()>, args| {
        let ptr = args[0].as_i32() as usize;
        let len = args[1].as_i32() as usize;
        let mem = caller.memory(0).unwrap();
        if ptr + len <= mem.len() {
            let val = i32::from_le_bytes([mem[ptr], mem[ptr + 1], mem[ptr + 2], mem[ptr + 3]]);
            Ok(Some(Value::I32(val)))
        } else {
            Err(wasbi::types::WasmError::MemoryOutOfBounds)
        }
    });

    match instance.call("f", &[]) {
        ExecResult::HostCall(idx, ref args, count) => {
            let ret = linker
                .dispatch(&mut instance, idx, &args[..count as usize])
                .unwrap();
            match instance.resume(ret) {
                ExecResult::Returned(Value::I32(42)) => {}
                other => panic!("expected 42, got {:?}", other),
            }
        }
        other => panic!("expected HostCall, got {:?}", other),
    }
}

#[test]
fn host_call_modifies_instance_state() {
    // Verify host function can set instance finished
    let mut buf = Vec::from(HEADER);
    buf.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]); // () -> ()
    let mut imp = Vec::new();
    imp.push(0x01);
    imp.push(0x03);
    imp.extend_from_slice(b"env");
    imp.push(0x04);
    imp.extend_from_slice(b"exit");
    imp.push(0x00);
    imp.push(0x00);
    buf.push(0x02);
    buf.extend_from_slice(&leb128(imp.len() as u32));
    buf.extend_from_slice(&imp);
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    buf.extend_from_slice(&[0x07, 0x05, 0x01, 0x01, b'f', 0x00, 0x01]);
    let body: &[u8] = &[0x10, 0x00]; // call exit
    let mut func_body = Vec::new();
    func_body.push(0x00);
    func_body.extend_from_slice(body);
    func_body.push(0x0B);
    let mut code = Vec::new();
    code.push(0x01);
    code.extend_from_slice(&leb128(func_body.len() as u32));
    code.extend_from_slice(&func_body);
    buf.push(0x0A);
    buf.extend_from_slice(&leb128(code.len() as u32));
    buf.extend_from_slice(&code);

    let engine = Engine::default();
    let module = Module::new(&engine, &buf).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    let mut linker = Linker::new();
    linker.func_wrap("env", "exit", |mut caller: Caller<'_, ()>, _args| {
        caller.set_finished(true);
        Ok(None)
    });

    assert!(!instance.is_finished());
    match instance.call("f", &[]) {
        ExecResult::HostCall(idx, ref args, count) => {
            let ret = linker
                .dispatch(&mut instance, idx, &args[..count as usize])
                .unwrap();
            let _ = instance.resume(ret);
            assert!(instance.is_finished());
        }
        other => panic!("expected HostCall, got {:?}", other),
    }
}

#[test]
fn linker_multiple_modules() {
    let mut linker = Linker::new();
    linker
        .func_wrap("env", "get_x", |_inst: Caller<'_, ()>, _args| {
            Ok(Some(Value::I32(10)))
        })
        .func_wrap("env", "get_y", |_inst: Caller<'_, ()>, _args| {
            Ok(Some(Value::I32(20)))
        })
        .func_wrap("math", "add", |_inst: Caller<'_, ()>, args| {
            Ok(Some(Value::I32(args[0].as_i32() + args[1].as_i32())))
        });
    // Just verify fluent API with multiple modules compiles and works
}
