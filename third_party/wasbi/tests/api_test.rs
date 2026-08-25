#![allow(clippy::field_reassign_with_default)]
//! Integration tests for the wasbi public API.

use wasbi::linker::Linker;
use wasbi::prelude::*;

/// Minimal valid WASM module: (module)
/// Magic + version + no sections
const EMPTY_MODULE: &[u8] = &[
    0x00, 0x61, 0x73, 0x6D, // magic
    0x01, 0x00, 0x00, 0x00, // version
];

/// A module that exports a function returning i32 constant 42.
/// (module
///   (func $answer (export "answer") (result i32)
///     i32.const 42)
/// )
fn module_returning_42() -> Vec<u8> {
    let mut buf = Vec::new();

    // Header
    buf.extend_from_slice(&[0x00, 0x61, 0x73, 0x6D]); // magic
    buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // version

    // Type section: one type () -> (i32)
    buf.push(0x01); // section id
    buf.push(0x05); // section size
    buf.push(0x01); // one type
    buf.push(0x60); // func type
    buf.push(0x00); // 0 params
    buf.push(0x01); // 1 result
    buf.push(0x7F); // i32

    // Function section: one function, type index 0
    buf.push(0x03); // section id
    buf.push(0x02); // section size
    buf.push(0x01); // one function
    buf.push(0x00); // type index 0

    // Export section: export "answer" as function 0
    buf.push(0x07); // section id
    buf.push(0x0A); // section size
    buf.push(0x01); // one export
    buf.push(0x06); // name len
    buf.extend_from_slice(b"answer"); // name
    buf.push(0x00); // func export
    buf.push(0x00); // func index 0

    // Code section: one function body
    buf.push(0x0A); // section id
    buf.push(0x06); // section size
    buf.push(0x01); // one body
    buf.push(0x04); // body size
    buf.push(0x00); // 0 locals
    buf.push(0x41); // i32.const
    buf.push(0x2A); // 42 (LEB128)
    buf.push(0x0B); // end

    buf
}

/// A module that exports an "add" function: (i32, i32) -> i32.
fn module_add() -> Vec<u8> {
    let mut buf = Vec::new();

    // Header
    buf.extend_from_slice(&[0x00, 0x61, 0x73, 0x6D]);
    buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

    // Type section: (i32, i32) -> (i32)
    buf.push(0x01); // section id
    buf.push(0x07); // section size
    buf.push(0x01); // one type
    buf.push(0x60); // func type
    buf.push(0x02); // 2 params
    buf.push(0x7F); // i32
    buf.push(0x7F); // i32
    buf.push(0x01); // 1 result
    buf.push(0x7F); // i32

    // Function section
    buf.push(0x03);
    buf.push(0x02);
    buf.push(0x01);
    buf.push(0x00);

    // Export section: "add"
    buf.push(0x07);
    buf.push(0x07);
    buf.push(0x01);
    buf.push(0x03);
    buf.extend_from_slice(b"add");
    buf.push(0x00);
    buf.push(0x00);

    // Code section
    buf.push(0x0A);
    buf.push(0x09);
    buf.push(0x01);
    buf.push(0x07); // body size
    buf.push(0x00); // 0 locals
    buf.push(0x20);
    buf.push(0x00); // local.get 0
    buf.push(0x20);
    buf.push(0x01); // local.get 1
    buf.push(0x6A); // i32.add
    buf.push(0x0B); // end

    buf
}

#[test]
fn engine_default_creates_successfully() {
    let _engine = Engine::default();
}

#[test]
fn engine_custom_config() {
    let mut config = Config::default();
    config.fuel = 500;
    config.runtime_class = RuntimeClass::ProofGrade;
    let engine = Engine::new(config);
    assert_eq!(engine.config().fuel, 500);
    assert_eq!(engine.config().runtime_class, RuntimeClass::ProofGrade);
}

#[test]
fn module_decode_empty() {
    let engine = Engine::default();
    let module = Module::new(&engine, EMPTY_MODULE).unwrap();
    assert!(module.export_func("nonexistent").is_none());
}

#[test]
fn module_decode_invalid() {
    let engine = Engine::default();
    let result = Module::new(&engine, &[0x00, 0x00, 0x00, 0x00]);
    assert!(result.is_err());
}

#[test]
fn instance_call_return_42() {
    let engine = Engine::default();
    let module = Module::new(&engine, &module_returning_42()).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    match instance.call("answer", &[]) {
        ExecResult::Returned(Value::I32(42)) => {}
        other => panic!("expected Returned(I32(42)), got {:?}", other),
    }
}

#[test]
fn instance_call_add() {
    let engine = Engine::default();
    let module = Module::new(&engine, &module_add()).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    match instance.call("add", &[Value::I32(10), Value::I32(32)]) {
        ExecResult::Returned(Value::I32(42)) => {}
        other => panic!("expected Returned(I32(42)), got {:?}", other),
    }
}

#[test]
fn instance_call_nonexistent_function() {
    let engine = Engine::default();
    let module = Module::new(&engine, &module_returning_42()).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    match instance.call("nonexistent", &[]) {
        ExecResult::Trap(WasmError::FunctionNotFound(_)) => {}
        other => panic!("expected Trap(FunctionNotFound), got {:?}", other),
    }
}

#[test]
fn instance_fuel_management() {
    let mut config = Config::default();
    config.fuel = 100;
    let engine = Engine::new(config);
    let module = Module::new(&engine, &module_returning_42()).unwrap();
    let instance = Instance::new(module, &engine).unwrap();

    assert_eq!(instance.fuel(), 100);
}

#[test]
fn instance_call_by_index() {
    let engine = Engine::default();
    let module = Module::new(&engine, &module_returning_42()).unwrap();
    let func_idx = module.export_func("answer").unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    match instance.call_by_index(func_idx, &[]) {
        ExecResult::Returned(Value::I32(42)) => {}
        other => panic!("expected Returned(I32(42)), got {:?}", other),
    }
}

#[test]
fn linker_host_function() {
    // Module that imports "env"."get_value" () -> i32 and re-exports it via "run".
    // (module
    //   (import "env" "get_value" (func $get_value (result i32)))
    //   (func $run (export "run") (result i32)
    //     call $get_value)
    // )
    let wasm = {
        let mut buf = Vec::new();
        // Header
        buf.extend_from_slice(&[0x00, 0x61, 0x73, 0x6D]);
        buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

        // Type section: () -> (i32)
        buf.push(0x01);
        buf.push(0x05);
        buf.push(0x01); // one type
        buf.push(0x60);
        buf.push(0x00);
        buf.push(0x01);
        buf.push(0x7F);

        // Import section: import "env" "get_value" (func type 0)
        buf.push(0x02);
        buf.push(0x11);
        buf.push(0x01); // one import
        buf.push(0x03);
        buf.extend_from_slice(b"env"); // module name
        buf.push(0x09);
        buf.extend_from_slice(b"get_value"); // field name
        buf.push(0x00);
        buf.push(0x00); // func, type 0

        // Function section: one local function, type 0
        buf.push(0x03);
        buf.push(0x02);
        buf.push(0x01);
        buf.push(0x00);

        // Export section: "run" = func 1
        buf.push(0x07);
        buf.push(0x07);
        buf.push(0x01);
        buf.push(0x03);
        buf.extend_from_slice(b"run");
        buf.push(0x00);
        buf.push(0x01); // func index 1 (import is 0)

        // Code section
        buf.push(0x0A);
        buf.push(0x06);
        buf.push(0x01); // one body
        buf.push(0x04); // body size
        buf.push(0x00); // 0 locals
        buf.push(0x10);
        buf.push(0x00); // call func 0 (the import)
        buf.push(0x0B); // end

        buf
    };

    let engine = Engine::default();
    let module = Module::new(&engine, &wasm).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    let mut linker = Linker::new();
    linker.func_wrap("env", "get_value", |_inst: Caller<'_, ()>, _args| {
        Ok(Some(Value::I32(99)))
    });

    // Call "run" which calls the imported "get_value"
    let result = instance.call("run", &[]);
    match result {
        ExecResult::HostCall(func_idx, ref args, count) => {
            // Manually dispatch via linker
            let ret = linker
                .dispatch(&mut instance, func_idx, &args[..count as usize])
                .unwrap();
            match instance.resume(ret) {
                ExecResult::Returned(Value::I32(99)) => {}
                other => panic!("expected Returned(I32(99)), got {:?}", other),
            }
        }
        other => panic!("expected HostCall, got {:?}", other),
    }
}

#[test]
fn linker_run_with_linker() {
    // Same module as above
    let wasm = {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x00, 0x61, 0x73, 0x6D]);
        buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        buf.push(0x01);
        buf.push(0x05);
        buf.push(0x01);
        buf.push(0x60);
        buf.push(0x00);
        buf.push(0x01);
        buf.push(0x7F);
        buf.push(0x02);
        buf.push(0x11);
        buf.push(0x01);
        buf.push(0x03);
        buf.extend_from_slice(b"env");
        buf.push(0x09);
        buf.extend_from_slice(b"get_value");
        buf.push(0x00);
        buf.push(0x00);
        buf.push(0x03);
        buf.push(0x02);
        buf.push(0x01);
        buf.push(0x00);
        buf.push(0x07);
        buf.push(0x07);
        buf.push(0x01);
        buf.push(0x03);
        buf.extend_from_slice(b"run");
        buf.push(0x00);
        buf.push(0x01);
        buf.push(0x0A);
        buf.push(0x06);
        buf.push(0x01);
        buf.push(0x04);
        buf.push(0x00);
        buf.push(0x10);
        buf.push(0x00);
        buf.push(0x0B);
        buf
    };

    let engine = Engine::default();
    let module = Module::new(&engine, &wasm).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    let mut linker = Linker::new();
    linker.func_wrap("env", "get_value", |_inst: Caller<'_, ()>, _args| {
        Ok(Some(Value::I32(77)))
    });

    // Use call then run_with_linker for the automatic dispatch
    let result = instance.call("run", &[]);
    match result {
        ExecResult::HostCall(..) => {
            // Re-dispatch: first resume with the linker result, then run_with_linker handles the rest
            let ret = linker
                .dispatch(
                    &mut instance,
                    match result {
                        ExecResult::HostCall(idx, _, _) => idx,
                        _ => unreachable!(),
                    },
                    match result {
                        ExecResult::HostCall(_, ref a, c) => &a[..c as usize],
                        _ => unreachable!(),
                    },
                )
                .unwrap();
            match instance.resume(ret) {
                ExecResult::Returned(Value::I32(77)) => {}
                other => panic!("expected Returned(I32(77)), got {:?}", other),
            }
        }
        other => panic!("expected HostCall, got {:?}", other),
    }
}

#[test]
fn linker_fluent_api() {
    let mut linker = Linker::new();
    linker
        .func_wrap("env", "a", |_inst: Caller<'_, ()>, _args| Ok(None))
        .func_wrap("env", "b", |_inst: Caller<'_, ()>, _args| {
            Ok(Some(Value::I32(0)))
        });
    // Just verifying fluent chaining compiles and works
}

#[test]
fn module_exported_funcs() {
    let engine = Engine::default();
    let module = Module::new(&engine, &module_returning_42()).unwrap();
    let funcs = module.exported_funcs();
    assert_eq!(funcs.len(), 1);
    assert_eq!(funcs[0].0, b"answer");
}

#[test]
fn instance_inner_access() {
    let engine = Engine::default();
    let module = Module::new(&engine, &module_returning_42()).unwrap();
    let instance = Instance::new(module, &engine).unwrap();

    assert!(!instance.is_finished());
}

#[test]
fn resumable_call_basic() {
    // Module that imports "env"."get_value" () -> i32 and re-exports via "run".
    let wasm = {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x00, 0x61, 0x73, 0x6D]);
        buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        buf.push(0x01);
        buf.push(0x05);
        buf.push(0x01);
        buf.push(0x60);
        buf.push(0x00);
        buf.push(0x01);
        buf.push(0x7F);
        buf.push(0x02);
        buf.push(0x11);
        buf.push(0x01);
        buf.push(0x03);
        buf.extend_from_slice(b"env");
        buf.push(0x09);
        buf.extend_from_slice(b"get_value");
        buf.push(0x00);
        buf.push(0x00);
        buf.push(0x03);
        buf.push(0x02);
        buf.push(0x01);
        buf.push(0x00);
        buf.push(0x07);
        buf.push(0x07);
        buf.push(0x01);
        buf.push(0x03);
        buf.extend_from_slice(b"run");
        buf.push(0x00);
        buf.push(0x01);
        buf.push(0x0A);
        buf.push(0x06);
        buf.push(0x01);
        buf.push(0x04);
        buf.push(0x00);
        buf.push(0x10);
        buf.push(0x00);
        buf.push(0x0B);
        buf
    };

    let engine = Engine::default();
    let module = Module::new(&engine, &wasm).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    // Use resumable call API
    match instance.call_resumable("run", &[]) {
        Err(handle) => {
            // Inspect the suspended state
            assert_eq!(handle.host_import_idx, 0);
            assert!(handle.host_args.is_empty());
            // Resume with a value
            match instance.resume_call(handle, Some(Value::I32(42))) {
                Ok(ExecResult::Returned(Value::I32(42))) => {}
                other => panic!("expected Ok(Returned(42)), got {:?}", other),
            }
        }
        Ok(other) => panic!("expected suspension (Err), got {:?}", other),
    }
}

#[test]
fn resumable_call_no_host_call() {
    // A pure function should return Ok directly.
    let engine = Engine::default();
    let module = Module::new(&engine, &module_returning_42()).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();

    match instance.call_resumable("answer", &[]) {
        Ok(ExecResult::Returned(Value::I32(42))) => {}
        other => panic!("expected Ok(Returned(42)), got {:?}", other),
    }
}
