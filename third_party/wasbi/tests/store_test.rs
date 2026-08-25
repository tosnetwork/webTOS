#![allow(clippy::vec_init_then_push)]
#![cfg(feature = "spec-test-internals")]
//! Store multi-module linking tests.

use wasbi::decoder;
use wasbi::engine::Engine;
use wasbi::internal::runtime::ExecResult;
use wasbi::internal::store::Store;
use wasbi::types::{Value, WasmError};

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

/// Helper: encode a WASM section (id, payload).
fn section(id: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![id];
    out.extend_from_slice(&leb128(payload.len() as u32));
    out.extend_from_slice(payload);
    out
}

// ────────────────────────────────────────────────────────────────────────────
// Module A: exports function "add" : (i32, i32) -> i32
//   body: local.get 0 ; local.get 1 ; i32.add
// ────────────────────────────────────────────────────────────────────────────
fn module_a_export_add() -> Vec<u8> {
    let mut buf = Vec::from(HEADER);

    // Type section: one type (i32, i32) -> (i32)
    buf.extend_from_slice(&section(
        0x01,
        &[
            0x01, // 1 type
            0x60, // func
            0x02, 0x7F, 0x7F, // 2 params: i32, i32
            0x01, 0x7F, // 1 result: i32
        ],
    ));

    // Function section: 1 function, type 0
    buf.extend_from_slice(&section(0x03, &[0x01, 0x00]));

    // Export section: export "add" as func 0
    {
        let mut exp = Vec::new();
        exp.push(0x01); // 1 export
        exp.push(0x03); // name len
        exp.extend_from_slice(b"add");
        exp.push(0x00); // func
        exp.push(0x00); // index 0
        buf.extend_from_slice(&section(0x07, &exp));
    }

    // Code section
    {
        let body: &[u8] = &[
            0x00, // 0 locals
            0x20, 0x00, // local.get 0
            0x20, 0x01, // local.get 1
            0x6A, // i32.add
            0x0B, // end
        ];
        let mut code = Vec::new();
        code.push(0x01); // 1 function body
        code.extend_from_slice(&leb128(body.len() as u32));
        code.extend_from_slice(body);
        buf.extend_from_slice(&section(0x0A, &code));
    }

    buf
}

// ────────────────────────────────────────────────────────────────────────────
// Module B: imports "A"."add" : (i32, i32) -> i32
//           exports "call_add" : () -> i32
//           body: i32.const 10 ; i32.const 32 ; call 0
// ────────────────────────────────────────────────────────────────────────────
fn module_b_import_add() -> Vec<u8> {
    let mut buf = Vec::from(HEADER);

    // Type section: 2 types
    //   type 0: (i32, i32) -> (i32)
    //   type 1: () -> (i32)
    buf.extend_from_slice(&section(
        0x01,
        &[
            0x02, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F, // type 0
            0x60, 0x00, 0x01, 0x7F, // type 1
        ],
    ));

    // Import section: import "A"."add" as func, type 0
    {
        let mut imp = Vec::new();
        imp.push(0x01); // 1 import
        imp.push(0x01); // module name len
        imp.push(b'A');
        imp.push(0x03); // field name len
        imp.extend_from_slice(b"add");
        imp.push(0x00); // import kind: func
        imp.push(0x00); // type index 0
        buf.extend_from_slice(&section(0x02, &imp));
    }

    // Function section: 1 local func, type 1
    buf.extend_from_slice(&section(0x03, &[0x01, 0x01]));

    // Export section: export "call_add" as func 1
    {
        let mut exp = Vec::new();
        exp.push(0x01); // 1 export
        exp.push(0x08); // name len
        exp.extend_from_slice(b"call_add");
        exp.push(0x00); // func
        exp.push(0x01); // index 1 (import is 0)
        buf.extend_from_slice(&section(0x07, &exp));
    }

    // Code section
    {
        let body: &[u8] = &[
            0x00, // 0 locals
            0x41, 0x0A, // i32.const 10
            0x41, 0x20, // i32.const 32
            0x10, 0x00, // call 0 (the import)
            0x0B, // end
        ];
        let mut code = Vec::new();
        code.push(0x01);
        code.extend_from_slice(&leb128(body.len() as u32));
        code.extend_from_slice(body);
        buf.extend_from_slice(&section(0x0A, &code));
    }

    buf
}

// ────────────────────────────────────────────────────────────────────────────
// Module that exports a mutable i32 global "g" with initial value 100,
// plus a setter "set_g(i32)" and getter "get_g() -> i32"
// ────────────────────────────────────────────────────────────────────────────
fn module_export_mutable_global() -> Vec<u8> {
    let mut buf = Vec::from(HEADER);

    // Type section:
    //   type 0: (i32) -> ()   — set_g
    //   type 1: () -> (i32)   — get_g
    buf.extend_from_slice(&section(
        0x01,
        &[
            0x02, 0x60, 0x01, 0x7F, 0x00, // type 0
            0x60, 0x00, 0x01, 0x7F, // type 1
        ],
    ));

    // Function section: 2 functions
    buf.extend_from_slice(&section(0x03, &[0x02, 0x00, 0x01]));

    // Global section: 1 global, i32, mutable, init = 100
    // Note: i32.const uses signed LEB128. 100 = 0x64 = 0b01100100.
    // Bit 6 is set so a single byte 0x64 would be sign-extended to -28.
    // Use two bytes: 0xE4 0x00 for unsigned 100 in signed LEB128.
    buf.extend_from_slice(&section(
        0x06,
        &[
            0x01, // 1 global
            0x7F, // i32
            0x01, // mutable
            0x41, 0xE4, 0x00, // i32.const 100 (signed LEB128)
            0x0B, // end
        ],
    ));

    // Export section: "g" = global 0, "set_g" = func 0, "get_g" = func 1
    {
        let mut exp = Vec::new();
        exp.push(0x03); // 3 exports
        exp.push(0x01);
        exp.push(b'g');
        exp.push(0x03); // global
        exp.push(0x00); // index 0
        exp.push(0x05);
        exp.extend_from_slice(b"set_g");
        exp.push(0x00); // func
        exp.push(0x00); // index 0
        exp.push(0x05);
        exp.extend_from_slice(b"get_g");
        exp.push(0x00); // func
        exp.push(0x01); // index 1
        buf.extend_from_slice(&section(0x07, &exp));
    }

    // Code section
    {
        // set_g: local.get 0 ; global.set 0
        let body0: &[u8] = &[
            0x00, 0x20, 0x00, // local.get 0
            0x24, 0x00, // global.set 0
            0x0B,
        ];
        // get_g: global.get 0
        let body1: &[u8] = &[
            0x00, 0x23, 0x00, // global.get 0
            0x0B,
        ];
        let mut code = Vec::new();
        code.push(0x02);
        code.extend_from_slice(&leb128(body0.len() as u32));
        code.extend_from_slice(body0);
        code.extend_from_slice(&leb128(body1.len() as u32));
        code.extend_from_slice(body1);
        buf.extend_from_slice(&section(0x0A, &code));
    }

    buf
}

// ────────────────────────────────────────────────────────────────────────────
// Module that imports "A"."g" as mutable i32 global, and exports "read_g"
//   read_g() -> i32 : global.get 0  (the imported global)
// ────────────────────────────────────────────────────────────────────────────
fn module_import_mutable_global() -> Vec<u8> {
    let mut buf = Vec::from(HEADER);

    // Type section: () -> (i32)
    buf.extend_from_slice(&section(0x01, &[0x01, 0x60, 0x00, 0x01, 0x7F]));

    // Import section: "A"."g" as global i32 mutable
    {
        let mut imp = Vec::new();
        imp.push(0x01);
        imp.push(0x01);
        imp.push(b'A');
        imp.push(0x01);
        imp.push(b'g');
        imp.push(0x03); // import kind: global
        imp.push(0x7F); // i32
        imp.push(0x01); // mutable
        buf.extend_from_slice(&section(0x02, &imp));
    }

    // Function section: 1 func, type 0
    buf.extend_from_slice(&section(0x03, &[0x01, 0x00]));

    // Export section: "read_g" = func 0
    {
        let mut exp = Vec::new();
        exp.push(0x01);
        exp.push(0x06);
        exp.extend_from_slice(b"read_g");
        exp.push(0x00); // func
        exp.push(0x00); // index 0
        buf.extend_from_slice(&section(0x07, &exp));
    }

    // Code section
    {
        // read_g: global.get 0 (imported global)
        let body: &[u8] = &[
            0x00, 0x23, 0x00, // global.get 0
            0x0B,
        ];
        let mut code = Vec::new();
        code.push(0x01);
        code.extend_from_slice(&leb128(body.len() as u32));
        code.extend_from_slice(body);
        buf.extend_from_slice(&section(0x0A, &code));
    }

    buf
}

// ────────────────────────────────────────────────────────────────────────────
// Module that exports a simple "const42" : () -> i32 that returns 42
// ────────────────────────────────────────────────────────────────────────────
fn module_const42() -> Vec<u8> {
    let mut buf = Vec::from(HEADER);

    buf.extend_from_slice(&section(0x01, &[0x01, 0x60, 0x00, 0x01, 0x7F]));
    buf.extend_from_slice(&section(0x03, &[0x01, 0x00]));
    {
        let mut exp = Vec::new();
        exp.push(0x01);
        exp.push(0x07);
        exp.extend_from_slice(b"const42");
        exp.push(0x00);
        exp.push(0x00);
        buf.extend_from_slice(&section(0x07, &exp));
    }
    {
        let body: &[u8] = &[
            0x00, 0x41, 0x2A, // i32.const 42
            0x0B,
        ];
        let mut code = Vec::new();
        code.push(0x01);
        code.extend_from_slice(&leb128(body.len() as u32));
        code.extend_from_slice(body);
        buf.extend_from_slice(&section(0x0A, &code));
    }

    buf
}

// ────────────────────────────────────────────────────────────────────────────
// Module that imports "alias"."const42" : () -> i32 and re-exports as "proxy"
// ────────────────────────────────────────────────────────────────────────────
fn module_import_from_alias(import_module: &str, import_field: &str) -> Vec<u8> {
    let mut buf = Vec::from(HEADER);

    // Type section: () -> (i32)
    buf.extend_from_slice(&section(0x01, &[0x01, 0x60, 0x00, 0x01, 0x7F]));

    // Import section
    {
        let mut imp = Vec::new();
        imp.push(0x01);
        imp.extend_from_slice(&leb128(import_module.len() as u32));
        imp.extend_from_slice(import_module.as_bytes());
        imp.extend_from_slice(&leb128(import_field.len() as u32));
        imp.extend_from_slice(import_field.as_bytes());
        imp.push(0x00); // func
        imp.push(0x00); // type 0
        buf.extend_from_slice(&section(0x02, &imp));
    }

    // Function section: 1 func, type 0
    buf.extend_from_slice(&section(0x03, &[0x01, 0x00]));

    // Export: "proxy" = func 1 (local func that calls import)
    {
        let mut exp = Vec::new();
        exp.push(0x01);
        exp.push(0x05);
        exp.extend_from_slice(b"proxy");
        exp.push(0x00);
        exp.push(0x01); // func index 1 (import is 0)
        buf.extend_from_slice(&section(0x07, &exp));
    }

    // Code section: proxy calls import 0
    {
        let body: &[u8] = &[
            0x00, 0x10, 0x00, // call 0 (import)
            0x0B,
        ];
        let mut code = Vec::new();
        code.push(0x01);
        code.extend_from_slice(&leb128(body.len() as u32));
        code.extend_from_slice(body);
        buf.extend_from_slice(&section(0x0A, &code));
    }

    buf
}

// ────────────────────────────────────────────────────────────────────────────
// Module that imports "A"."add" with WRONG type: (i32) -> (i32) instead of
// (i32, i32) -> (i32)
// ────────────────────────────────────────────────────────────────────────────
fn module_wrong_import_type() -> Vec<u8> {
    let mut buf = Vec::from(HEADER);

    // Type section: wrong arity — only 1 param instead of 2
    buf.extend_from_slice(&section(
        0x01,
        &[
            0x01, 0x60, 0x01, 0x7F, 0x01, 0x7F, // (i32) -> (i32)
        ],
    ));

    // Import section: "A"."add" as func, type 0 (wrong type)
    {
        let mut imp = Vec::new();
        imp.push(0x01);
        imp.push(0x01);
        imp.push(b'A');
        imp.push(0x03);
        imp.extend_from_slice(b"add");
        imp.push(0x00); // func
        imp.push(0x00); // type 0
        buf.extend_from_slice(&section(0x02, &imp));
    }

    // Function section: no local funcs
    buf.extend_from_slice(&section(0x03, &[0x00]));

    // Code section: empty (no local funcs)
    buf.extend_from_slice(&section(0x0A, &[0x00]));

    buf
}

// ────────────────────────────────────────────────────────────────────────────
// Module that exports "write_mem": writes i32.const 0xAB at address 0
//   uses its own memory
// ────────────────────────────────────────────────────────────────────────────
fn module_export_memory_with_writer() -> Vec<u8> {
    let mut buf = Vec::from(HEADER);

    // Type section: () -> ()
    buf.extend_from_slice(&section(0x01, &[0x01, 0x60, 0x00, 0x00]));

    // Function section: 1 func
    buf.extend_from_slice(&section(0x03, &[0x01, 0x00]));

    // Memory section: 1 page
    buf.extend_from_slice(&section(0x05, &[0x01, 0x00, 0x01]));

    // Export section: "mem" = memory 0, "write_mem" = func 0
    {
        let mut exp = Vec::new();
        exp.push(0x02);
        exp.push(0x03);
        exp.extend_from_slice(b"mem");
        exp.push(0x02); // memory
        exp.push(0x00);
        exp.push(0x09);
        exp.extend_from_slice(b"write_mem");
        exp.push(0x00); // func
        exp.push(0x00);
        buf.extend_from_slice(&section(0x07, &exp));
    }

    // Code section: write_mem stores 0xAB at address 0
    {
        let body: &[u8] = &[
            0x00, 0x41, 0x00, // i32.const 0 (address)
            0x41, 0xAB, 0x01, // i32.const 171 (0xAB)
            0x3A, 0x00, 0x00, // i32.store8 align=0 offset=0
            0x0B,
        ];
        let mut code = Vec::new();
        code.push(0x01);
        code.extend_from_slice(&leb128(body.len() as u32));
        code.extend_from_slice(body);
        buf.extend_from_slice(&section(0x0A, &code));
    }

    buf
}

// ────────────────────────────────────────────────────────────────────────────
// Module that imports "A"."mem" and exports "read_mem" : () -> i32
//   reads byte at address 0 from imported memory
// ────────────────────────────────────────────────────────────────────────────
fn module_import_memory_reader() -> Vec<u8> {
    let mut buf = Vec::from(HEADER);

    // Type section: () -> (i32)
    buf.extend_from_slice(&section(0x01, &[0x01, 0x60, 0x00, 0x01, 0x7F]));

    // Import: "A"."mem" as memory min 1
    {
        let mut imp = Vec::new();
        imp.push(0x01);
        imp.push(0x01);
        imp.push(b'A');
        imp.push(0x03);
        imp.extend_from_slice(b"mem");
        imp.push(0x02); // memory
        imp.push(0x00); // no max
        imp.push(0x01); // min = 1
        buf.extend_from_slice(&section(0x02, &imp));
    }

    // Function section
    buf.extend_from_slice(&section(0x03, &[0x01, 0x00]));

    // Export: "read_mem" = func 0
    {
        let mut exp = Vec::new();
        exp.push(0x01);
        exp.push(0x08);
        exp.extend_from_slice(b"read_mem");
        exp.push(0x00);
        exp.push(0x00);
        buf.extend_from_slice(&section(0x07, &exp));
    }

    // Code section: load byte at address 0
    {
        let body: &[u8] = &[
            0x00, 0x41, 0x00, // i32.const 0
            0x2D, 0x00, 0x00, // i32.load8_u align=0 offset=0
            0x0B,
        ];
        let mut code = Vec::new();
        code.push(0x01);
        code.extend_from_slice(&leb128(body.len() as u32));
        code.extend_from_slice(body);
        buf.extend_from_slice(&section(0x0A, &code));
    }

    buf
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn single_module_instantiation_and_call() {
    let wasm = module_a_export_add();
    let module = decoder::decode(&wasm).expect("decode failed");

    let engine = Engine::default();
    let mut store = Store::new(engine);
    let idx = store
        .instantiate(module, Some("A"))
        .expect("instantiate failed");

    let result = store.call(idx, "add", &[Value::I32(3), Value::I32(4)]);
    match result {
        ExecResult::Returned(Value::I32(7)) => {}
        other => panic!("expected Returned(I32(7)), got {:?}", other),
    }
}

#[test]
fn two_modules_import_export_function() {
    let engine = Engine::default();
    let mut store = Store::new(engine);

    // Module A exports "add"
    let mod_a = decoder::decode(&module_a_export_add()).expect("decode A");
    let idx_a = store.instantiate(mod_a, Some("A")).expect("instantiate A");

    // Module B imports "A"."add" and exports "call_add"
    let mod_b = decoder::decode(&module_b_import_add()).expect("decode B");
    let idx_b = store.instantiate(mod_b, Some("B")).expect("instantiate B");

    // Call B's "call_add" which internally calls A's "add(10, 32)"
    let result = store.call(idx_b, "call_add", &[]);
    match result {
        ExecResult::Returned(Value::I32(42)) => {}
        other => panic!("expected Returned(I32(42)), got {:?}", other),
    }

    // Verify A's "add" still works directly
    let result = store.call(idx_a, "add", &[Value::I32(100), Value::I32(200)]);
    match result {
        ExecResult::Returned(Value::I32(300)) => {}
        other => panic!("expected Returned(I32(300)), got {:?}", other),
    }
}

#[test]
#[ignore] // Store syncs by size heuristic, not true shared memory — see docs/LIMITATIONS.md
fn memory_sharing_write_in_a_read_in_b() {
    let engine = Engine::default();
    let mut store = Store::new(engine);

    // Module A exports memory and a write function
    let mod_a = decoder::decode(&module_export_memory_with_writer()).expect("decode A");
    let idx_a = store.instantiate(mod_a, Some("A")).expect("instantiate A");

    // Module B imports A's memory and reads from it
    let mod_b = decoder::decode(&module_import_memory_reader()).expect("decode B");
    let idx_b = store.instantiate(mod_b, Some("B")).expect("instantiate B");

    // Write 0xAB at address 0 in module A
    let result = store.call(idx_a, "write_mem", &[]);
    match result {
        ExecResult::Ok => {}
        other => panic!("expected Ok from write_mem, got {:?}", other),
    }

    // Read from address 0 in module B — should see 0xAB (shared memory)
    let result = store.call(idx_b, "read_mem", &[]);
    match result {
        ExecResult::Returned(Value::I32(0xAB)) => {}
        other => panic!("expected Returned(I32(0xAB)), got {:?}", other),
    }
}

#[test]
fn global_sharing_modify_in_a_read_in_b() {
    let engine = Engine::default();
    let mut store = Store::new(engine);

    // Module A: mutable global "g" init=100, exports set_g/get_g
    let mod_a = decoder::decode(&module_export_mutable_global()).expect("decode A");
    let idx_a = store.instantiate(mod_a, Some("A")).expect("instantiate A");

    // Module B: imports "A"."g", exports read_g
    let mod_b = decoder::decode(&module_import_mutable_global()).expect("decode B");
    let idx_b = store.instantiate(mod_b, Some("B")).expect("instantiate B");

    // Initial value should be 100
    let result = store.call(idx_b, "read_g", &[]);
    match result {
        ExecResult::Returned(Value::I32(100)) => {}
        other => panic!("expected initial Returned(I32(100)), got {:?}", other),
    }

    // Set global to 999 via module A
    let result = store.call(idx_a, "set_g", &[Value::I32(999)]);
    match result {
        ExecResult::Ok => {}
        other => panic!("expected Ok from set_g, got {:?}", other),
    }

    // Read from module B — should see 999
    let result = store.call(idx_b, "read_g", &[]);
    match result {
        ExecResult::Returned(Value::I32(999)) => {}
        other => panic!("expected Returned(I32(999)), got {:?}", other),
    }

    // Also verify via get_g in module A
    let result = store.call(idx_a, "get_g", &[]);
    match result {
        ExecResult::Returned(Value::I32(999)) => {}
        other => panic!("expected Returned(I32(999)) from A, got {:?}", other),
    }
}

#[test]
fn register_and_alias() {
    let engine = Engine::default();
    let mut store = Store::new(engine);

    // Module that exports "const42"
    let mod_orig = decoder::decode(&module_const42()).expect("decode orig");
    let idx = store
        .instantiate(mod_orig, Some("original"))
        .expect("instantiate");

    // Register the same instance under an alias name
    store.register("alias", idx);

    // Verify lookup works for both names
    assert_eq!(store.lookup("original"), Some(idx));
    assert_eq!(store.lookup("alias"), Some(idx));

    // Module that imports from "alias"."const42"
    let mod_c = decoder::decode(&module_import_from_alias("alias", "const42")).expect("decode C");
    let idx_c = store.instantiate(mod_c, Some("C")).expect("instantiate C");

    // Call proxy which calls aliased const42
    let result = store.call(idx_c, "proxy", &[]);
    match result {
        ExecResult::Returned(Value::I32(42)) => {}
        other => panic!("expected Returned(I32(42)), got {:?}", other),
    }
}

#[test]
fn import_validation_wrong_function_type() {
    let engine = Engine::default();
    let mut store = Store::new(engine);

    // Module A: exports "add" : (i32, i32) -> (i32)
    let mod_a = decoder::decode(&module_a_export_add()).expect("decode A");
    store.instantiate(mod_a, Some("A")).expect("instantiate A");

    // Module with wrong import type: (i32) -> (i32) instead of (i32, i32) -> (i32)
    let mod_bad = decoder::decode(&module_wrong_import_type()).expect("decode bad");
    let result = store.instantiate(mod_bad, None);
    match result {
        Err(WasmError::TypeMismatch) => {}
        Ok(_) => panic!("expected TypeMismatch error, but instantiation succeeded"),
        Err(e) => panic!("expected TypeMismatch, got {:?}", e),
    }
}
