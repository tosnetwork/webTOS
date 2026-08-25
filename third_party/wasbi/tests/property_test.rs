//! Property-based tests for wasbi invariants.

use wasbi::decoder::decode;
use wasbi::prelude::*;
use wasbi::validator::validate;

const HEADER: &[u8] = &[0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];

/// Property: decode never panics on any 8-byte prefix
#[test]
fn decode_never_panics_on_short_inputs() {
    for len in 0..=8 {
        for b in 0..=255u8 {
            let mut input = vec![b; len];
            if len >= 4 {
                // Try with valid magic but varying rest
                input[0] = 0x00;
                input[1] = 0x61;
                input[2] = 0x73;
                input[3] = 0x6D;
            }
            let _ = decode(&input);
        }
    }
}

/// Property: valid modules always have non-negative function counts
#[test]
fn decoded_module_counts_are_consistent() {
    let module = decode(HEADER).unwrap();
    assert!(
        module.get_func_types().len() >= module.get_functions().len()
            || module.get_functions().is_empty()
    );
    assert_eq!(module.get_exports().len(), 0); // empty module
    assert_eq!(module.get_imports().len(), 0);
}

/// Property: validation of an empty module always succeeds
#[test]
fn empty_module_always_valid() {
    let module = decode(HEADER).unwrap();
    validate(&module).unwrap();
}

/// Property: decode errors are always in the Decode layer
#[test]
fn decode_errors_are_decode_layer() {
    use wasbi::types::ErrorLayer;
    let bad_inputs: Vec<&[u8]> = vec![
        &[],
        &[0xFF],
        &[0x00, 0x61, 0x73, 0x6D, 0x02, 0x00, 0x00, 0x00], // bad version
        &[0x00, 0x61],                                     // truncated
    ];
    for input in bad_inputs {
        if let Err(e) = decode(input) {
            assert_eq!(
                e.layer(),
                ErrorLayer::Decode,
                "input {:?} produced non-decode error",
                input
            );
        }
    }
}

/// Property: re-decoding the same bytes produces equivalent modules
#[test]
fn decode_is_deterministic() {
    // Build a module with various sections
    let mut buf = Vec::from(HEADER);
    buf.extend_from_slice(&[0x01, 0x04, 0x01, 0x60, 0x00, 0x00]); // type
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]); // func
    buf.extend_from_slice(&[0x0A, 0x04, 0x01, 0x02, 0x00, 0x0B]); // code

    let m1 = decode(&buf).unwrap();
    let m2 = decode(&buf).unwrap();
    assert_eq!(m1.get_func_types().len(), m2.get_func_types().len());
    assert_eq!(m1.get_functions().len(), m2.get_functions().len());
    assert_eq!(m1.get_exports().len(), m2.get_exports().len());
    assert_eq!(m1.get_code().len(), m2.get_code().len());
}

/// Property: fuel consumption is monotonic (fuel only decreases)
#[test]
fn fuel_only_decreases() {
    let mut buf = Vec::from(HEADER);
    buf.extend_from_slice(&[0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F]); // () -> (i32)
    buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    buf.extend_from_slice(&[0x07, 0x05, 0x01, 0x01, b'f', 0x00, 0x00]);
    buf.extend_from_slice(&[0x0A, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2A, 0x0B]);

    let engine = Engine::default();
    let module = Module::new(&engine, &buf).unwrap();
    let mut instance = Instance::new(module, &engine).unwrap();
    let fuel_before = instance.fuel();
    let _ = instance.call("f", &[]);
    let fuel_after = instance.fuel();
    assert!(
        fuel_after < fuel_before,
        "fuel should decrease after execution"
    );
}

/// Property: instantiation of a valid module never panics
#[test]
fn valid_module_instantiation_never_panics() {
    let modules: Vec<Vec<u8>> = vec![
        // Empty module
        Vec::from(HEADER),
        // Module with memory
        {
            let mut b = Vec::from(HEADER);
            b.extend_from_slice(&[0x05, 0x03, 0x01, 0x00, 0x01]);
            b
        },
        // Module with global
        {
            let mut b = Vec::from(HEADER);
            b.extend_from_slice(&[0x06, 0x06, 0x01, 0x7F, 0x00, 0x41, 0x00, 0x0B]);
            b
        },
        // Module with table
        {
            let mut b = Vec::from(HEADER);
            b.extend_from_slice(&[0x04, 0x04, 0x01, 0x70, 0x00, 0x01]);
            b
        },
    ];

    let engine = Engine::default();
    for wasm in &modules {
        let module = Module::new(&engine, wasm).unwrap();
        let _ = Instance::new(module, &engine).unwrap();
    }
}
