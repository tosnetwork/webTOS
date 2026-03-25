#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz decoder + validator: any input must not panic
    if let Ok(module) = wasm_spec_test::wasm::decoder::decode(data) {
        let _ = wasm_spec_test::wasm::validator::validate(&module);
    }
});
