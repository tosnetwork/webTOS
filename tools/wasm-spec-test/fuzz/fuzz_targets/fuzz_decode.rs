#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the decoder: any input must not panic
    let _ = wasm_spec_test::wasm::decoder::decode(data);
});
