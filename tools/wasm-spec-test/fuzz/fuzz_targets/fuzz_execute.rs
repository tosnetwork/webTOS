#![no_main]
use libfuzzer_sys::fuzz_target;
use wasm_spec_test::wasm::runtime::WasmInstance;
use wasm_spec_test::wasm::types::RuntimeClass;

fuzz_target!(|data: &[u8]| {
    // Fuzz full pipeline: decode → validate → instantiate → execute start
    // Any input must not panic
    let module = match wasm_spec_test::wasm::decoder::decode(data) {
        Ok(m) => m,
        Err(_) => return,
    };
    if wasm_spec_test::wasm::validator::validate(&module).is_err() {
        return;
    }
    let mut instance = match WasmInstance::with_class(module, 100_000, RuntimeClass::BestEffort) {
        Ok(i) => i,
        Err(_) => return,
    };
    let _ = instance.run_start();
});
