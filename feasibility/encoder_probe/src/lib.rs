// Probe: does wasm-encoder compile to wasm32 and emit a working module at
// runtime, from inside a wasm module? Builds a tiny add function and returns
// its byte length so the call cannot be optimized away.
use wasm_encoder::{
    CodeSection, ExportKind, ExportSection, Function, FunctionSection, Instruction,
    Module, TypeSection, ValType,
};

#[no_mangle]
pub extern "C" fn emit_add_module(out_ptr: *mut u8, out_cap: usize) -> usize {
    let mut m = Module::new();
    let mut types = TypeSection::new();
    types.ty().function([ValType::I32, ValType::I32], [ValType::I32]);
    m.section(&types);
    let mut funcs = FunctionSection::new();
    funcs.function(0);
    m.section(&funcs);
    let mut exports = ExportSection::new();
    exports.export("add", ExportKind::Func, 0);
    m.section(&exports);
    let mut code = CodeSection::new();
    let mut f = Function::new([]);
    f.instruction(&Instruction::LocalGet(0));
    f.instruction(&Instruction::LocalGet(1));
    f.instruction(&Instruction::I32Add);
    f.instruction(&Instruction::End);
    code.function(&f);
    m.section(&code);
    let bytes = m.finish();
    let n = bytes.len().min(out_cap);
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr, n); }
    bytes.len()
}
