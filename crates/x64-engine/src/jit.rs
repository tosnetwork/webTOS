//! p-code block → WebAssembly translation (the JIT's front half).
//!
//! A hot block is translated once to a wasm function that executes its p-code
//! straight through, and the browser runs that function at near-native speed
//! instead of the interpreter simulating each op. This module emits the wasm;
//! the host instantiates it and dispatches to it. `feasibility/` measured why
//! this is worth doing (~490x on the table for compute) and proved the
//! mechanism; this is the real thing.
//!
//! ## The register space
//!
//! p-code operates on varnodes — typed storage slots with an id, an offset,
//! and a size. The interpreter keeps them in one flat byte array (`Regs`,
//! 0x20000 bytes). The emitted wasm imports that array as linear memory and
//! reads and writes the *same* byte offsets, so JIT'd code and interpreted
//! code see the same registers. [`var_offset`] must therefore match the
//! interpreter's `Regs::var_offset` exactly, which the gate checks by
//! comparing the whole register space bit for bit after a block runs both
//! ways.
//!
//! ## Tiered by construction
//!
//! [`translate_block`] returns `None` the moment it meets an op it cannot
//! translate. That block stays interpreted; only fully-translatable blocks
//! become wasm. The JIT never has to be complete to be correct — it only ever
//! compiles what it fully understands, and the interpreter is the floor.
//!
//! ## For the op handlers
//!
//! Each p-code op is handled in [`translate_instruction`]. A handler emits
//! wasm that computes the op's result and stores it to the output varnode,
//! using the shared helpers below so every handler addresses the register
//! space the same way:
//!
//! - [`emit_store_addr`] pushes the output's byte address (wasm `store` wants
//!   the address underneath the value, so this comes first).
//! - [`emit_load`] pushes an operand — a varnode loaded from memory, or a
//!   constant — as the wasm type for its size.
//! - [`emit_store`] stores the value on top of the stack to the output.
//!
//! So a binary op is: store-addr(out), load(a), load(b), the wasm op,
//! store(out). `IntAdd` below is the worked reference; the rest follow it.

use pcode::{Op, Value, VarNode};
use wasm_encoder::{
    CodeSection, EntityType, ExportKind, ExportSection, Function, FunctionSection, Instruction,
    MemArg, MemoryType, Module, TypeSection, ValType,
};

/// The register space is 0x20000 bytes — two 64 KiB wasm pages.
pub const REG_SPACE_BYTES: u32 = 0x20000;
const REG_PAGES: u64 = (REG_SPACE_BYTES as u64).div_ceil(65536);

/// The byte offset of a varnode in the register space.
///
/// This mirrors `icicle_cpu::Regs::var_offset` exactly. It has to: the wasm
/// this module emits reads and writes these offsets, and the interpreter reads
/// and writes the same array. The gate compares the whole space after a block
/// runs both ways, so a mismatch here fails loudly rather than silently
/// corrupting a register.
pub fn var_offset(var: VarNode) -> u32 {
    const REG_OFFSET: i32 = 0x200 * 16;
    (REG_OFFSET + var.id as i32 * 16 + var.offset as i32) as u32
}

/// The wasm value type a varnode of this byte size is computed in.
///
/// 1, 2, and 4-byte varnodes are computed in `i32`; 8-byte in `i64`. Wider
/// sizes — 10-byte x87, 16-byte SIMD — have no direct wasm type and are not
/// handled here; a block using them bails to the interpreter.
pub fn wasm_ty(size: u8) -> Option<ValType> {
    match size {
        1 | 2 | 4 => Some(ValType::I32),
        8 => Some(ValType::I64),
        _ => None,
    }
}

/// Whether the two operands and the output of a same-width op are all a size
/// this JIT handles. A convenience for handlers whose inputs and output share
/// a width (the arithmetic and logic ops).
pub fn same_width(out: VarNode, a: Value, b: Value) -> Option<u8> {
    let size = out.size;
    wasm_ty(size)?;
    if a.size() != size || b.size() != size {
        return None;
    }
    Some(size)
}

/// Pushes the byte address of `out` in the register space, so a following
/// `store` writes there. Wasm `store` consumes `[address, value]`, address
/// first, which is why this is emitted before the value is computed.
pub fn emit_store_addr(f: &mut Function, out: VarNode) {
    f.instruction(&Instruction::I32Const(var_offset(out) as i32));
}

/// Pushes an operand onto the wasm stack in the wasm type for `size`.
///
/// A constant becomes an `iN.const`. A varnode becomes a load from the
/// register space at its offset — zero-extended for the sub-word sizes, since
/// a varnode's bytes are its value and the high bits of the wasm register are
/// not part of it. Returns `None` for a size this JIT does not handle.
pub fn emit_load(f: &mut Function, value: Value, size: u8) -> Option<()> {
    let ty = wasm_ty(size)?;
    match value {
        Value::Const(c, _) => match ty {
            ValType::I32 => f.instruction(&Instruction::I32Const(c as i32)),
            ValType::I64 => f.instruction(&Instruction::I64Const(c as i64)),
            _ => return None,
        },
        Value::Var(var) => {
            let addr = var_offset(var);
            f.instruction(&Instruction::I32Const(addr as i32));
            let arg = MemArg {
                offset: 0,
                align: 0,
                memory_index: 0,
            };
            match size {
                1 => f.instruction(&Instruction::I32Load8U(arg)),
                2 => f.instruction(&Instruction::I32Load16U(arg)),
                4 => f.instruction(&Instruction::I32Load(arg)),
                8 => f.instruction(&Instruction::I64Load(arg)),
                _ => return None,
            }
        }
    };
    Some(())
}

/// Stores the value on top of the stack to `out`, given the address `emit_store_addr`
/// pushed underneath it. Sub-word sizes store only their low bytes.
pub fn emit_store(f: &mut Function, out: VarNode) -> Option<()> {
    wasm_ty(out.size)?;
    let arg = MemArg {
        offset: 0,
        align: 0,
        memory_index: 0,
    };
    match out.size {
        1 => f.instruction(&Instruction::I32Store8(arg)),
        2 => f.instruction(&Instruction::I32Store16(arg)),
        4 => f.instruction(&Instruction::I32Store(arg)),
        8 => f.instruction(&Instruction::I64Store(arg)),
        _ => return None,
    };
    Some(())
}

/// Translates one p-code instruction into wasm appended to `f`, or returns
/// `None` if the op (or a size it uses) is not handled — which bails the whole
/// block to the interpreter.
///
/// This is the dispatch the op handlers plug into. `IntAdd` is the worked
/// reference; each remaining integer op is one arm here, mostly a single wasm
/// binary instruction between the shared load/store helpers.
pub fn translate_instruction(f: &mut Function, inst: &pcode::Instruction) -> Option<()> {
    let out = inst.output;
    let [a, b] = inst.inputs.get();

    match inst.op {
        // Metadata: marks an instruction boundary. No machine effect; the
        // interpreter uses it for the instruction count, which the block
        // driver accounts for separately. Emit nothing.
        Op::InstructionMarker => Some(()),

        // The reference. out = a + b, all one width.
        //   store-addr(out); load(a); load(b); iN.add; store(out)
        Op::IntAdd => {
            let size = same_width(out, a, b)?;
            emit_store_addr(f, out);
            emit_load(f, a, size)?;
            emit_load(f, b, size)?;
            match size {
                8 => f.instruction(&Instruction::I64Add),
                _ => f.instruction(&Instruction::I32Add),
            };
            emit_store(f, out)
        }

        // Everything else is not handled yet — the three op slices land here.
        // Until then, any block containing another op bails to the interpreter.
        _ => None,
    }
}

/// Translates a whole p-code block to a wasm module whose exported `run`
/// executes it against the register space (imported as memory `env.regs`), or
/// returns `None` if any instruction is unhandled.
///
/// The module is self-contained bytes ready for `WebAssembly.instantiate`; the
/// host supplies the register memory and calls `run`.
pub fn translate_block(block: &pcode::Block) -> Option<Vec<u8>> {
    let mut body = Function::new([]);
    for inst in &block.instructions {
        translate_instruction(&mut body, inst)?;
    }
    body.instruction(&Instruction::End);

    let mut module = Module::new();

    let mut types = TypeSection::new();
    types.ty().function([], []);
    module.section(&types);

    // Import the register space as memory, so JIT'd code and the interpreter
    // share it. The host binds `env.regs` to the real register bytes.
    let mut imports = wasm_encoder::ImportSection::new();
    imports.import(
        "env",
        "regs",
        EntityType::Memory(MemoryType {
            minimum: REG_PAGES,
            maximum: None,
            memory64: false,
            shared: false,
            page_size_log2: None,
        }),
    );
    module.section(&imports);

    let mut funcs = FunctionSection::new();
    funcs.function(0);
    module.section(&funcs);

    let mut exports = ExportSection::new();
    exports.export("run", ExportKind::Func, 0);
    module.section(&exports);

    let mut code = CodeSection::new();
    code.function(&body);
    module.section(&code);

    Some(module.finish())
}
