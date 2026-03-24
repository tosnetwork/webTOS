//! WASM binary format types for the ATOS minimal interpreter.
//!
//! Small tables use fixed-size arrays; large buffers (code, memory)
//! are heap-allocated via `Vec`.

/// Value types supported by this interpreter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValType {
    I32,
    I64,
    F32,
    F64,
}

/// A runtime value on the operand stack or in a local variable.
#[derive(Debug, Clone, Copy)]
pub enum Value {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
}

impl Value {
    /// Return zero for the given type.
    pub const fn default_for(ty: ValType) -> Self {
        match ty {
            ValType::I32 => Value::I32(0),
            ValType::I64 => Value::I64(0),
            ValType::F32 => Value::F32(0.0),
            ValType::F64 => Value::F64(0.0),
        }
    }

    pub fn as_i32(self) -> i32 {
        match self {
            Value::I32(v) => v,
            Value::I64(v) => v as i32,
            Value::F32(v) => v as i32,
            Value::F64(v) => v as i32,
        }
    }

    pub fn as_i64(self) -> i64 {
        match self {
            Value::I32(v) => v as i64,
            Value::I64(v) => v,
            Value::F32(v) => v as i64,
            Value::F64(v) => v as i64,
        }
    }

    pub fn as_f32(self) -> f32 {
        match self {
            Value::I32(v) => v as f32,
            Value::I64(v) => v as f32,
            Value::F32(v) => v,
            Value::F64(v) => v as f32,
        }
    }

    pub fn as_f64(self) -> f64 {
        match self {
            Value::I32(v) => v as f64,
            Value::I64(v) => v as f64,
            Value::F32(v) => v as f64,
            Value::F64(v) => v,
        }
    }
}

/// Per-agent execution class controlling which WASM features are allowed.
///
/// - **ProofGrade**: strict determinism — no floats, no SIMD, no threads.
///   Execution can be replayed and independently verified. Produces
///   cryptographically meaningful ExecutionReceipts.
/// - **ReplayGrade**: relaxed — floats and SIMD allowed, no threads.
///   Execution is reproducible on the same hardware but not formally provable.
///   Suitable for AI inference, data processing, and general computation.
/// - **BestEffort**: full features — floats, SIMD, threads (future).
///   No replay or proof guarantees. Suitable for tool agents and I/O helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RuntimeClass {
    ProofGrade = 0,
    ReplayGrade = 1,
    BestEffort = 2,
}

/// Default runtime class for new agents.
pub const DEFAULT_RUNTIME_CLASS: RuntimeClass = RuntimeClass::ProofGrade;

/// Legacy constant — kept for backward compatibility during transition.
/// New code should use `RuntimeClass` per-instance instead.
pub const STRICT_DETERMINISM: bool = true;

/// WASM instruction opcodes — full MVP set (float opcodes always defined,
/// enforcement is per-instance via RuntimeClass).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    // ── Control ────────────────────────────────────────────────────────
    Unreachable = 0x00,
    Nop = 0x01,
    Block = 0x02,
    Loop = 0x03,
    If = 0x04,
    Else = 0x05,
    End = 0x0B,
    Br = 0x0C,
    BrIf = 0x0D,
    Return = 0x0F,
    Call = 0x10,

    BrTable = 0x0E,
    CallIndirect = 0x11,
    ReturnCall = 0x12,
    ReturnCallIndirect = 0x13,

    // ── Parametric ─────────────────────────────────────────────────────
    Drop = 0x1A,
    Select = 0x1B,

    // ── Variable access ────────────────────────────────────────────────
    LocalGet = 0x20,
    LocalSet = 0x21,
    LocalTee = 0x22,
    GlobalGet = 0x23,
    GlobalSet = 0x24,
    TableGet = 0x25,
    TableSet = 0x26,

    // ── Memory ──────────────────────────────────────────────────────────
    I32Load = 0x28,
    I64Load = 0x29,
    F32Load = 0x2A,
    F64Load = 0x2B,
    I32Load8S = 0x2C,
    I32Load8U = 0x2D,
    I32Load16S = 0x2E,
    I32Load16U = 0x2F,
    I64Load8S = 0x30,
    I64Load8U = 0x31,
    I64Load16S = 0x32,
    I64Load16U = 0x33,
    I64Load32S = 0x34,
    I64Load32U = 0x35,
    I32Store = 0x36,
    I64Store = 0x37,
    F32Store = 0x38,
    F64Store = 0x39,
    I32Store8 = 0x3A,
    I32Store16 = 0x3B,
    I64Store8 = 0x3C,
    I64Store16 = 0x3D,
    I64Store32 = 0x3E,
    MemorySize = 0x3F,
    MemoryGrow = 0x40,

    // ── Constants ──────────────────────────────────────────────────────
    I32Const = 0x41,
    I64Const = 0x42,
    F32Const = 0x43,
    F64Const = 0x44,

    // ── i32 Comparison ─────────────────────────────────────────────────
    I32Eqz = 0x45,
    I32Eq = 0x46,
    I32Ne = 0x47,
    I32LtS = 0x48,
    I32LtU = 0x49,
    I32GtS = 0x4A,
    I32GtU = 0x4B,
    I32LeS = 0x4C,
    I32LeU = 0x4D,
    I32GeS = 0x4E,
    I32GeU = 0x4F,

    // ── i64 Comparison ─────────────────────────────────────────────────
    I64Eqz = 0x50,
    I64Eq = 0x51,
    I64Ne = 0x52,
    I64LtS = 0x53,
    I64LtU = 0x54,
    I64GtS = 0x55,
    I64GtU = 0x56,
    I64LeS = 0x57,
    I64LeU = 0x58,
    I64GeS = 0x59,
    I64GeU = 0x5A,

    // ── f32 Comparison ─────────────────────────────────────────────────
    F32Eq = 0x5B,
    F32Ne = 0x5C,
    F32Lt = 0x5D,
    F32Gt = 0x5E,
    F32Le = 0x5F,
    F32Ge = 0x60,

    // ── f64 Comparison ─────────────────────────────────────────────────
    F64Eq = 0x61,
    F64Ne = 0x62,
    F64Lt = 0x63,
    F64Gt = 0x64,
    F64Le = 0x65,
    F64Ge = 0x66,

    // ── i32 Arithmetic ─────────────────────────────────────────────────
    I32Clz = 0x67,
    I32Ctz = 0x68,
    I32Popcnt = 0x69,
    I32Add = 0x6A,
    I32Sub = 0x6B,
    I32Mul = 0x6C,
    I32DivS = 0x6D,
    I32DivU = 0x6E,
    I32RemS = 0x6F,
    I32RemU = 0x70,
    I32And = 0x71,
    I32Or = 0x72,
    I32Xor = 0x73,
    I32Shl = 0x74,
    I32ShrS = 0x75,
    I32ShrU = 0x76,
    I32Rotl = 0x77,
    I32Rotr = 0x78,

    // ── i64 Arithmetic ─────────────────────────────────────────────────
    I64Clz = 0x79,
    I64Ctz = 0x7A,
    I64Popcnt = 0x7B,
    I64Add = 0x7C,
    I64Sub = 0x7D,
    I64Mul = 0x7E,
    I64DivS = 0x7F,
    I64DivU = 0x80,
    I64RemS = 0x81,
    I64RemU = 0x82,
    I64And = 0x83,
    I64Or = 0x84,
    I64Xor = 0x85,
    I64Shl = 0x86,
    I64ShrS = 0x87,
    I64ShrU = 0x88,
    I64Rotl = 0x89,
    I64Rotr = 0x8A,

    // ── f32 Unary ───────────────────────────────────────────────────────
    F32Abs = 0x8B,
    F32Neg = 0x8C,
    F32Ceil = 0x8D,
    F32Floor = 0x8E,
    F32Trunc = 0x8F,
    F32Nearest = 0x90,
    F32Sqrt = 0x91,

    // ── f32 Binary ──────────────────────────────────────────────────────
    F32Add = 0x92,
    F32Sub = 0x93,
    F32Mul = 0x94,
    F32Div = 0x95,
    F32Min = 0x96,
    F32Max = 0x97,
    F32Copysign = 0x98,

    // ── f64 Unary ───────────────────────────────────────────────────────
    F64Abs = 0x99,
    F64Neg = 0x9A,
    F64Ceil = 0x9B,
    F64Floor = 0x9C,
    F64Trunc = 0x9D,
    F64Nearest = 0x9E,
    F64Sqrt = 0x9F,

    // ── f64 Binary ──────────────────────────────────────────────────────
    F64Add = 0xA0,
    F64Sub = 0xA1,
    F64Mul = 0xA2,
    F64Div = 0xA3,
    F64Min = 0xA4,
    F64Max = 0xA5,
    F64Copysign = 0xA6,

    // ── Conversion ─────────────────────────────────────────────────────
    I32WrapI64 = 0xA7,
    I32TruncF32S = 0xA8,
    I32TruncF32U = 0xA9,
    I32TruncF64S = 0xAA,
    I32TruncF64U = 0xAB,
    I64ExtendI32S = 0xAC,
    I64ExtendI32U = 0xAD,
    I64TruncF32S = 0xAE,
    I64TruncF32U = 0xAF,
    I64TruncF64S = 0xB0,
    I64TruncF64U = 0xB1,
    F32ConvertI32S = 0xB2,
    F32ConvertI32U = 0xB3,
    F32ConvertI64S = 0xB4,
    F32ConvertI64U = 0xB5,
    F32DemoteF64 = 0xB6,
    F64ConvertI32S = 0xB7,
    F64ConvertI32U = 0xB8,
    F64ConvertI64S = 0xB9,
    F64ConvertI64U = 0xBA,
    F64PromoteF32 = 0xBB,
    I32ReinterpretF32 = 0xBC,
    I64ReinterpretF64 = 0xBD,
    F32ReinterpretI32 = 0xBE,
    F64ReinterpretI64 = 0xBF,

    // ── Sign extension (MVP post-proposal, widely used by compilers) ──
    I32Extend8S = 0xC0,
    I32Extend16S = 0xC1,
    I64Extend8S = 0xC2,
    I64Extend16S = 0xC3,
    I64Extend32S = 0xC4,
}

impl Opcode {
    /// Try to decode a byte into an opcode.
    pub fn from_byte(b: u8) -> Option<Opcode> {
        match b {
            // Control
            0x00 => Some(Opcode::Unreachable),
            0x01 => Some(Opcode::Nop),
            0x02 => Some(Opcode::Block),
            0x03 => Some(Opcode::Loop),
            0x04 => Some(Opcode::If),
            0x05 => Some(Opcode::Else),
            0x0B => Some(Opcode::End),
            0x0C => Some(Opcode::Br),
            0x0D => Some(Opcode::BrIf),
            0x0E => Some(Opcode::BrTable),
            0x0F => Some(Opcode::Return),
            0x10 => Some(Opcode::Call),
            0x11 => Some(Opcode::CallIndirect),
            0x12 => Some(Opcode::ReturnCall),
            0x13 => Some(Opcode::ReturnCallIndirect),
            // Parametric
            0x1A => Some(Opcode::Drop),
            0x1B => Some(Opcode::Select),
            // Variable access
            0x20 => Some(Opcode::LocalGet),
            0x21 => Some(Opcode::LocalSet),
            0x22 => Some(Opcode::LocalTee),
            0x23 => Some(Opcode::GlobalGet),
            0x24 => Some(Opcode::GlobalSet),
            0x25 => Some(Opcode::TableGet),
            0x26 => Some(Opcode::TableSet),
            // Memory
            0x28 => Some(Opcode::I32Load),
            0x29 => Some(Opcode::I64Load),
            0x2A => Some(Opcode::F32Load),
            0x2B => Some(Opcode::F64Load),
            0x2C => Some(Opcode::I32Load8S),
            0x2D => Some(Opcode::I32Load8U),
            0x2E => Some(Opcode::I32Load16S),
            0x2F => Some(Opcode::I32Load16U),
            0x30 => Some(Opcode::I64Load8S),
            0x31 => Some(Opcode::I64Load8U),
            0x32 => Some(Opcode::I64Load16S),
            0x33 => Some(Opcode::I64Load16U),
            0x34 => Some(Opcode::I64Load32S),
            0x35 => Some(Opcode::I64Load32U),
            0x36 => Some(Opcode::I32Store),
            0x37 => Some(Opcode::I64Store),
            0x38 => Some(Opcode::F32Store),
            0x39 => Some(Opcode::F64Store),
            0x3A => Some(Opcode::I32Store8),
            0x3B => Some(Opcode::I32Store16),
            0x3C => Some(Opcode::I64Store8),
            0x3D => Some(Opcode::I64Store16),
            0x3E => Some(Opcode::I64Store32),
            0x3F => Some(Opcode::MemorySize),
            0x40 => Some(Opcode::MemoryGrow),
            // Constants
            0x41 => Some(Opcode::I32Const),
            0x42 => Some(Opcode::I64Const),
            0x43 => Some(Opcode::F32Const),
            0x44 => Some(Opcode::F64Const),
            // i32 comparison
            0x45 => Some(Opcode::I32Eqz),
            0x46 => Some(Opcode::I32Eq),
            0x47 => Some(Opcode::I32Ne),
            0x48 => Some(Opcode::I32LtS),
            0x49 => Some(Opcode::I32LtU),
            0x4A => Some(Opcode::I32GtS),
            0x4B => Some(Opcode::I32GtU),
            0x4C => Some(Opcode::I32LeS),
            0x4D => Some(Opcode::I32LeU),
            0x4E => Some(Opcode::I32GeS),
            0x4F => Some(Opcode::I32GeU),
            // i64 comparison
            0x50 => Some(Opcode::I64Eqz),
            0x51 => Some(Opcode::I64Eq),
            0x52 => Some(Opcode::I64Ne),
            0x53 => Some(Opcode::I64LtS),
            0x54 => Some(Opcode::I64LtU),
            0x55 => Some(Opcode::I64GtS),
            0x56 => Some(Opcode::I64GtU),
            0x57 => Some(Opcode::I64LeS),
            0x58 => Some(Opcode::I64LeU),
            0x59 => Some(Opcode::I64GeS),
            0x5A => Some(Opcode::I64GeU),
            // f32 comparison
            0x5B => Some(Opcode::F32Eq),
            0x5C => Some(Opcode::F32Ne),
            0x5D => Some(Opcode::F32Lt),
            0x5E => Some(Opcode::F32Gt),
            0x5F => Some(Opcode::F32Le),
            0x60 => Some(Opcode::F32Ge),
            // f64 comparison
            0x61 => Some(Opcode::F64Eq),
            0x62 => Some(Opcode::F64Ne),
            0x63 => Some(Opcode::F64Lt),
            0x64 => Some(Opcode::F64Gt),
            0x65 => Some(Opcode::F64Le),
            0x66 => Some(Opcode::F64Ge),
            // i32 arithmetic
            0x67 => Some(Opcode::I32Clz),
            0x68 => Some(Opcode::I32Ctz),
            0x69 => Some(Opcode::I32Popcnt),
            0x6A => Some(Opcode::I32Add),
            0x6B => Some(Opcode::I32Sub),
            0x6C => Some(Opcode::I32Mul),
            0x6D => Some(Opcode::I32DivS),
            0x6E => Some(Opcode::I32DivU),
            0x6F => Some(Opcode::I32RemS),
            0x70 => Some(Opcode::I32RemU),
            0x71 => Some(Opcode::I32And),
            0x72 => Some(Opcode::I32Or),
            0x73 => Some(Opcode::I32Xor),
            0x74 => Some(Opcode::I32Shl),
            0x75 => Some(Opcode::I32ShrS),
            0x76 => Some(Opcode::I32ShrU),
            0x77 => Some(Opcode::I32Rotl),
            0x78 => Some(Opcode::I32Rotr),
            // i64 arithmetic
            0x79 => Some(Opcode::I64Clz),
            0x7A => Some(Opcode::I64Ctz),
            0x7B => Some(Opcode::I64Popcnt),
            0x7C => Some(Opcode::I64Add),
            0x7D => Some(Opcode::I64Sub),
            0x7E => Some(Opcode::I64Mul),
            0x7F => Some(Opcode::I64DivS),
            0x80 => Some(Opcode::I64DivU),
            0x81 => Some(Opcode::I64RemS),
            0x82 => Some(Opcode::I64RemU),
            0x83 => Some(Opcode::I64And),
            0x84 => Some(Opcode::I64Or),
            0x85 => Some(Opcode::I64Xor),
            0x86 => Some(Opcode::I64Shl),
            0x87 => Some(Opcode::I64ShrS),
            0x88 => Some(Opcode::I64ShrU),
            0x89 => Some(Opcode::I64Rotl),
            0x8A => Some(Opcode::I64Rotr),
            // f32 unary
            0x8B => Some(Opcode::F32Abs),
            0x8C => Some(Opcode::F32Neg),
            0x8D => Some(Opcode::F32Ceil),
            0x8E => Some(Opcode::F32Floor),
            0x8F => Some(Opcode::F32Trunc),
            0x90 => Some(Opcode::F32Nearest),
            0x91 => Some(Opcode::F32Sqrt),
            // f32 binary
            0x92 => Some(Opcode::F32Add),
            0x93 => Some(Opcode::F32Sub),
            0x94 => Some(Opcode::F32Mul),
            0x95 => Some(Opcode::F32Div),
            0x96 => Some(Opcode::F32Min),
            0x97 => Some(Opcode::F32Max),
            0x98 => Some(Opcode::F32Copysign),
            // f64 unary
            0x99 => Some(Opcode::F64Abs),
            0x9A => Some(Opcode::F64Neg),
            0x9B => Some(Opcode::F64Ceil),
            0x9C => Some(Opcode::F64Floor),
            0x9D => Some(Opcode::F64Trunc),
            0x9E => Some(Opcode::F64Nearest),
            0x9F => Some(Opcode::F64Sqrt),
            // f64 binary
            0xA0 => Some(Opcode::F64Add),
            0xA1 => Some(Opcode::F64Sub),
            0xA2 => Some(Opcode::F64Mul),
            0xA3 => Some(Opcode::F64Div),
            0xA4 => Some(Opcode::F64Min),
            0xA5 => Some(Opcode::F64Max),
            0xA6 => Some(Opcode::F64Copysign),
            // Conversion
            0xA7 => Some(Opcode::I32WrapI64),
            0xA8 => Some(Opcode::I32TruncF32S),
            0xA9 => Some(Opcode::I32TruncF32U),
            0xAA => Some(Opcode::I32TruncF64S),
            0xAB => Some(Opcode::I32TruncF64U),
            0xAC => Some(Opcode::I64ExtendI32S),
            0xAD => Some(Opcode::I64ExtendI32U),
            0xAE => Some(Opcode::I64TruncF32S),
            0xAF => Some(Opcode::I64TruncF32U),
            0xB0 => Some(Opcode::I64TruncF64S),
            0xB1 => Some(Opcode::I64TruncF64U),
            0xB2 => Some(Opcode::F32ConvertI32S),
            0xB3 => Some(Opcode::F32ConvertI32U),
            0xB4 => Some(Opcode::F32ConvertI64S),
            0xB5 => Some(Opcode::F32ConvertI64U),
            0xB6 => Some(Opcode::F32DemoteF64),
            0xB7 => Some(Opcode::F64ConvertI32S),
            0xB8 => Some(Opcode::F64ConvertI32U),
            0xB9 => Some(Opcode::F64ConvertI64S),
            0xBA => Some(Opcode::F64ConvertI64U),
            0xBB => Some(Opcode::F64PromoteF32),
            0xBC => Some(Opcode::I32ReinterpretF32),
            0xBD => Some(Opcode::I64ReinterpretF64),
            0xBE => Some(Opcode::F32ReinterpretI32),
            0xBF => Some(Opcode::F64ReinterpretI64),
            // Sign extension
            0xC0 => Some(Opcode::I32Extend8S),
            0xC1 => Some(Opcode::I32Extend16S),
            0xC2 => Some(Opcode::I64Extend8S),
            0xC3 => Some(Opcode::I64Extend16S),
            0xC4 => Some(Opcode::I64Extend32S),
            _ => None,
        }
    }
}

// ─── Limits ──────────────────────────────────────────────────────────────────

pub const MAX_FUNCTIONS: usize = 64;
pub const MAX_LOCALS: usize = 32;
pub const MAX_STACK: usize = 256;
pub const MAX_MEMORY_PAGES: usize = 16;      // 16 * 64 KiB = 1 MiB max
pub const WASM_PAGE_SIZE: usize = 65536;      // Standard WASM page size (64 KiB)
pub const MAX_IMPORTS: usize = 16;
pub const MAX_EXPORTS: usize = 16;
pub const MAX_CODE_SIZE: usize = 65536;       // 64 KB max code
pub const MAX_CALL_DEPTH: usize = 64;
pub const MAX_PARAMS: usize = 8;
pub const MAX_RESULTS: usize = 4;
pub const MAX_NAME_BYTES: usize = 256;
pub const MAX_BLOCK_DEPTH: usize = 64;
pub const MAX_GLOBALS: usize = 64;
pub const MAX_TABLE_SIZE: usize = 4096;
pub const MAX_DATA_SEGMENTS: usize = 64;
pub const MAX_ELEMENT_SEGMENTS: usize = 64;
pub const MAX_BR_TABLE_SIZE: usize = 256;

// ─── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum WasmError {
    InvalidMagic,
    UnsupportedVersion,
    InvalidSection,
    InvalidOpcode(u8),
    StackOverflow,
    StackUnderflow,
    TypeMismatch,
    OutOfBounds,
    DivisionByZero,
    UnreachableExecuted,
    ImportNotFound(u32),
    FunctionNotFound(u32),
    TooManyFunctions,
    TooManyImports,
    CodeTooLarge,
    InvalidLEB128,
    OutOfFuel,
    MemoryOutOfBounds,
    CallStackOverflow,
    InvalidBlockType,
    BranchDepthExceeded,
    UnexpectedEnd,
    IntegerOverflow,
    FloatsDisabled,
    UndefinedElement,
    IndirectCallTypeMismatch,
    ImmutableGlobal,
    GlobalIndexOutOfBounds,
    UnsupportedProposal,
    TableIndexOutOfBounds,
}
