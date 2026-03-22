//! WASM binary format types for the AOS minimal interpreter.
//!
//! All structures use fixed-size arrays — no heap allocation.

/// Value types supported by this interpreter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValType {
    I32,
    I64,
}

/// A runtime value on the operand stack or in a local variable.
#[derive(Debug, Clone, Copy)]
pub enum Value {
    I32(i32),
    I64(i64),
}

impl Value {
    /// Return zero for the given type.
    pub const fn default_for(ty: ValType) -> Self {
        match ty {
            ValType::I32 => Value::I32(0),
            ValType::I64 => Value::I64(0),
        }
    }

    pub fn as_i32(self) -> i32 {
        match self {
            Value::I32(v) => v,
            Value::I64(v) => v as i32,
        }
    }

    pub fn as_i64(self) -> i64 {
        match self {
            Value::I32(v) => v as i64,
            Value::I64(v) => v,
        }
    }
}

/// WASM instruction opcodes — minimal subset for basic programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    // Control
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

    // Variable access
    LocalGet = 0x20,
    LocalSet = 0x21,
    LocalTee = 0x22,

    // Memory
    I32Load = 0x28,
    I64Load = 0x29,
    I32Store = 0x36,
    I64Store = 0x37,

    // Constants
    I32Const = 0x41,
    I64Const = 0x42,

    // Comparison
    I32Eqz = 0x45,
    I32Eq = 0x46,
    I32Ne = 0x47,
    I32LtS = 0x48,
    I32GtS = 0x4A,
    I32LeS = 0x4C,
    I32GeS = 0x4E,

    // Arithmetic — i32
    I32Add = 0x6A,
    I32Sub = 0x6B,
    I32Mul = 0x6C,
    I32DivS = 0x6D,
    I32RemS = 0x6F,
    I32And = 0x71,
    I32Or = 0x72,
    I32Xor = 0x73,
    I32Shl = 0x74,
    I32ShrS = 0x75,

    // Arithmetic — i64
    I64Add = 0x7C,
    I64Sub = 0x7D,
    I64Mul = 0x7E,

    // Conversion
    I32WrapI64 = 0xA7,
    I64ExtendI32S = 0xAC,
}

impl Opcode {
    /// Try to decode a byte into an opcode.
    pub fn from_byte(b: u8) -> Option<Opcode> {
        match b {
            0x00 => Some(Opcode::Unreachable),
            0x01 => Some(Opcode::Nop),
            0x02 => Some(Opcode::Block),
            0x03 => Some(Opcode::Loop),
            0x04 => Some(Opcode::If),
            0x05 => Some(Opcode::Else),
            0x0B => Some(Opcode::End),
            0x0C => Some(Opcode::Br),
            0x0D => Some(Opcode::BrIf),
            0x0F => Some(Opcode::Return),
            0x10 => Some(Opcode::Call),
            0x20 => Some(Opcode::LocalGet),
            0x21 => Some(Opcode::LocalSet),
            0x22 => Some(Opcode::LocalTee),
            0x28 => Some(Opcode::I32Load),
            0x29 => Some(Opcode::I64Load),
            0x36 => Some(Opcode::I32Store),
            0x37 => Some(Opcode::I64Store),
            0x41 => Some(Opcode::I32Const),
            0x42 => Some(Opcode::I64Const),
            0x45 => Some(Opcode::I32Eqz),
            0x46 => Some(Opcode::I32Eq),
            0x47 => Some(Opcode::I32Ne),
            0x48 => Some(Opcode::I32LtS),
            0x4A => Some(Opcode::I32GtS),
            0x4C => Some(Opcode::I32LeS),
            0x4E => Some(Opcode::I32GeS),
            0x6A => Some(Opcode::I32Add),
            0x6B => Some(Opcode::I32Sub),
            0x6C => Some(Opcode::I32Mul),
            0x6D => Some(Opcode::I32DivS),
            0x6F => Some(Opcode::I32RemS),
            0x71 => Some(Opcode::I32And),
            0x72 => Some(Opcode::I32Or),
            0x73 => Some(Opcode::I32Xor),
            0x74 => Some(Opcode::I32Shl),
            0x75 => Some(Opcode::I32ShrS),
            0x7C => Some(Opcode::I64Add),
            0x7D => Some(Opcode::I64Sub),
            0x7E => Some(Opcode::I64Mul),
            0xA7 => Some(Opcode::I32WrapI64),
            0xAC => Some(Opcode::I64ExtendI32S),
            _ => None,
        }
    }
}

// ─── Limits ──────────────────────────────────────────────────────────────────

pub const MAX_FUNCTIONS: usize = 64;
pub const MAX_LOCALS: usize = 32;
pub const MAX_STACK: usize = 256;
pub const MAX_MEMORY_PAGES: usize = 16; // 16 * 64 KiB = 1 MiB max
pub const WASM_PAGE_SIZE: usize = 65536;
pub const MAX_IMPORTS: usize = 16;
pub const MAX_EXPORTS: usize = 16;
pub const MAX_CODE_SIZE: usize = 65536;
pub const MAX_CALL_DEPTH: usize = 64;
pub const MAX_PARAMS: usize = 8;
pub const MAX_RESULTS: usize = 4;
pub const MAX_NAME_BYTES: usize = 256;
pub const MAX_BLOCK_DEPTH: usize = 64;

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
}
