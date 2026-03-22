//! eBPF-lite instruction set and types.
//!
//! Defines the bytecode encoding, opcodes, action codes, and error types
//! for the eBPF-lite policy runtime.

/// eBPF-lite register set: r0-r10 (r10 = frame pointer, read-only)
pub const NUM_REGS: usize = 11;

/// Maximum program size in instructions
pub const MAX_INSNS: usize = 256;

/// Maximum stack size (in bytes)
pub const STACK_SIZE: usize = 512;

/// eBPF instruction encoding (8 bytes each, matching Linux eBPF)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Insn {
    pub opcode: u8,
    pub regs: u8, // dst:4 | src:4
    pub off: i16,
    pub imm: i32,
}

impl Insn {
    pub fn dst(&self) -> usize {
        (self.regs & 0x0F) as usize
    }
    pub fn src(&self) -> usize {
        ((self.regs >> 4) & 0x0F) as usize
    }
}

// Instruction classes (opcode & 0x07)
pub const BPF_LD: u8 = 0x00;
pub const BPF_LDX: u8 = 0x01;
pub const BPF_ST: u8 = 0x02;
pub const BPF_STX: u8 = 0x03;
pub const BPF_ALU: u8 = 0x04;
pub const BPF_JMP: u8 = 0x05;
pub const BPF_ALU64: u8 = 0x07;

// ALU operations (opcode & 0xF0)
pub const BPF_ADD: u8 = 0x00;
pub const BPF_SUB: u8 = 0x10;
pub const BPF_MUL: u8 = 0x20;
pub const BPF_DIV: u8 = 0x30;
pub const BPF_OR: u8 = 0x40;
pub const BPF_AND: u8 = 0x50;
pub const BPF_LSH: u8 = 0x60;
pub const BPF_RSH: u8 = 0x70;
pub const BPF_NEG: u8 = 0x80;
pub const BPF_MOD: u8 = 0x90;
pub const BPF_XOR: u8 = 0xA0;
pub const BPF_MOV: u8 = 0xB0;

// Source operand (opcode & 0x08)
pub const BPF_K: u8 = 0x00; // immediate
pub const BPF_X: u8 = 0x08; // register

// Jump operations (opcode & 0xF0 for JMP class)
pub const BPF_JA: u8 = 0x00;
pub const BPF_JEQ: u8 = 0x10;
pub const BPF_JGT: u8 = 0x20;
pub const BPF_JGE: u8 = 0x30;
pub const BPF_JSET: u8 = 0x40;
pub const BPF_JNE: u8 = 0x50;
pub const BPF_CALL: u8 = 0x80;
pub const BPF_EXIT: u8 = 0x90;
pub const BPF_JLT: u8 = 0xA0;
pub const BPF_JLE: u8 = 0xB0;

// Memory sizes (opcode & 0x18 for LD/ST classes)
pub const BPF_W: u8 = 0x00;  // 32-bit
pub const BPF_H: u8 = 0x08;  // 16-bit
pub const BPF_B: u8 = 0x10;  // 8-bit
pub const BPF_DW: u8 = 0x18; // 64-bit

pub const BPF_MEM: u8 = 0x60;

// Helper function IDs
pub const HELPER_MAP_LOOKUP: u32 = 1;
pub const HELPER_MAP_UPDATE: u32 = 2;
pub const HELPER_MAP_DELETE: u32 = 3;
pub const HELPER_GET_AGENT_ID: u32 = 4;
pub const HELPER_GET_ENERGY: u32 = 5;
pub const HELPER_EMIT_EVENT: u32 = 6;
pub const HELPER_GET_TICK: u32 = 7;

/// Action codes returned by eBPF programs
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u64)]
pub enum Action {
    Allow = 0,
    Deny = 1,
    Log = 2,
}

impl Action {
    pub fn from_u64(v: u64) -> Self {
        match v {
            0 => Action::Allow,
            2 => Action::Log,
            _ => Action::Deny, // default deny for unknown
        }
    }
}

/// Errors produced by the eBPF-lite subsystem.
#[derive(Debug)]
pub enum EbpfError {
    InvalidProgram,
    ProgramTooLarge,
    InvalidOpcode(u8),
    InvalidRegister(u8),
    DivisionByZero,
    OutOfBounds,
    InvalidHelper(u32),
    VerificationFailed(&'static str),
    MaxInstructionsExceeded,
    MapFull,
    KeyTooLarge,
    ValueTooLarge,
    NoFreeSlot,
}
