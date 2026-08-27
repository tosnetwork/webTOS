//! Standalone instruction decoding, for the differential-decode harness.
//!
//! Exposes "decode one instruction from a byte window" without executing it,
//! so a reference decoder (e.g. iced-x86) can be compared against the SLEIGH
//! lifter this engine uses. The property that matters most is the decoded
//! *length*: a one-byte disagreement makes every later fetch land
//! mid-instruction, which is exactly the class of bug that blocks Node/V8.

use icicle_cpu::{
    lifter::{DecodeError, InstructionLifter, InstructionSource},
    Arch, Cpu,
};

/// A fixed 16-byte instruction window over a borrowed `Arch`, so a decoder
/// can run with no memory map or VM.
struct ByteWindow<'a> {
    arch: &'a Arch,
    bytes: [u8; 16],
}

impl InstructionSource for ByteWindow<'_> {
    fn arch(&self) -> &Arch {
        self.arch
    }

    fn read_bytes(&mut self, vaddr: u64, buf: &mut [u8]) {
        // Address 0 is the base of the window; the harness always decodes at
        // offset 0, and anything past the window reads as zero.
        let start = vaddr as usize;
        for (i, out) in buf.iter_mut().enumerate() {
            *out = self.bytes.get(start + i).copied().unwrap_or(0);
        }
    }

    fn ensure_exec(&mut self, _vaddr: u64, _size: usize) -> bool {
        true // the whole window is executable for decoding purposes
    }
}

/// The result of decoding one instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// Number of bytes the SLEIGH lifter consumed.
    pub len: usize,
    /// SLEIGH disassembly text (`invalid_instruction` when unrenderable).
    pub disasm: String,
}

/// Decodes the single instruction at the start of `bytes` (up to 15 bytes
/// are consulted) using the SLEIGH tables of `cpu`'s architecture. Returns
/// the decoded length and disassembly, or a decode error.
pub fn decode_one(cpu: &Cpu, bytes: &[u8]) -> Result<Decoded, DecodeError> {
    let mut window = ByteWindow {
        arch: &cpu.arch,
        bytes: [0; 16],
    };
    let n = bytes.len().min(16);
    window.bytes[..n].copy_from_slice(&bytes[..n]);

    let mut lifter = InstructionLifter::new();
    // Decode in the architecture's default ISA mode (x86-64 long mode); the
    // default lifter context is 16-bit, which would decode REX prefixes as
    // 16-bit instructions.
    let isa_mode = cpu.isa_mode() as usize;
    if let Some(&ctx) = cpu.arch.isa_mode_context.get(isa_mode) {
        lifter.set_context(ctx);
    }
    let inst = lifter.decode(&mut window, 0)?;
    let len = inst.num_bytes() as usize;
    lifter.disasm_current(&window);
    Ok(Decoded {
        len,
        disasm: lifter.disasm.clone(),
    })
}
