//! AOS eBPF-lite binary format (.bin) reader and writer.
//!
//! Binary layout:
//! ```text
//! offset  size  field
//! ------  ----  -----
//!   0       4   magic = b"AEBF"
//!   4       1   version = 1
//!   5       2   insn_count (little-endian u16)
//!   7       1   padding (zero)
//!   8   N*8     instructions, each 8 bytes (little-endian)
//! ```
//!
//! Each instruction is laid out as:
//!   byte 0: opcode
//!   byte 1: regs  (dst:4 | src:4)
//!   byte 2-3: off (i16, little-endian)
//!   byte 4-7: imm (i32, little-endian)

use std::io::{self, Read, Write};
use crate::types::Insn;

pub const MAGIC: &[u8; 4] = b"AEBF";
pub const VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 8;

/// A parsed AOS eBPF binary file.
pub struct AebfBinary {
    #[allow(dead_code)]
    pub version: u8,
    pub instructions: Vec<Insn>,
}

/// Write instructions to a binary stream.
pub fn write_binary<W: Write>(writer: &mut W, insns: &[Insn]) -> io::Result<()> {
    if insns.len() > u16::MAX as usize {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "too many instructions"));
    }

    // Header
    writer.write_all(MAGIC)?;
    writer.write_all(&[VERSION])?;
    writer.write_all(&(insns.len() as u16).to_le_bytes())?;
    writer.write_all(&[0u8])?; // padding

    // Instructions
    for insn in insns {
        writer.write_all(&[insn.opcode])?;
        writer.write_all(&[insn.regs])?;
        writer.write_all(&insn.off.to_le_bytes())?;
        writer.write_all(&insn.imm.to_le_bytes())?;
    }

    Ok(())
}

/// Read and parse a binary stream into an `AebfBinary`.
pub fn read_binary<R: Read>(reader: &mut R) -> io::Result<AebfBinary> {
    let mut header = [0u8; HEADER_SIZE];
    reader.read_exact(&mut header)?;

    // Check magic
    if &header[0..4] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid magic: expected {:?}, got {:?}",
                MAGIC,
                &header[0..4]
            ),
        ));
    }

    let version    = header[4];
    let insn_count = u16::from_le_bytes([header[5], header[6]]) as usize;
    // header[7] is padding, ignored

    if version != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported binary version {}", version),
        ));
    }

    let mut instructions = Vec::with_capacity(insn_count);
    let mut buf = [0u8; 8];
    for _ in 0..insn_count {
        reader.read_exact(&mut buf)?;
        let opcode = buf[0];
        let regs   = buf[1];
        let off    = i16::from_le_bytes([buf[2], buf[3]]);
        let imm    = i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        instructions.push(Insn { opcode, regs, off, imm });
    }

    Ok(AebfBinary { version, instructions })
}
