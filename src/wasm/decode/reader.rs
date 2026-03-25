//! Low-level byte reading and LEB128 decoding helpers.

use crate::wasm::types::*;

// ─── Byte reading helpers ───────────────────────────────────────────────────

pub(crate) fn read_byte(bytes: &[u8], pos: &mut usize) -> Result<u8, WasmError> {
    if *pos >= bytes.len() {
        return Err(WasmError::UnexpectedEnd);
    }
    let b = bytes[*pos];
    *pos += 1;
    Ok(b)
}

pub(crate) fn peek_byte(bytes: &[u8], pos: usize) -> Result<u8, WasmError> {
    if pos >= bytes.len() {
        return Err(WasmError::UnexpectedEnd);
    }
    Ok(bytes[pos])
}

// ─── LEB128 helpers ─────────────────────────────────────────────────────────

pub fn decode_leb128_u32(bytes: &[u8], pos: &mut usize) -> Result<u32, WasmError> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= bytes.len() {
            return Err(WasmError::UnexpectedEnd);
        }
        let byte = bytes[*pos];
        *pos += 1;
        if shift == 28 && byte > 0x0F {
            return Err(WasmError::InvalidLEB128);
        }
        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 35 {
            return Err(WasmError::InvalidLEB128);
        }
    }
}

pub fn decode_leb128_u64(bytes: &[u8], pos: &mut usize) -> Result<u64, WasmError> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= bytes.len() {
            return Err(WasmError::UnexpectedEnd);
        }
        let byte = bytes[*pos];
        *pos += 1;
        if shift == 63 && byte > 0x01 {
            return Err(WasmError::InvalidLEB128);
        }
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 70 {
            return Err(WasmError::InvalidLEB128);
        }
    }
}

pub fn decode_leb128_i32(bytes: &[u8], pos: &mut usize) -> Result<i32, WasmError> {
    let mut result: i32 = 0;
    let mut shift: u32 = 0;
    let size = 32;
    loop {
        if *pos >= bytes.len() {
            return Err(WasmError::UnexpectedEnd);
        }
        let byte = bytes[*pos];
        *pos += 1;
        if shift == 28 {
            // 5th byte for i32: only lower 4 bits contribute to the value.
            // Bit 3 is the sign bit. Bits 4-6 must be copies of bit 3.
            // Also, the continuation bit (bit 7) must be 0.
            if byte & 0x80 != 0 {
                return Err(WasmError::InvalidLEB128);
            }
            let sign_bit = (byte >> 3) & 1;
            let upper = (byte >> 4) & 0x07;
            if sign_bit == 0 && upper != 0 {
                return Err(WasmError::InvalidLEB128);
            }
            if sign_bit == 1 && upper != 0x07 {
                return Err(WasmError::InvalidLEB128);
            }
            result |= ((byte & 0x7F) as i32) << shift;
            shift += 7;
            // Sign extend if needed
            if shift < size && (byte & 0x40) != 0 {
                result |= !0 << shift;
            }
            return Ok(result);
        }
        result |= ((byte & 0x7F) as i32) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            // Sign extend if needed
            if shift < size && (byte & 0x40) != 0 {
                result |= !0 << shift;
            }
            return Ok(result);
        }
        if shift >= 35 {
            return Err(WasmError::InvalidLEB128);
        }
    }
}

pub fn decode_leb128_i64(bytes: &[u8], pos: &mut usize) -> Result<i64, WasmError> {
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    let size = 64;
    loop {
        if *pos >= bytes.len() {
            return Err(WasmError::UnexpectedEnd);
        }
        let byte = bytes[*pos];
        *pos += 1;
        if shift == 63 {
            // 10th byte for i64: only bit 0 contributes (bit 63 of the value).
            // Continuation bit (bit 7) must be 0.
            // Bits 1-6 must be copies of bit 0 (sign-consistent).
            if byte & 0x80 != 0 {
                return Err(WasmError::InvalidLEB128);
            }
            // Valid values: 0x00 (positive) or 0x7F (negative)
            if byte != 0x00 && byte != 0x7F {
                return Err(WasmError::InvalidLEB128);
            }
            result |= ((byte & 0x7F) as i64) << shift;
            // Sign extend if needed (bit 6 = 0x40 set means negative)
            if (byte & 0x40) != 0 {
                // No need to sign-extend past 64 bits
            }
            return Ok(result);
        }
        result |= ((byte & 0x7F) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < size && (byte & 0x40) != 0 {
                result |= !0i64 << shift;
            }
            return Ok(result);
        }
        if shift >= 70 {
            return Err(WasmError::InvalidLEB128);
        }
    }
}

// ─── UTF-8 validation ───────────────────────────────────────────────────────

pub(crate) fn validate_utf8(bytes: &[u8]) -> Result<(), WasmError> {
    core::str::from_utf8(bytes).map_err(|_| WasmError::MalformedUtf8)?;
    Ok(())
}

/// Read a length-prefixed name from the byte stream and validate UTF-8.
pub(crate) fn read_name<'a>(bytes: &'a [u8], pos: &mut usize) -> Result<&'a [u8], WasmError> {
    let len = decode_leb128_u32(bytes, pos)? as usize;
    if *pos + len > bytes.len() {
        return Err(WasmError::UnexpectedEnd);
    }
    let name = &bytes[*pos..*pos + len];
    validate_utf8(name)?;
    *pos += len;
    Ok(name)
}
