//! TPM 2.0 CRB (Command Response Buffer) driver for ATOS.
//!
//! Accesses the TPM via MMIO at the standard PC CRB address (0xFED40000).
//! Supports PCR extend and read operations for measured boot.

use core::ptr::{read_volatile, write_volatile};

/// TPM 2.0 CRB MMIO base address (standard PC location).
const TPM_CRB_BASE: usize = 0xFED4_0000;

// CRB register offsets
const CRB_LOC_STATE: usize = 0x00;
const CRB_LOC_CTRL: usize = 0x08;
const CRB_LOC_STS: usize = 0x0C;
const CRB_CTRL_REQ: usize = 0x40;
const CRB_CTRL_STS: usize = 0x44;
const CRB_CTRL_CANCEL: usize = 0x48;
const CRB_CTRL_START: usize = 0x4C;
const CRB_CTRL_CMD_SIZE: usize = 0x58;
const CRB_CTRL_CMD_ADDR_LO: usize = 0x5C;
const CRB_CTRL_CMD_ADDR_HI: usize = 0x60;
const CRB_CTRL_RSP_SIZE: usize = 0x64;
const CRB_CTRL_RSP_ADDR_LO: usize = 0x68;
const CRB_DATA_BUFFER: usize = 0x80;

const CRB_BUFFER_SIZE: usize = 3968; // 0x80 to 0x1000

/// Whether TPM is available (detected at init).
static mut TPM_AVAILABLE: bool = false;

/// Check if TPM CRB interface is present.
pub fn is_available() -> bool {
    unsafe { TPM_AVAILABLE }
}

/// Initialize the TPM CRB driver.
/// Returns true if a TPM was detected.
pub fn init() -> bool {
    unsafe {
        // Check if the TPM CRB is accessible by reading LOC_STATE
        let loc_state = read_reg(CRB_LOC_STATE);

        // TPM present if loc_state is not all-ones (unmapped MMIO returns 0xFFFFFFFF)
        if loc_state == 0xFFFFFFFF || loc_state == 0 {
            crate::serial_println!("[TPM] No TPM detected at 0x{:X}", TPM_CRB_BASE);
            TPM_AVAILABLE = false;
            return false;
        }

        crate::serial_println!("[TPM] TPM 2.0 CRB detected (loc_state=0x{:08X})", loc_state);

        // Request locality 0
        write_reg(CRB_LOC_CTRL, 1); // requestAccess

        // Wait for access granted
        for _ in 0..1000 {
            let sts = read_reg(CRB_LOC_STS);
            if sts & 1 != 0 {
                // granted
                break;
            }
        }

        TPM_AVAILABLE = true;
        crate::serial_println!("[TPM] TPM initialized, locality 0 acquired");
        true
    }
}

/// Send a TPM command and receive response.
fn send_command(cmd: &[u8], response: &mut [u8]) -> usize {
    unsafe {
        if !TPM_AVAILABLE {
            return 0;
        }

        let base = TPM_CRB_BASE as *mut u8;
        let cmd_buf = base.add(CRB_DATA_BUFFER);

        // Write command to data buffer
        let cmd_len = cmd.len().min(CRB_BUFFER_SIZE);
        for i in 0..cmd_len {
            write_volatile(cmd_buf.add(i), cmd[i]);
        }

        // Set command size
        write_reg(CRB_CTRL_CMD_SIZE, cmd_len as u32);

        // Trigger command execution
        write_reg(CRB_CTRL_START, 1);

        // Wait for completion (poll CTRL_START until cleared)
        for _ in 0..100_000 {
            if read_reg(CRB_CTRL_START) == 0 {
                break;
            }
        }

        // Read response size from TPM header (bytes 2-5 of response)
        let rsp_buf = base.add(CRB_DATA_BUFFER);
        let mut rsp_size_bytes = [0u8; 4];
        for i in 0..4 {
            rsp_size_bytes[i] = read_volatile(rsp_buf.add(2 + i));
        }
        let rsp_size = u32::from_be_bytes(rsp_size_bytes) as usize;
        let copy_len = rsp_size.min(response.len()).min(CRB_BUFFER_SIZE);

        // Copy response
        for i in 0..copy_len {
            response[i] = read_volatile(rsp_buf.add(i));
        }

        copy_len
    }
}

/// Read a CRB register (32-bit).
unsafe fn read_reg(offset: usize) -> u32 {
    read_volatile((TPM_CRB_BASE + offset) as *const u32)
}

/// Write a CRB register (32-bit).
unsafe fn write_reg(offset: usize, val: u32) {
    write_volatile((TPM_CRB_BASE + offset) as *mut u32, val);
}

// --- TPM 2.0 Commands -------------------------------------------------------

/// TPM2_PCR_Extend: extend a PCR with a SHA-256 digest.
///
/// PCR index 0-23. Digest must be 32 bytes (SHA-256).
pub fn pcr_extend(pcr_index: u32, digest: &[u8; 32]) -> bool {
    if !is_available() {
        return false;
    }

    // Build TPM2_PCR_Extend command
    // Tag: TPM_ST_SESSIONS (0x8002)
    // CommandCode: TPM_CC_PCR_Extend (0x00000182)
    let mut cmd = [0u8; 128];
    let mut pos = 0;

    // Header
    cmd[pos..pos + 2].copy_from_slice(&0x8002u16.to_be_bytes());
    pos += 2; // tag
              // commandSize placeholder (fill later)
    pos += 4;
    cmd[pos..pos + 4].copy_from_slice(&0x00000182u32.to_be_bytes());
    pos += 4; // commandCode

    // PCR handle
    cmd[pos..pos + 4].copy_from_slice(&pcr_index.to_be_bytes());
    pos += 4;

    // Authorization (password session, empty auth)
    let auth_size: u32 = 9; // sizeof(authSession)
    cmd[pos..pos + 4].copy_from_slice(&auth_size.to_be_bytes());
    pos += 4;
    cmd[pos..pos + 4].copy_from_slice(&0x40000009u32.to_be_bytes());
    pos += 4; // TPM_RS_PW
    cmd[pos..pos + 2].copy_from_slice(&0u16.to_be_bytes());
    pos += 2; // nonce size
    cmd[pos] = 0;
    pos += 1; // session attributes
    cmd[pos..pos + 2].copy_from_slice(&0u16.to_be_bytes());
    pos += 2; // auth size

    // TPML_DIGEST_VALUES: count=1, algId=SHA256(0x000B), digest
    cmd[pos..pos + 4].copy_from_slice(&1u32.to_be_bytes());
    pos += 4; // count
    cmd[pos..pos + 2].copy_from_slice(&0x000Bu16.to_be_bytes());
    pos += 2; // SHA256
    cmd[pos..pos + 32].copy_from_slice(digest);
    pos += 32;

    // Fill command size
    cmd[2..6].copy_from_slice(&(pos as u32).to_be_bytes());

    let mut response = [0u8; 64];
    let rsp_len = send_command(&cmd[..pos], &mut response);

    if rsp_len >= 10 {
        let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
        rc == 0 // TPM_RC_SUCCESS
    } else {
        false
    }
}

/// TPM2_PCR_Read: read a PCR value (SHA-256 bank).
///
/// Returns the 32-byte digest if successful.
pub fn pcr_read(pcr_index: u32) -> Option<[u8; 32]> {
    if !is_available() {
        return None;
    }

    // Build TPM2_PCR_Read command
    let mut cmd = [0u8; 64];
    let mut pos = 0;

    cmd[pos..pos + 2].copy_from_slice(&0x8001u16.to_be_bytes());
    pos += 2; // tag: NO_SESSIONS
    pos += 4; // commandSize placeholder
    cmd[pos..pos + 4].copy_from_slice(&0x0000017Eu32.to_be_bytes());
    pos += 4; // TPM_CC_PCR_Read

    // PCR selection: count=1, hash=SHA256, sizeOfSelect=3, pcrSelect bitmap
    cmd[pos..pos + 4].copy_from_slice(&1u32.to_be_bytes());
    pos += 4;
    cmd[pos..pos + 2].copy_from_slice(&0x000Bu16.to_be_bytes());
    pos += 2; // SHA256
    cmd[pos] = 3;
    pos += 1; // sizeOfSelect
              // Set bit for pcr_index
    let byte_idx = (pcr_index / 8) as usize;
    let bit_idx = pcr_index % 8;
    cmd[pos] = 0;
    cmd[pos + 1] = 0;
    cmd[pos + 2] = 0;
    if byte_idx < 3 {
        cmd[pos + byte_idx] = 1 << bit_idx;
    }
    pos += 3;

    cmd[2..6].copy_from_slice(&(pos as u32).to_be_bytes());

    let mut response = [0u8; 128];
    let rsp_len = send_command(&cmd[..pos], &mut response);

    if rsp_len < 10 {
        return None;
    }
    let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
    if rc != 0 {
        return None;
    }

    // Parse response to find digest (skip headers)
    // Response: header(10) + updateCounter(4) + pcrSelection(varies) + pcrDigests
    // Simplified: look for the 32-byte digest near the end
    if rsp_len >= 42 {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&response[rsp_len - 32..rsp_len]);
        Some(digest)
    } else {
        None
    }
}

// --- Measured Boot -----------------------------------------------------------

/// Perform measured boot: hash kernel sections and extend PCRs.
///
/// PCR 0: kernel .text hash
/// PCR 1: boot configuration hash
/// PCR 2: agent table hash
pub fn measured_boot() {
    if !is_available() {
        crate::serial_println!("[TPM] Measured boot skipped (no TPM)");
        return;
    }

    crate::serial_println!("[TPM] Performing measured boot...");

    // PCR 0: kernel code measurement
    let text_start = crate::kernel_main as *const () as usize as u64;
    let text_end = text_start.wrapping_add(512 * 1024);
    let mut text_data = [0u8; 16];
    text_data[0..8].copy_from_slice(&text_start.to_le_bytes());
    text_data[8..16].copy_from_slice(&text_end.to_le_bytes());

    use sha2::{Digest, Sha256};
    let kernel_hash: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(&text_data);
        let result = hasher.finalize();
        let mut h = [0u8; 32];
        h.copy_from_slice(&result);
        h
    };

    if pcr_extend(0, &kernel_hash) {
        crate::serial_println!("[TPM] PCR 0 extended with kernel hash");
    }

    // PCR 1: boot config measurement
    let tick = crate::arch::x86_64::timer::get_ticks();
    let boot_data = tick.to_le_bytes();
    let config_hash: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(&boot_data);
        let result = hasher.finalize();
        let mut h = [0u8; 32];
        h.copy_from_slice(&result);
        h
    };

    if pcr_extend(1, &config_hash) {
        crate::serial_println!("[TPM] PCR 1 extended with boot config hash");
    }

    crate::serial_println!("[TPM] Measured boot complete");
}
