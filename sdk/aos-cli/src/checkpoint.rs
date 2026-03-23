//! Checkpoint file parser
//!
//! Parses AOS checkpoint binary files (raw disk images).

const CHECKPOINT_MAGIC: u32 = 0x414F5343; // "AOSC"
const SECTOR_SIZE: usize = 512;
// Checkpoint starts at LBA 2048 in disk images
const CHECKPOINT_OFFSET: usize = 2048 * SECTOR_SIZE;

pub fn parse_and_display(data: &[u8]) {
    // Try reading from LBA 2048 offset (disk image) or from start (raw checkpoint)
    let header_data = if data.len() > CHECKPOINT_OFFSET + SECTOR_SIZE {
        &data[CHECKPOINT_OFFSET..]
    } else {
        data
    };

    if header_data.len() < SECTOR_SIZE {
        eprintln!("[aos-replay] Data too small for checkpoint header");
        return;
    }

    // Parse header
    let magic = u32::from_le_bytes(header_data[0..4].try_into().unwrap());
    if magic != CHECKPOINT_MAGIC {
        eprintln!("[aos-replay] Invalid checkpoint magic: {:#x} (expected AOSC = {:#x})", magic, CHECKPOINT_MAGIC);
        eprintln!("[aos-replay] Tip: use a raw disk image from 'make test' (e.g., /tmp/aos_test.img)");
        return;
    }

    let version = u32::from_le_bytes(header_data[4..8].try_into().unwrap());
    let tick = u64::from_le_bytes(header_data[8..16].try_into().unwrap());
    let event_seq = u64::from_le_bytes(header_data[16..24].try_into().unwrap());
    let agent_count = u16::from_le_bytes(header_data[24..26].try_into().unwrap());
    let merkle_count = u16::from_le_bytes(header_data[26..28].try_into().unwrap());

    println!("╔══════════════════════════════════════════════╗");
    println!("║       AOS CHECKPOINT ANALYSIS               ║");
    println!("╠══════════════════════════════════════════════╣");
    println!("║ Magic:   AOSC (valid)                       ║");
    println!("║ Version: {:35} ║", version);
    println!("║ Tick:    {:35} ║", tick);
    println!("║ Events:  {:35} ║", event_seq);
    println!("║ Agents:  {:35} ║", agent_count);
    println!("║ Merkle roots: {:30} ║", merkle_count);
    println!("╠══════════════════════════════════════════════╣");
    println!("║ Agents:                                     ║");

    // Parse agent records
    for i in 0..agent_count as usize {
        let offset = (i + 1) * SECTOR_SIZE;
        if offset + SECTOR_SIZE > header_data.len() { break; }
        let agent_data = &header_data[offset..offset + SECTOR_SIZE];

        let id = u16::from_le_bytes(agent_data[0..2].try_into().unwrap());
        let status = agent_data[2];
        let mode = agent_data[3];
        let energy = u64::from_le_bytes(agent_data[4..12].try_into().unwrap());

        let status_str = match status {
            0 => "Created",
            1 => "Ready",
            2 => "Running",
            3 => "BlockedRecv",
            4 => "BlockedSend",
            5 => "Suspended",
            6 => "Exited",
            7 => "Faulted",
            _ => "Unknown",
        };

        let mode_str = match mode {
            0 => "kernel",
            1 => "user",
            _ => "?",
        };

        println!("║   Agent {:2}: {:10} {:6} energy={:<8} ║",
            id, status_str, mode_str, energy);
    }

    // Parse Merkle roots
    let merkle_offset = (agent_count as usize + 1) * SECTOR_SIZE;
    if merkle_offset + SECTOR_SIZE <= header_data.len() {
        println!("╠══════════════════════════════════════════════╣");
        println!("║ Merkle roots:                               ║");
        let merkle_data = &header_data[merkle_offset..merkle_offset + SECTOR_SIZE];
        for i in 0..merkle_count as usize {
            let off = i * 16;
            if off + 16 > merkle_data.len() { break; }
            let root = &merkle_data[off..off + 16];
            let is_zero = root.iter().all(|&b| b == 0);
            if !is_zero {
                println!("║   Keyspace {:2}: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}...    ║",
                    i, root[0], root[1], root[2], root[3],
                    root[4], root[5], root[6], root[7]);
            }
        }
    }

    println!("╚══════════════════════════════════════════════╝");
}
