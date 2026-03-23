//! AOS Root Agent
//!
//! The root agent is the system supervisor. It holds wildcard capabilities
//! for all capability types, enabling it to delegate narrowed capabilities
//! to child agents.
//!
//! In Stage-1, the root agent periodically yields to let other agents run.
//! In later stages, it will supervise child agents, handle faults, and
//! manage resource allocation.

use crate::serial_println;
use crate::agent::*;
use crate::syscall;

/// Root agent entry point.
///
/// Runs an infinite loop, periodically logging a tick count and yielding
/// to allow other agents to execute.
pub extern "C" fn root_entry() -> ! {
    serial_println!("[ROOT] Root agent started");

    let mut count: u64 = 0;
    let mut checkpoint_done = false;
    loop {
        count += 1;
        if count % 100 == 0 {
            serial_println!("[ROOT] Root agent tick {}", count);
        }
        // Trigger a checkpoint once at tick 500
        if count == 500 && !checkpoint_done {
            serial_println!("[ROOT] Triggering checkpoint...");
            let result = syscall::syscall(SYS_CHECKPOINT, 0, 0, 0, 0, 0);
            serial_println!("[ROOT] Checkpoint result: {}", result);
            checkpoint_done = true;
        }
        // Verify checkpoint roundtrip at tick 600 (checkpoint was at tick 500)
        if count == 600 && checkpoint_done {
            serial_println!("[ROOT] Verifying checkpoint from disk...");

            // Load header
            if let Some(header) = crate::checkpoint::load_header_from_disk() {
                serial_println!("[ROOT] \u{2713} Checkpoint loaded: tick={} event_seq={} agents={} merkle_roots={}",
                    header.tick, header.event_sequence, header.agent_count, header.merkle_root_count);

                // Verify magic
                if header.magic == 0x414F5343 {
                    serial_println!("[ROOT] \u{2713} Magic: AOSC (valid)");
                } else {
                    serial_println!("[ROOT] \u{2717} Magic: {:#x} (INVALID)", header.magic);
                }

                // Load and verify Merkle roots
                let roots = crate::checkpoint::load_merkle_from_disk(&header);
                let mut non_zero = 0;
                for root in roots.iter() {
                    if root.iter().any(|&b| b != 0) {
                        non_zero += 1;
                    }
                }
                serial_println!("[ROOT] \u{2713} Merkle roots loaded: {} non-zero keyspaces", non_zero);

                // Run replay divergence check
                serial_println!("[ROOT] Running Merkle divergence check...");
                match crate::replay::enter_replay() {
                    Ok(()) => {
                        let report = crate::replay::check_divergence();
                        crate::replay::print_report(&report);
                        crate::replay::exit_replay();
                    }
                    Err(e) => {
                        serial_println!("[ROOT] Replay failed: {}", e);
                    }
                }

                serial_println!("[ROOT] === CHECKPOINT ROUNDTRIP TEST COMPLETE ===");
            } else {
                serial_println!("[ROOT] \u{2717} No checkpoint found on disk!");
            }
        }

        // Yield to let other agents run
        syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
    }
}
