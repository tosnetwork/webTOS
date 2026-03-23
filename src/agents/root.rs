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
        // Yield to let other agents run
        syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
    }
}
