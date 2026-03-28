use crate::serial_println;

/// Remote administration system agent.
/// All admin operations go through authenticated mailbox messages.
/// No shell access — this is the ATOS way.
pub fn admind_main() {
    serial_println!("[ADMIND] Administration service started");
    // Listen for admin commands:
    // 0x01 STATUS: system health summary
    // 0x02 AGENT_LIST: list running agents
    // 0x03 AGENT_KILL: terminate agent by ID (requires admin capability)
    // 0x04 ENERGY_REPORT: energy accounting summary
    // 0x05 METRICS: system metrics snapshot
    loop { unsafe { core::arch::asm!("hlt"); } }
}
