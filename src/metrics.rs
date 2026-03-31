/// System-wide metrics counters
pub struct SystemMetrics {
    pub total_syscalls: u64,
    pub total_agents_spawned: u64,
    pub total_agents_exited: u64,
    pub total_energy_consumed: u64,
    pub total_messages_sent: u64,
    pub total_messages_received: u64,
    pub total_state_operations: u64,
    pub total_checkpoints: u64,
    pub total_receipts_emitted: u64,
    pub uptime_ticks: u64,
}

static mut METRICS: SystemMetrics = SystemMetrics {
    total_syscalls: 0,
    total_agents_spawned: 0,
    total_agents_exited: 0,
    total_energy_consumed: 0,
    total_messages_sent: 0,
    total_messages_received: 0,
    total_state_operations: 0,
    total_checkpoints: 0,
    total_receipts_emitted: 0,
    uptime_ticks: 0,
};

pub fn increment_syscall_count() {
    unsafe {
        METRICS.total_syscalls += 1;
    }
}

pub fn increment_agent_spawned() {
    unsafe {
        METRICS.total_agents_spawned += 1;
    }
}

pub fn increment_agent_exited() {
    unsafe {
        METRICS.total_agents_exited += 1;
    }
}

pub fn increment_messages_sent() {
    unsafe {
        METRICS.total_messages_sent += 1;
    }
}

pub fn increment_energy_consumed(amount: u64) {
    unsafe {
        METRICS.total_energy_consumed += amount;
    }
}

pub fn get_metrics() -> &'static SystemMetrics {
    unsafe { &METRICS }
}

pub fn increment_uptime() {
    unsafe {
        METRICS.uptime_ticks += 1;
    }
}
