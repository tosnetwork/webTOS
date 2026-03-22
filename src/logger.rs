//! AOS Kernel Logger
//!
//! Provides log-level-gated macros for kernel logging over serial output.
//! The log level can be adjusted at runtime via `set_level()`.
//!
//! Log levels (ordered by verbosity):
//!   Error < Warn < Info < Debug < Trace
//!
//! A message is emitted only if the current log level is >= the message level.

/// Log severity levels, ordered from least verbose to most verbose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

/// Current global log level.
///
/// Safety: Stage-1 is single-core. No concurrent access.
static mut LOG_LEVEL: LogLevel = LogLevel::Info;

/// Set the global log level.
///
/// Messages with a level above this threshold will be suppressed.
pub fn set_level(level: LogLevel) {
    // Safety: single-core, no concurrent access in Stage-1
    unsafe {
        LOG_LEVEL = level;
    }
}

/// Get the current global log level.
pub fn level() -> LogLevel {
    // Safety: single-core, no concurrent access in Stage-1
    unsafe { LOG_LEVEL }
}

/// Log a message at INFO level.
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        if $crate::logger::level() >= $crate::logger::LogLevel::Info {
            $crate::serial_println!("[INFO] {}", format_args!($($arg)*));
        }
    };
}

/// Log a message at ERROR level.
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        if $crate::logger::level() >= $crate::logger::LogLevel::Error {
            $crate::serial_println!("[ERROR] {}", format_args!($($arg)*));
        }
    };
}

/// Log a message at WARN level.
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        if $crate::logger::level() >= $crate::logger::LogLevel::Warn {
            $crate::serial_println!("[WARN] {}", format_args!($($arg)*));
        }
    };
}

/// Log a message at DEBUG level.
#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        if $crate::logger::level() >= $crate::logger::LogLevel::Debug {
            $crate::serial_println!("[DEBUG] {}", format_args!($($arg)*));
        }
    };
}

/// Log a message at TRACE level.
#[macro_export]
macro_rules! log_trace {
    ($($arg:tt)*) => {
        if $crate::logger::level() >= $crate::logger::LogLevel::Trace {
            $crate::serial_println!("[TRACE] {}", format_args!($($arg)*));
        }
    };
}
