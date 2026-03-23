//! ATOS Synchronization Primitives
//!
//! Provides a simple spinlock for protecting shared kernel data.
//! In Stage-2 (single-core), the spinlock disables interrupts.
//! In Stage-3+ (SMP), it will use atomic compare-and-swap.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

pub struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// Safety: SpinLock provides mutual exclusion
unsafe impl<T: Send> Sync for SpinLock<T> {}
unsafe impl<T: Send> Send for SpinLock<T> {}

/// Read the RFLAGS register.
#[inline(always)]
fn read_rflags() -> u64 {
    let flags: u64;
    unsafe { core::arch::asm!("pushfq; pop {}", out(reg) flags, options(nomem)); }
    flags
}

impl<T> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        SpinLock {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    pub fn lock(&self) -> SpinLockGuard<T> {
        // Save interrupt state and disable interrupts
        let flags = read_rflags();
        let irq_was_enabled = flags & (1 << 9) != 0;
        unsafe { core::arch::asm!("cli", options(nomem, nostack)); }

        // Spin until we acquire the lock
        while self.locked.compare_exchange_weak(
            false, true, Ordering::Acquire, Ordering::Relaxed
        ).is_err() {
            core::hint::spin_loop();
        }

        SpinLockGuard { lock: self, irq_was_enabled }
    }

    /// Acquire the lock WITHOUT disabling/restoring interrupts.
    /// The caller is responsible for managing interrupt state.
    /// Use this when the caller already has cli/sti brackets.
    pub fn lock_raw(&self) -> SpinLockGuard<T> {
        while self.locked.compare_exchange_weak(
            false, true, Ordering::Acquire, Ordering::Relaxed
        ).is_err() {
            core::hint::spin_loop();
        }

        SpinLockGuard { lock: self, irq_was_enabled: false }
    }
}

pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    irq_was_enabled: bool,
}

impl<'a, T> core::ops::Deref for SpinLockGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> core::ops::DerefMut for SpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for SpinLockGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
        // Only restore interrupts if they were enabled before we acquired the lock
        if self.irq_was_enabled {
            unsafe { core::arch::asm!("sti", options(nomem, nostack)); }
        }
    }
}
