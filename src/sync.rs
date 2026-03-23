//! AOS Synchronization Primitives
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

impl<T> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        SpinLock {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    pub fn lock(&self) -> SpinLockGuard<T> {
        // Disable interrupts to prevent deadlock on single-core
        unsafe { core::arch::asm!("cli", options(nomem, nostack)); }

        // Spin until we acquire the lock
        while self.locked.compare_exchange_weak(
            false, true, Ordering::Acquire, Ordering::Relaxed
        ).is_err() {
            core::hint::spin_loop();
        }

        SpinLockGuard { lock: self, restore_irq: true }
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

        SpinLockGuard { lock: self, restore_irq: false }
    }
}

pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    restore_irq: bool,
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
        if self.restore_irq {
            unsafe { core::arch::asm!("sti", options(nomem, nostack)); }
        }
    }
}
