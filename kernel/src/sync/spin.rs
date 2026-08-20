use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

/// Non-sleeping mutual exclusion for short kernel critical sections.
///
/// E3 callers must not hold this lock across subsystem finalization, usercopy,
/// page-table publication, or any operation that may later block. Interrupt
/// interrupt-shared F3 state must use `IrqSpinMutex` rather than acquiring
/// this plain lock from an interrupt handler.
pub(crate) struct SpinMutex<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

impl<T> SpinMutex<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    pub(crate) fn lock(&self) -> SpinMutexGuard<'_, T> {
        loop {
            if let Some(guard) = self.try_lock() {
                return guard;
            }
            while self.locked.load(Ordering::Relaxed) {
                spin_loop();
            }
        }
    }

    pub(crate) fn try_lock(&self) -> Option<SpinMutexGuard<'_, T>> {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| SpinMutexGuard { mutex: self })
    }

    #[cfg(test)]
    pub(crate) fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
}

#[allow(
    unsafe_code,
    reason = "Acquire/Release ownership of the lock serializes access to the UnsafeCell payload"
)]
unsafe impl<T: Send> Sync for SpinMutex<T> {}

pub(crate) struct SpinMutexGuard<'a, T> {
    mutex: &'a SpinMutex<T>,
}

impl<T> Deref for SpinMutexGuard<'_, T> {
    type Target = T;

    #[allow(
        unsafe_code,
        reason = "the live guard owns the mutex and therefore exclusive read access to the UnsafeCell payload"
    )]
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.mutex.value.get() }
    }
}

impl<T> DerefMut for SpinMutexGuard<'_, T> {
    #[allow(
        unsafe_code,
        reason = "the live guard owns the mutex and therefore exclusive mutable access to the UnsafeCell payload"
    )]
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.mutex.value.get() }
    }
}

impl<T> Drop for SpinMutexGuard<'_, T> {
    fn drop(&mut self) {
        self.mutex.locked.store(false, Ordering::Release);
    }
}
