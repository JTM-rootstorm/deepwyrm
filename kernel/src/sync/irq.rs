//! IRQ-safe non-sleeping lock for short timer/interrupt critical sections.
//!
//! Local acquisition saves IF and disables maskable interrupts before it can
//! contend on the underlying SMP-safe spin lock. Releasing restores exactly
//! the prior local IF state. NMI/#DF/#MC paths must never acquire this lock.

use core::ops::{Deref, DerefMut};

use super::spin::{SpinMutex, SpinMutexGuard};

pub(crate) struct IrqSpinMutex<T> {
    inner: SpinMutex<T>,
}

impl<T> IrqSpinMutex<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self {
            inner: SpinMutex::new(value),
        }
    }

    pub(crate) fn lock(&self) -> IrqSpinMutexGuard<'_, T> {
        let interrupts_were_enabled = disable_and_save_interrupts();
        let inner = self.inner.lock();
        IrqSpinMutexGuard {
            inner: Some(inner),
            interrupts_were_enabled,
        }
    }
}

#[must_use = "dropping the guard releases the lock and restores the prior IF state"]
pub(crate) struct IrqSpinMutexGuard<'a, T> {
    inner: Option<SpinMutexGuard<'a, T>>,
    interrupts_were_enabled: bool,
}

impl<T> Deref for IrqSpinMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner.as_deref().expect("IRQ lock guard remains live")
    }
}

impl<T> DerefMut for IrqSpinMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner
            .as_deref_mut()
            .expect("IRQ lock guard remains live")
    }
}

impl<T> Drop for IrqSpinMutexGuard<'_, T> {
    fn drop(&mut self) {
        drop(self.inner.take());
        restore_interrupts(self.interrupts_were_enabled);
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "F3 IRQ locking must atomically snapshot IF and disable local maskable interrupts before spinning"
)]
fn disable_and_save_interrupts() -> bool {
    let rflags: u64;
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {}",
            "cli",
            out(reg) rflags,
            options(nomem),
        );
    }
    rflags & (1 << 9) != 0
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "guard release restores IF only when it was set before F3 IRQ-lock acquisition"
)]
fn restore_interrupts(was_enabled: bool) {
    if was_enabled {
        unsafe { core::arch::asm!("sti", options(nomem, nostack, preserves_flags)) };
    }
}

#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
fn disable_and_save_interrupts() -> bool {
    false
}

#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
fn restore_interrupts(_was_enabled: bool) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_guard_serializes_payload_and_releases_on_drop() {
        let lock = IrqSpinMutex::new(7_u64);
        {
            let mut guard = lock.lock();
            *guard = 9;
        }
        assert_eq!(*lock.lock(), 9);
    }
}
