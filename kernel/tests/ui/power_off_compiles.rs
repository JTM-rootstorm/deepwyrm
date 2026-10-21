#![no_std]

include!("power_stub.rs");

use runtime_authority::RuntimeAuthorityLock;

// Control: the decision is taken under the guard, which is dropped before the
// halt loop enables interrupts.
pub(crate) fn power_off_after_release(lock: &RuntimeAuthorityLock<u32>) -> ! {
    let [mut handle] = lock.handles::<1>();
    let guard = handle.lock();
    drop(guard);
    power::soft_off_then_halt(handle.guard_free())
}
