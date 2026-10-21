#![no_std]

include!("power_stub.rs");

use runtime_authority::RuntimeAuthorityLock;

// The halt loop runs `sti; hlt`, so it cannot be entered while this CPU's
// runtime guard is alive (DW0-H §12.8; design §11.2.6).
pub(crate) fn power_off_under_guard(lock: &RuntimeAuthorityLock<u32>) -> ! {
    let [mut handle] = lock.handles::<1>();
    let _guard = handle.lock();
    power::soft_off_then_halt(handle.guard_free())
}
