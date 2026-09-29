#![no_std]

include!("root_switch_stub.rs");

use root_switch::PreparedSchedulerRootSwitch;
use runtime_authority::RuntimeAuthorityHandle;

// A CR3 switch cannot run while this CPU holds the runtime authority guard:
// the token that `execute_on` needs cannot be minted from a locked handle.
fn execute_under_the_guard<T: RootSwitchTarget>(
    prepared: PreparedSchedulerRootSwitch,
    target: &mut T,
    handle: &mut RuntimeAuthorityHandle<'_, ()>,
) {
    let guard = handle.lock();
    let _ = prepared.execute_on(target, handle.guard_free());
    drop(guard);
}
