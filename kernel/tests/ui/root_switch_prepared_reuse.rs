#![no_std]

include!("root_switch_stub.rs");

use root_switch::PreparedSchedulerRootSwitch;
use runtime_authority::RuntimeAuthorityHandle;

// A prepared flight is consumed by its one CR3 execution.
fn execute_twice<T: RootSwitchTarget>(
    prepared: PreparedSchedulerRootSwitch,
    target: &mut T,
    handle: &mut RuntimeAuthorityHandle<'_, ()>,
) {
    let _ = prepared.execute_on(target, handle.guard_free());
    let _ = prepared.execute_on(target, handle.guard_free());
}
