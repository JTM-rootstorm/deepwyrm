#![no_std]

include!("root_switch_stub.rs");

use root_switch::PreparedSchedulerRootSwitch;

// A prepared flight is consumed by its one CR3 execution.
fn execute_twice<T: RootSwitchTarget>(prepared: PreparedSchedulerRootSwitch, target: &mut T) {
    let _ = prepared.execute_on(target);
    let _ = prepared.execute_on(target);
}
