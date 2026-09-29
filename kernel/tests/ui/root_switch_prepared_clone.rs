#![no_std]

include!("root_switch_stub.rs");

use root_switch::PreparedSchedulerRootSwitch;

// A prepared flight cannot be duplicated into a second execution.
fn clone_prepared(prepared: &PreparedSchedulerRootSwitch) {
    let _ = <PreparedSchedulerRootSwitch as Clone>::clone(prepared);
}
