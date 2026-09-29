#![no_std]

// Control case: the stand-in context compiles, so every compile-fail case below
// fails for its own reason and not because the harness drifted.
include!("root_switch_stub.rs");

use root_switch::{PreparedSchedulerRootSwitch, PreparedStopRootSwitch, RootSwitchFlight};
use runtime_authority::RuntimeAuthorityHandle;

pub(crate) fn prepare_execute_commit<T: RootSwitchTarget>(
    flight: RootSwitchFlight,
    prepared: PreparedKernelExecutionRootSwitch,
    scheduler: PreparedSchedulerRootSwitch,
    target: &mut T,
    handle: &mut RuntimeAuthorityHandle<'_, ()>,
) {
    let stop = PreparedStopRootSwitch::new(flight, prepared);
    if let Ok(executed) = stop.execute_on(target, handle.guard_free()) {
        let _: RootSwitchFlight = executed.flight;
        let _ = executed.into_executed();
    }
    if let Err(failure) = scheduler.execute_on(target, handle.guard_free()) {
        let _ = failure.into_kind();
    }
    // The guard and the token take turns on the one handle.
    drop(handle.lock());
}
