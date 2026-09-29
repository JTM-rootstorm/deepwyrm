#![no_std]

// Control case: the stand-in context compiles, so every compile-fail case below
// fails for its own reason and not because the harness drifted.
include!("root_switch_stub.rs");

use root_switch::{PreparedSchedulerRootSwitch, PreparedStopRootSwitch, RootSwitchFlight};

pub(crate) fn prepare_execute_commit<T: RootSwitchTarget>(
    flight: RootSwitchFlight,
    prepared: PreparedKernelExecutionRootSwitch,
    scheduler: PreparedSchedulerRootSwitch,
    target: &mut T,
) {
    if let Ok(executed) = PreparedStopRootSwitch::new(flight, prepared).execute_on(target) {
        let _: RootSwitchFlight = executed.flight;
        let _ = executed.into_executed();
    }
    if let Err(failure) = scheduler.execute_on(target) {
        let _ = failure.into_kind();
    }
}
