#![no_std]

include!("root_switch_stub.rs");

use root_switch::{ExecutedStopRootSwitch, RootSwitchFlight};

// Only `execute_on` may produce the commit input: the carrier cannot commit a
// root it did not load.
fn forge_executed(
    flight: RootSwitchFlight,
    executed: ExecutedKernelExecutionRootSwitch,
) -> ExecutedStopRootSwitch {
    ExecutedStopRootSwitch { flight, executed }
}
