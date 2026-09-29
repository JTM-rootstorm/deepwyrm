#![no_std]

include!("root_switch_stub.rs");

use root_switch::{FailedStopRootSwitch, RootSwitchFlight};

// Only `execute_on` may produce the cancel input: a flight cannot be cancelled
// back to a root it never tried to leave.
fn forge_failed(
    flight: RootSwitchFlight,
    error: RootBindingError,
    previous: ActiveRootSelection,
) -> FailedStopRootSwitch {
    FailedStopRootSwitch {
        flight,
        error,
        previous,
    }
}
