#![no_std]

include!("f11_full_kernel_modules.rs");

use task::CarrierRuntimeState;

// Only the AP kernel-root entry's commit may mint the executing state an AP
// publishes ready with (TSV row 102).
fn ready_without_entering_the_kernel_root() -> CarrierRuntimeState {
    CarrierRuntimeState::after_kernel_root_entry()
}
