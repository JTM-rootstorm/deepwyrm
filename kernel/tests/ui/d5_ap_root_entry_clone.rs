#![no_std]

include!("f11_full_kernel_modules.rs");

use task::CarrierRuntimeState;

// One kernel-root entry admits one ready publication.
fn duplicate(state: &CarrierRuntimeState) {
    let _ = <CarrierRuntimeState as Clone>::clone(state);
}
