#![no_std]

include!("f11_full_kernel_modules.rs");

use syscall::native::FinalizersDrained;

// One drain proves one return.
fn duplicate(proof: &FinalizersDrained) {
    let _ = <FinalizersDrained as Clone>::clone(proof);
}
