#![no_std]

include!("f11_full_kernel_modules.rs");

use syscall::native::FinalizersDrained;

// Only a completed drain may mint the proof.
fn forge() -> FinalizersDrained {
    FinalizersDrained::assume()
}
