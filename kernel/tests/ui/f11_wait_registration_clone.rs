#![no_std]

include!("f11_full_kernel_modules.rs");

use wait::WaitRegistration;

fn clone_registration(registration: &WaitRegistration) {
    let _ = <WaitRegistration as Clone>::clone(registration);
}
