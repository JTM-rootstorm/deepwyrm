#![no_std]

include!("f11_full_kernel_modules.rs");

use time::TimerPayloadBinding;

fn clone_binding(binding: &TimerPayloadBinding) {
    let _ = <TimerPayloadBinding as Clone>::clone(binding);
}
