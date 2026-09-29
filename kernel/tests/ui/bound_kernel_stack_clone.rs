#![no_std]
#![allow(dead_code)]

include!("boundary_tokens_stub.rs");

use boundary_tokens::BoundKernelStack;

// One binding, one CPL3 entry: the proof is not duplicable.
fn duplicate(bound: &BoundKernelStack) {
    let _ = <BoundKernelStack as Clone>::clone(bound);
}
