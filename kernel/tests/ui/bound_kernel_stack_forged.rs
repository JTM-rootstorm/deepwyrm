#![no_std]
#![allow(dead_code)]

include!("boundary_tokens_stub.rs");

use boundary_tokens::BoundKernelStack;

// Only the live boundary, after binding or re-checking the entry record, may
// mint the proof `enter_bound_validated_user` takes.
fn forge(stack: kernel_stack::KernelStackBounds) -> BoundKernelStack {
    BoundKernelStack::assume(stack)
}
