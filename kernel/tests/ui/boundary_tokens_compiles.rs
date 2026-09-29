#![no_std]
#![allow(dead_code)]

// Control case: the stand-in context compiles.
include!("boundary_tokens_stub.rs");

use boundary_tokens::BoundKernelStack;

fn stack_of(bound: &BoundKernelStack) -> kernel_stack::KernelStackBounds {
    bound.stack()
}
