#![allow(dead_code)]

#[path = "../../src/memory/kernel_stack.rs"]
mod kernel_stack;

mod memory {
    pub(crate) mod kernel_stack {
        pub(crate) use crate::kernel_stack::*;
    }
}

#[path = "../../src/arch/x86_64/context.rs"]
mod context;

use context::InitialKernelContinuation;

fn clone_initial_continuation(continuation: &InitialKernelContinuation) {
    let _ = <InitialKernelContinuation as Clone>::clone(continuation);
}
