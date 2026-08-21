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

use context::KernelSwitchPlan;

fn clone_switch_plan(plan: &KernelSwitchPlan) {
    let _ = <KernelSwitchPlan as Clone>::clone(plan);
}
