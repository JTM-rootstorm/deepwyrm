#![no_std]

include!("f11_full_kernel_modules.rs");

use syscall::NativeWaitControl;
use task::{ExecutionDomain, TaskAuthority};

fn safe_code_cannot_produce_a_suspend_plan<
    const EXECUTION: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    execution: &ExecutionDomain<EXECUTION>,
    control: &mut NativeWaitControl,
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
) {
    let _plan = control.prepare_suspend(tasks, execution, 0xffff_8000_0012_3000);
}
