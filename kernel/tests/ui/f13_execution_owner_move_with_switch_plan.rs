#![no_std]

include!("f11_full_kernel_modules.rs");

use syscall::NativeWaitControl;
use task::{ExecutionDomain, TaskAuthority};

fn move_execution_owner_while_plan_is_live<
    const EXECUTION: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    execution: ExecutionDomain<EXECUTION>,
    control: &mut NativeWaitControl,
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
) {
    #[allow(
        unsafe_code,
        reason = "the compile-fail fixture isolates owner stationarity after explicitly accepting the physical-carrier contract"
    )]
    let plan = unsafe { control.prepare_suspend(tasks, &execution, 0xffff_8000_0012_3000) };
    let moved = execution;
    core::hint::black_box(plan);
    core::hint::black_box(moved);
}
