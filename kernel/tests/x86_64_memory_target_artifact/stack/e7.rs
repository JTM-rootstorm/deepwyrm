use super::*;

pub(crate) fn validate_e7_stack_margin(sizes: &[StackSize], disassembly: &str) {
    const BOOT_STACK_BYTES: usize = 256 * 1024;
    const THREAD_STACK_BYTES: usize = 256 * 1024;
    const REQUIRED_SPARE_BYTES: usize = 32 * 1024;
    const ARCHITECTURAL_HEADROOM_BYTES: usize = 4 * 1024;
    const RAW_SYSCALL_FRAME_BYTES: usize = 144;
    const ASSEMBLY_CALL_RETURN_BYTES: usize = size_of::<u64>();
    const TIMER_IRQ_ENTRY_BYTES: usize =
        3 * size_of::<u64>() + 15 * size_of::<u64>() + 15 + size_of::<u64>();
    const F2_PROBE_STACK_BYTES: usize = 16 * 1024;
    const F2_SWITCH_FRAME_BYTES: usize = 7 * size_of::<u64>();
    const E7_RUNTIME: &str = "deepwyrm_kernel::arch::x86_64::mm::transition::activation::test_support::e7::E7SmokeRuntime<128, 544>";

    let plain = |description: &str, needle: &str| {
        one_stack_size(sizes, description, |symbol| {
            symbol.contains(needle) && !symbol.contains("::{closure")
        })
    };

    let f2_probe_alternate = plain(
        "F2 target continuation alternate",
        "context::target_probe::alternate_entry",
    );
    let f2_alternate_total = f2_probe_alternate
        .checked_add(F2_SWITCH_FRAME_BYTES)
        .and_then(|bytes| bytes.checked_add(ARCHITECTURAL_HEADROOM_BYTES))
        .expect("F2 target probe stack bound fits usize");
    assert!(
        f2_alternate_total <= F2_PROBE_STACK_BYTES,
        "F2 alternate probe stack too small: used={f2_alternate_total} capacity={F2_PROBE_STACK_BYTES}"
    );

    let boot_prefix = [
        one_stack_size(sizes, "E7 kernel main", |symbol| {
            symbol == "deepwyrm_kernel::kernel_main"
        }),
        plain(
            "E7 task runner",
            "test_support::task::run_task_guest_test::<128, 544>",
        ),
        plain("E7 active runner", ">>::run_task_userspace_test"),
        plain(
            "E7 selector runner",
            "test_support::e7::run_task_userspace_test::<128, 544>",
        ),
    ];
    let send_live_ipi = one_stack_symbol(sizes, "live IPI send boundary", |symbol| {
        symbol.ends_with("arch::x86_64::ipi::send_live_ipi")
    });
    let live_ipi_transport_send =
        one_stack_symbol(sizes, "stationary live IPI transport", |symbol| {
            symbol.contains("arch::x86_64::ipi::transport_send::<")
                && symbol.contains("StationaryLiveIpiTransport")
                && !symbol.contains("::{closure")
        });
    let mut resolutions = BTreeMap::new();
    resolutions.insert(send_live_ipi, vec![live_ipi_transport_send]);
    let timer_set = one_stack_symbol(sizes, "E7 Timer set transaction", |symbol| {
        symbol == "<deepwyrm_kernel::time::timer::TimerAuthority<1>>::set::<1>"
    });
    let timer_set_locked = one_stack_symbol(sizes, "E7 locked Timer set transaction", |symbol| {
        symbol
            == "<deepwyrm_kernel::time::timer::TimerAuthority<1>>::set_with_readiness_hook::<1, <deepwyrm_kernel::time::timer::TimerAuthority<1>>::set<1>::{closure#0}>"
    });
    let timer_finalization =
        one_stack_symbol(sizes, "E7 Timer finalization transaction", |symbol| {
            symbol == "<deepwyrm_kernel::time::timer::TimerAuthority<1>>::take_finalization"
        });
    let replace_live_timer_deadline = one_stack_symbol(
        sizes,
        "E7 live Timer deadline replacement",
        |symbol| {
            symbol.ends_with(
                "time::live::LiveTimerDeadlineAuthority as deepwyrm_kernel::time::timer::TimerDeadlineAuthority>::replace_timer_deadline",
            )
        },
    );
    let cancel_live_timer_deadline = one_stack_symbol(
        sizes,
        "E7 live Timer deadline cancellation",
        |symbol| {
            symbol.ends_with(
                "time::live::LiveTimerDeadlineAuthority as deepwyrm_kernel::time::timer::TimerDeadlineAuthority>::cancel_timer_deadline",
            )
        },
    );
    resolutions.insert(timer_set_locked.clone(), vec![replace_live_timer_deadline]);
    resolutions.insert(timer_finalization, vec![cancel_live_timer_deadline]);
    let graph = DirectCallGraph::new(sizes, disassembly);
    assert!(
        graph.reaches(
            "E7 Timer set wrapper",
            |symbol| symbol == timer_set,
            |symbol| symbol == timer_set_locked,
        ),
        "E7 Timer set wrapper does not reach its accepted locked helper"
    );
    let boot_setup = graph
        .with_resolutions(&resolutions)
        .stack_bound("E7 setup path", |symbol| {
            symbol.ends_with("test_support::e7::enter_smoke::<128, 544>")
                && !symbol.contains("::{closure")
        });
    let boot_prefix_bytes = boot_prefix
        .into_iter()
        .try_fold(0_usize, usize::checked_add)
        .expect("E7 boot prefix fits usize");
    let boot_return_count = boot_setup
        .call_count
        .checked_add(boot_prefix.len())
        .expect("E7 boot return count fits usize");
    let boot_setup_total = boot_prefix_bytes
        .checked_add(boot_setup.bytes)
        .and_then(|bytes| bytes.checked_add(boot_return_count * size_of::<u64>()))
        .and_then(|bytes| bytes.checked_add(ARCHITECTURAL_HEADROOM_BYTES))
        .expect("E7 bootstrap stack bound fits usize");
    let enter_smoke = plain(
        "E7 enter-smoke interrupt prefix",
        "test_support::e7::enter_smoke::<128, 544>",
    );
    let probe_prefix = plain(
        "F3 target deadline probe",
        "time::live::probes::run_target_deadline_probe",
    )
    .max(plain(
        "F8 target Timer probe",
        "time::live::probes::run_target_timer_probe",
    ));
    let timer_dispatch = one_stack_symbol(sizes, "x86 timer dispatcher", |symbol| {
        symbol == "dw_x86_64_timer_interrupt_dispatch"
    });
    let deadline_wake = one_stack_symbol(sizes, "F3 deadline wake trampoline", |symbol| {
        symbol.contains("time::live::wake_trampoline::<")
            && symbol.contains("time::live::probes::ProbeWakeTarget")
            && !symbol.contains("::{closure")
    });
    let timer_expiry = one_stack_symbol(sizes, "F8 Timer expiry trampoline", |symbol| {
        symbol.contains("time::live::timer_expiry_trampoline::<")
            && symbol.contains("time::live::probes::TimerProbeTarget")
            && !symbol.contains("::{closure")
    });
    let mut timer_resolutions = resolutions.clone();
    timer_resolutions.insert(timer_dispatch.clone(), vec![deadline_wake, timer_expiry]);
    let timer_interrupt = graph
        .with_resolutions(&timer_resolutions)
        .stack_bound("E7 timer interrupt path", |symbol| symbol == timer_dispatch);
    let timer_interrupt_returns = boot_prefix
        .len()
        .checked_add(2)
        .and_then(|count| count.checked_add(timer_interrupt.call_count))
        .expect("E7 timer interrupt return count fits usize");
    let timer_interrupt_total = boot_prefix_bytes
        .checked_add(enter_smoke)
        .and_then(|bytes| bytes.checked_add(probe_prefix))
        .and_then(|bytes| bytes.checked_add(TIMER_IRQ_ENTRY_BYTES))
        .and_then(|bytes| bytes.checked_add(timer_interrupt.bytes))
        .and_then(|bytes| bytes.checked_add(timer_interrupt_returns * size_of::<u64>()))
        .and_then(|bytes| bytes.checked_add(ARCHITECTURAL_HEADROOM_BYTES))
        .expect("E7 timer interrupt stack bound fits usize");
    let boot_total = boot_setup_total.max(timer_interrupt_total);
    assert!(
        boot_total + REQUIRED_SPARE_BYTES <= BOOT_STACK_BYTES,
        "E7 bootstrap stack bound too small: used={boot_total} spare={} required={REQUIRED_SPARE_BYTES}",
        BOOT_STACK_BYTES.saturating_sub(boot_total)
    );

    let trampoline = one_stack_symbol(sizes, "E7 runtime trampoline", |symbol| {
        symbol.contains("syscall::live::native_runtime_trampoline::<")
            && symbol.contains(E7_RUNTIME)
            && !symbol.contains("::{closure")
    });
    let dispatch_bound = one_stack_symbol(sizes, "bound syscall dispatcher", |symbol| {
        symbol.ends_with("arch::x86_64::syscall::live::dispatch_bound_runtime")
    });
    let syscall_dispatch = one_stack_symbol(sizes, "x86 syscall dispatcher", |symbol| {
        symbol == "dw_x86_64_syscall_dispatch"
    });
    let runtime_handler = one_stack_symbol(sizes, "E7 runtime handler", |symbol| {
        symbol.contains(E7_RUNTIME)
            && symbol
                .ends_with(" as deepwyrm_kernel::syscall::native::NativeSyscallHandler>::handle")
    });
    resolutions.insert(dispatch_bound, vec![trampoline.clone()]);
    assert!(
        graph.reaches(
            "E7 runtime dispatch",
            |symbol| symbol == trampoline,
            |symbol| symbol == runtime_handler,
        ),
        "E7 syscall graph does not reach its concrete smoke runtime handler"
    );
    let thread = graph
        .with_resolutions(&resolutions)
        .stack_bound("E7 syscall dispatch path", |symbol| {
            symbol == syscall_dispatch
        });
    let thread_total = RAW_SYSCALL_FRAME_BYTES
        .checked_add(ASSEMBLY_CALL_RETURN_BYTES)
        .and_then(|bytes| bytes.checked_add(thread.bytes))
        .and_then(|bytes| bytes.checked_add(thread.call_count * size_of::<u64>()))
        .and_then(|bytes| bytes.checked_add(ARCHITECTURAL_HEADROOM_BYTES))
        .expect("E7 Thread stack bound fits usize");
    assert!(
        thread_total + REQUIRED_SPARE_BYTES <= THREAD_STACK_BYTES,
        "E7 Thread stack bound too small: used={thread_total} spare={} required={REQUIRED_SPARE_BYTES}",
        THREAD_STACK_BYTES.saturating_sub(thread_total)
    );

    eprintln!(
        "task-syscall-smoke stack bootstrap={boot_total} setup={boot_setup_total} timer-interrupt={timer_interrupt_total} thread={thread_total} bootstrap-spare={} thread-spare={} boot-terminal={} timer-terminal={} thread-terminal={}",
        BOOT_STACK_BYTES - boot_total,
        THREAD_STACK_BYTES - thread_total,
        boot_setup.terminal,
        timer_interrupt.terminal,
        thread.terminal,
    );
}
