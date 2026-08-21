use super::ist::validate_ist_stack_margin;
use super::*;

pub(crate) fn validate_f12_stack_context_evidence(
    sizes: &[StackSize],
    symbols: &str,
    disassembly: &str,
) {
    const F12_USER_STACK_BYTES: usize = 4096;
    const F12_USER_THREADS: usize = 2;
    const F12_USER_SLICE_BYTES: usize = F12_USER_STACK_BYTES / F12_USER_THREADS;
    const FIRST_RUN_ABI_WORD_BYTES: usize = size_of::<u64>();
    const RAW_SYSCALL_FRAME_BYTES: usize = 144;
    const ASSEMBLY_CALL_RETURN_BYTES: usize = size_of::<u64>();
    const TIMER_IRQ_ENTRY_BYTES: usize =
        3 * size_of::<u64>() + 15 * size_of::<u64>() + 15 + size_of::<u64>();
    const REQUIRED_SPARE_BYTES: usize = 32 * 1024;

    assert_eq!(F12_USER_STACK_BYTES % F12_USER_THREADS, 0);
    assert_eq!(F12_USER_SLICE_BYTES, 2048);
    assert_eq!(
        F12_USER_SLICE_BYTES * F12_USER_THREADS,
        F12_USER_STACK_BYTES
    );
    for required in [
        "native_runtime_fresh_thread",
        "native_runtime_trampoline",
        "KernelSwitchPlan",
        "dw_x86_64_switch_kernel_context",
        "F12Runtime",
        "F12DeadlineWakeTarget",
    ] {
        assert!(
            symbols.contains(required),
            "F12 target artifact omitted context evidence {required}"
        );
    }
    for address in ["0x50002000", "0x50002800", "0x50003000"] {
        assert!(
            disassembly.contains(address),
            "F12 target artifact omitted its linked user-stack boundary {address}"
        );
    }
    assert!(
        !symbols.contains("timer_expiry_trampoline::<deepwyrm_kernel::arch::x86_64::mm::transition::activation::test_support::f12"),
        "F12 selector unexpectedly bound the Timer-expiry service its guest does not exercise"
    );
    validate_f2_kernel_context_switch(disassembly);

    let symbol = |description: &str, predicate: &dyn Fn(&str) -> bool| {
        one_stack_symbol(sizes, description, predicate)
    };
    let fresh_handler = symbol("F12 fresh handler", &|name| {
        name.contains("native_runtime_fresh_thread::<") && name.contains("F12Runtime<")
    });
    let trampoline = symbol("F12 runtime trampoline", &|name| {
        name.contains("native_runtime_trampoline::<") && name.contains("F12Runtime<")
    });
    let first_run = symbol("x86 first-run entry", &|name| {
        name == "dw_x86_64_first_run_thread_entry"
    });
    let dispatch_bound = symbol("bound syscall dispatcher", &|name| {
        name.ends_with("arch::x86_64::syscall::live::dispatch_bound_runtime")
    });
    let syscall_dispatch = symbol("x86 syscall dispatcher", &|name| {
        name == "dw_x86_64_syscall_dispatch"
    });
    let timer_dispatch = symbol("x86 timer dispatcher", &|name| {
        name == "dw_x86_64_timer_interrupt_dispatch"
    });
    let deadline_wake = symbol("F12 deadline wake trampoline", &|name| {
        name.contains("time::live::wake_trampoline::<") && name.contains("F12DeadlineWakeTarget")
    });
    let timer_halt = symbol("timer fail-stop", &|name| {
        name.ends_with("time::live::halt_forever")
    });
    let wait_begin = symbol("F12 registered-wait transaction", &|name| {
        name.contains("wait::engine::begin_registered_wait::<")
            && name.contains("OwnedLiveUserOutput")
            && !name.contains("::{closure")
    });
    let atomic_wait_begin = symbol("F12 atomic-wait transaction", &|name| {
        name.starts_with("deepwyrm_kernel::atomic_wait::begin_atomic_wait::<")
            && name.contains("OwnedLiveAtomicU32")
            // The transaction's generic load argument is itself a closure, so
            // filtering every name containing `::{closure` would also reject
            // the outer monomorph. Its emitted helper closures end in `}`,
            // while the transaction symbol ends at the generic `>`.
            && name.ends_with('>')
    });
    let register_wait_deadline = symbol("F12 live wait-deadline registration", &|name| {
        name.ends_with(
            "wait::engine::LiveWaitDeadlineAuthority as deepwyrm_kernel::wait::engine::WaitDeadlineAuthority>::register_wait_deadline",
        )
    });
    let cancel_wait_deadline = symbol("F12 exact wait-deadline cancellation", &|name| {
        name == "deepwyrm_kernel::wait::engine::cancel_deadline_exact"
    });
    let cancel_atomic_wait_deadline = symbol("F12 atomic-wait deadline cancellation", &|name| {
        name == "deepwyrm_kernel::atomic_wait::cancel_deadline"
    });
    let cancel_live_wait_deadline = symbol("F12 live wait-deadline cancellation", &|name| {
        name.ends_with(
            "wait::engine::LiveWaitDeadlineAuthority as deepwyrm_kernel::wait::engine::WaitDeadlineAuthority>::cancel_wait_deadline",
        )
    });
    let timer_set = symbol("F12 Timer set transaction", &|name| {
        name == "<deepwyrm_kernel::time::timer::TimerAuthority<1>>::set::<4>"
    });
    let timer_set_locked = symbol("F12 locked Timer set transaction", &|name| {
        name == "<deepwyrm_kernel::time::timer::TimerAuthority<1>>::set_with_readiness_hook::<4, <deepwyrm_kernel::time::timer::TimerAuthority<1>>::set<4>::{closure#0}>"
    });
    let timer_cancel = symbol("F12 Timer cancellation transaction", &|name| {
        name == "<deepwyrm_kernel::time::timer::TimerAuthority<1>>::cancel"
    });
    let timer_finalization = symbol("F12 Timer finalization transaction", &|name| {
        name == "<deepwyrm_kernel::time::timer::TimerAuthority<1>>::take_finalization"
    });
    let replace_live_timer_deadline = symbol("F12 live Timer deadline replacement", &|name| {
        name.ends_with(
            "time::live::LiveTimerDeadlineAuthority as deepwyrm_kernel::time::timer::TimerDeadlineAuthority>::replace_timer_deadline",
        )
    });
    let cancel_live_timer_deadline = symbol("F12 live Timer deadline cancellation", &|name| {
        name.ends_with(
            "time::live::LiveTimerDeadlineAuthority as deepwyrm_kernel::time::timer::TimerDeadlineAuthority>::cancel_timer_deadline",
        )
    });
    let scheduler_prepare_block = symbol("F12 scheduler block preparation", &|name| {
        name == "<deepwyrm_kernel::task::scheduler::CooperativeScheduler<2>>::prepare_block_current"
    });
    let scheduler_commit_block = symbol("F12 scheduler block commit", &|name| {
        name == "<deepwyrm_kernel::task::scheduler::CooperativeScheduler<2>>::commit_block"
    });
    let scheduler_guard_deref_mut = symbol("scheduler guard mutable dereference", &|name| {
        name == "<deepwyrm_kernel::sync::irq::IrqSpinMutexGuard<deepwyrm_kernel::task::scheduler::SchedulerState<2>> as core::ops::deref::DerefMut>::deref_mut"
    });
    let scheduler_guard_deref = symbol("scheduler guard shared dereference", &|name| {
        name == "<deepwyrm_kernel::sync::irq::IrqSpinMutexGuard<deepwyrm_kernel::task::scheduler::SchedulerState<2>> as core::ops::deref::Deref>::deref"
    });
    let mut runtime_resolutions = BTreeMap::new();
    runtime_resolutions.insert(first_run.clone(), vec![fresh_handler]);
    runtime_resolutions.insert(dispatch_bound, vec![trampoline.clone()]);
    // Selector 13 constructs only `LiveWaitDeadlineAuthority` at every F
    // service call site. The erased deadline call in the monomorphized wait
    // transaction therefore has this one emitted target.
    runtime_resolutions.insert(wait_begin, vec![register_wait_deadline.clone()]);
    runtime_resolutions.insert(atomic_wait_begin, vec![register_wait_deadline]);
    runtime_resolutions.insert(
        cancel_wait_deadline,
        vec![cancel_live_wait_deadline.clone()],
    );
    runtime_resolutions.insert(cancel_atomic_wait_deadline, vec![cancel_live_wait_deadline]);
    // The accepted artifact loads the locked set helper through an immutable
    // call slot, which the artifact resolver converts into a direct edge from
    // the public wrapper. The helper owns the one remaining erased deadline
    // call. The F12 service constructs only `LiveTimerDeadlineAuthority`, so
    // that exact indirect owner has the one emitted replacement target.
    runtime_resolutions.insert(timer_set_locked.clone(), vec![replace_live_timer_deadline]);
    runtime_resolutions.insert(timer_cancel, vec![cancel_live_timer_deadline.clone()]);
    runtime_resolutions.insert(timer_finalization, vec![cancel_live_timer_deadline]);
    // Debug codegen spills these two statically typed guard-method addresses
    // through local stack words before calling them. The closed source type is
    // `IrqSpinMutexGuard<SchedulerState<2>>`; no trait object or alternate
    // runtime implementation participates in this monomorph.
    runtime_resolutions.insert(scheduler_prepare_block, vec![scheduler_guard_deref]);
    runtime_resolutions.insert(
        scheduler_commit_block,
        vec![scheduler_guard_deref_mut.clone(); 2],
    );
    let graph = DirectCallGraph::new(sizes, disassembly);
    assert!(
        graph.reaches(
            "F12 Timer set wrapper",
            |name| name == timer_set,
            |name| name == timer_set_locked,
        ),
        "F12 public Timer set wrapper does not reach its accepted locked helper"
    );
    let mut runtime_graph = graph.with_resolutions(&runtime_resolutions);
    let fresh = runtime_graph.stack_bound("F12 fresh-thread path", |name| name == first_run);
    let syscall =
        runtime_graph.stack_bound("F12 syscall dispatch path", |name| name == syscall_dispatch);
    let terminal = runtime_graph.stack_bound("F12 terminal-reaper path", |name| {
        name.contains("native_runtime_terminal_reaper::<") && name.contains("F12Runtime<")
    });
    assert!(
        graph.reaches(
            "F12 runtime dispatch",
            |name| name == trampoline,
            |name| name.contains("FServiceState<") && name.contains(">>::dispatch::<"),
        ),
        "F12 syscall graph does not reach FService dispatch"
    );

    // Immutable call slots are resolved from the accepted ELF before this
    // validator runs. The remaining two erased timer calls are the bound F12
    // deadline target and the unreachable Timer-expiry target. No typed F12
    // Timer-expiry trampoline is emitted, so the latter is charged as its
    // fail-stop path instead of being waived.
    let mut timer_resolutions = BTreeMap::new();
    timer_resolutions.insert(timer_dispatch.clone(), vec![deadline_wake, timer_halt]);
    let timer = graph
        .with_resolutions(&timer_resolutions)
        .stack_bound("F12 APIC timer interrupt path", |name| {
            name == timer_dispatch
        });
    let setup = graph.stack_bound("F12 selector setup", |name| {
        name.contains("f12::enter_f12::<") && !name.contains("::{closure")
    });

    let fresh_total = FIRST_RUN_ABI_WORD_BYTES
        .checked_add(fresh.bytes)
        .and_then(|bytes| bytes.checked_add(fresh.call_count * size_of::<u64>()))
        .expect("F12 fresh-thread bound fits usize");
    let syscall_total = RAW_SYSCALL_FRAME_BYTES
        .checked_add(ASSEMBLY_CALL_RETURN_BYTES)
        .and_then(|bytes| bytes.checked_add(syscall.bytes))
        .and_then(|bytes| bytes.checked_add(syscall.call_count * size_of::<u64>()))
        .expect("F12 syscall bound fits usize");
    // poll_idle_suspend has returned at STI;HLT. The live interrupted prefix
    // is the raw syscall frame, dispatch frames, runtime trampoline, and the
    // return word for its zero-frame wait_for_suspend_interrupt call.
    let syscall_prefix = RAW_SYSCALL_FRAME_BYTES
        + ASSEMBLY_CALL_RETURN_BYTES
        + one_stack_size(sizes, "x86 syscall dispatcher", |name| {
            name == "dw_x86_64_syscall_dispatch"
        })
        + size_of::<u64>()
        + one_stack_size(sizes, "bound syscall dispatcher", |name| {
            name.ends_with("arch::x86_64::syscall::live::dispatch_bound_runtime")
        })
        + size_of::<u64>()
        + one_stack_size(sizes, "F12 runtime trampoline", |name| name == trampoline)
        + size_of::<u64>();
    let timer_total = syscall_prefix
        .checked_add(TIMER_IRQ_ENTRY_BYTES)
        .and_then(|bytes| bytes.checked_add(timer.bytes))
        .and_then(|bytes| bytes.checked_add(timer.call_count * size_of::<u64>()))
        .expect("F12 preempted timer bound fits usize");
    let setup_total = setup.bytes + setup.call_count * size_of::<u64>();
    let boot_payload = linked_boot_stack_payload_bytes(symbols);
    assert!(
        setup_total + REQUIRED_SPARE_BYTES <= boot_payload,
        "F12 selector setup exceeds the retained boot-stack payload: total={setup_total} payload={boot_payload} required-spare={REQUIRED_SPARE_BYTES}"
    );
    eprintln!(
        "F12 setup total={setup_total} boot-payload={boot_payload} spare={} required-spare={REQUIRED_SPARE_BYTES}",
        boot_payload - setup_total,
    );
    let (path, total) = [
        ("fresh-entry", fresh_total),
        ("syscall", syscall_total),
        ("idle-timer-preemption", timer_total),
    ]
    .into_iter()
    .max_by_key(|(_, bytes)| *bytes)
    .expect("F12 has stack paths");
    let linked_payload = linked_thread_kernel_stack_payload_bytes(symbols);
    assert!(
        total + REQUIRED_SPARE_BYTES <= linked_payload,
        "F12 cumulative target stack bound exceeds linked per-thread payload: path={path} total={total} payload={linked_payload} required-spare={REQUIRED_SPARE_BYTES}; fresh={fresh_total} syscall={syscall_total} idle-prefix={syscall_prefix} irq-entry={TIMER_IRQ_ENTRY_BYTES} timer-graph-frames={} timer-graph-returns={}",
        timer.bytes,
        timer.call_count * size_of::<u64>(),
    );
    eprintln!(
        "F12 stack path={path} total={total} payload={linked_payload} spare={} required-spare={REQUIRED_SPARE_BYTES} fresh={fresh_total} syscall={syscall_total} idle-prefix={syscall_prefix} irq-entry={TIMER_IRQ_ENTRY_BYTES} timer-frames={} timer-returns={} user-slices={F12_USER_THREADS}x{F12_USER_SLICE_BYTES}",
        linked_payload - total,
        timer.bytes,
        timer.call_count * size_of::<u64>(),
    );
    let terminal_total = ASSEMBLY_CALL_RETURN_BYTES
        .checked_add(terminal.bytes)
        .and_then(|bytes| bytes.checked_add(terminal.call_count * size_of::<u64>()))
        .expect("F12 terminal-reaper bound fits usize");
    let terminal_payload = linked_terminal_reaper_stack_payload_bytes(symbols);
    assert!(
        terminal_total + REQUIRED_SPARE_BYTES <= terminal_payload,
        "F12 terminal-reaper stack bound exceeds its independent linked payload: total={terminal_total} payload={terminal_payload} required-spare={REQUIRED_SPARE_BYTES} frames={} returns={}",
        terminal.bytes,
        ASSEMBLY_CALL_RETURN_BYTES + terminal.call_count * size_of::<u64>(),
    );
    eprintln!(
        "F12 terminal-reaper total={terminal_total} payload={terminal_payload} spare={} required-spare={REQUIRED_SPARE_BYTES} frames={} returns={}",
        terminal_payload - terminal_total,
        terminal.bytes,
        ASSEMBLY_CALL_RETURN_BYTES + terminal.call_count * size_of::<u64>(),
    );
    validate_ist_stack_margin("ipc-blocking-smoke", sizes, disassembly);
}
