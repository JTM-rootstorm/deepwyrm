use super::ist::validate_ist_stack_margin;
use super::*;

pub(crate) fn validate_f9_stack_context_evidence(
    sizes: &[StackSize],
    symbols: &str,
    disassembly: &str,
) {
    const F9_USER_STACK_BYTES: usize = 4096;
    const F9_USER_THREADS: usize = 2;
    const F9_USER_SLICE_BYTES: usize = F9_USER_STACK_BYTES / F9_USER_THREADS;
    const FIRST_RUN_ABI_WORD_BYTES: usize = size_of::<u64>();
    const RAW_SYSCALL_FRAME_BYTES: usize = 144;
    const ASSEMBLY_CALL_RETURN_BYTES: usize = size_of::<u64>();
    const REQUIRED_SPARE_BYTES: usize = 32 * 1024;

    assert_eq!(F9_USER_STACK_BYTES % F9_USER_THREADS, 0);
    assert_eq!(F9_USER_SLICE_BYTES, 2048);
    assert_eq!(F9_USER_SLICE_BYTES * F9_USER_THREADS, F9_USER_STACK_BYTES);
    for required in [
        "native_runtime_fresh_thread",
        "native_runtime_trampoline",
        "KernelSwitchPlan",
        "dw_x86_64_switch_kernel_context",
        "F9Runtime",
    ] {
        assert!(
            symbols.contains(required),
            "F9 target artifact omitted context evidence {required}"
        );
    }
    for address in ["0x50001000", "0x50001800", "0x50002000"] {
        assert!(
            disassembly.contains(address),
            "F9 target artifact omitted its linked user-stack boundary {address}"
        );
    }
    validate_f2_kernel_context_switch(disassembly);

    let symbol = |description: &str, predicate: &dyn Fn(&str) -> bool| {
        one_stack_symbol(sizes, description, predicate)
    };
    let fresh_handler = symbol("F9 fresh handler", &|name| {
        name.contains("native_runtime_fresh_thread::<")
            && name.contains("F9Runtime<")
            && !name.contains("::{closure")
    });
    let trampoline = symbol("F9 runtime trampoline", &|name| {
        name.contains("native_runtime_trampoline::<")
            && name.contains("F9Runtime<")
            && !name.contains("::{closure")
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
    let rendezvous_reaper = symbol("x86 rendezvous reaper", &|name| {
        name == "dw_x86_64_rendezvous_reaper"
    });
    let rendezvous_reaper_handler = symbol("F9 rendezvous reaper handler", &|name| {
        name.contains("native_runtime_rendezvous_reaper::<")
            && name.contains("F9Runtime<")
            && !name.contains("::{closure")
    });
    let send_live_ipi = symbol("live IPI send boundary", &|name| {
        name.ends_with("arch::x86_64::ipi::send_live_ipi")
    });
    let live_ipi_transport_send = symbol("stationary live IPI transport", &|name| {
        name.contains("arch::x86_64::ipi::transport_send::<")
            && name.contains("StationaryLiveIpiTransport")
            && !name.contains("::{closure")
    });
    let atomic_wait_begin = symbol("F9 atomic-wait transaction", &|name| {
        name.starts_with("deepwyrm_kernel::atomic_wait::begin_atomic_wait::<")
            && name.contains("OwnedLiveAtomicU32, 1, 1, 2, 1, 4, 2,")
            && name.ends_with('>')
    });
    let register_wait_deadline = symbol("F9 live wait-deadline registration", &|name| {
        name.ends_with(
            "wait::engine::LiveWaitDeadlineAuthority as deepwyrm_kernel::wait::engine::WaitDeadlineAuthority>::register_wait_deadline",
        )
    });
    let cancel_atomic_wait_deadline = symbol("F9 atomic-wait deadline cancellation", &|name| {
        name == "deepwyrm_kernel::atomic_wait::cancel_deadline"
    });
    let cancel_live_wait_deadline = symbol("F9 live wait-deadline cancellation", &|name| {
        name.ends_with(
            "wait::engine::LiveWaitDeadlineAuthority as deepwyrm_kernel::wait::engine::WaitDeadlineAuthority>::cancel_wait_deadline",
        )
    });

    let mut resolutions = BTreeMap::new();
    resolutions.insert(first_run.clone(), vec![fresh_handler]);
    resolutions.insert(dispatch_bound, vec![trampoline]);
    resolutions.insert(rendezvous_reaper, vec![rendezvous_reaper_handler]);
    resolutions.insert(send_live_ipi, vec![live_ipi_transport_send]);
    resolutions.insert(atomic_wait_begin, vec![register_wait_deadline]);
    resolutions.insert(cancel_atomic_wait_deadline, vec![cancel_live_wait_deadline]);
    let graph = DirectCallGraph::new(sizes, disassembly);
    let mut resolved = graph.with_resolutions(&resolutions);
    let fresh = resolved.stack_bound("F9 fresh-thread path", |name| name == first_run);
    let syscall = resolved.stack_bound("F9 syscall dispatch path", |name| name == syscall_dispatch);
    let terminal = resolved.stack_bound("F9 terminal-reaper path", |name| {
        name.contains("native_runtime_terminal_reaper::<")
            && name.contains("F9Runtime<")
            && !name.contains("::{closure")
    });
    let setup = resolved.stack_bound("F9 selector setup", |name| {
        name.contains("f9::enter_f9::<") && !name.contains("::{closure")
    });

    let setup_total = setup.bytes + setup.call_count * size_of::<u64>();
    let fresh_total = FIRST_RUN_ABI_WORD_BYTES
        .checked_add(fresh.bytes)
        .and_then(|bytes| bytes.checked_add(fresh.call_count * size_of::<u64>()))
        .expect("F9 fresh-thread bound fits usize");
    let syscall_total = RAW_SYSCALL_FRAME_BYTES
        .checked_add(ASSEMBLY_CALL_RETURN_BYTES)
        .and_then(|bytes| bytes.checked_add(syscall.bytes))
        .and_then(|bytes| bytes.checked_add(syscall.call_count * size_of::<u64>()))
        .expect("F9 syscall bound fits usize");
    let boot_payload = linked_boot_stack_payload_bytes(symbols);
    assert!(
        setup_total + REQUIRED_SPARE_BYTES <= boot_payload,
        "F9 selector setup exceeds the retained boot-stack payload: total={setup_total} payload={boot_payload} required-spare={REQUIRED_SPARE_BYTES}"
    );
    eprintln!(
        "F9 setup total={setup_total} boot-payload={boot_payload} spare={} required-spare={REQUIRED_SPARE_BYTES}",
        boot_payload - setup_total,
    );
    let (path, total) = [("fresh-entry", fresh_total), ("syscall", syscall_total)]
        .into_iter()
        .max_by_key(|(_, bytes)| *bytes)
        .expect("F9 has stack paths");
    let linked_payload = linked_thread_kernel_stack_payload_bytes(symbols);
    assert!(
        total + REQUIRED_SPARE_BYTES <= linked_payload,
        "F9 cumulative target stack bound exceeds linked per-thread payload: path={path} total={total} payload={linked_payload} required-spare={REQUIRED_SPARE_BYTES}; fresh={fresh_total} syscall={syscall_total}"
    );
    eprintln!(
        "F9 stack path={path} total={total} payload={linked_payload} spare={} required-spare={REQUIRED_SPARE_BYTES} fresh={fresh_total} syscall={syscall_total} user-slices={F9_USER_THREADS}x{F9_USER_SLICE_BYTES}",
        linked_payload - total,
    );
    let terminal_total = ASSEMBLY_CALL_RETURN_BYTES
        .checked_add(terminal.bytes)
        .and_then(|bytes| bytes.checked_add(terminal.call_count * size_of::<u64>()))
        .expect("F9 terminal-reaper bound fits usize");
    let terminal_payload = linked_terminal_reaper_stack_payload_bytes(symbols);
    assert!(
        terminal_total + REQUIRED_SPARE_BYTES <= terminal_payload,
        "F9 terminal-reaper stack bound exceeds its independent linked payload: total={terminal_total} payload={terminal_payload} required-spare={REQUIRED_SPARE_BYTES} frames={} returns={}",
        terminal.bytes,
        ASSEMBLY_CALL_RETURN_BYTES + terminal.call_count * size_of::<u64>(),
    );
    eprintln!(
        "F9 terminal-reaper total={terminal_total} payload={terminal_payload} spare={} required-spare={REQUIRED_SPARE_BYTES} frames={} returns={}",
        terminal_payload - terminal_total,
        terminal.bytes,
        ASSEMBLY_CALL_RETURN_BYTES + terminal.call_count * size_of::<u64>(),
    );
    validate_ist_stack_margin("atomic-wait-wake", sizes, disassembly);
}
