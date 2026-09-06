use super::*;

pub(crate) fn validate_wyr1e_privilege_entry_stack_margin(
    sizes: &[StackSize],
    disassembly: &str,
    privilege_entry_stack_bytes: usize,
    execution_threads: usize,
) {
    const ARCHITECTURAL_HEADROOM_BYTES: usize = 4 * 1024;
    const REQUIRED_SPARE_BYTES: usize = 32 * 1024;
    const TERMINAL_PANIC_BYTES: usize = 16 * 1024;
    const CPL3_HARDWARE_FRAME_BYTES: usize = 5 * size_of::<u64>();
    const SAVED_GPR_BYTES: usize = 15 * size_of::<u64>();
    const WORST_ALIGNMENT_BYTES: usize = 15;
    const ENTRY_CALL_RETURN_BYTES: usize = size_of::<u64>();
    const ENTRY_BYTES: usize = CPL3_HARDWARE_FRAME_BYTES
        + SAVED_GPR_BYTES
        + WORST_ALIGNMENT_BYTES
        + ENTRY_CALL_RETURN_BYTES;

    let entry = function_body(disassembly, "dw_x86_64_q35_com2_entry");
    assert_eq!(entry.matches("\tpush\t").count(), 15);
    assert_eq!(entry.matches("\tswapgs").count(), 2);
    assert_eq!(
        entry
            .matches(" <dw_x86_64_q35_com2_interrupt_dispatch>")
            .count(),
        2
    );
    assert_eq!(entry.matches("\tiretq").count(), 1);
    assert!(entry.contains("\ttest\tal, 0x3"));
    assert!(entry.contains("\tje\t"));
    assert!(!entry.contains("pre_iret"));
    assert!(!entry.contains("gs:[0x8]"));

    let select = |description: &str, predicate: &dyn Fn(&str) -> bool| {
        let symbol = one_stack_symbol(sizes, description, predicate);
        let bytes = one_stack_size(sizes, description, |candidate| candidate == symbol);
        (symbol, bytes)
    };
    let (dispatch, dispatch_bytes) = select("q35 COM2 dispatcher", &|symbol| {
        symbol == "dw_x86_64_q35_com2_interrupt_dispatch"
    });
    let (handler, handler_bytes) = select("selector-33 q35 handler", &|symbol| {
        symbol.contains("arch::x86_64::external_interrupt::dispatch_handler::<")
            && symbol.contains("PrimordialRuntimeShared")
    });
    let (snapshot, snapshot_bytes) = select("q35 delivery snapshot", &|symbol| {
        symbol
            == "<deepwyrm_kernel::device::q35_interrupt::Q35InterruptPlatform>::snapshot_delivery"
    });
    let (deliver, deliver_bytes) = select("q35 Interrupt delivery", &|symbol| {
        symbol
            == "<deepwyrm_kernel::device::interrupt::InterruptAuthority<8>>::deliver_classified::<64>"
    });
    let (ready, ready_bytes) = select("q35 ready wakes", &|symbol| {
        symbol == "<deepwyrm_kernel::wait::WaitRegistry<64>>::ready_wakes"
    });
    let (_ready_fold, ready_fold_bytes) = select("q35 ready-wakes fold", &|symbol| {
        symbol.contains("<deepwyrm_kernel::wait::WaitRegistry<64>>::ready_wakes::{closure#2}")
            && symbol.contains("Iterator>::fold::<u32")
    });
    let (record_pending, record_pending_bytes) = select("q35 coalesced record", &|symbol| {
        symbol
            == "<deepwyrm_kernel::device::q35_interrupt::Q35InterruptPlatform>::record_pending_delivery"
    });
    let (complete_wakes, complete_wakes_bytes) = select("q35 wake completion", &|symbol| {
        symbol
            == format!(
                "deepwyrm_kernel::wait::complete_irq_signal_wakes::<64, {execution_threads}>"
            )
    });
    let (wake, wake_bytes) = select("q35 execution wake", &|symbol| {
        symbol
            == format!(
                "<deepwyrm_kernel::task::execution::ExecutionDomain<{execution_threads}>>::wake"
            )
    });
    let (wake_on, wake_on_bytes) = select("q35 scheduler wake", &|symbol| {
        symbol
            == format!(
                "<deepwyrm_kernel::task::scheduler::CooperativeScheduler<{execution_threads}>>::wake_on"
            )
    });
    let (assert_invariants, assert_invariants_bytes) = select(
        "q35 scheduler invariant check",
        &|symbol| {
            symbol.contains(
                &format!(
                    "<deepwyrm_kernel::task::scheduler::SchedulerState<{execution_threads}>>::assert_invariants"
                ),
            )
        },
    );
    let (_eoi, eoi_bytes) = select("q35 EOI transport", &|symbol| {
        symbol.contains("arch::x86_64::ipi::transport_eoi::<")
            && symbol.contains("StationaryLiveIpiTransport")
    });
    let (after_eoi, after_eoi_bytes) = select("q35 post-EOI completion", &|symbol| {
        symbol.contains("activation::primordial::complete_q35_handler_after_eoi")
    });

    for (caller, callee) in [
        (&handler, &snapshot),
        (&handler, &deliver),
        (&deliver, &ready),
        (&handler, &record_pending),
        (&handler, &complete_wakes),
        (&complete_wakes, &wake),
        (&wake, &wake_on),
        (&wake_on, &assert_invariants),
    ] {
        let body = function_body(disassembly, caller);
        assert!(
            body.contains(&format!(" <{callee}>")),
            "selector-33 emitted chain omitted {caller} -> {callee}"
        );
    }
    let ready_body = function_body(disassembly, &ready);
    assert!(
        ready_body.contains("<deepwyrm_kernel::wait::WaitRegistry<64>>::ready_wakes::{closure#2}")
            && ready_body.contains("Iterator>::fold::<u32"),
        "selector-33 ready-wakes frame omitted its exact zero-frame fold target"
    );
    assert!(
        function_body(disassembly, &handler).contains(&format!(" <{after_eoi}>")),
        "selector-33 handler omitted its exact post-EOI completion target"
    );

    let dispatcher = function_body(disassembly, &dispatch);
    let dynamic_calls = dispatcher
        .lines()
        .filter(|line| line.contains("\tcall\tqword ptr [rip + "))
        .collect::<Vec<_>>();
    assert_eq!(dynamic_calls.len(), 3);
    assert!(dynamic_calls[0].contains("external_interrupt::HANDLER>"));
    assert!(dynamic_calls[1].contains("arch::x86_64::ipi::TRANSPORT"));
    assert!(dynamic_calls[2].contains("arch::x86_64::ipi::TRANSPORT"));
    let handler_slot = dispatcher.find(dynamic_calls[0]).unwrap();
    let first_eoi = dispatcher.find(dynamic_calls[1]).unwrap();
    let second_eoi = dispatcher.find(dynamic_calls[2]).unwrap();
    let completion_tail = dispatcher
        .find("\tjmp\trcx")
        .expect("q35 dispatcher omitted the post-EOI completion tail");
    assert!(handler_slot < first_eoi);
    assert!(first_eoi < completion_tail && completion_tail < second_eoi);
    assert_eq!(dispatcher.matches("\tjmp\trcx").count(), 1);

    let phase_total = |frames: &[usize]| {
        let frame_bytes = frames
            .iter()
            .copied()
            .try_fold(0_usize, usize::checked_add)
            .expect("selector-33 phase frame sizes fit usize");
        let return_bytes = frames
            .len()
            .saturating_sub(1)
            .checked_mul(size_of::<u64>())
            .expect("selector-33 phase return count fits usize");
        ENTRY_BYTES
            .checked_add(frame_bytes)
            .and_then(|bytes| bytes.checked_add(return_bytes))
            .expect("selector-33 phase stack bound fits usize")
    };
    let ready_total = phase_total(&[
        dispatch_bytes,
        handler_bytes,
        deliver_bytes,
        ready_bytes,
        ready_fold_bytes,
    ]);
    let wake_total = phase_total(&[
        dispatch_bytes,
        handler_bytes,
        complete_wakes_bytes,
        wake_bytes,
        wake_on_bytes,
        assert_invariants_bytes,
    ]);
    let snapshot_total = phase_total(&[dispatch_bytes, handler_bytes, snapshot_bytes]);
    let record_total = phase_total(&[dispatch_bytes, handler_bytes, record_pending_bytes]);
    let eoi_total = phase_total(&[dispatch_bytes, eoi_bytes]);
    let post_eoi_total = phase_total(&[after_eoi_bytes]);
    let (phase, normal_total) = [
        ("ready-wakes", ready_total),
        ("wake-publication", wake_total),
        ("snapshot", snapshot_total),
        ("record-pending", record_total),
        ("EOI", eoi_total),
        ("post-EOI", post_eoi_total),
    ]
    .into_iter()
    .max_by_key(|(_, bytes)| *bytes)
    .expect("selector-33 has entry phases");
    let required = normal_total
        .checked_add(ARCHITECTURAL_HEADROOM_BYTES)
        .and_then(|bytes| bytes.checked_add(REQUIRED_SPARE_BYTES))
        .expect("selector-33 normal stack requirement fits usize");
    assert!(
        required <= privilege_entry_stack_bytes,
        "selector-33 privilege-entry stack too small: phase={phase} used={normal_total} architectural-headroom={ARCHITECTURAL_HEADROOM_BYTES} required-spare={REQUIRED_SPARE_BYTES} required={required} capacity={privilege_entry_stack_bytes}"
    );
    let terminal_required = normal_total
        .checked_add(size_of::<u64>())
        .and_then(|bytes| bytes.checked_add(TERMINAL_PANIC_BYTES))
        .and_then(|bytes| bytes.checked_add(ARCHITECTURAL_HEADROOM_BYTES))
        .expect("selector-33 terminal stack requirement fits usize");
    assert!(
        terminal_required <= privilege_entry_stack_bytes,
        "selector-33 terminal panic path exceeds privilege-entry stack: used={normal_total} panic-return={} terminal-panic={TERMINAL_PANIC_BYTES} architectural-headroom={ARCHITECTURAL_HEADROOM_BYTES} required={terminal_required} capacity={privilege_entry_stack_bytes}",
        size_of::<u64>()
    );
    eprintln!(
        "interactive-wyrmsh privilege-entry phase={phase} used={normal_total} required={required} capacity={privilege_entry_stack_bytes} terminal-required={terminal_required}; ready={ready_total} wake={wake_total} snapshot={snapshot_total} record={record_total} eoi={eoi_total} post-eoi={post_eoi_total}"
    );
}
