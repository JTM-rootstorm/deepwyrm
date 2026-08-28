use super::*;

pub(crate) fn validate_dw1c_stack_margins(
    sizes: &[StackSize],
    thread_stack_bytes: usize,
    terminal_stack_bytes: usize,
) {
    const RAW_SYSCALL_FRAME_BYTES: usize = 144;
    // One assembly call into the dispatcher plus six calls between the seven
    // trace-witnessed Rust frames below.
    const TRACE_CALL_RETURN_WORDS: usize = 7;
    const ARCHITECTURAL_HEADROOM_BYTES: usize = 4 * 1024;
    const REQUIRED_SPARE_BYTES: usize = 32 * 1024;

    // This is the exact live chain captured when the old 256-KiB stack crossed
    // its guard during selector 28 AddressRegion::Commit. Keep it trace-bound:
    // a whole-program call graph would invent mutually exclusive branches and
    // would also collapse distinct monomorphizations with identical demangles.
    let syscall_dispatch = one_stack_size(sizes, "DW1C syscall dispatcher", |symbol| {
        symbol == "dw_x86_64_syscall_dispatch"
    });
    let bound_dispatch = one_stack_size(sizes, "DW1C bound dispatcher", |symbol| {
        symbol.ends_with("arch::x86_64::syscall::live::dispatch_bound_runtime")
    });
    let runtime_trampoline = one_stack_size(sizes, "DW1C runtime trampoline", |symbol| {
        symbol.contains("arch::x86_64::syscall::live::native_runtime_trampoline::<")
            && symbol.contains("RuntimeCarrierFacade<")
            && !symbol.contains("::{closure")
    });
    let dispatch_frame = one_stack_size(sizes, "DW1C runtime dispatch frame", |symbol| {
        symbol.contains("syscall::native::dispatch_frame::<")
            && symbol.contains("RuntimeCarrierFacade<128, 4096>")
            && !symbol.contains("::{closure")
    });
    let runtime_handler = one_stack_size(sizes, "DW1C runtime handler", |symbol| {
        symbol.contains("RuntimeCarrierFacade<128, 4096>")
            && symbol
                .ends_with("as deepwyrm_kernel::syscall::native::NativeSyscallHandler>::handle")
    });
    let service_dispatch = one_stack_size(sizes, "DW1C F-service dispatch", |symbol| {
        symbol.contains("FServiceState<")
            && symbol.contains(", 256, 24, 12>>::dispatch_prepared::<")
            && symbol.contains("::dispatch_prepared::<")
            && symbol.contains("PrimordialRuntimeCarrier<128, 4096>")
            && symbol.contains("NativeSyscallHandler>::handle::{closure#3}")
    });
    let coherent_commit = one_stack_size(sizes, "DW1C coherent AddressRegion commit", |symbol| {
        symbol.contains("AddressRegion<10>>::commit_specs::<40, 40, 256,")
            && symbol.contains("CoherentAddressSpacePublisher<")
            && symbol.contains("TrackedActiveTarget, 128, 4096, 6, 59, 53>")
            && symbol.contains("LiveTlbShootdownDriver")
    });
    let frames = [
        syscall_dispatch,
        bound_dispatch,
        runtime_trampoline,
        dispatch_frame,
        runtime_handler,
        service_dispatch,
        coherent_commit,
    ];
    let frame_bytes = frames
        .into_iter()
        .try_fold(0_usize, usize::checked_add)
        .expect("DW1C observed frame sizes fit usize");
    assert_eq!(frames.len(), TRACE_CALL_RETURN_WORDS);
    let return_bytes = TRACE_CALL_RETURN_WORDS
        .checked_mul(size_of::<u64>())
        .expect("DW1C return-word count fits usize");
    let total = RAW_SYSCALL_FRAME_BYTES
        .checked_add(frame_bytes)
        .and_then(|bytes| bytes.checked_add(return_bytes))
        .and_then(|bytes| bytes.checked_add(ARCHITECTURAL_HEADROOM_BYTES))
        .expect("DW1C syscall stack bound fits usize");

    assert!(
        total + REQUIRED_SPARE_BYTES <= thread_stack_bytes,
        "DW1C syscall chain exceeds the linked per-thread stack: total={total} \
         linked={thread_stack_bytes} required-spare={REQUIRED_SPARE_BYTES} \
         frames={frame_bytes} returns={return_bytes}",
    );
    eprintln!(
        "normal-preemption-smp thread-stack observed-chain={total} \
         linked={thread_stack_bytes} remaining={} required-spare={REQUIRED_SPARE_BYTES}",
        thread_stack_bytes - total,
    );

    // The second frozen selector-28 candidate reached the real terminal
    // teardown path and crossed 3,416 bytes into the old 132-KiB reaper guard.
    // Preserve that measured high-water mark while charging any future growth
    // in the exact target-emitted frames that were live at the fault.
    const OBSERVED_TERMINAL_DEPTH_BYTES: usize = 138_584;
    const TERMINAL_TRACE_CALL_RETURN_WORDS: usize = 8;
    const TERMINAL_ANCHOR_BASELINE_BYTES: usize = 131_760;
    let terminal_reaper = one_stack_size(sizes, "DW1C terminal reaper", |symbol| {
        symbol.contains("syscall::live::native_runtime_terminal_reaper::<")
            && symbol.contains("RuntimeCarrierFacade<128, 4096>")
    });
    let terminate_current = one_stack_size(sizes, "DW1C terminal runtime", |symbol| {
        symbol.contains("RuntimeCarrierFacade<128, 4096>")
            && symbol.ends_with(
                "as deepwyrm_kernel::syscall::native::NativeSyscallFrameRuntime>::terminate_current",
            )
    });
    let finish_inactive = one_stack_size(sizes, "DW1C inactive process teardown", |symbol| {
        symbol.contains("PrimordialRuntimeCarrier<128, 4096>>::finish_inactive_process_teardown")
    });
    let unmap_inactive = one_stack_size(sizes, "DW1C inactive userspace unmap", |symbol| {
        symbol.contains("PrimordialRuntimeCarrier<128, 4096>>::unmap_inactive_userspace")
    });
    let platform_unmap = one_stack_size(sizes, "DW1C live platform unmap", |symbol| {
        symbol.contains("LivePlatform<128, 4096>")
            && symbol.contains("PrimordialPlatform>::unmap::<10, 40, 40, 256>")
    });
    let region_unmap = one_stack_size(sizes, "DW1C coherent AddressRegion unmap", |symbol| {
        symbol.contains("AddressRegion<10>>::unmap::<40, 40, 256,")
            && symbol.contains("CoherentAddressSpacePublisher<")
            && symbol.contains("TrackedActiveTarget, 128, 4096, 6, 59, 53>")
            && symbol.contains("LiveTlbShootdownDriver")
    });
    let terminal_commit = one_stack_size(sizes, "DW1C terminal AddressRegion commit", |symbol| {
        symbol.contains("AddressRegion<10>>::commit_specs::<40, 40, 256,")
            && symbol.contains("CoherentAddressSpacePublisher<")
            && symbol.contains("TrackedActiveTarget, 128, 4096, 6, 59, 53>")
            && symbol.contains("LiveTlbShootdownDriver")
    });
    let prepare_replace = one_stack_size(sizes, "DW1C terminal MemoryObject replace", |symbol| {
        symbol.contains("MemoryObjectAuthority<40, 40>>::prepare_replace::<10, 256>")
    });
    let terminal_anchor_bytes = [
        terminal_reaper,
        terminate_current,
        finish_inactive,
        unmap_inactive,
        platform_unmap,
        region_unmap,
        terminal_commit,
        prepare_replace,
    ]
    .into_iter()
    .try_fold(0_usize, usize::checked_add)
    .expect("DW1C terminal trace frame sizes fit usize");
    let terminal_growth = terminal_anchor_bytes.saturating_sub(TERMINAL_ANCHOR_BASELINE_BYTES);
    let terminal_returns = TERMINAL_TRACE_CALL_RETURN_WORDS
        .checked_mul(size_of::<u64>())
        .expect("DW1C terminal return-word count fits usize");
    let terminal_total = OBSERVED_TERMINAL_DEPTH_BYTES
        .checked_add(terminal_growth)
        .and_then(|bytes| bytes.checked_add(terminal_returns))
        .and_then(|bytes| bytes.checked_add(ARCHITECTURAL_HEADROOM_BYTES))
        .expect("DW1C terminal stack bound fits usize");
    eprintln!(
        "normal-preemption-smp terminal-stack observed-depth={OBSERVED_TERMINAL_DEPTH_BYTES} \
         anchors={terminal_anchor_bytes} growth={terminal_growth} returns={terminal_returns} \
         linked={terminal_stack_bytes}"
    );
    assert!(
        terminal_total + REQUIRED_SPARE_BYTES <= terminal_stack_bytes,
        "DW1C terminal teardown exceeds the linked reaper stack: total={terminal_total} \
         linked={terminal_stack_bytes} required-spare={REQUIRED_SPARE_BYTES} \
         observed-depth={OBSERVED_TERMINAL_DEPTH_BYTES} anchors={terminal_anchor_bytes} \
         anchor-baseline={TERMINAL_ANCHOR_BASELINE_BYTES} returns={terminal_returns}",
    );
}
