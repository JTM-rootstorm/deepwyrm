use super::*;

pub(crate) fn validate_dw1c_thread_stack_margin(sizes: &[StackSize], thread_stack_bytes: usize) {
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
            && symbol.contains("RuntimeCarrierFacade<128, 544>")
            && !symbol.contains("::{closure")
    });
    let runtime_handler = one_stack_size(sizes, "DW1C runtime handler", |symbol| {
        symbol.contains("RuntimeCarrierFacade<128, 544>")
            && symbol
                .ends_with("as deepwyrm_kernel::syscall::native::NativeSyscallHandler>::handle")
    });
    let service_dispatch = one_stack_size(sizes, "DW1C F-service dispatch", |symbol| {
        symbol.contains("FServiceState<")
            && symbol.contains(", 256, 24, 12>>::dispatch_prepared::<")
            && symbol.contains("::dispatch_prepared::<")
            && symbol.contains("PrimordialRuntimeCarrier<128, 544>")
            && symbol.contains("NativeSyscallHandler>::handle::{closure#3}")
    });
    let coherent_commit = one_stack_size(sizes, "DW1C coherent AddressRegion commit", |symbol| {
        symbol.contains("AddressRegion<10>>::commit_specs::<40, 40, 256,")
            && symbol.contains("CoherentAddressSpacePublisher<")
            && symbol.contains("TrackedActiveTarget, 128, 544, 6, 59, 53>")
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
}
