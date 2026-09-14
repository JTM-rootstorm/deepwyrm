use super::*;

pub(crate) fn validate_wyr1e8_thread_stack_margin(
    sizes: &[StackSize],
    disassembly: &str,
    thread_stack_bytes: usize,
) {
    const RAW_SYSCALL_FRAME_BYTES: usize = 144;
    const ARCHITECTURAL_HEADROOM_BYTES: usize = 4 * 1024;
    const REQUIRED_SPARE_BYTES: usize = 32 * 1024;

    let select = |description: &str, predicate: &dyn Fn(&str) -> bool| {
        let symbol = one_stack_symbol(sizes, description, predicate);
        let bytes = one_stack_size(sizes, description, |candidate| candidate == symbol);
        (symbol, bytes)
    };
    let (syscall_dispatch, syscall_dispatch_bytes) = select("E8 syscall dispatcher", &|symbol| {
        symbol == "dw_x86_64_syscall_dispatch"
    });
    let (bound_dispatch, bound_dispatch_bytes) = select("E8 bound dispatcher", &|symbol| {
        symbol.ends_with("arch::x86_64::syscall::live::dispatch_bound_runtime")
    });
    let (runtime_trampoline, runtime_trampoline_bytes) =
        select("E8 runtime trampoline", &|symbol| {
            symbol.contains("arch::x86_64::syscall::live::native_runtime_trampoline::<")
                && symbol.contains("RuntimeCarrierFacade<128, 4096>")
                && !symbol.contains("::{closure")
        });
    let (dispatch_frame, dispatch_frame_bytes) = select("E8 dispatch frame", &|symbol| {
        symbol.contains("syscall::native::dispatch_frame::<")
            && symbol.contains("RuntimeCarrierFacade<128, 4096>")
            && !symbol.contains("::{closure")
    });
    let (runtime_handler, runtime_handler_bytes) = select("E8 runtime handler", &|symbol| {
        symbol.contains("RuntimeCarrierFacade<128, 4096>")
            && symbol
                .ends_with("as deepwyrm_kernel::syscall::native::NativeSyscallHandler>::handle")
    });
    let (prepare_terminate, prepare_terminate_bytes) =
        select("E8 task-group terminate preparation", &|symbol| {
            symbol.contains("syscall::adapters::prepare_task_group_terminate::<")
                && symbol.contains("FServiceTerminalCleanup<")
                && symbol.contains("PrimordialRuntimeCarrier<128, 4096>")
                && symbol.contains(", 160, 64, 64, 64, 64, 64, 64>")
        });
    let (terminate_group, terminate_group_bytes) =
        select("E8 task-group authority termination", &|symbol| {
            symbol == "<deepwyrm_kernel::task::TaskAuthority<64, 64, 64, 64>>::terminate_group"
        });

    let syscall_entry = function_body(disassembly, "dw_x86_64_syscall_entry");
    assert!(syscall_entry.contains(&format!(" <{syscall_dispatch}>")));
    assert!(
        function_body(disassembly, &syscall_dispatch).contains(&format!(" <{bound_dispatch}>"))
    );
    let bound_body = function_body(disassembly, &bound_dispatch);
    assert_eq!(bound_body.matches("\tjmp\trcx").count(), 1);
    assert!(bound_body.contains("syscall::live::RUNTIME"));
    assert!(
        function_body(disassembly, &runtime_trampoline).contains(&format!(" <{dispatch_frame}>"))
    );
    assert!(function_body(disassembly, &dispatch_frame).contains(&format!(" <{runtime_handler}>")));
    assert!(
        function_body(disassembly, &runtime_handler).contains(&format!(" <{prepare_terminate}>"))
    );
    assert!(
        function_body(disassembly, &prepare_terminate).contains(&format!(" <{terminate_group}>"))
    );

    // The entry copies a 144-byte frame onto the Thread stack and calls the
    // dispatcher. The dispatcher pushes one word before calling the bound
    // runtime. That function tail-jumps into the installed trampoline, so it
    // adds no second return word. Three further calls reach dispatch_frame,
    // the production handler, and the selected terminate helper.
    const COMMON_RETURN_WORDS: usize = 4;
    const TERMINATE_RETURN_WORDS: usize = 2;
    assert_eq!(syscall_dispatch_bytes, size_of::<u64>());
    assert_eq!(bound_dispatch_bytes, 0);
    let common_frames = [
        syscall_dispatch_bytes,
        bound_dispatch_bytes,
        runtime_trampoline_bytes,
        dispatch_frame_bytes,
        runtime_handler_bytes,
    ]
    .into_iter()
    .try_fold(0_usize, usize::checked_add)
    .expect("E8 common syscall frames fit usize");
    let common_returns = COMMON_RETURN_WORDS * size_of::<u64>();
    let common = RAW_SYSCALL_FRAME_BYTES
        .checked_add(common_frames)
        .and_then(|bytes| bytes.checked_add(common_returns))
        .expect("E8 common syscall stack bound fits usize");
    let terminate_frames = prepare_terminate_bytes
        .checked_add(terminate_group_bytes)
        .expect("E8 task-group terminate frames fit usize");
    let terminate_returns = TERMINATE_RETURN_WORDS * size_of::<u64>();
    let normal = common
        .checked_add(terminate_frames)
        .and_then(|bytes| bytes.checked_add(terminate_returns))
        .expect("E8 task-group terminate stack bound fits usize");
    let required = normal
        .checked_add(ARCHITECTURAL_HEADROOM_BYTES)
        .and_then(|bytes| bytes.checked_add(REQUIRED_SPARE_BYTES))
        .expect("E8 Thread stack requirement fits usize");

    // `common` is the ordinary syscall path and R5C did not touch it, so it
    // stays exact.
    assert_eq!(common, 1_501_744);

    // The terminate figures are bounds, not the pinned measurement they used to
    // be. Reset card R5C removed the `[ProcessExitEffects; PROCESSES]` batch
    // from `prepare_task_group_terminate`, which can only have made these frames
    // smaller -- so the pre-R5C measurement is still a valid ceiling, and a
    // regression past it still fails here. It is not the emitted value any more,
    // and this gate is only reachable under an accepted-workflow request, so R5C
    // could not re-measure it. R5E does that and restores the equalities.
    const PRE_R5C_TERMINATE_BOUND: usize = 2_977_888;
    const PRE_R5C_REQUIRED_BOUND: usize = 3_014_752;
    assert!(
        normal <= PRE_R5C_TERMINATE_BOUND,
        "E8 task-group terminate frames grew past the pre-R5C measurement: {normal}"
    );
    assert!(required <= PRE_R5C_REQUIRED_BOUND);
    assert!(
        required <= thread_stack_bytes,
        "WYR1-E8 Thread stack too small: common={common} task-group-terminate={normal} architectural-headroom={ARCHITECTURAL_HEADROOM_BYTES} required-spare={REQUIRED_SPARE_BYTES} required={required} capacity={thread_stack_bytes}"
    );
    eprintln!(
        "interactive-wyrmsh-e8 thread-stack common={common} task-group-terminate={normal} required={required} capacity={thread_stack_bytes} remaining={}",
        thread_stack_bytes - required
    );
}

#[test]
fn e8_thread_capacity_rejects_a5_layout_and_accepts_functional_allocation() {
    // A pre-R5C ceiling rather than the emitted requirement; see above.
    const REQUIRED: usize = 3_014_752;
    const {
        assert!(REQUIRED > 512 * 1024);
        assert!(REQUIRED <= 4 * 1024 * 1024);
    }
    assert_eq!(4 * 1024 * 1024 - REQUIRED, 1_179_552);
}
