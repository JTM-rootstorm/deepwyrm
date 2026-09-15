use super::*;

/// The R5E-measured E8 syscall chain, restored to exact equalities.
///
/// `EXPECTED_COMMON` is the ordinary native syscall path: the architectural
/// entry frame plus the dispatcher, the bound dispatcher, the trampoline that
/// now carries the folded dispatch frame, and the production handler.
/// `EXPECTED_TERMINATE` adds the task-group terminate helpers, and
/// `EXPECTED_REQUIRED` adds architectural headroom and required spare.
pub(crate) const EXPECTED_COMMON: usize = 50_528;
pub(crate) const EXPECTED_TERMINATE: usize = 72_608;
pub(crate) const EXPECTED_REQUIRED: usize = 109_472;

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
    // R5E: `dispatch_frame` is no longer emitted as its own function. R5B to
    // R5D took the by-value termination batches out of the frames below it,
    // and the remaining body is small enough that LLVM folds it into its one
    // caller, the trampoline. Its slots are therefore already inside
    // `runtime_trampoline_bytes`, and the trampoline calls the handler
    // directly, one return word shallower than before. Assert the fold rather
    // than tolerate it: if a later change re-emits the frame, this fails and
    // the chain must be re-measured instead of silently losing a level.
    assert!(
        !sizes.iter().any(|entry| {
            entry.symbol.contains("syscall::native::dispatch_frame::<")
                && entry.symbol.contains("RuntimeCarrierFacade<128, 4096>")
        }),
        "E8 dispatch_frame is emitted again; re-measure the common syscall chain"
    );
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
        function_body(disassembly, &runtime_trampoline).contains(&format!(" <{runtime_handler}>")),
        "E8 trampoline no longer reaches the production handler directly"
    );
    assert!(
        function_body(disassembly, &runtime_handler).contains(&format!(" <{prepare_terminate}>"))
    );
    assert!(
        function_body(disassembly, &prepare_terminate).contains(&format!(" <{terminate_group}>"))
    );

    // The entry copies a 144-byte frame onto the Thread stack and calls the
    // dispatcher. The dispatcher pushes one word before calling the bound
    // runtime. That function tail-jumps into the installed trampoline, so it
    // adds no second return word. The trampoline, which now carries the
    // folded dispatch frame, calls the production handler, and the handler
    // calls the selected terminate helper.
    const COMMON_RETURN_WORDS: usize = 3;
    const TERMINATE_RETURN_WORDS: usize = 2;
    assert_eq!(syscall_dispatch_bytes, size_of::<u64>());
    assert_eq!(bound_dispatch_bytes, 0);
    let common_frames = [
        syscall_dispatch_bytes,
        bound_dispatch_bytes,
        runtime_trampoline_bytes,
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

    // R5E re-measured this chain under the accepted workflow and restored the
    // equalities R5C had to leave as ceilings. The pre-R5C figures are kept in
    // the comment because they are what the reduced budget is justified
    // against: common was 1,501,744, the terminate path 2,977,888, and the
    // requirement 3,014,752, which is why the arena was widened to 4 MiB.
    assert_eq!(common, EXPECTED_COMMON);
    assert_eq!(normal, EXPECTED_TERMINATE);
    assert_eq!(required, EXPECTED_REQUIRED);
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
fn e8_thread_capacity_fits_the_ordinary_thread_stack_after_r5() {
    // Before R5 this requirement was 3,014,752 bytes, which is why E8 alone
    // linked a 4 MiB Thread stack: the pre-R5 figure did not fit the ordinary
    // 512 KiB arena, and 64 of them cost 256 MiB of linked BSS. R5B to R5D
    // took the by-value termination batches out of the chain, so R5E returns
    // E8 to the frozen E3 size; only the count still differs.
    const PRE_R5_REQUIRED: usize = 3_014_752;
    const ORDINARY: usize = 512 * 1024;
    const {
        assert!(PRE_R5_REQUIRED > ORDINARY);
        assert!(EXPECTED_REQUIRED <= ORDINARY);
    }
    assert_eq!(ORDINARY - EXPECTED_REQUIRED, 414_816);
}
