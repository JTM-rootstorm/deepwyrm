use super::*;

/// Reset-card-R1 thread-stack bound for selector 34 (`dynamic-launch-saturation`).
///
/// Item 4 of `DW1_WYR1_RESET_R1C_VM_REQUEST.md`. This replaces the readiness
/// gate that held the bound open while the selector's release artifact carried
/// no native runtime at all: `deepwyrm` `50cd68f` asserted that the five runtime
/// anchors were absent and failed the moment they appeared, which is what forced
/// this function to be written in the same change that made it measurable.
///
/// Structure follows `validate_wyr1e8_thread_stack_margin`: the same trace-bound
/// chain, the same call-edge verification from accepted objdump, and the same
/// refusal to infer a whole-program call graph that would invent mutually
/// exclusive branches. The monomorphization parameters differ because R1's
/// geometry is its own — `160, 16, 16, 16, 48, 48, 16` against E8's
/// `160, 64, 64, 64, 64, 64, 64` — and matching on them is deliberate: a
/// geometry change that alters these tables must fail here rather than silently
/// measure a different kernel.
pub(crate) fn validate_r1_thread_stack_margin(
    sizes: &[StackSize],
    disassembly: &str,
    thread_stack_bytes: usize,
) {
    const RAW_SYSCALL_FRAME_BYTES: usize = 144;
    const ARCHITECTURAL_HEADROOM_BYTES: usize = 4 * 1024;
    const REQUIRED_SPARE_BYTES: usize = 32 * 1024;
    const ORDINARY_THREAD_ARENA_PAYLOAD_BYTES: usize = 512 * 1024;

    // R1 must stay on the ordinary 16 x 512 KiB arena. E8's widened arena is
    // what let its termination path reach a 4 MiB per-thread stack, and plan
    // section 12 forbids growing a stack in place of reducing frames. The arena
    // is also the ceiling on the selector's identity capacity, so a change here
    // is the same change that would break `r1_resource_geometry`'s const
    // assertion against `E3_THREAD_STACK_COUNT`.
    assert_eq!(
        thread_stack_bytes, ORDINARY_THREAD_ARENA_PAYLOAD_BYTES,
        "selector 34 must keep the ordinary per-thread arena"
    );

    let select = |description: &str, predicate: &dyn Fn(&str) -> bool| {
        let symbol = one_stack_symbol(sizes, description, predicate);
        let bytes = one_stack_size(sizes, description, |candidate| candidate == symbol);
        (symbol, bytes)
    };
    let (syscall_dispatch, syscall_dispatch_bytes) = select("R1 syscall dispatcher", &|symbol| {
        symbol == "dw_x86_64_syscall_dispatch"
    });
    let (bound_dispatch, bound_dispatch_bytes) = select("R1 bound dispatcher", &|symbol| {
        symbol.ends_with("arch::x86_64::syscall::live::dispatch_bound_runtime")
    });
    let (runtime_trampoline, runtime_trampoline_bytes) =
        select("R1 runtime trampoline", &|symbol| {
            symbol.contains("arch::x86_64::syscall::live::native_runtime_trampoline::<")
                && symbol.contains("RuntimeCarrierFacade<128, 4096>")
                && !symbol.contains("::{closure")
        });
    let (dispatch_frame, dispatch_frame_bytes) = select("R1 dispatch frame", &|symbol| {
        symbol.contains("syscall::native::dispatch_frame::<")
            && symbol.contains("RuntimeCarrierFacade<128, 4096>")
            && !symbol.contains("::{closure")
    });
    let (runtime_handler, runtime_handler_bytes) = select("R1 runtime handler", &|symbol| {
        symbol.contains("RuntimeCarrierFacade<128, 4096>")
            && symbol
                .ends_with("as deepwyrm_kernel::syscall::native::NativeSyscallHandler>::handle")
    });
    let (prepare_terminate, prepare_terminate_bytes) =
        select("R1 task-group terminate preparation", &|symbol| {
            symbol.contains("syscall::adapters::prepare_task_group_terminate::<")
                && symbol.contains("FServiceTerminalCleanup<")
                && symbol.contains("PrimordialRuntimeCarrier<128, 4096>")
                && symbol.contains(", 160, 16, 16, 16, 48, 48, 16>")
        });
    let (terminate_group, terminate_group_bytes) =
        select("R1 task-group authority termination", &|symbol| {
            symbol
                == "<deepwyrm_kernel::task::TaskAuthority<16, 16, 16, 48>>::terminate_group::<160>"
        });

    // Every edge in the measured chain is proved from the accepted
    // disassembly, so a refactor that reroutes the path fails here instead of
    // leaving the bound measuring a chain that no longer runs.
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
    // runtime, which tail-jumps into the installed trampoline and so adds no
    // second return word. Three further calls reach dispatch_frame, the
    // production handler, and the selected terminate helper.
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
    .expect("R1 common syscall frames fit usize");
    let common_returns = COMMON_RETURN_WORDS * size_of::<u64>();
    let common = RAW_SYSCALL_FRAME_BYTES
        .checked_add(common_frames)
        .and_then(|bytes| bytes.checked_add(common_returns))
        .expect("R1 common syscall stack bound fits usize");
    let terminate_frames = prepare_terminate_bytes
        .checked_add(terminate_group_bytes)
        .expect("R1 task-group terminate frames fit usize");
    let terminate_returns = TERMINATE_RETURN_WORDS * size_of::<u64>();
    let normal = common
        .checked_add(terminate_frames)
        .and_then(|bytes| bytes.checked_add(terminate_returns))
        .expect("R1 task-group terminate stack bound fits usize");
    let required = normal
        .checked_add(ARCHITECTURAL_HEADROOM_BYTES)
        .and_then(|bytes| bytes.checked_add(REQUIRED_SPARE_BYTES))
        .expect("R1 Thread stack requirement fits usize");

    // Recomputed from emitted .stack_sizes, pinned so a frame regression is a
    // gate failure rather than a quiet loss of margin. R1's figures are roughly
    // an eighth of E8's for the same chain, which is the whole point of keeping
    // this selector's per-Process tables narrow.
    assert_eq!(common, 179_168);
    assert_eq!(normal, 345_344);
    assert_eq!(required, 382_208);
    assert!(
        required <= thread_stack_bytes,
        "R1 Thread stack too small: common={common} task-group-terminate={normal} \
         architectural-headroom={ARCHITECTURAL_HEADROOM_BYTES} \
         required-spare={REQUIRED_SPARE_BYTES} required={required} \
         capacity={thread_stack_bytes}"
    );
    eprintln!(
        "dynamic-launch-saturation thread-stack common={common} \
         task-group-terminate={normal} required={required} \
         capacity={thread_stack_bytes} remaining={}",
        thread_stack_bytes - required
    );
}

/// The claim R1's geometry rests on: this selector genuinely fits the ordinary
/// arena, so it never needed E8's widened one.
///
/// If this ever stopped holding, the choice would not be "link the 64-slot
/// arena": that arena is 64 x 4 MiB, and switching to it is what plan section 12
/// forbids. It would mean reducing the frames instead.
#[test]
pub(super) fn r1_thread_requirement_fits_the_ordinary_arena_without_e8s_widening() {
    const REQUIRED: usize = 382_208;
    const ORDINARY: usize = 512 * 1024;
    const E8_REQUIRED: usize = 3_014_752;
    const {
        assert!(REQUIRED <= ORDINARY);
        // Real margin, not a hairline fit: a single added frame must not need a
        // new arena.
        assert!(REQUIRED + 64 * 1024 <= ORDINARY);
        // And the reason the narrow tables matter, stated as arithmetic.
        assert!(REQUIRED * 7 < E8_REQUIRED);
    }
    assert_eq!(ORDINARY - REQUIRED, 142_080);
}
