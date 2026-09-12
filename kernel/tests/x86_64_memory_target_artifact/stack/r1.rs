use super::*;

/// Reset-card-R1 thread-stack readiness gate for selector 34
/// (`dynamic-launch-saturation`).
///
/// This is deliberately **not** a thread-stack bound. Item 4 of
/// `DW1_WYR1_RESET_R1C_VM_REQUEST.md` cannot be written against this build:
/// selector 34's release kernel instantiates no native runtime syscall
/// surface, so the frames a bound would measure do not exist. Syscall entry
/// tail-jumps through the per-CPU `RUNTIME` pointer, which no
/// `bind_native_runtime_carrier_for_slot` monomorph in this artifact ever
/// fills, so none of E8's or DW1-C's anchors are emitted and any
/// `one_stack_size` matcher would fail with "expected one, found 0".
///
/// What this validator does instead is pin the two facts that *are* observable
/// now, and fail the moment the third becomes writable:
///
/// 1. R1 uses the ordinary 16 x 512 KiB thread arena, not E8's 64 x 4 MiB one.
/// 2. The native runtime chain is absent — so the missing bound is a recorded
///    consequence of the missing product, not an oversight.
///
/// When card R1's product installs the runtime surface, the anchors appear and
/// this gate fails by construction, which is the intent: item 4 must be written
/// in the same change that makes it measurable, rather than being remembered.
pub(crate) fn validate_r1_thread_stack_readiness(sizes: &[StackSize], thread_stack_bytes: usize) {
    const EXPECTED_THREAD_STACK_PAYLOAD_BYTES: usize = 512 * 1024;
    const REQUIRED_SPARE_BYTES: usize = 32 * 1024;

    assert_eq!(
        thread_stack_bytes, EXPECTED_THREAD_STACK_PAYLOAD_BYTES,
        "selector 34 must keep the ordinary per-thread arena that \
         normal-preemption-smp measures; E8's widened arena is what forced its \
         multi-megabyte terminate path, and reset plan section 12 forbids \
         growing a stack in place of reducing frames"
    );

    let present = present_native_runtime_anchors(sizes);
    assert!(
        present.is_empty(),
        "selector 34 now carries native runtime frames {present:?}: card R1's \
         product has installed the syscall surface, so the R1 thread-stack \
         bound (item 4 of DW1_WYR1_RESET_R1C_VM_REQUEST.md) is now measurable \
         and must be written here — measure the retained chain against \
         linked={thread_stack_bytes} required-spare={REQUIRED_SPARE_BYTES} \
         rather than pinning constants, matching \
         validate_primordial_boot_stack_margin"
    );
    eprintln!(
        "dynamic-launch-saturation thread-stack bound=pending-product \
         native-runtime-anchors=0/{} linked={thread_stack_bytes} \
         required-spare={REQUIRED_SPARE_BYTES}",
        NATIVE_RUNTIME_ANCHORS.len(),
    );
}

/// The anchors whose appearance means a bound is writable. These are the
/// symbols E8's and DW1-C's thread-stack validators measure, matched loosely on
/// purpose: R1's own monomorphizations will not carry E8's capacity parameters,
/// so an exact-signature matcher would keep reporting "absent" after the
/// surface arrives.
type AnchorPredicate = fn(&str) -> bool;

const NATIVE_RUNTIME_ANCHORS: [(&str, AnchorPredicate); 5] = [
    ("runtime trampoline", |symbol| {
        symbol.contains("syscall::live::native_runtime_trampoline::<")
    }),
    ("runtime dispatch frame", |symbol| {
        symbol.contains("syscall::native::dispatch_frame::<")
    }),
    ("native syscall handler", |symbol| {
        symbol.ends_with("as deepwyrm_kernel::syscall::native::NativeSyscallHandler>::handle")
    }),
    ("terminal reaper", |symbol| {
        symbol.contains("syscall::live::native_runtime_terminal_reaper::<")
    }),
    ("task-group terminate", |symbol| {
        symbol.contains("::prepare_task_group_terminate")
    }),
];

fn present_native_runtime_anchors(sizes: &[StackSize]) -> Vec<&'static str> {
    NATIVE_RUNTIME_ANCHORS
        .into_iter()
        .filter(|(_, predicate)| sizes.iter().any(|entry| predicate(&entry.symbol)))
        .map(|(name, _)| name)
        .collect()
}

#[cfg(test)]
fn frame(symbol: &str) -> StackSize {
    StackSize {
        bytes: 64,
        symbol: symbol.to_owned(),
    }
}

#[test]
pub(super) fn r1_readiness_ignores_the_frames_the_selector_does_carry() {
    // Every one of these is present in the selector-34 release artifact today
    // and none of them is a native runtime frame, so none may arm the gate.
    let sizes = [
        frame("dw_x86_64_syscall_dispatch"),
        frame("deepwyrm_kernel::arch::x86_64::syscall::live::dispatch_bound_runtime"),
        frame("deepwyrm_kernel::arch::x86_64::syscall::live::install_syscall_boundary"),
        frame("dw_x86_64_rendezvous_reaper"),
        frame("deepwyrm_kernel::arch::x86_64::linked_terminal_reaper_stack_layout"),
        frame(
            "deepwyrm_kernel::arch::x86_64::mm::transition::activation::primordial::enter::<128, 4096>",
        ),
    ];
    assert_eq!(present_native_runtime_anchors(&sizes), Vec::<&str>::new());
    validate_r1_thread_stack_readiness(&sizes, 512 * 1024);
}

#[test]
pub(super) fn r1_readiness_arms_on_each_native_runtime_anchor() {
    // One monomorphization per anchor, written the way this selector's own
    // geometry would spell it rather than the way E8's does, so the gate is
    // proved to arm without depending on E8's capacity parameters.
    let arming = [
        "deepwyrm_kernel::arch::x86_64::syscall::live::native_runtime_trampoline::<deepwyrm_kernel::arch::x86_64::mm::activation::primordial::RuntimeCarrierFacade<48, 4096>>",
        "deepwyrm_kernel::syscall::native::dispatch_frame::<deepwyrm_kernel::arch::x86_64::mm::activation::primordial::RuntimeCarrierFacade<48, 4096>>",
        "<deepwyrm_kernel::arch::x86_64::mm::activation::primordial::RuntimeCarrierFacade<48, 4096> as deepwyrm_kernel::syscall::native::NativeSyscallHandler>::handle",
        "deepwyrm_kernel::arch::x86_64::syscall::live::native_runtime_terminal_reaper::<deepwyrm_kernel::arch::x86_64::mm::activation::primordial::RuntimeCarrierFacade<48, 4096>>",
        "<deepwyrm_kernel::task::TaskAuthority<32, 32, 32, 48>>::prepare_task_group_terminate",
    ];
    assert_eq!(arming.len(), NATIVE_RUNTIME_ANCHORS.len());
    for (index, symbol) in arming.iter().enumerate() {
        let sizes = [frame(symbol)];
        let present = present_native_runtime_anchors(&sizes);
        assert_eq!(
            present,
            vec![NATIVE_RUNTIME_ANCHORS[index].0],
            "anchor {index} did not arm on its own monomorphization"
        );
    }
    let all = arming
        .iter()
        .map(|symbol| frame(symbol))
        .collect::<Vec<_>>();
    assert_eq!(present_native_runtime_anchors(&all).len(), arming.len());
}

#[test]
#[should_panic(expected = "is now measurable")]
pub(super) fn r1_readiness_fails_once_the_product_installs_the_runtime_surface() {
    let sizes = [frame(
        "deepwyrm_kernel::arch::x86_64::syscall::live::native_runtime_trampoline::<deepwyrm_kernel::arch::x86_64::mm::activation::primordial::RuntimeCarrierFacade<48, 4096>>",
    )];
    validate_r1_thread_stack_readiness(&sizes, 512 * 1024);
}

#[test]
#[should_panic(expected = "ordinary per-thread arena")]
pub(super) fn r1_readiness_rejects_the_widened_e8_arena() {
    validate_r1_thread_stack_readiness(&[], 4 * 1024 * 1024);
}
