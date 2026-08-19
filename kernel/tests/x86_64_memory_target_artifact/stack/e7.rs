use super::*;

pub(crate) fn validate_e7_stack_margin(sizes: &[StackSize]) {
    const BOOT_STACK_BYTES: usize = 128 * 1024;
    const THREAD_STACK_BYTES: usize = 64 * 1024;
    const REQUIRED_SPARE_BYTES: usize = 32 * 1024;
    const ARCHITECTURAL_HEADROOM_BYTES: usize = 4 * 1024;
    const RETURN_ADDRESS_BYTES: usize = 64 * size_of::<u64>();
    const F2_PROBE_STACK_BYTES: usize = 16 * 1024;
    const F2_SWITCH_FRAME_BYTES: usize = 7 * size_of::<u64>();

    let exact = |name: &str| one_stack_size(sizes, name, |symbol| symbol == name);
    let plain = |description: &str, needle: &str| {
        one_stack_size(sizes, description, |symbol| {
            symbol.contains(needle) && !symbol.contains("::{closure")
        })
    };
    let frame = |name: &'static str, bytes: usize| AuditedStackFrame { name, bytes };

    let f2_probe_wrapper = plain(
        "F2 target continuation wrapper",
        "context::validate_target_continuation_roundtrip",
    );
    let f2_probe_run = plain("F2 target continuation run", "context::target_probe::run");
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

    let boot_retained = [
        frame("e7-kernel-main", exact("deepwyrm_kernel::kernel_main")),
        frame(
            "e7-task-runner",
            plain(
                "E7 task runner",
                "test_support::task::run_task_guest_test::<128, 544>",
            ),
        ),
        frame(
            "e7-active-runner",
            plain("E7 active runner", ">>::run_task_userspace_test"),
        ),
        frame(
            "e7-selector-runner",
            plain(
                "E7 selector runner",
                "test_support::e7::run_task_userspace_test::<128, 544>",
            ),
        ),
        frame(
            "e7-enter-smoke",
            plain(
                "E7 enter smoke",
                "test_support::e7::enter_smoke::<128, 544>",
            ),
        ),
        frame(
            "e7-build-runtime",
            plain(
                "E7 build runtime",
                "test_support::e7::build_smoke_runtime::<128, 544>",
            ),
        ),
    ];
    let protect_prefix = [
        frame(
            "e7-protect-helper",
            plain(
                "E7 protect helper",
                "test_support::e7::protect_page::<128, 544>",
            ),
        ),
        frame(
            "e7-address-protect",
            plain(
                "E7 AddressRegion protect",
                "AddressRegion<3>>::protect::<3, 3, 8,",
            ),
        ),
        frame(
            "e7-address-rebuild",
            plain(
                "E7 AddressRegion rebuild",
                "AddressRegion<3>>::rebuild::<3, 3, 8,",
            ),
        ),
        frame(
            "e7-address-commit",
            plain(
                "E7 AddressRegion commit",
                "AddressRegion<3>>::commit_specs::<3, 3, 8,",
            ),
        ),
    ];
    let prepare_branch = [
        frame(
            "e7-prepare-replace",
            plain(
                "E7 prepare replace",
                "MemoryObjectAuthority<3, 3>>::prepare_replace::<3, 8>",
            ),
        ),
        frame(
            "e7-plan-replace",
            plain(
                "E7 plan replace",
                "MemoryObjectAuthority<3, 3>>::plan_replace::<3>",
            ),
        ),
        frame(
            "e7-object-slot",
            plain(
                "E7 object slot",
                "MemoryObjectAuthority<3, 3>>::object_slot",
            ),
        ),
        frame(
            "e7-lease-slot",
            plain("E7 lease slot", "MemoryObjectAuthority<3, 3>>::lease_slot"),
        ),
        frame(
            "e7-object-range",
            exact("deepwyrm_kernel::memory::vm::object::object_range"),
        ),
    ];
    let publish_branch = [
        frame(
            "e7-publish-replace",
            plain(
                "E7 publish replace",
                "AddressSpacePublisher>::publish_replace",
            ),
        ),
        frame(
            "e7-publish-pages",
            plain("E7 publish pages", ">::publish_pages"),
        ),
        frame(
            "e7-publish-page",
            plain("E7 publish page", "journal::publisher::publish_page::<"),
        ),
        frame(
            "e7-page-protect",
            plain(
                "E7 PageTableRoot protect",
                "PageTableRoot>::protect_page::<",
            ),
        ),
        frame(
            "e7-owned-validate",
            plain("E7 owned journal validate", ">::validate_plan"),
        ),
        frame(
            "e7-stage-table",
            plain("E7 staged table commit", ">::stage_table_commit"),
        ),
        frame(
            "e7-owned-publish",
            one_stack_size(sizes, "E7 owned journal publish", |symbol| {
                symbol.contains("OwnedPageTableJournal<") && symbol.ends_with(">::publish")
            }),
        ),
        frame(
            "e7-journal-publish",
            one_stack_size(sizes, "E7 journal publish", |symbol| {
                symbol.contains("PageTableJournal<")
                    && !symbol.contains("OwnedPageTableJournal")
                    && symbol.ends_with(">::publish")
            }),
        ),
    ];
    let boot_prepare = audited_stack_path(&[&boot_retained, &protect_prefix, &prepare_branch])
        .expect("E7 bootstrap prepare stack manifest is unique");
    let boot_publish = audited_stack_path(&[&boot_retained, &protect_prefix, &publish_branch])
        .expect("E7 bootstrap publish stack manifest is unique");
    let f2_probe_branch = [
        frame("f2-probe-wrapper", f2_probe_wrapper),
        frame("f2-probe-run", f2_probe_run),
        frame("f2-switch-frame", F2_SWITCH_FRAME_BYTES),
    ];
    let boot_probe = audited_stack_path(&[&boot_retained, &f2_probe_branch])
        .expect("F2 target probe bootstrap stack manifest is unique");
    let boot = audited_stack_upper_bound(&[boot_prepare, boot_publish, boot_probe]);
    let boot_total = boot
        .bytes
        .checked_add(RETURN_ADDRESS_BYTES)
        .and_then(|bytes| bytes.checked_add(ARCHITECTURAL_HEADROOM_BYTES))
        .expect("E7 bootstrap stack bound fits usize");
    assert!(
        boot_total + REQUIRED_SPARE_BYTES <= BOOT_STACK_BYTES,
        "E7 bootstrap stack bound too small: used={boot_total} spare={} required={REQUIRED_SPARE_BYTES}",
        BOOT_STACK_BYTES.saturating_sub(boot_total)
    );

    let syscall_common = [
        frame(
            "e7-native-trampoline",
            plain(
                "E7 native trampoline",
                "syscall::live::native_runtime_trampoline::<",
            ),
        ),
        frame(
            "e7-dispatch-frame",
            plain("E7 dispatch frame", "syscall::native::dispatch_frame::<"),
        ),
        frame(
            "e7-dispatch-native",
            plain("E7 dispatch native", "syscall::native::dispatch_native::<"),
        ),
        frame(
            "e7-runtime-handle",
            plain("E7 runtime handler", "NativeSyscallHandler>::handle"),
        ),
    ];
    let abi_branch = [
        frame(
            "e7-abi-get-info",
            plain("E7 abi_get_info", "syscall::adapters::abi_get_info::<"),
        ),
        frame(
            "e7-user-preflight-output",
            plain("E7 preflight output", "usercopy::preflight_user_output::<"),
        ),
        frame(
            "e7-user-pin",
            plain(
                "E7 live user pin",
                "LiveProcessAddressSpace<128, 544> as deepwyrm_kernel::memory::usercopy::UserPageAccess>::pin",
            ),
        ),
        frame(
            "e7-user-preflight-all",
            plain(
                "E7 preflight all",
                "usercopy::preflight_all::<deepwyrm_kernel::arch::x86_64::mm::transition::activation::user_access::PinnedLiveUserPages>",
            ),
        ),
        frame(
            "e7-live-preflight",
            plain(
                "E7 live preflight",
                "PinnedLiveUserPages as deepwyrm_kernel::memory::usercopy::PinnedUserPages>::preflight",
            ),
        ),
        frame(
            "e7-live-walk",
            plain(
                "E7 live walk",
                "LiveProcessAddressSpace<128, 544>>::walk_leaf",
            ),
        ),
        frame(
            "e7-live-read-entry",
            plain(
                "E7 live read entry",
                "LiveProcessAddressSpace<128, 544>>::read_entry",
            ),
        ),
    ];
    let exit_branch = [
        frame(
            "e7-process-exit-adapter",
            plain(
                "E7 process_exit adapter",
                "syscall::adapters::process_exit::<8, 1, 1, 1, 1, 1>",
            ),
        ),
        frame(
            "e7-task-exit-process",
            plain(
                "E7 task exit_process",
                "TaskAuthority<1, 1, 1, 1>>::exit_process::<8>",
            ),
        ),
        frame(
            "e7-terminate-process",
            plain(
                "E7 terminate process",
                "TaskAuthority<1, 1, 1, 1>>::terminate_process_common",
            ),
        ),
        frame(
            "e7-drain-handles",
            plain("E7 drain handles", "HandleTable<1>>::drain::<8>"),
        ),
        frame(
            "e7-collect-effects",
            plain(
                "E7 collect effects",
                "syscall::adapters::collect_process_effects::<8, 1, 1, 1>",
            ),
        ),
        frame(
            "e7-collect-pins",
            plain(
                "E7 collect pins",
                "syscall::adapters::collect_retired_pins::<8, 1>",
            ),
        ),
        frame(
            "e7-retire-pins",
            plain(
                "E7 retire pins",
                "ExecutionDomain<1>>::retire_exit_pins::<1>",
            ),
        ),
    ];
    let reschedule_branch = [
        frame(
            "e7-terminate-current",
            plain(
                "E7 terminate current",
                "NativeSyscallFrameRuntime>::terminate_current",
            ),
        ),
        frame(
            "e7-finalize-refs",
            plain(
                "E7 finalize refs",
                "E7SmokeRuntime<128, 544>>::finalize_task_refs",
            ),
        ),
        frame(
            "e7-finish-release",
            plain(
                "E7 finish task release",
                "E7SmokeRuntime<128, 544>>::finish_task_release",
            ),
        ),
        frame(
            "e7-take-finalization",
            plain(
                "E7 take finalization",
                "TaskAuthority<1, 1, 1, 1>>::take_finalization",
            ),
        ),
        frame(
            "e7-complete-finalization",
            plain(
                "E7 complete task finalization",
                "task::complete_task_finalization::<8>",
            ),
        ),
    ];

    let abi = audited_stack_path(&[&syscall_common, &abi_branch])
        .expect("E7 ABI syscall stack manifest is unique");
    let exit = audited_stack_path(&[&syscall_common, &exit_branch])
        .expect("E7 exit syscall stack manifest is unique");
    let reschedule = audited_stack_path(&[&syscall_common, &reschedule_branch])
        .expect("E7 terminal-control stack manifest is unique");
    let thread = audited_stack_upper_bound(&[abi, exit, reschedule]);
    let thread_total = thread
        .bytes
        .checked_add(RETURN_ADDRESS_BYTES)
        .and_then(|bytes| bytes.checked_add(ARCHITECTURAL_HEADROOM_BYTES))
        .expect("E7 Thread stack bound fits usize");
    assert!(
        thread_total + REQUIRED_SPARE_BYTES <= THREAD_STACK_BYTES,
        "E7 Thread stack bound too small: used={thread_total} spare={} required={REQUIRED_SPARE_BYTES}",
        THREAD_STACK_BYTES.saturating_sub(thread_total)
    );

    eprintln!(
        "task-syscall-smoke stack bootstrap={} thread={} bootstrap-spare={} thread-spare={}",
        boot_total,
        thread_total,
        BOOT_STACK_BYTES - boot_total,
        THREAD_STACK_BYTES - thread_total
    );
}
