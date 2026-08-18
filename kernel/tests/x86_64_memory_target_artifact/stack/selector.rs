use super::ist::validate_ist_stack_margin;
use super::*;

pub(crate) fn validate_selector_stack_margin(
    selector: &str,
    sizes: &[StackSize],
    disassembly: &str,
) {
    const BOOT_STACK_BYTES: usize = 128 * 1024;
    const REQUIRED_SPARE_BYTES: usize = 32 * 1024;
    const ARCHITECTURAL_HEADROOM_BYTES: usize = 4 * 1024;
    const RETURN_ADDRESS_COUNT: usize = 32;
    const RETURN_ADDRESS_BYTES: usize = RETURN_ADDRESS_COUNT * size_of::<u64>();
    // Page-fault hardware pushes RIP, CS, RFLAGS, and the error word. The
    // vector stub and common entry then retain 16 GPR/CR2 words and may discard
    // one alignment word before calling Rust. Function-call return addresses
    // remain covered by RETURN_ADDRESS_BYTES above.
    const PAGE_FAULT_ENTRY_BYTES: usize = (4 + 1 + 16 + 1) * size_of::<u64>();

    let exact = |name: &str| one_stack_size(sizes, name, |symbol| symbol == name);
    let contains_plain = |description: &str, needle: &str| {
        one_stack_size(sizes, description, |symbol| {
            symbol.contains(needle) && !symbol.contains("::{closure")
        })
    };
    let suffix = |description: &str, ending: &str| {
        one_stack_size(sizes, description, |symbol| symbol.ends_with(ending))
    };
    let frame = |name: &'static str, bytes: usize| AuditedStackFrame { name, bytes };

    let kernel_main = exact("deepwyrm_kernel::kernel_main");
    let memory_guest_runner = suffix(
        "memory guest runner",
        "deepwyrm_kernel::test_support::memory::run_memory_guest_test::<128, 544>",
    );
    let memory_foundation_runner =
        contains_plain("memory foundation runner", ">::run_memory_foundation_test");
    let mapped_case_runner = suffix("mapped-case runner", ">::run_mapped_case");
    let retained_runner = [
        AuditedStackFrame {
            name: "kernel-main",
            bytes: kernel_main,
        },
        AuditedStackFrame {
            name: "memory-guest-runner",
            bytes: memory_guest_runner,
        },
        AuditedStackFrame {
            name: "memory-foundation-runner",
            bytes: memory_foundation_runner,
        },
        AuditedStackFrame {
            name: "mapped-case-runner",
            bytes: mapped_case_runner,
        },
    ];
    let mapped_case_closure = suffix(
        "mapped-case common closure",
        ">::run_mapped_case::{closure#10}",
    );
    let mapped_case_common = [AuditedStackFrame {
        name: "mapped-case-common",
        bytes: mapped_case_closure,
    }];

    let (branch_name, branch) = match selector {
        "memory-mapping" => (
            "mapping-selector",
            suffix(
                "mapping selector closure",
                ">::run_mapped_case::{closure#10}::{closure#1}",
            ),
        ),
        "memory-unmapping" => (
            "unmapping-selector",
            suffix(
                "unmapping selector closure",
                ">::run_mapped_case::{closure#10}::{closure#2}",
            ),
        ),
        "memory-permissions" => (
            "permissions-selector",
            suffix(
                "permissions selector closure",
                ">::run_mapped_case::{closure#10}::{closure#3}",
            ),
        ),
        "memory-invalid-pointer" => (
            "invalid-pointer-selector",
            suffix(
                "invalid-pointer selector closure",
                ">::run_mapped_case::{closure#10}::{closure#4}",
            ),
        ),
        "memory-user-kernel-isolation" => (
            "isolation-selector",
            suffix(
                "isolation selector closure",
                ">::run_mapped_case::{closure#10}::{closure#5}",
            ),
        ),
        "memory-shared-memory-object" => (
            "shared-object-selector",
            suffix(
                "shared-object selector closure",
                ">::run_mapped_case::{closure#10}::{closure#6}",
            ),
        ),
        _ => panic!("unknown memory selector {selector}"),
    };
    let selector_branch = [AuditedStackFrame {
        name: branch_name,
        bytes: branch,
    }];

    let map = contains_plain("AddressRegion::map", "AddressRegion<2>>::map::<1, 2,");
    let unmap = contains_plain("AddressRegion::unmap", "AddressRegion<2>>::unmap::<1, 2,");
    let protect = contains_plain(
        "AddressRegion::protect",
        "AddressRegion<2>>::protect::<1, 2,",
    );
    let rebuild = contains_plain(
        "AddressRegion::rebuild",
        "AddressRegion<2>>::rebuild::<1, 2,",
    );
    let commit_specs = contains_plain(
        "AddressRegion::commit_specs",
        "AddressRegion<2>>::commit_specs::<1, 2,",
    );
    let prepare_replace = contains_plain(
        "MemoryObjectAuthority::prepare_replace",
        "MemoryObjectAuthority<1, 2>>::prepare_replace::<2, 1>",
    );
    let prepare_object_slot = contains_plain(
        "MemoryObjectAuthority::object_slot",
        "MemoryObjectAuthority<1, 2>>::object_slot",
    );
    let prepare_lease_slot = contains_plain(
        "MemoryObjectAuthority::lease_slot",
        "MemoryObjectAuthority<1, 2>>::lease_slot",
    );
    let prepare_object_range = exact("deepwyrm_kernel::memory::vm::object::object_range");
    let prepare_next_generation = exact("deepwyrm_kernel::memory::vm::object::next_generation");
    let prepared_tickets = contains_plain(
        "PreparedReplace::tickets",
        "PreparedReplace<1, 2, 2, 1>>::tickets",
    );
    let prepared_commit = contains_plain(
        "PreparedReplace::commit",
        "PreparedReplace<1, 2, 2, 1>>::commit",
    );
    let publish_replace = suffix(
        "AddressSpacePublisher::publish_replace",
        " as deepwyrm_kernel::memory::vm::address_region::AddressSpacePublisher>::publish_replace",
    );
    let publish_pages = suffix(
        "X86AddressSpacePublisher::publish_pages",
        ">::publish_pages",
    );
    let publish_page = contains_plain(
        "journal publish_page",
        "journal::publisher::publish_page::<",
    );
    let map_page = contains_plain("PageTableRoot::map_page", "PageTableRoot>::map_page::<");
    let mm_commit = contains_plain(
        "page-table commit bridge",
        "deepwyrm_kernel::arch::x86_64::mm::commit::<",
    );
    let owned_commit = one_stack_size(sizes, "owned journal transaction commit", |symbol| {
        symbol.contains("OwnedPageTableJournal<")
            && symbol
                .ends_with(" as deepwyrm_kernel::arch::x86_64::mm::PageTableTransaction>::commit")
    });
    let validate_plan = contains_plain("owned journal validate_plan", ">::validate_plan");
    let table_reference = contains_plain("owned journal table_reference", ">::table_reference");
    let table_identity = suffix("frame-role table_identity", ">::table_identity");
    let journal_commit = one_stack_size(sizes, "page-table journal transaction commit", |symbol| {
        symbol.contains("PageTableJournal<")
            && !symbol.contains("OwnedPageTableJournal")
            && symbol
                .ends_with(" as deepwyrm_kernel::arch::x86_64::mm::PageTableTransaction>::commit")
    });
    let stage_plan = suffix("PageTableJournal::stage_plan", ">::stage_plan");
    let stage_plan_inner = suffix("PageTableJournal::stage_plan_inner", ">::stage_plan_inner");
    let stage_mutation = suffix("PageTableJournal::stage_mutation", ">::stage_mutation");
    let logical_entry = suffix("PageTableJournal::logical_entry", ">::logical_entry");
    let target_read = contains_plain(
        "active scratch read",
        "ActiveScratchTarget<deepwyrm_kernel::arch::x86_64::mm::transition::activation::LiveActiveScratchIo>>::read_location",
    );
    let target_validate = contains_plain(
        "active scratch location validation",
        "ActiveScratchTarget<deepwyrm_kernel::arch::x86_64::mm::transition::activation::LiveActiveScratchIo>>::validate_location",
    );
    let target_access = contains_plain(
        "active scratch frame access",
        "ActiveScratchTarget<deepwyrm_kernel::arch::x86_64::mm::transition::activation::LiveActiveScratchIo>>::access_frame_entry",
    );
    let target_restore = suffix("active scratch restore", ">::restore_scratch_mapping");
    let backend_load = suffix(
        "active scratch backend load",
        " as deepwyrm_kernel::arch::x86_64::mm::transition::activation::ActiveScratchIo>::load",
    );
    let backend_cas = suffix(
        "active scratch backend compare_exchange",
        " as deepwyrm_kernel::arch::x86_64::mm::transition::activation::ActiveScratchIo>::compare_exchange",
    );
    let owned_publish = one_stack_size(sizes, "owned journal publish", |symbol| {
        symbol.contains(
            "OwnedPageTableJournal<deepwyrm_kernel::arch::x86_64::mm::transition::activation::ActiveScratchTarget",
        ) && symbol.ends_with(">::publish")
    });
    let journal_publish = one_stack_size(sizes, "page-table journal publish", |symbol| {
        symbol.contains("PageTableJournal<")
            && !symbol.contains("OwnedPageTableJournal")
            && symbol.ends_with(">::publish")
    });
    let target_apply = suffix(
        "active scratch target apply",
        " as deepwyrm_kernel::arch::x86_64::mm::journal::AtomicPageTableTarget>::apply",
    );
    let target_write = contains_plain(
        "active scratch write",
        "ActiveScratchTarget<deepwyrm_kernel::arch::x86_64::mm::transition::activation::LiveActiveScratchIo>>::write_location",
    );
    let role_stage = suffix("frame-role staged commit", ">::stage_table_commit");
    let role_validate = suffix("frame-role table validation", ">::validate_table_identity");
    let role_record = suffix("frame-role record lookup", ">::record");
    let copy_from_user = contains_plain("copy_from_user", "usercopy::copy_from_user::<");
    let usercopy_preflight = contains_plain("usercopy preflight_all", "usercopy::preflight_all::<");
    let active_user_preflight = suffix(
        "active user-page preflight",
        " as deepwyrm_kernel::memory::usercopy::PinnedUserPages>::preflight",
    );
    let walk_leaf = contains_plain(
        "active-root walk_leaf",
        "ActiveRootTestAuthority<128, 544>>::walk_leaf",
    );

    let initial_map = [
        frame("address-region-map", map),
        frame("address-region-commit-specs", commit_specs),
    ];
    let unmap_operation = [
        frame("address-region-unmap", unmap),
        frame("address-region-rebuild", rebuild),
        frame("address-region-commit-specs", commit_specs),
    ];
    let protect_operation = [
        frame("address-region-protect", protect),
        frame("address-region-rebuild", rebuild),
        frame("address-region-commit-specs", commit_specs),
    ];
    let operation_paths: Vec<&[AuditedStackFrame]> = match selector {
        "memory-mapping" | "memory-user-kernel-isolation" => vec![&initial_map],
        "memory-unmapping" | "memory-shared-memory-object" => {
            vec![&initial_map, &unmap_operation]
        }
        "memory-permissions" | "memory-invalid-pointer" => {
            vec![&initial_map, &protect_operation]
        }
        _ => unreachable!("selector validated above"),
    };

    let prepare_object = [
        frame("prepare-replace", prepare_replace),
        frame("prepare-object-slot", prepare_object_slot),
    ];
    let prepare_lease = [
        frame("prepare-replace", prepare_replace),
        frame("prepare-lease-slot", prepare_lease_slot),
    ];
    let prepare_range = [
        frame("prepare-replace", prepare_replace),
        frame("prepare-object-range", prepare_object_range),
    ];
    let prepare_generation = [
        frame("prepare-replace", prepare_replace),
        frame("prepare-next-generation", prepare_next_generation),
    ];
    let inspect_prepared_tickets = [frame("prepared-tickets", prepared_tickets)];
    let publish_prefix = [
        frame("address-space-publish-replace", publish_replace),
        frame("x86-publish-pages", publish_pages),
    ];
    let validate_publication = [
        frame("journal-publish-page", publish_page),
        frame("page-table-map-page", map_page),
        frame("page-table-commit-bridge", mm_commit),
        frame("owned-journal-commit", owned_commit),
        frame("owned-journal-validate-plan", validate_plan),
        frame("owned-journal-table-reference", table_reference),
        frame("frame-role-table-identity", table_identity),
    ];
    let stage_common = [
        frame("journal-publish-page", publish_page),
        frame("page-table-map-page", map_page),
        frame("page-table-commit-bridge", mm_commit),
        frame("owned-journal-commit", owned_commit),
        frame("journal-commit", journal_commit),
        frame("journal-stage-plan", stage_plan),
        frame("journal-stage-plan-inner", stage_plan_inner),
        frame("journal-stage-mutation", stage_mutation),
        frame("journal-logical-entry", logical_entry),
        frame("active-scratch-read", target_read),
        frame("active-scratch-validate", target_validate),
        frame("active-scratch-access", target_access),
    ];
    let scratch_restore = [
        frame("active-scratch-restore", target_restore),
        frame("active-scratch-backend-cas", backend_cas),
    ];
    let scratch_load = [frame("active-scratch-backend-load", backend_load)];
    let apply_write = [
        frame("owned-journal-publish", owned_publish),
        frame("journal-publish", journal_publish),
        frame("active-target-apply", target_apply),
        frame("active-scratch-write", target_write),
        frame("active-scratch-validate", target_validate),
        frame("active-scratch-access", target_access),
        frame("active-scratch-restore", target_restore),
        frame("active-scratch-backend-cas", backend_cas),
    ];
    let apply_read = [
        frame("owned-journal-publish", owned_publish),
        frame("journal-publish", journal_publish),
        frame("active-target-apply", target_apply),
        frame("active-scratch-read", target_read),
        frame("active-scratch-validate", target_validate),
        frame("active-scratch-access", target_access),
        frame("active-scratch-restore", target_restore),
        frame("active-scratch-backend-cas", backend_cas),
    ];
    let publish_roles = [
        frame("owned-journal-publish", owned_publish),
        frame("frame-role-stage-table-commit", role_stage),
        frame("frame-role-validate-table-identity", role_validate),
        frame("frame-role-record", role_record),
    ];
    let finish_prepared = [frame("prepared-replace-commit", prepared_commit)];

    let transaction_paths: Vec<Vec<&[AuditedStackFrame]>> = vec![
        vec![&prepare_object],
        vec![&prepare_lease],
        vec![&prepare_range],
        vec![&prepare_generation],
        vec![&inspect_prepared_tickets],
        vec![&publish_prefix, &validate_publication],
        vec![&publish_prefix, &stage_common, &scratch_restore],
        vec![&publish_prefix, &stage_common, &scratch_load],
        vec![&publish_prefix, &apply_write],
        vec![&publish_prefix, &apply_read],
        vec![&publish_prefix, &publish_roles],
        vec![&finish_prepared],
    ];
    let mut publication_chain = 0;
    for operation in operation_paths {
        for descendant in &transaction_paths {
            let mut segments = vec![
                retained_runner.as_slice(),
                mapped_case_common.as_slice(),
                selector_branch.as_slice(),
                operation,
            ];
            segments.extend(descendant.iter().copied());
            let measured = audited_stack_path_bytes(&segments).unwrap_or_else(|error| {
                panic!("{selector} publication stack manifest is invalid: {error:?}")
            });
            publication_chain = publication_chain.max(measured);
        }
    }

    let usercopy_common = [
        frame("copy-from-user", copy_from_user),
        frame("usercopy-preflight-all", usercopy_preflight),
        frame("active-user-page-preflight", active_user_preflight),
        frame("active-root-walk-leaf", walk_leaf),
        frame("active-scratch-read", target_read),
        frame("active-scratch-validate", target_validate),
        frame("active-scratch-access", target_access),
    ];
    for scratch_tail in [&scratch_restore[..], &scratch_load[..]] {
        let usercopy = audited_stack_path_bytes(&[
            &retained_runner,
            &mapped_case_common,
            &selector_branch,
            &usercopy_common,
            scratch_tail,
        ])
        .unwrap_or_else(|error| panic!("{selector} usercopy stack manifest is invalid: {error:?}"));
        publication_chain = publication_chain.max(usercopy);
    }

    let complete_pass = exact("deepwyrm_kernel::test_support::x86_64::complete_pass");
    let complete_known = exact("deepwyrm_kernel::test_support::x86_64::complete_known_outcome");
    let complete = contains_plain(
        "terminal completion",
        "test_support::transport::complete::<",
    );
    let emit_completion = contains_plain(
        "completion emission",
        "test_support::transport::emit_completion::<",
    );
    let serial_record = suffix(
        "QEMU completion serial write",
        " as deepwyrm_kernel::test_support::transport::CompletionTransport>::write_serial_record",
    );
    let emit_raw = exact("deepwyrm_kernel::debug::emit_early_raw_record");
    let bounded_raw = contains_plain("bounded raw record", "debug::write_bounded_raw_record::<");
    let raw_bytes = suffix("COM1 raw bytes", ">::write_raw_bytes");
    let hardware_byte = suffix("COM1 hardware byte", ">::write_hardware_byte");
    let port_read = suffix(
        "COM1 port read",
        " as deepwyrm_kernel::debug::PortIo>::read_u8",
    );
    let completion_path = [
        frame("complete-pass", complete_pass),
        frame("complete-known-outcome", complete_known),
        frame("completion-transport", complete),
        frame("emit-completion", emit_completion),
        frame("completion-serial-record", serial_record),
        frame("emit-early-raw-record", emit_raw),
        frame("bounded-raw-record", bounded_raw),
        frame("com1-raw-bytes", raw_bytes),
        frame("com1-hardware-byte", hardware_byte),
        frame("com1-port-read", port_read),
    ];
    let normal_terminal_chain = audited_stack_path_bytes(&[&retained_runner, &completion_path])
        .unwrap_or_else(|error| {
            panic!("{selector} normal-terminal stack manifest is invalid: {error:?}")
        });

    let expect_fault = exact("deepwyrm_kernel::test_support::x86_64::expect_terminal_page_fault");
    let arm_fault = exact("deepwyrm_kernel::test_support::x86_64::arm_expected_page_fault");
    let exception_dispatch = exact("dw_x86_64_exception_dispatch");
    let report_exception = contains_plain(
        "early exception report",
        "arch::x86_64::exceptions::report_early_exception::<",
    );
    let exception_reporter = suffix(
        "serial early exception reporter",
        " as deepwyrm_kernel::arch::x86_64::exceptions::EarlyExceptionReporter>::report_and_halt",
    );
    let emit_panic = exact("deepwyrm_kernel::debug::emit_early_panic_record");
    let panic_record = contains_plain("panic record emission", "debug::emit_panic_record::<");
    let render_panic = contains_plain("panic record rendering", "debug::render_panic_record::<");
    let write_limited = contains_plain("bounded panic field", "debug::write_limited::<");
    let formatted_bytes = suffix("COM1 formatted bytes", ">::write_bytes");
    let panic_serial_path = [
        frame("emit-early-panic-record", emit_panic),
        frame("emit-panic-record", panic_record),
        frame("render-panic-record", render_panic),
        frame("write-limited", write_limited),
        frame("com1-formatted-bytes", formatted_bytes),
        frame("com1-hardware-byte", hardware_byte),
        frame("com1-port-read", port_read),
    ];
    let complete_exception = exact("deepwyrm_kernel::test_support::x86_64::complete_exception");
    let live_fault_match =
        exact("deepwyrm_kernel::test_support::x86_64::live_expected_page_fault_matches");
    let expected_fault_match =
        exact("deepwyrm_kernel::test_support::identity::expected_page_fault_matches");
    let fault_handler_prefix = [
        frame("exception-dispatch", exception_dispatch),
        frame("report-early-exception", report_exception),
        frame("serial-exception-reporter", exception_reporter),
    ];
    let expected_fault_classification = [
        frame("complete-exception", complete_exception),
        frame("live-expected-page-fault-match", live_fault_match),
        frame("expected-page-fault-match", expected_fault_match),
    ];
    let fault_entry = [frame(
        "x86-page-fault-entry-snapshot",
        PAGE_FAULT_ENTRY_BYTES,
    )];
    let fault_expectation = [frame("expect-terminal-page-fault", expect_fault)];
    let fault_arming = [frame("arm-expected-page-fault", arm_fault)];
    let fault_terminal_chain = if matches!(selector, "memory-unmapping" | "memory-permissions") {
        let arming_chain = audited_stack_path_bytes(&[
            &retained_runner,
            &mapped_case_common,
            &selector_branch,
            &fault_expectation,
            &fault_arming,
        ])
        .unwrap_or_else(|error| {
            panic!("{selector} fault-arming stack manifest is invalid: {error:?}")
        });
        let delivered_panic = audited_stack_path_bytes(&[
            &retained_runner,
            &mapped_case_common,
            &selector_branch,
            &fault_expectation,
            &fault_entry,
            &fault_handler_prefix,
            &panic_serial_path,
        ])
        .unwrap_or_else(|error| {
            panic!("{selector} #PF panic stack manifest is invalid: {error:?}")
        });
        let delivered_completion = audited_stack_path_bytes(&[
            &retained_runner,
            &mapped_case_common,
            &selector_branch,
            &fault_expectation,
            &fault_entry,
            &fault_handler_prefix,
            &expected_fault_classification,
            &completion_path,
        ])
        .unwrap_or_else(|error| {
            panic!("{selector} #PF completion stack manifest is invalid: {error:?}")
        });
        arming_chain.max(delivered_panic).max(delivered_completion)
    } else {
        0
    };

    let measured_chain = publication_chain
        .max(normal_terminal_chain)
        .max(fault_terminal_chain);
    let total = measured_chain + RETURN_ADDRESS_BYTES + ARCHITECTURAL_HEADROOM_BYTES;
    assert!(
        total <= BOOT_STACK_BYTES,
        "{selector} target stack bound exceeds the boot stack: measured chain {measured_chain}, \
         return addresses {RETURN_ADDRESS_BYTES}, required architectural headroom \
         {ARCHITECTURAL_HEADROOM_BYTES}, total {total}, boot stack {BOOT_STACK_BYTES}"
    );
    assert!(
        BOOT_STACK_BYTES - total >= REQUIRED_SPARE_BYTES,
        "{selector} target stack bound leaves less than the required {REQUIRED_SPARE_BYTES}-byte \
         spare: total {total}, boot stack {BOOT_STACK_BYTES}"
    );
    eprintln!(
        "{selector} stack publication={publication_chain} normal-terminal={normal_terminal_chain} \
         fault-terminal={fault_terminal_chain} measured={measured_chain} \
         returns={RETURN_ADDRESS_BYTES} headroom={ARCHITECTURAL_HEADROOM_BYTES} \
         total={total} spare={}",
        BOOT_STACK_BYTES - total
    );
    validate_ist_stack_margin(selector, sizes, disassembly);
}
