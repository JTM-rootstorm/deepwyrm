#[allow(dead_code)]
#[path = "../build.rs"]
mod kernel_build;

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

#[test]
fn layout_manifest_is_exact_and_fails_closed_on_drift() {
    let source = fs::read_to_string(layout_path()).expect("read canonical layout manifest");
    let layout = kernel_build::Layout::parse(&source).expect("parse canonical layout manifest");
    assert_eq!(layout.link_base, 0xffff_ffff_8000_0000);
    assert_eq!(layout.base_page_size, 4_096);
    assert_eq!(layout.kernel_boot_stack_size, 1_048_576);
    assert_eq!(layout.kernel_boot_stack_alignment, 4_096);
    assert_eq!(layout.temporary_virtual_address, 0xffff_ff00_0000_0000);
    assert_eq!(layout.temporary_indices, [510, 0, 0, 0]);
    assert_eq!(
        layout.temporary_virtual_address,
        deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS
    );
    assert_eq!(
        layout.temporary_indices,
        [
            deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_PML4_INDEX,
            deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_PDPT_INDEX,
            deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_PD_INDEX,
            deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_PT_INDEX,
        ]
    );
    assert_eq!(
        layout.minimum_table_frame_count,
        u64::from(deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_MIN_TABLE_FRAME_COUNT)
    );
    assert_eq!(
        layout.maximum_table_frame_count,
        u64::from(deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT)
    );
    assert_eq!(
        deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET,
        deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_V1_SIZE
    );
    assert_eq!(
        deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_MAX_BYTE_LEN,
        deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAMES_OFFSET
            + deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT
                * deepwyrm_abi::DW_BOOT_X86_64_PAGING_HANDOFF_TABLE_FRAME_STRIDE
    );
    assert_eq!(
        layout.max_normalized_memory_map_entries,
        deepwyrm_kernel::boot::MAX_BOOT_MEMORY_MAP_ENTRIES as u64
    );
    assert_eq!(
        layout.max_module_entries,
        deepwyrm_kernel::boot::MAX_BOOT_MODULE_ENTRIES as u64
    );

    for malformed in [
        format!("{source}\nunknown_contract_key = true\n"),
        source.replacen("version = 2", "version = 2\nversion = 2", 1),
        source.replace("version = 2", "version = 1"),
        source.replace(
            "kernel_boot_stack_size = 1048576",
            "kernel_boot_stack_size = 65536",
        ),
        source.replace(
            "allowed_program_header_types = [\"PT_LOAD\"]",
            "allowed_program_header_types = [\"PT_LOAD\", \"PT_NOTE\"]",
        ),
        source.replace(
            "defined_incoming_gprs = [\"RDI\"]",
            "defined_incoming_gprs = [\"RDI\", \"RSI\"]",
        ),
        source.replace(
            "p_paddr_policy = \"ignored\"",
            "p_paddr_policy = \"load-address\"",
        ),
        source.replace(
            "acpi_duplicate_selected_guid = \"reject\"",
            "acpi_duplicate_selected_guid = \"first\"",
        ),
        source.replace(
            "acpi_preferred_invalid = \"reject-no-downgrade\"",
            "acpi_preferred_invalid = \"fallback\"",
        ),
        source.replace(
            "acpi_rsdp_length_rule = \"revision-lt-2:20;revision-ge-2:declared-36..4096\"",
            "acpi_rsdp_length_rule = \"unbounded\"",
        ),
        source.replace(
            "acpi_table_traversal = \"deferred-dw0-c\"",
            "acpi_table_traversal = \"loader-walk\"",
        ),
        source.replace(
            "temporary_virtual_address = \"0xffffff0000000000\"",
            "temporary_virtual_address = \"0xffffffff80000000\"",
        ),
        source.replace("pml4_index = 510", "pml4_index = 511"),
        source.replace(
            "maximum_table_frame_count = 256",
            "maximum_table_frame_count = 257",
        ),
        source.replace(
            "initial_leaf = \"exactly-zero-non-present\"",
            "initial_leaf = \"present\"",
        ),
        source.replace("pcide_enabled = false", "pcide_enabled = true"),
        source.replace("pge_enabled = false", "pge_enabled = true"),
        source.replace(
            "identity_alias_mutable_by_deepwyrm = true",
            "identity_alias_mutable_by_deepwyrm = false",
        ),
    ] {
        assert!(kernel_build::Layout::parse(&malformed).is_err());
    }
}

#[test]
fn task_layout_manifest_is_kernel_private_exact_and_fails_closed_on_drift() {
    let source = fs::read_to_string(task_layout_path()).expect("read E4 task layout manifest");
    let layout = kernel_build::TaskLayout::parse(&source).expect("parse E4 task layout manifest");
    assert_eq!(layout.thread_kernel_stack_count, 16);
    assert_eq!(layout.thread_kernel_stack_size, 524_288);
    assert_eq!(layout.thread_kernel_stack_guard_size, 4_096);
    assert_eq!(layout.thread_kernel_stack_alignment, 4_096);
    assert_eq!(layout.privilege_entry_stack_count, 1);
    assert_eq!(layout.privilege_entry_stack_size, 16_384);
    assert_eq!(layout.privilege_entry_stack_guard_size, 4_096);
    assert_eq!(layout.privilege_entry_stack_alignment, 4_096);
    assert_eq!(layout.terminal_reaper_stack_count, 1);
    assert_eq!(layout.terminal_reaper_stack_size, 135_168);
    assert_eq!(layout.terminal_reaper_stack_guard_size, 4_096);
    assert_eq!(layout.terminal_reaper_stack_alignment, 4_096);
    for malformed in [
        format!("{source}\nunknown_task_layout_key = 1\n"),
        source.replace("version = 4", "version = 3"),
        source.replace(
            "thread_kernel_stack_count = 16",
            "thread_kernel_stack_count = 8",
        ),
        source.replace(
            "thread_kernel_stack_size = 524288",
            "thread_kernel_stack_size = 32768",
        ),
        source.replace(
            "thread_kernel_stack_guard_size = 4096",
            "thread_kernel_stack_guard_size = 8192",
        ),
        source.replace(
            "privilege_entry_stack_count = 1",
            "privilege_entry_stack_count = 2",
        ),
        source.replace(
            "privilege_entry_stack_size = 16384",
            "privilege_entry_stack_size = 8192",
        ),
        source.replace(
            "terminal_reaper_stack_count = 1",
            "terminal_reaper_stack_count = 2",
        ),
        source.replace(
            "terminal_reaper_stack_size = 135168",
            "terminal_reaper_stack_size = 65536",
        ),
        source.replace(
            "terminal_reaper_stack_guard_size = 4096",
            "terminal_reaper_stack_guard_size = 8192",
        ),
        source.replace(
            "terminal_reaper_stack_alignment = 4096",
            "terminal_reaper_stack_alignment = 8192",
        ),
    ] {
        assert!(kernel_build::TaskLayout::parse(&malformed).is_err());
    }
}

#[test]
fn e4_user_descriptors_and_rsp0_match_the_locked_contract() {
    let root = kernel_root();
    let gdt = fs::read_to_string(root.join("src/arch/x86_64/gdt.rs")).expect("read GDT source");
    let tss = fs::read_to_string(root.join("src/arch/x86_64/tss.rs")).expect("read TSS source");
    let x86 = fs::read_to_string(root.join("src/arch/x86_64/mod.rs")).expect("read x86 installer");
    let linker = fs::read_to_string(root.join("arch/x86_64/linker.ld")).expect("read linker");
    assert!(gdt.contains("SegmentSelector(0x2b)"));
    assert!(gdt.contains("SegmentSelector(0x33)"));
    assert!(gdt.contains("entries: [u64; 7]"));
    assert!(gdt.contains("0x00cf_f200_0000_ffff"));
    assert!(gdt.contains("0x00af_fa00_0000_ffff"));
    assert!(gdt.contains("GDT_HARDWARE_LIMIT"));
    assert!(tss.contains("io_map_base: size_of::<Self>() as u16"));
    assert!(x86.contains("tss.set_privilege_stack0(privilege_entry.top)"));
    assert!(x86.contains("linked_privilege_entry_stack_layout()"));
    assert!(x86.contains("fn opaque_linker_symbol_address(symbol: *const u8) -> u64"));
    assert!(x86.contains("address = inout(reg) address"));
    assert!(x86.matches("opaque_linker_symbol_address").count() >= 20);
    assert!(linker.contains("__dw_privilege_entry_stack_guard = .;"));
    assert!(linker.contains("__dw_privilege_entry_stack_top = .;"));
}

#[test]
fn guest_test_identity_is_resolved_only_from_the_canonical_selector() {
    let harness = fs::read_to_string(guest_harness_path()).expect("read guest harness manifest");
    for (selector, id) in [
        ("boot-handoff-pass", 1),
        ("exception-fail-path", 2),
        ("panic-path", 3),
        ("memory-mapping", 4),
        ("memory-unmapping", 5),
        ("memory-permissions", 6),
        ("memory-invalid-pointer", 7),
        ("memory-user-kernel-isolation", 8),
        ("memory-shared-memory-object", 9),
        ("task-syscall-smoke", 10),
        ("ipc-blocking-smoke", 13),
        ("atomic-wait-wake", 16),
        ("primordial-bootstrap", 18),
        ("primordial-blocking-cleanup", 19),
        ("primordial-user-exception", 20),
        ("primordial-invalid-return", 21),
        ("smp-runtime-stress", 22),
        ("smp-runtime-acceptance", 23),
        ("native-userspace-capability", 24),
        ("normal-preemption-up", 26),
        ("bootstrap-registry-launch", 27),
        ("normal-preemption-smp", 28),
    ] {
        assert_eq!(
            kernel_build::select_guest_test(true, Some(selector), false, &harness),
            Ok(Some(id)),
            "selector {selector} must retain its immutable harness ID"
        );
    }
    for selector in [
        "task-syscall-sanitize",
        "task-user-exception",
        "ipc-transfer-rollback",
        "wait-deadline-timer",
        "process-create-bootstrap",
    ] {
        assert!(
            kernel_build::select_guest_test(true, Some(selector), false, &harness).is_err(),
            "reserved selector {selector} must not produce a runnable build identity"
        );
    }
    assert!(kernel_build::select_guest_test(true, Some("unknown-test"), false, &harness).is_err());
    assert!(kernel_build::select_guest_test(true, None, false, &harness).is_err());
    assert!(kernel_build::select_guest_test(false, Some("panic-path"), false, "").is_err());
    assert!(kernel_build::select_guest_test(true, Some("panic-path"), true, &harness).is_err());
    assert_eq!(
        kernel_build::select_guest_test(false, None, false, ""),
        Ok(None)
    );
}

#[test]
fn selector26_private_evidence_surface_is_isolated_and_terminally_ordered() {
    let root = kernel_root();
    let build = fs::read_to_string(root.join("build.rs")).expect("read kernel build");
    let support =
        fs::read_to_string(root.join("src/test_support/mod.rs")).expect("read test support");
    let evidence = fs::read_to_string(root.join("src/test_support/dw1b_evidence.rs"))
        .expect("read selector-26 evidence");
    let terminal =
        fs::read_to_string(root.join("src/test_support/x86_64.rs")).expect("read terminal support");
    let debug = fs::read_to_string(root.join("src/debug/mod.rs")).expect("read debug support");
    let primordial = fs::read_to_string(root.join("src/arch/x86_64/mm/activation/primordial.rs"))
        .expect("read primordial runtime");
    let syscall =
        fs::read_to_string(root.join("src/syscall/mod.rs")).expect("read syscall exports");
    let adapters =
        fs::read_to_string(root.join("src/syscall/adapters.rs")).expect("read syscall adapters");
    let public_abi = fs::read_to_string(root.join("../abi/generated/deepwyrm_abi.rs"))
        .expect("read generated ABI");

    assert!(build.contains("selector == \"normal-preemption-up\""));
    assert!(build.contains("cargo:rustc-cfg=deepwyrm_dw1b_evidence"));
    assert!(support.contains("#[cfg(any(test, deepwyrm_dw1b_evidence))]\nmod dw1b_evidence;"));
    assert!(evidence.contains("pub(crate) const DW1B_EVIDENCE_RAW_SYSCALL: u32 = 0xffff_ff1a;"));
    assert!(!public_abi.contains("FFFF_FF1A"));
    assert!(!public_abi.contains("ffff_ff1a"));
    assert!(debug.contains("deepwyrm_dw1b_evidence"));
    assert!(debug.contains("fn write_bounded_test_evidence_record"));

    let completion = terminal
        .find("pub(crate) fn complete_dw1b_evidence")
        .expect("selector-26 terminal exists");
    let evidence_write = terminal[completion..]
        .find("write_evidence(permit.record())")
        .expect("DWPRE1 evidence write exists");
    let pass = terminal[completion..]
        .find("completion_record(CompletionOutcome::Pass, 0)")
        .expect("selector-26 PASS exists");
    assert!(evidence_write < pass, "DWPRE1 must precede PASS DWTEST1");

    assert!(primordial.contains("self.evidence_init_process != Some(self.process)"));
    assert!(primordial.contains("process_target_for_dw1b_evidence"));
    assert!(primordial.contains("exact_single_thread("));
    assert!(primordial.contains("Dw1bRawOperation::decode(arguments.as_array())"));
    assert!(primordial.contains(".progress(self.process, exchange_count, digest)"));
    assert!(primordial.contains("g5_probe.accepts_completion(&completion)"));
    assert!(primordial.contains("complete_dw1b_evidence(permit)"));
    assert!(syscall.contains("deepwyrm_dw1b_evidence"));
    assert!(syscall.contains("pub(crate) use adapters::process_create_with_root_observed;"));
    assert!(adapters.contains("process_create_with_root_observed"));
}

#[test]
fn selector27_private_wrb1_relay_is_exact_and_outside_public_abi() {
    let root = kernel_root();
    let build = fs::read_to_string(root.join("build.rs")).expect("read kernel build");
    let support =
        fs::read_to_string(root.join("src/test_support/mod.rs")).expect("read test support");
    let evidence = fs::read_to_string(root.join("src/test_support/wyr1b_evidence.rs"))
        .expect("read selector-27 evidence");
    let terminal =
        fs::read_to_string(root.join("src/test_support/x86_64.rs")).expect("read terminal support");
    let primordial = fs::read_to_string(root.join("src/arch/x86_64/mm/activation/primordial.rs"))
        .expect("read primordial runtime");
    let public_abi = fs::read_to_string(root.join("../abi/generated/deepwyrm_abi.rs"))
        .expect("read generated ABI");

    assert!(build.contains("selector == \"bootstrap-registry-launch\""));
    assert!(build.contains("cargo:rustc-cfg=deepwyrm_wyr1b_evidence"));
    assert!(support.contains("#[cfg(any(test, deepwyrm_wyr1b_evidence))]\nmod wyr1b_evidence;"));
    assert!(evidence.contains("pub(crate) const WYR1B_EVIDENCE_RAW_SYSCALL: u32 = 0xffff_ff1b;"));
    assert!(evidence.contains("WYR1B_EVIDENCE_RECORD_LEN: usize = 96"));
    assert!(evidence.contains("WYR1B_EVIDENCE_RECORD_CAPACITY: usize = 14"));
    assert!(evidence.contains("[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, TERMINAL_EVENT]"));
    assert!(!public_abi.contains("FFFF_FF1B"));
    assert!(!public_abi.contains("ffff_ff1b"));
    assert!(primordial.contains("WYR1B_EVIDENCE"));
    assert!(primordial.contains(".authorize_submission(self.process)"));
    assert!(primordial.contains("Wyr1bRetirementFacts"));
    assert!(primordial.contains("parse_wyr1b_bootfs_pages"));
    assert!(
        primordial.contains(
            "BuildGuestTest::BootstrapRegistryLaunch => G5PrimordialExpectation::Baseline"
        )
    );
    assert!(
        !primordial
            .contains("_ => unreachable!(\"primordial runtime requires a primordial selector\")"),
        "primordial probe admission must exhaustively classify every build selector"
    );

    let completion = terminal
        .find("pub(crate) fn complete_wyr1b_evidence")
        .expect("selector-27 terminal exists");
    let evidence_write = terminal[completion..]
        .find(".write_evidence(record)")
        .expect("WRB1 evidence write exists");
    let pass = terminal[completion..]
        .find("CompletionOutcome::Pass")
        .expect("selector-27 PASS exists");
    assert!(evidence_write < pass, "WRB1 must precede PASS DWTEST1");
}

#[test]
fn selector27_binds_reporter_start_to_fixed_stack_root_and_guard() {
    let root = kernel_root();
    let evidence = fs::read_to_string(root.join("src/test_support/wyr1b_evidence.rs"))
        .expect("read selector-27 evidence");
    let terminal =
        fs::read_to_string(root.join("src/test_support/x86_64.rs")).expect("read terminal support");
    let primordial = fs::read_to_string(root.join("src/arch/x86_64/mm/activation/primordial.rs"))
        .expect("read primordial runtime");

    for geometry in [
        "WYR1B_SYSTEM_INIT_STACK_TOP: u64 = 0x0000_7fff_ffff_0000",
        "WYR1B_SYSTEM_INIT_STACK_BYTES: u64 = 128 * 1024",
        "WYR1B_SYSTEM_INIT_STACK_TOP - WYR1B_SYSTEM_INIT_STACK_BYTES",
        "WYR1B_SYSTEM_INIT_STACK_TOP - 4096",
        "WYR1B_SYSTEM_INIT_STACK_BOTTOM - 4096",
    ] {
        assert!(
            evidence.contains(geometry),
            "missing fixed Wyrmroot child geometry {geometry}"
        );
    }
    for invariant in [
        "startup.reporter_process != reporter",
        "startup.reporter_thread != reporter_thread",
        "startup.reporter_root != reporter_root",
        "self.stack_pointer != WYR1B_SYSTEM_INIT_STACK_POINTER",
        "self.stack_mapping_start != WYR1B_SYSTEM_INIT_STACK_BOTTOM",
        "self.stack_mapping_bytes != WYR1B_SYSTEM_INIT_STACK_BYTES",
        "!self.stack_mapping_rw_nx",
        "!self.guard_absent",
    ] {
        assert!(
            evidence.contains(invariant),
            "missing reporter-start invariant {invariant}"
        );
    }

    let observer = primordial
        .split_once("fn observe_wyr1b_system_init_start(")
        .expect("selector-27 reporter-start observer")
        .1
        .split_once("fn drain_finalizers(")
        .expect("reporter-start observer extent")
        .0;
    for binding in [
        "process_thread_keys(reporter_process)",
        "thread_start_state(thread)",
        "root_region(reporter_process)",
        "region_process(reporter_root)",
        "mapping.protection() == Protection::READ_EXECUTE",
        "mapping.protection() == Protection::READ_WRITE",
        "WYR1B_SYSTEM_INIT_GUARD_START",
        "WYR1B_EVIDENCE.observe_reporter_start",
    ] {
        assert!(
            observer.contains(binding),
            "missing live start binding {binding}"
        );
    }

    let thread_start = primordial
        .split_once("NativeSyscallRequest::ThreadStart { args, args_size } => {")
        .expect("ThreadStart dispatch")
        .1
        .split_once("NativeSyscallRequest::ProcessTerminate")
        .expect("ThreadStart dispatch extent")
        .0;
    let commit = thread_start.find("thread_start_with_access(").unwrap();
    let release_user = thread_start.find("drop(user);").unwrap();
    let success = thread_start.find("if status == DW_STATUS_SUCCESS").unwrap();
    let observe = thread_start
        .find("self.observe_wyr1b_system_init_start()")
        .unwrap();
    assert!(commit < release_user);
    assert!(release_user < success);
    assert!(success < observe);

    for detail in [
        "StartupMissing => 0x2710_f00c",
        "StartupDuplicate => 0x2710_f00d",
        "StartupRoot => 0x2710_f00e",
        "StartupEntry => 0x2710_f00f",
        "StartupStackPointer => 0x2710_f010",
        "StartupStackMapping => 0x2710_f011",
        "StartupStackProtection => 0x2710_f012",
        "StartupGuard => 0x2710_f013",
    ] {
        assert!(
            terminal.contains(detail),
            "missing distinct terminal detail {detail}"
        );
    }
    for detail in [
        "StartupMissing => 0x2710_e00b",
        "StartupDuplicate => 0x2710_e00c",
        "StartupRoot => 0x2710_e00d",
        "StartupEntry => 0x2710_e00e",
        "StartupStackPointer => 0x2710_e00f",
        "StartupStackMapping => 0x2710_e010",
        "StartupStackProtection => 0x2710_e011",
        "StartupGuard => 0x2710_e012",
    ] {
        assert!(
            primordial.contains(detail),
            "missing distinct live detail {detail}"
        );
    }
}

#[test]
fn i1_evidence_nonce_is_build_owned_and_strict() {
    assert!(kernel_build::validate_i1_evidence_nonce("0123456789ABCDEF").is_ok());
    for nonce in [
        "0000000000000000",
        "0123456789abcdef",
        "0123456789ABCDE",
        "0123456789ABCDEFF",
        "0123456789ABCDEG",
    ] {
        assert!(kernel_build::validate_i1_evidence_nonce(nonce).is_err());
    }
}

#[test]
fn i1_evidence_has_one_terminal_com1_reporter() {
    let evidence = fs::read_to_string(kernel_root().join("src/test_support/evidence.rs"))
        .expect("read I1 evidence collector");
    let terminal = fs::read_to_string(kernel_root().join("src/test_support/x86_64.rs"))
        .expect("read terminal reporter");
    assert!(evidence.contains("Workers have no serial-port API"));
    assert!(!evidence.contains("emit_early_raw_record"));
    assert!(terminal.contains("I1_EVIDENCE.finalize_running_invariant"));
    assert!(terminal.contains("permit.flush"));
    assert!(terminal.contains("begin_test_serial_transaction"));
    assert!(terminal.contains(".write_evidence(record)"));
    assert!(terminal.contains("emit_early_raw_record(record)"));
}

#[test]
fn wyr1_terminal_outcomes_share_one_claimed_prefix_transaction() {
    let terminal = fs::read_to_string(kernel_root().join("src/test_support/x86_64.rs"))
        .expect("read terminal reporter");
    let start = terminal
        .find("fn complete_wyr1_evidence_kernel_terminal(")
        .expect("selector-25 kernel terminal helper");
    let end = terminal[start..]
        .find("\n#[cfg(deepwyrm_wyr1_evidence)]\nfn wyr1_failure_detail")
        .map(|offset| start + offset)
        .expect("selector-25 kernel terminal helper boundary");
    let shared = &terminal[start..end];
    let claim = shared.find("WYR1_EVIDENCE.claim_failure()").unwrap();
    let transaction = shared.find("begin_test_serial_transaction()").unwrap();
    let prefix = shared.find("permit\n        .flush_prefix").unwrap();
    let completion = shared.find("completion_record(outcome, detail)").unwrap();
    assert!(claim < transaction && transaction < prefix && prefix < completion);
    assert!(
        terminal.contains(
            "complete_wyr1_evidence_kernel_terminal(CompletionOutcome::Fail, 0x2510_ffff)"
        )
    );
    assert!(
        terminal
            .contains("complete_wyr1_evidence_kernel_terminal(CompletionOutcome::Fail, detail)")
    );
    assert!(
        terminal
            .contains("complete_wyr1_evidence_kernel_terminal(CompletionOutcome::Panic, detail)")
    );
}

#[test]
fn wyr1_reporter_enablement_requires_quiescence_after_root_retirement() {
    let primordial =
        fs::read_to_string(kernel_root().join("src/arch/x86_64/mm/activation/primordial.rs"))
            .expect("read primordial runtime");
    let start = primordial
        .find("fn enable_wyr1_reporter_after_retirement(")
        .expect("selector-25 reporter enablement");
    let end = primordial[start..]
        .find("\n    fn drain_finalizers(")
        .map(|offset| start + offset)
        .expect("selector-25 reporter enablement boundary");
    let enablement = &primordial[start..end];
    assert!(
        enablement.contains(
            ".process_quiescence_proof(self.primordial_process)\n                .is_err()"
        )
    );
    assert!(
        !enablement.contains(
            ".process_quiescence_proof(self.primordial_process)\n                .is_ok()"
        )
    );
    assert!(enablement.contains(".root_region(self.primordial_process)"));
    assert!(enablement.contains(".is_some()"));
    assert!(enablement.contains("process_lifecycle(reporter)"));
}

#[test]
fn wrcap_relay_is_selector_only_bounded_and_precedes_terminal_completion() {
    let build = fs::read_to_string(kernel_root().join("build.rs")).expect("read kernel build");
    let relay = fs::read_to_string(kernel_root().join("src/test_support/wrcap.rs"))
        .expect("read WRCAP1 relay");
    let support = fs::read_to_string(kernel_root().join("src/test_support/mod.rs"))
        .expect("read test-support boundary");
    let primordial =
        fs::read_to_string(kernel_root().join("src/arch/x86_64/mm/activation/primordial.rs"))
            .expect("read primordial runtime");
    let debug = fs::read_to_string(kernel_root().join("src/debug/tests.rs"))
        .expect("read COM1 ordering tests");
    let terminal = fs::read_to_string(kernel_root().join("src/test_support/x86_64.rs"))
        .expect("read terminal reporter");

    assert!(build.contains("cfg(deepwyrm_wrcap_relay)"));
    assert!(build.contains("selector == \"native-userspace-capability\""));
    assert!(support.contains(
        "DWEVID1, WRCAP1, WYR1EVID1, DWPRE1, and WRB1 terminal reporters are selector-exclusive"
    ));
    assert!(support.contains("#[cfg(any(test, deepwyrm_wrcap_relay))]\nmod wrcap;"));
    assert!(relay.contains("const WRCAP_RECORD_COUNT: usize = 15;"));
    assert!(relay.contains("const WRCAP_RECORD_KINDS: [u8; WRCAP_RECORD_COUNT]"));
    assert!(relay.contains("let expected_kind = WRCAP_RECORD_KINDS[transcript.seen];"));
    assert!(relay.contains("pub(crate) const WRCAP_RECORD_LEN: usize = 117;"));
    assert!(relay.contains("transcript.records[index].copy_from_slice(record)"));
    assert!(primordial.contains(
        "#[cfg(all(feature = \"test-support\", deepwyrm_wrcap_relay))]\n    fn drain_wrcap_record"
    ));
    assert_eq!(primordial.matches("self.drain_wrcap_record();").count(), 1);
    assert!(terminal.contains("WRCAP_RELAY.claim_reporter()"));
    assert!(terminal.contains("WRCAP1 reporter owns its serial transaction"));
    assert!(terminal.contains("wrcap_flush_failure(outcome, detail, error)"));
    assert!(terminal.contains("if outcome == CompletionOutcome::Pass"));
    assert!(terminal.contains("(outcome, detail)"));
    assert!(debug.contains("one_com1_transaction_orders_fifteen_wrcap_records_before_dwtest1"));
}

#[test]
fn guest_test_manifest_rejects_ambiguous_or_reserved_ids() {
    for malformed in [
        "schema_version = 2\n[guest_test.a]\nid = 1\nstate = \"implemented\"\n[guest_test.a]\nid = 2\nstate = \"implemented\"\n",
        "schema_version = 2\n[guest_test.a]\nid = 1\nstate = \"implemented\"\n[guest_test.b]\nid = 1\nstate = \"implemented\"\n",
        "schema_version = 2\n[guest_test.a]\nid = 0\nstate = \"implemented\"\n",
        "schema_version = 2\n[guest_test.a]\nid = 4294967296\nstate = \"implemented\"\n",
        "schema_version = 2\n[guest_test.a]\nid = 1\nid = 2\nstate = \"implemented\"\n",
        "schema_version = 2\n[guest_test.a]\nid = 1\nstate = \"invalid\"\n",
        "schema_version = 2\n[guest_test.a]\nid = 1\nstate = \"implemented\"\nstate = \"reserved\"\n",
        "schema_version = 2\n[guest_test.a]\n",
        "schema_version = 2\n[guest_test.a]\nname = \"a\"\n",
        "schema_version = 2\n[unknown.a]\nid = 1\nstate = \"implemented\"\n",
        "schema_version = 3\n[guest_test.a]\nid = 1\nstate = \"implemented\"\n",
        "schema_version = 2\n[guest_test.INVALID]\nid = 1\nstate = \"implemented\"\n",
    ] {
        assert!(
            kernel_build::select_guest_test(true, Some("a"), false, malformed).is_err(),
            "accepted malformed guest harness:\n{malformed}"
        );
    }
}

#[test]
fn entry_shim_switches_stacks_before_its_first_push() {
    let assembly = fs::read_to_string(entry_assembly_path()).expect("read entry assembly");
    let entry = assembly
        .split_once("_dw_kernel_entry:")
        .expect("entry label")
        .1;
    let cli = entry.find("cli").expect("cli");
    let cld = entry.find("cld").expect("cld");
    let stack_switch = entry
        .find("leaq __dw_boot_stack_top(%rip), %rsp")
        .expect("kernel stack switch");
    let call = entry
        .find("callq dw_kernel_rust_entry")
        .expect("System V Rust call");
    assert!(stack_switch < cli && cli < cld && cld < call);

    let before_stack_switch = &entry[..stack_switch];
    for forbidden in ["push", "pop", "call", "ret", "%rsp"] {
        assert!(
            !before_stack_switch.contains(forbidden),
            "`{forbidden}` used before the kernel-owned stack switch"
        );
    }
    assert!(entry[call..].contains("hlt"));
    assert!(assembly.contains(".skip DW_KERNEL_BOOT_STACK_SIZE"));
    assert!(assembly.contains(".balign DW_KERNEL_BOOT_STACK_ALIGNMENT"));

    let rust_entry = fs::read_to_string(entry_rust_path()).expect("read Rust entry boundary");
    assert!(rust_entry.contains("extern \"sysv64\" fn dw_kernel_rust_entry"));
    let normalize = rust_entry
        .find("normalize_dw0_c_cpu_state();")
        .expect("consumer-owned CPU normalization call");
    let kernel_main = rust_entry
        .find("crate::kernel_main(boot_info_physical)")
        .expect("kernel main call");
    assert!(normalize < kernel_main);
    for required in [
        "\"pushfq\"",
        "\"mov {scratch}, cr4\"",
        "\"btr {scratch}, 21\"",
        "\"mov cr4, {scratch}\"",
        "\"btr qword ptr [rsp], 18\"",
        "\"popfq\"",
    ] {
        assert!(
            rust_entry.contains(required),
            "entry normalization omitted `{required}`"
        );
    }
    assert_eq!(rust_entry.matches("\"pushfq\"").count(), 1);
    assert_eq!(rust_entry.matches("\"popfq\"").count(), 1);
    assert_eq!(rust_entry.matches("\"mov cr4, {scratch}\"").count(), 1);
    assert!(!rust_entry.contains("options(nomem"));
    assert!(rust_entry.contains("crate::kernel_main(boot_info_physical)"));
    assert!(rust_entry.contains("#[allow("));
    assert!(rust_entry.contains("unsafe_code,"));
}

#[test]
fn production_entry_dispatches_primordial_runtime_and_keeps_test_hooks_feature_gated() {
    let kernel = fs::read_to_string(kernel_root().join("src/lib.rs")).expect("read kernel root");
    assert!(kernel.contains("#[cfg(feature = \"test-support\")]\npub mod test_support;"));

    let gated_start = kernel
        .find("#[cfg(feature = \"test-support\")]\n        match test_support::BUILD_GUEST_TEST")
        .expect("test-support dispatcher has its local feature gate");
    let production_start = kernel[gated_start..]
        .find("#[cfg(not(feature = \"test-support\"))]\n        active_paging.run_primordial")
        .map(|offset| gated_start + offset)
        .expect("production primordial dispatcher follows the test-only dispatcher");
    let gated_dispatch = &kernel[gated_start..production_start];
    assert!(gated_dispatch.contains("test_support::run_memory_guest_test(active_paging)"));
    assert!(kernel.contains(
        "#[cfg(not(feature = \"test-support\"))]\n        active_paging.run_primordial(primordial_modules)"
    ));
    assert!(!kernel.contains("#[cfg(not(feature = \"test-support\"))]\n        loop {"));
}

#[test]
fn g3_primordial_mapping_failures_remain_recoverable_and_rollback_owned_candidates() {
    let primordial =
        fs::read_to_string(kernel_root().join("src/arch/x86_64/mm/activation/primordial.rs"))
            .expect("read G3 primordial runtime source");
    let user_access =
        fs::read_to_string(kernel_root().join("src/arch/x86_64/mm/activation/user_access.rs"))
            .expect("read G3 live user-access source");

    for forbidden in [
        "primordial map lacks a PDPT candidate",
        "primordial map lacks a PD candidate",
        "primordial map lacks a PT candidate",
        "primordial map publisher unavailable",
    ] {
        assert!(
            !primordial.contains(forbidden),
            "recoverable G3 map failure regressed to a panic: {forbidden}"
        );
    }
    assert!(primordial.contains(".map_err(|_| DW_STATUS_NO_RESOURCES)?"));
    assert!(primordial.contains(".map_err(|_| DW_STATUS_BAD_STATE)?"));
    assert!(
        primordial
            .matches("for candidate in candidates.into_iter().flatten()")
            .count()
            >= 2,
        "both primordial construction and syscall mapping paths must recycle unused candidates"
    );
    assert!(primordial.contains("cancel_zeroed(failure.into_grant())"));
    assert!(user_access.contains("cancel_zeroed(failure.into_grant())"));
    assert!(primordial.contains("const PRIMORDIAL_BOOTFS_MAX_PAGES: usize = 17;"));
    assert!(primordial.contains("deepwyrm_wyr1b_evidence"));
    assert!(
        primordial
            .contains("const PRIMORDIAL_BOOTFS_MAX_PAGES: usize = parse_wyr1b_bootfs_pages();")
    );
    assert!(
        primordial.contains(
            "#[cfg(all(deepwyrm_i2_stress, not(deepwyrm_wrcap_relay)))]\nconst PRIMORDIAL_BOOTFS_MAX_PAGES: usize = 32;"
        )
    );
    assert!(
        primordial.contains(
            "#[cfg(deepwyrm_wrcap_relay)]\nconst PRIMORDIAL_BOOTFS_MAX_PAGES: usize = 39;"
        )
    );
    assert!(primordial.contains(
        "#[cfg(deepwyrm_wyr1_evidence)]\nconst PRIMORDIAL_BOOTFS_MAX_PAGES: usize = 128;"
    ));
    assert!(primordial.contains(
        "#[cfg(deepwyrm_dw1b_evidence)]\nconst PRIMORDIAL_BOOTFS_MAX_PAGES: usize = parse_dw1b_bootfs_pages();"
    ));
    assert!(primordial.contains("const PRIMORDIAL_STACK_MAPPING_PAGES: usize ="));
    assert!(primordial.contains("const PRIMORDIAL_MAX_MAPPING_PAGES: usize ="));
    assert!(primordial.contains("if PRIMORDIAL_BOOTFS_MAX_PAGES > PRIMORDIAL_STACK_MAPPING_PAGES"));
    assert!(primordial.contains("PRIMORDIAL_MAX_MAPPING_PAGES + PRIMORDIAL_TABLE_CANDIDATES"));
    assert!(primordial.contains("PRIMORDIAL_INVALIDATIONS: usize = PRIMORDIAL_MAX_MAPPING_PAGES"));
}

#[test]
fn g5_primordial_blocking_uses_the_f12_idle_suspend_resume_flow() {
    let primordial =
        fs::read_to_string(kernel_root().join("src/arch/x86_64/mm/activation/primordial.rs"))
            .expect("read G5 primordial runtime source");

    assert!(primordial.contains("self.services.prepare_suspend_on("));
    assert!(primordial.contains("self.services.poll_idle_suspend_on("));
    assert!(primordial.contains("self.services.resume_suspended("));
    assert!(primordial.contains("bind_deadline_wake_target(target)"));
    assert!(!primordial.contains("primordial bootstrap blocked despite its prepublished INIT"));
    assert!(!primordial.contains("primordial bootstrap reached an unexpected idle suspension"));
    assert!(!primordial.contains("primordial bootstrap unexpectedly resumed a blocked syscall"));
}

#[test]
fn wyr1_bootfs_capacity_owns_the_page_ceiling_without_recursive_media_identity() {
    let primordial =
        fs::read_to_string(kernel_root().join("src/arch/x86_64/mm/activation/primordial.rs"))
            .expect("read primordial runtime source");
    assert!(primordial.contains("const PRIMORDIAL_BOOTFS_MAX_PAGES: usize = 128;"));
    assert!(primordial.contains("accepted WYR1-A inputs were 170,496 and 169,896 bytes"));
    assert!(primordial.contains("integrated WYR1-B regression inputs are 309,192 and 308,576"));
    assert!(primordial.contains("functional-first selector-local ceiling is 128"));
    assert!(primordial.contains("Deepwyrm owns this page ceiling and its rejection"));
    assert!(primordial.contains("hashes belong to receipt/root evidence"));
    assert!(primordial.contains("integration_bootfs_page_count(128 * 4096), Some(128)"));
    assert!(primordial.contains("integration_bootfs_page_count(128 * 4096 + 1), Some(129)"));
    assert!(primordial.contains("integration_bootfs_page_count(usize::MAX), None"));
    assert!(primordial.contains("Some(1..=PRIMORDIAL_BOOTFS_MAX_PAGES)"));
    assert!(primordial.contains("crate::test_support::complete_fail(0x2510_b001)"));
}

#[test]
fn g5_terminal_completion_drains_all_primordial_authority_before_capacity_proof() {
    let primordial =
        fs::read_to_string(kernel_root().join("src/arch/x86_64/mm/activation/primordial.rs"))
            .expect("read G5 primordial runtime source");
    let completion = fs::read_to_string(kernel_root().join("src/boot/primordial/construction.rs"))
        .expect("read primordial completion source");
    let primordial_unmap_start = primordial
        .find("fn unmap_primordial_userspace(")
        .expect("guarded primordial unmap helper");
    let current_unmap_start = primordial[primordial_unmap_start..]
        .find("fn unmap_current_userspace(")
        .map(|offset| primordial_unmap_start + offset)
        .expect("exact current-root unmap helper");
    let primordial_unmap = &primordial[primordial_unmap_start..current_unmap_start];
    for required in [
        "self.primordial_process",
        "self.primordial_root_key",
        "self.primordial_address_space",
        "self.unmap_current_userspace(",
    ] {
        assert!(
            primordial_unmap.contains(required),
            "primordial unmap wrapper omitted exact binding {required}"
        );
    }

    let inactive_unmap_start = primordial[current_unmap_start..]
        .find("fn unmap_inactive_userspace(")
        .map(|offset| current_unmap_start + offset)
        .expect("exact inactive-root unmap helper");
    let current_unmap = &primordial[current_unmap_start..inactive_unmap_start];
    for required in [
        "validate_current_process_root_selection(",
        "self.process != process",
        "self.root_key != root_key",
        ".current_process_address_space(",
        ".publisher::<",
        ".unmap(",
    ] {
        assert!(
            current_unmap.contains(required),
            "current-root unmap omitted guard {required}"
        );
    }
    assert!(!current_unmap.contains("LivePlatform {"));
    assert!(!current_unmap.contains("self.active.identity"));

    let terminal_start = primordial
        .find("fn finish_terminal_teardown(")
        .expect("terminal teardown helper");
    let terminal_end = primordial[terminal_start..]
        .find("impl<const RANGE_CAPACITY")
        .map(|offset| terminal_start + offset)
        .expect("terminal teardown implementation boundary");
    let terminal = &primordial[terminal_start..terminal_end];

    for required in [
        "process_quiescence_proof(self.process)",
        "blocked_operations_drained(&self.tasks, &proof)",
        "unmap_primordial_userspace(&proof)",
        "if self.process == self.primordial_process",
        "prepare_process_root_selection(",
        "self.primordial_address_space",
        "self.unmap_inactive_userspace(self.process, self.root_key, &proof)",
        "teardown_empty_child_address_space(self.process, address_space)",
        "retire_quiesced_root(",
        "release_terminal_authority()",
        "drain_finalizers()",
        "prove_registry_capacity()",
    ] {
        assert!(
            terminal.contains(required),
            "primordial terminal teardown omitted {required}"
        );
    }
    assert!(!terminal.contains("LivePlatform {"));
    let child_unmap = terminal
        .find("self.unmap_inactive_userspace(self.process, self.root_key, &proof)")
        .unwrap();
    let child_root_reclaim = terminal
        .find("teardown_empty_child_address_space(self.process, address_space)")
        .unwrap();
    let portable_root_retire = terminal.find("retire_quiesced_root(").unwrap();
    assert!(child_unmap < child_root_reclaim && child_root_reclaim < portable_root_retire);
    let observe = completion
        .find("let exit = backend.observe_exit();")
        .unwrap();
    let drain = completion
        .find("let quiescent = backend.verify_quiescent();")
        .unwrap();
    let disposition = completion.find("match disposition").unwrap();
    assert!(observe < drain && drain < disposition);
}

#[test]
fn i0_live_handle_capacity_covers_both_init_duplicates_before_three_moves() {
    fn claim(live: &mut usize, capacity: usize, count: usize) -> bool {
        let Some(next) = live.checked_add(count) else {
            return false;
        };
        if next > capacity {
            return false;
        }
        *live = next;
        true
    }

    fn move_out(live: &mut usize, count: usize) -> bool {
        let Some(next) = live.checked_sub(count) else {
            return false;
        };
        *live = next;
        true
    }

    fn occupancy_before_init_duplicates(capacity: usize) -> usize {
        let mut live = 0;
        for count in [4, 1, 2, 1] {
            assert!(claim(&mut live, capacity, count));
        }
        live
    }

    let primordial =
        fs::read_to_string(kernel_root().join("src/arch/x86_64/mm/activation/primordial.rs"))
            .expect("read I0 primordial runtime source");
    let normalized_primordial = primordial.split_whitespace().collect::<Vec<_>>().join(" ");
    for required in [
        "const INITIAL_BOOTSTRAP_HANDLES: usize = 4;",
        "const CHANNEL_CREATE_REDUCE_NET_HANDLES: usize = 1;",
        "const PROCESS_ROOT_HANDLES: usize = 2;",
        "const THREAD_HANDLES: usize = 1;",
        "const INIT_DUPLICATE_HANDLES: usize = 2;",
        "const INIT_MOVED_HANDLES: usize = 3;",
        "const HANDLES: usize = BOOTSTRAP_HANDLE_PEAK;",
        "const _: [(); 10] = [(); HANDLES];",
        "const HANDLES: usize = BOOTSTRAP_HANDLE_PEAK + 1;",
        "const _: [(); 11] = [(); HANDLES];",
        "const _: [(); 7] = [(); BOOTSTRAP_HANDLE_PEAK - INIT_MOVED_HANDLES];",
    ] {
        assert!(
            primordial.contains(required),
            "live handle-capacity contract omitted {required}"
        );
    }
    assert!(normalized_primordial.contains(
        "const BOOTSTRAP_HANDLE_PEAK: usize = INITIAL_BOOTSTRAP_HANDLES + \
         CHANNEL_CREATE_REDUCE_NET_HANDLES + PROCESS_ROOT_HANDLES + THREAD_HANDLES + \
         INIT_DUPLICATE_HANDLES;"
    ));

    let mut old_capacity = occupancy_before_init_duplicates(8);
    assert_eq!(old_capacity, 8);
    assert!(!claim(&mut old_capacity, 8, 1));
    assert_eq!(old_capacity, 8, "failed duplicate must not overclaim");

    let mut chosen_capacity = occupancy_before_init_duplicates(10);
    assert!(claim(&mut chosen_capacity, 10, 1));
    assert!(claim(&mut chosen_capacity, 10, 1));
    assert_eq!(chosen_capacity, 10);
    assert!(!claim(&mut chosen_capacity, 10, 1));
    assert_eq!(chosen_capacity, 10, "full table must not overclaim");
    assert!(move_out(&mut chosen_capacity, 3));
    assert_eq!(chosen_capacity, 7);
}

#[test]
fn e7_user_contract_uses_generated_syscall_veneer_and_generated_abi_values() {
    let source = fs::read_to_string(kernel_root().join("tests/userspace/e7_task_smoke.S"))
        .expect("read E7 userspace source");
    let veneer = fs::read_to_string(kernel_root().join("../abi/generated/syscall_veneer_x86_64.S"))
        .expect("read generated syscall veneer");
    let linker = fs::read_to_string(kernel_root().join("tests/userspace/e7_user.ld"))
        .expect("read E7 userspace linker script");

    assert!(source.contains("callq dw_syscall6"));
    assert!(
        !source
            .lines()
            .any(|line| line.trim_start().starts_with("syscall"))
    );
    assert!(veneer.contains(".globl dw_syscall6"));
    assert!(veneer.lines().any(|line| line.trim() == "syscall"));
    assert!(linker.contains("ENTRY(_start)"));
    assert!(linker.contains("FLAGS(5)"));
    assert!(!linker.contains("FLAGS(7)"));
    assert!(linker.contains("SIZEOF(.text) <= 4096"));

    assert_eq!(kernel_build::E7_USER_ENTRY, 0x4000_0000);
    assert_eq!(kernel_build::E7_USER_DATA, 0x4000_1000);
    assert_eq!(kernel_build::E7_USER_STACK_BOTTOM, 0x5000_0000);
    assert_eq!(kernel_build::E7_USER_STACK_TOP, 0x5000_1000);
    assert_eq!(
        kernel_build::E7_SYSCALL_ABI_GET_INFO,
        deepwyrm_abi::DW_SYSCALL_ABI_GET_INFO.0
    );
    assert_eq!(
        kernel_build::E7_SYSCALL_PROCESS_EXIT,
        deepwyrm_abi::DW_SYSCALL_PROCESS_EXIT.0
    );
    assert_eq!(
        kernel_build::E7_STATUS_NOT_SUPPORTED,
        deepwyrm_abi::DW_STATUS_NOT_SUPPORTED.0
    );
    assert_eq!(
        kernel_build::E7_ABI_INFO_SIZE,
        deepwyrm_abi::DW_ABI_INFO_V1_SIZE
    );
    assert_eq!(kernel_build::E7_ABI_VERSION, deepwyrm_abi::DW_ABI_VERSION);
    assert_eq!(kernel_build::E7_PAGE_SIZE, deepwyrm_abi::DW_BASE_PAGE_SIZE);
}

#[test]
fn kernel_assembler_disables_clang_default_configuration_discovery() {
    let build_script =
        fs::read_to_string(kernel_root().join("build.rs")).expect("read kernel build script");
    let assembler = build_script
        .split_once("pub(crate) fn assemble_source")
        .expect("assembler helper")
        .1
        .split_once("fn required_env")
        .expect("assembler helper terminator")
        .0;
    assert_eq!(
        assembler.matches(".arg(\"--no-default-config\")").count(),
        1
    );
    assert!(
        assembler.find(".arg(\"--no-default-config\")")
            < assembler.find("--target={KERNEL_TARGET}"),
        "Clang default configuration must be disabled before target selection"
    );
}

#[test]
fn linked_entry_and_rust_boundary_match_the_canonical_elf_policy() {
    let clang = env::var_os("DEEPWYRM_CLANG").unwrap_or_else(|| "clang".into());
    if !tool_available(&clang)
        || !tool_available(OsStr::new("rustc"))
        || !tool_available(OsStr::new("ld.lld"))
        || !tool_available(OsStr::new("llvm-nm"))
    {
        eprintln!("skipping x86_64 entry link probe: clang, rustc, ld.lld, or llvm-nm unavailable");
        return;
    }

    let source = fs::read_to_string(layout_path()).expect("read canonical layout manifest");
    let layout = kernel_build::Layout::parse(&source).expect("parse canonical layout manifest");
    let task_source = fs::read_to_string(task_layout_path()).expect("read E4 task layout manifest");
    let task_layout =
        kernel_build::TaskLayout::parse(&task_source).expect("parse E4 task layout manifest");
    let temporary = TemporaryDirectory::new("deepwyrm-x86_64-entry-contract");
    let entry_object = temporary.path.join("entry.o");
    let exceptions_object = temporary.path.join("exceptions.o");
    let ap_trampoline_object = temporary.path.join("ap-trampoline.o");
    let rust_object = temporary.path.join("rust-boundary.o");
    let section_object = temporary.path.join("section-probe.o");
    let kernel_elf = temporary.path.join("deepwyrm-kernel.elf");

    let rust_source = temporary.path.join("rust-boundary.rs");
    let entry_path = entry_rust_path();
    fs::write(
        &rust_source,
        format!(
            r#"#![no_std]
#![deny(unsafe_code)]

#[path = "{}"]
mod entry;

#[inline(never)]
fn kernel_main(_boot_info_physical: u64) -> ! {{
    loop {{ core::hint::spin_loop(); }}
}}

#[allow(unsafe_code, reason = "fixed symbol required by the audited exception assembly boundary")]
#[unsafe(no_mangle)]
extern "sysv64" fn dw_x86_64_exception_dispatch(
    _vector: u64,
    _error_code: u64,
    _frame: *const u64,
) -> ! {{
    loop {{ core::hint::spin_loop(); }}
}}

#[allow(unsafe_code, reason = "fixed symbol required by the audited returning timer assembly boundary")]
#[unsafe(no_mangle)]
extern "sysv64" fn dw_x86_64_timer_interrupt_dispatch() {{}}

#[allow(unsafe_code, reason = "fixed symbol required by the audited DW1-B CPL3 timer-return boundary")]
#[unsafe(no_mangle)]
extern "sysv64" fn dw_x86_64_timer_pre_iret_gate(_frame: *mut u64) {{}}

#[allow(unsafe_code, reason = "fixed symbol required by the audited terminal APIC assembly boundary")]
#[unsafe(no_mangle)]
extern "sysv64" fn dw_x86_64_terminal_interrupt_dispatch(_vector: u64) -> ! {{
    loop {{ core::hint::spin_loop(); }}
}}
"#,
            entry_path.display()
        ),
    )
    .expect("write Rust boundary probe");

    run_success(
        Command::new("rustc")
            .args([
                "--edition=2024",
                "--crate-type=lib",
                "--emit=obj",
                "-C",
                "panic=abort",
                "-C",
                "relocation-model=static",
                "-C",
                "code-model=kernel",
                "-C",
                "no-redzone=yes",
            ])
            .arg(&rust_source)
            .arg("-o")
            .arg(&rust_object),
        "compile the actual Rust entry boundary",
    );

    kernel_build::assemble_source(&entry_assembly_path(), &entry_object, layout)
        .expect("assemble the actual entry shim through the kernel build helper");
    kernel_build::assemble_source(&exceptions_assembly_path(), &exceptions_object, layout)
        .expect("assemble the actual exception stubs through the kernel build helper");
    kernel_build::assemble_source(
        &ap_trampoline_assembly_path(),
        &ap_trampoline_object,
        layout,
    )
    .expect("assemble the actual AP trampoline through the kernel build helper");

    let section_source = temporary.path.join("section-probe.S");
    fs::write(
        &section_source,
        r#".section .rodata,"a",@progbits
.globl dw_test_rodata_probe
dw_test_rodata_probe:
.quad 0x1122334455667788
.section .data,"aw",@progbits
.globl dw_test_data_probe
dw_test_data_probe:
.quad 0x8877665544332211
.section .bss,"aw",@nobits
.globl dw_test_bss_probe
dw_test_bss_probe:
.skip 64
.section .note.GNU-stack,"",@progbits
"#,
    )
    .expect("write section probe");
    run_success(
        Command::new(&clang)
            .arg("--no-default-config")
            .arg("--target=x86_64-unknown-none")
            .args(["-ffreestanding", "-fno-pic", "-c"])
            .arg(&section_source)
            .arg("-o")
            .arg(&section_object),
        "assemble the section-layout probe",
    );

    let link_arguments = kernel_build::linker_arguments(
        layout,
        task_layout,
        &linker_path(),
        &[
            entry_object.as_path(),
            exceptions_object.as_path(),
            ap_trampoline_object.as_path(),
        ],
    );
    run_success(
        Command::new("ld.lld")
            .args(["-m", "elf_x86_64"])
            .args(link_arguments)
            .args([
                "--undefined=dw_test_rodata_probe",
                "--undefined=dw_test_data_probe",
                "--undefined=dw_test_bss_probe",
            ])
            .arg(&rust_object)
            .arg(&section_object)
            .arg("-o")
            .arg(&kernel_elf),
        "link the entry artifact probe",
    );

    let elf = fs::read(&kernel_elf).expect("read linked ELF probe");
    validate_elf(&elf, layout);

    let symbols = run_success(
        Command::new("llvm-nm")
            .arg("--defined-only")
            .arg(&kernel_elf),
        "inspect retained entry symbols",
    );
    let symbols = String::from_utf8(symbols.stdout).expect("llvm-nm output is UTF-8");
    for symbol in [
        "_dw_kernel_entry",
        "dw_kernel_rust_entry",
        "dw_x86_64_exception_handler_table",
        "dw_x86_64_exception_vector_0",
        "dw_x86_64_exception_vector_31",
        "dw_x86_64_apic_timer_entry",
        "dw_x86_64_apic_error_entry",
        "dw_x86_64_apic_spurious_entry",
        "dw_x86_64_exception_dispatch",
        "dw_x86_64_timer_interrupt_dispatch",
        "dw_x86_64_terminal_interrupt_dispatch",
        "__dw_ist_region_start",
        "__dw_ist_region_end",
        "__dw_thread_kernel_stack_region_start",
        "__dw_thread_kernel_stack_region_end",
        "__dw_privilege_entry_stack_guard",
        "__dw_privilege_entry_stack_bottom",
        "__dw_privilege_entry_stack_top",
        "__dw_terminal_reaper_stack_guard",
        "__dw_terminal_reaper_stack_bottom",
        "__dw_terminal_reaper_stack_top",
        "__dw_double_fault_ist_guard",
        "__dw_double_fault_ist_bottom",
        "__dw_double_fault_ist_top",
        "__dw_nmi_ist_guard",
        "__dw_nmi_ist_bottom",
        "__dw_nmi_ist_top",
        "__dw_machine_check_ist_guard",
        "__dw_machine_check_ist_bottom",
        "__dw_machine_check_ist_top",
    ] {
        assert!(
            symbols.lines().any(|line| line.ends_with(symbol)),
            "missing retained symbol `{symbol}`"
        );
    }

    let symbol_addresses = symbols
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let address = u64::from_str_radix(fields.next()?, 16).ok()?;
            let _kind = fields.next()?;
            let name = fields.next()?;
            Some((name, address))
        })
        .collect::<BTreeMap<_, _>>();
    let address = |name: &str| {
        *symbol_addresses
            .get(name)
            .unwrap_or_else(|| panic!("missing address for `{name}`"))
    };
    let page = layout.base_page_size;
    let stacks = [
        (
            "__dw_double_fault_ist_guard",
            "__dw_double_fault_ist_bottom",
            "__dw_double_fault_ist_top",
        ),
        (
            "__dw_nmi_ist_guard",
            "__dw_nmi_ist_bottom",
            "__dw_nmi_ist_top",
        ),
        (
            "__dw_machine_check_ist_guard",
            "__dw_machine_check_ist_bottom",
            "__dw_machine_check_ist_top",
        ),
    ];
    for (guard, bottom, top) in stacks {
        assert_eq!(address(guard) % page, 0, "{guard} alignment");
        assert_eq!(address(bottom) - address(guard), page, "{guard} extent");
        assert_eq!(address(top) - address(bottom), 4 * page, "{top} extent");
    }
    assert_eq!(
        address("__dw_ist_region_start"),
        address("__dw_double_fault_ist_guard")
    );
    assert_eq!(
        address("__dw_double_fault_ist_top"),
        address("__dw_nmi_ist_guard")
    );
    assert_eq!(
        address("__dw_nmi_ist_top"),
        address("__dw_machine_check_ist_guard")
    );
    assert_eq!(
        address("__dw_ist_region_end") - address("__dw_ist_region_start"),
        15 * page
    );
}

fn validate_elf(bytes: &[u8], layout: kernel_build::Layout) {
    assert_eq!(&bytes[..4], b"\x7fELF");
    assert_eq!(bytes[4], 2, "ELFCLASS64");
    assert_eq!(bytes[5], 1, "ELFDATA2LSB");
    assert_eq!(u16_at(bytes, 16), 2, "ET_EXEC");
    assert_eq!(u16_at(bytes, 18), 62, "EM_X86_64");

    let entry = u64_at(bytes, 24);
    assert_eq!(entry, layout.link_base);
    let program_header_offset = usize::try_from(u64_at(bytes, 32)).expect("program header offset");
    let program_header_size = usize::from(u16_at(bytes, 54));
    let program_header_count = usize::from(u16_at(bytes, 56));
    assert_eq!(program_header_size, 56);

    let mut loads = Vec::new();
    for index in 0..program_header_count {
        let offset = program_header_offset + index * program_header_size;
        let header = ProgramHeader {
            kind: u32_at(bytes, offset),
            flags: u32_at(bytes, offset + 4),
            file_offset: u64_at(bytes, offset + 8),
            virtual_address: u64_at(bytes, offset + 16),
            file_size: u64_at(bytes, offset + 32),
            memory_size: u64_at(bytes, offset + 40),
            alignment: u64_at(bytes, offset + 48),
        };
        assert_eq!(header.kind, PT_LOAD, "only PT_LOAD is canonical");
        loads.push(header);
    }

    assert_eq!(loads.len(), 3);
    assert_eq!(
        loads.iter().map(|header| header.flags).collect::<Vec<_>>(),
        [PF_R | PF_X, PF_R, PF_R | PF_W]
    );
    for (index, header) in loads.iter().enumerate() {
        assert!(header.virtual_address >= 0xffff_8000_0000_0000);
        assert_eq!(header.alignment, layout.base_page_size);
        assert_eq!(
            header.file_offset % header.alignment,
            header.virtual_address % header.alignment
        );
        assert!(header.file_size <= header.memory_size);
        assert_ne!(header.flags & (PF_W | PF_X), PF_W | PF_X, "RWX PT_LOAD");
        let end = header
            .virtual_address
            .checked_add(header.memory_size)
            .expect("PT_LOAD range does not overflow");
        assert!(
            layout.temporary_virtual_address < header.virtual_address
                || layout.temporary_virtual_address >= end,
            "temporary mapping overlaps a PT_LOAD"
        );
        if let Some(next) = loads.get(index + 1) {
            assert!(end <= next.virtual_address, "overlapping PT_LOAD ranges");
        }
    }
    assert!(loads.iter().any(|header| {
        header.flags & PF_X != 0
            && entry >= header.virtual_address
            && entry < header.virtual_address + header.memory_size
    }));
}

#[derive(Clone, Copy)]
struct ProgramHeader {
    kind: u32,
    flags: u32,
    file_offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("u16 field"))
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32 field"))
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("u64 field"))
}

fn run_success(command: &mut Command, description: &str) -> Output {
    let output = command.output().unwrap_or_else(|error| {
        panic!("could not {description}: {error}");
    });
    assert!(
        output.status.success(),
        "could not {description}: status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn tool_available(program: &OsStr) -> bool {
    Command::new(program)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn kernel_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn layout_path() -> PathBuf {
    kernel_root().join("arch/x86_64/layout.toml")
}

fn task_layout_path() -> PathBuf {
    kernel_root().join("arch/x86_64/task_layout.toml")
}

fn linker_path() -> PathBuf {
    kernel_root().join("arch/x86_64/linker.ld")
}

fn guest_harness_path() -> PathBuf {
    kernel_root().join("../tooling/guest-harness.toml")
}

fn entry_assembly_path() -> PathBuf {
    kernel_root().join("src/arch/x86_64/entry.S")
}

fn entry_rust_path() -> PathBuf {
    kernel_root().join("src/arch/x86_64/entry.rs")
}

fn exceptions_assembly_path() -> PathBuf {
    kernel_root().join("src/arch/x86_64/exceptions.S")
}

fn ap_trampoline_assembly_path() -> PathBuf {
    kernel_root().join("src/arch/x86_64/ap_trampoline.S")
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let path = env::temp_dir().join(format!("{label}-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).expect("create test temporary directory");
        Self { path }
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
