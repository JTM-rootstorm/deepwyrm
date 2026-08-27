use super::ist::validate_ist_stack_margin;
use super::*;

pub(crate) fn validate_selector_stack_margin(
    selector: &str,
    sizes: &[StackSize],
    disassembly: &str,
    boot_stack_bytes: usize,
) {
    const REQUIRED_SPARE_BYTES: usize = 32 * 1024;
    const ARCHITECTURAL_HEADROOM_BYTES: usize = 4 * 1024;
    const RETURN_ADDRESS_COUNT: usize = 32;
    const RETURN_ADDRESS_BYTES: usize = RETURN_ADDRESS_COUNT * size_of::<u64>();
    // Page-fault hardware pushes RIP, CS, RFLAGS, and the error word. The
    // vector stub and E4 common entry then retain 18 normalized words: saved
    // RAX, copied old RSP/SS, CR2, and the remaining GPRs. It may discard one
    // alignment word before calling Rust. Function-call return addresses
    // remain covered by RETURN_ADDRESS_BYTES above.
    const PAGE_FAULT_ENTRY_BYTES: usize = (4 + 1 + 18 + 1) * size_of::<u64>();

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

    let graph = DirectCallGraph::new(sizes, disassembly);
    let common_setup = graph.stack_bound("mapped-case common setup", |symbol| {
        symbol.ends_with(">::run_mapped_case::{closure#10}")
    });
    let selector_operation = graph.stack_bound(selector, |symbol| {
        symbol.ends_with(match selector {
            "memory-mapping" => ">::run_mapped_case::{closure#10}::{closure#1}",
            "memory-unmapping" => ">::run_mapped_case::{closure#10}::{closure#2}",
            "memory-permissions" => ">::run_mapped_case::{closure#10}::{closure#3}",
            "memory-invalid-pointer" => ">::run_mapped_case::{closure#10}::{closure#4}",
            "memory-user-kernel-isolation" => ">::run_mapped_case::{closure#10}::{closure#5}",
            "memory-shared-memory-object" => ">::run_mapped_case::{closure#10}::{closure#6}",
            _ => unreachable!("selector validated above"),
        })
    });
    let retained_bytes = audited_stack_path_bytes(&[&retained_runner])
        .expect("memory selector retained stack manifest is unique");
    let common_setup_chain = retained_bytes
        .checked_add(common_setup.bytes)
        .and_then(|bytes| bytes.checked_add(common_setup.call_count * size_of::<u64>()))
        .expect("memory common setup stack bound fits usize");
    let selector_operation_chain = retained_bytes
        .checked_add(mapped_case_closure)
        .and_then(|bytes| bytes.checked_add(selector_operation.bytes))
        .and_then(|bytes| bytes.checked_add(selector_operation.call_count * size_of::<u64>()))
        .expect("memory selector operation stack bound fits usize");
    let publication_chain = common_setup_chain.max(selector_operation_chain);

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
        total <= boot_stack_bytes,
        "{selector} target stack bound exceeds the boot stack: measured chain {measured_chain}, \
         return addresses {RETURN_ADDRESS_BYTES}, required architectural headroom \
         {ARCHITECTURAL_HEADROOM_BYTES}, total {total}, boot stack {boot_stack_bytes}"
    );
    assert!(
        boot_stack_bytes - total >= REQUIRED_SPARE_BYTES,
        "{selector} target stack bound leaves less than the required {REQUIRED_SPARE_BYTES}-byte \
         spare: total {total}, boot stack {boot_stack_bytes}"
    );
    eprintln!(
        "{selector} stack publication={publication_chain} normal-terminal={normal_terminal_chain} \
         fault-terminal={fault_terminal_chain} measured={measured_chain} \
         returns={RETURN_ADDRESS_BYTES} headroom={ARCHITECTURAL_HEADROOM_BYTES} \
         total={total} spare={}",
        boot_stack_bytes - total
    );
    validate_ist_stack_margin(selector, sizes, disassembly);
}
