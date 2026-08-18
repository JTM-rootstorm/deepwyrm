use super::*;

pub(super) fn validate_ist_stack_margin(selector: &str, sizes: &[StackSize], disassembly: &str) {
    const IST_STACK_BYTES: usize = 16 * 1024;
    const REQUIRED_SPARE_BYTES: usize = 4 * 1024;
    // An IST transition retains old SS/RSP, RFLAGS, CS, and RIP. Hardware or
    // the vector stub then supplies two error/vector words, the common entry
    // retains sixteen GPR/CR2 words, stack alignment may consume 15 bytes,
    // and the explicit assembly-to-Rust call pushes one return address. Rust
    // call return addresses are derived below from the deepest enumerated
    // non-inlined path rather than represented by a fixed allowance.
    const IST_ENTRY_BYTES: usize = (5 + 2 + 18) * size_of::<u64>() + 15 + size_of::<u64>();

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

    let handler_prefix = [
        frame(
            "ist-exception-dispatch",
            exact("dw_x86_64_exception_dispatch"),
        ),
        frame(
            "ist-report-early-exception",
            contains_plain(
                "IST early exception report",
                "arch::x86_64::exceptions::report_early_exception::<",
            ),
        ),
        frame(
            "ist-serial-exception-reporter",
            suffix(
                "IST serial early exception reporter",
                " as deepwyrm_kernel::arch::x86_64::exceptions::EarlyExceptionReporter>::report_and_halt",
            ),
        ),
    ];
    let hardware_byte = suffix("IST COM1 hardware byte", ">::write_hardware_byte");
    let port_read = suffix(
        "IST COM1 port read",
        " as deepwyrm_kernel::debug::PortIo>::read_u8",
    );
    let output_guard = exact("<deepwyrm_kernel::debug::OutputGuard>::acquire");
    let panic_common = [
        frame(
            "ist-emit-early-panic-record",
            exact("deepwyrm_kernel::debug::emit_early_panic_record"),
        ),
        frame(
            "ist-emit-panic-record",
            contains_plain("IST panic record emission", "debug::emit_panic_record::<"),
        ),
        frame(
            "ist-render-panic-record",
            contains_plain(
                "IST panic record rendering",
                "debug::render_panic_record::<",
            ),
        ),
        frame("ist-panic-output-guard", output_guard),
    ];
    let panic_bounded_text = [
        frame(
            "ist-write-limited",
            contains_plain("IST bounded panic field", "debug::write_limited::<"),
        ),
        frame(
            "ist-com1-formatted-bytes",
            suffix("IST COM1 formatted bytes", ">::write_bytes"),
        ),
        frame("ist-com1-hardware-byte", hardware_byte),
        frame("ist-com1-port-read", port_read),
    ];
    let fmt_write = exact(
        "<deepwyrm_kernel::debug::Com1<deepwyrm_kernel::debug::X86PortIo> as core::fmt::Write>::write_fmt",
    );
    let fmt_spec = exact(
        "<&mut deepwyrm_kernel::debug::Com1<deepwyrm_kernel::debug::X86PortIo> as core::fmt::Write::write_fmt::SpecWriteFmt>::spec_write_fmt",
    );
    let fmt_write_str = exact(
        "<deepwyrm_kernel::debug::Com1<deepwyrm_kernel::debug::X86PortIo> as core::fmt::Write>::write_str",
    );
    let fmt_arguments = fixed_x86_64_stack_frame(
        disassembly,
        "<core::fmt::Arguments>::as_statically_known_str",
    );
    let fmt_core_write = fixed_x86_64_stack_frame(disassembly, "core::fmt::write");
    let fmt_display_u32 = fixed_x86_64_stack_frame(disassembly, "<u32 as core::fmt::Display>::fmt");
    let fmt_lower_hex_u64 =
        fixed_x86_64_stack_frame(disassembly, "<u64 as core::fmt::LowerHex>::fmt");
    let fmt_pad_integral =
        fixed_x86_64_stack_frame(disassembly, "<core::fmt::Formatter>::pad_integral");
    let fmt_write_prefix = fixed_x86_64_stack_frame(
        disassembly,
        "<core::fmt::Formatter>::pad_integral::write_prefix",
    );
    let fmt_padding_branch = ist_padding_branch(
        exact(
            "<deepwyrm_kernel::debug::Com1<deepwyrm_kernel::debug::X86PortIo> as core::fmt::Write>::write_char",
        ),
        exact("core::char::methods::encode_utf8_raw"),
        exact("core::slice::raw::from_raw_parts_mut::precondition_check"),
        exact("<*const ()>::is_aligned_to"),
    );
    let panic_optional_u32_argument = [
        frame(
            "ist-write-optional-u32-argument",
            contains_plain("IST optional u32 rendering", "debug::write_optional_u32::<"),
        ),
        frame(
            "ist-u32-display-argument",
            exact("<core::fmt::rt::Argument>::new_display::<u32>"),
        ),
    ];
    let panic_optional_u32 = [
        frame(
            "ist-write-optional-u32",
            contains_plain("IST optional u32 rendering", "debug::write_optional_u32::<"),
        ),
        frame("ist-com1-write-fmt-u32", fmt_write),
        frame("ist-com1-spec-write-fmt-u32", fmt_spec),
        frame("ist-fmt-arguments-u32", fmt_arguments),
        frame("ist-core-fmt-write-u32", fmt_core_write),
        frame("ist-u32-display", fmt_display_u32),
        frame("ist-u32-pad-integral", fmt_pad_integral),
        frame("ist-u32-write-prefix", fmt_write_prefix),
        frame("ist-com1-write-str-u32", fmt_write_str),
        frame(
            "ist-com1-formatted-u32-bytes",
            suffix("IST COM1 formatted u32 bytes", ">::write_bytes"),
        ),
        frame("ist-com1-u32-hardware-byte", hardware_byte),
        frame("ist-com1-u32-port-read", port_read),
    ];
    let panic_address_argument = [
        frame(
            "ist-write-address-argument",
            contains_plain("IST address rendering", "debug::write_address::<"),
        ),
        frame(
            "ist-u64-lower-hex-argument",
            exact("<core::fmt::rt::Argument>::new_lower_hex::<u64>"),
        ),
    ];
    let panic_address = [
        frame(
            "ist-write-address",
            contains_plain("IST address rendering", "debug::write_address::<"),
        ),
        frame("ist-com1-write-fmt-address", fmt_write),
        frame("ist-com1-spec-write-fmt-address", fmt_spec),
        frame("ist-fmt-arguments-address", fmt_arguments),
        frame("ist-core-fmt-write-address", fmt_core_write),
        frame("ist-u64-lower-hex", fmt_lower_hex_u64),
        frame("ist-address-pad-integral", fmt_pad_integral),
        frame("ist-address-write-prefix", fmt_write_prefix),
        frame("ist-com1-write-str-address", fmt_write_str),
        frame(
            "ist-com1-formatted-address-bytes",
            suffix("IST COM1 formatted address bytes", ">::write_bytes"),
        ),
        frame("ist-com1-address-hardware-byte", hardware_byte),
        frame("ist-com1-address-port-read", port_read),
    ];
    let panic_address_padding = [
        frame(
            "ist-write-address-padding",
            contains_plain("IST address rendering", "debug::write_address::<"),
        ),
        frame("ist-com1-write-fmt-address-padding", fmt_write),
        frame("ist-com1-spec-write-fmt-address-padding", fmt_spec),
        frame("ist-fmt-arguments-address-padding", fmt_arguments),
        frame("ist-core-fmt-write-address-padding", fmt_core_write),
        frame("ist-u64-lower-hex-padding", fmt_lower_hex_u64),
        frame("ist-address-pad-integral-padding", fmt_pad_integral),
    ];
    let completion_common = [
        frame(
            "ist-complete-exception",
            exact("deepwyrm_kernel::test_support::x86_64::complete_exception"),
        ),
        frame(
            "ist-exception-outcome",
            exact("deepwyrm_kernel::test_support::identity::exception_outcome"),
        ),
        frame(
            "ist-exception-outcome-for",
            exact("deepwyrm_kernel::test_support::identity::exception_outcome_for"),
        ),
        frame(
            "ist-complete-panic",
            exact("deepwyrm_kernel::test_support::x86_64::complete_panic"),
        ),
        frame(
            "ist-complete-known-outcome",
            exact("deepwyrm_kernel::test_support::x86_64::complete_known_outcome"),
        ),
        frame(
            "ist-completion-record",
            exact("deepwyrm_kernel::test_support::identity::completion_record"),
        ),
        frame(
            "ist-completion-transport",
            contains_plain(
                "IST terminal completion",
                "test_support::transport::complete::<",
            ),
        ),
        frame(
            "ist-emit-completion",
            contains_plain(
                "IST completion emission",
                "test_support::transport::emit_completion::<",
            ),
        ),
    ];
    let completion_encode_hex = [
        frame(
            "ist-completion-record-encode-hex",
            exact("<deepwyrm_kernel::test_support::protocol::CompletionRecord>::encode"),
        ),
        frame(
            "ist-completion-encode-hex",
            exact("deepwyrm_kernel::test_support::protocol::encode_hex"),
        ),
    ];
    let completion_checksum = [
        frame(
            "ist-completion-record-encode-checksum",
            exact("<deepwyrm_kernel::test_support::protocol::CompletionRecord>::encode"),
        ),
        frame(
            "ist-completion-checksum",
            exact("deepwyrm_kernel::test_support::protocol::fnv1a32"),
        ),
        frame(
            "ist-completion-checksum-fold",
            exact(
                "<core::slice::iter::Iter<u8> as core::iter::traits::iterator::Iterator>::fold::<u32, deepwyrm_kernel::test_support::protocol::fnv1a32::{closure#0}>",
            ),
        ),
        frame(
            "ist-completion-checksum-step",
            exact("deepwyrm_kernel::test_support::protocol::fnv1a32::{closure#0}"),
        ),
    ];
    let completion_serial = [
        frame(
            "ist-completion-serial-record",
            suffix(
                "IST QEMU completion serial write",
                " as deepwyrm_kernel::test_support::transport::CompletionTransport>::write_serial_record",
            ),
        ),
        frame(
            "ist-emit-early-raw-record",
            exact("deepwyrm_kernel::debug::emit_early_raw_record"),
        ),
        frame(
            "ist-bounded-raw-record",
            contains_plain(
                "IST bounded raw record",
                "debug::write_bounded_raw_record::<",
            ),
        ),
        frame("ist-completion-output-guard", output_guard),
        frame(
            "ist-com1-raw-bytes",
            suffix("IST COM1 raw bytes", ">::write_raw_bytes"),
        ),
        frame("ist-com1-hardware-byte", hardware_byte),
        frame("ist-com1-port-read", port_read),
    ];
    let completion_drain = [
        frame(
            "ist-completion-serial-record-drain",
            suffix(
                "IST QEMU completion serial write for drain",
                " as deepwyrm_kernel::test_support::transport::CompletionTransport>::write_serial_record",
            ),
        ),
        frame(
            "ist-emit-early-raw-record-drain",
            exact("deepwyrm_kernel::debug::emit_early_raw_record"),
        ),
        frame(
            "ist-bounded-raw-record-drain",
            contains_plain(
                "IST bounded raw record for drain",
                "debug::write_bounded_raw_record::<",
            ),
        ),
        frame("ist-completion-drain-output-guard", output_guard),
        frame(
            "ist-com1-drain",
            suffix(
                "IST COM1 transmitter drain",
                ">::wait_until_transmitter_drained",
            ),
        ),
        frame("ist-com1-drain-port-read", port_read),
    ];
    let completion_debug_exit = [
        frame(
            "ist-completion-debug-exit",
            suffix(
                "IST completion debug-exit branch",
                " as deepwyrm_kernel::test_support::transport::CompletionTransport>::write_debug_exit",
            ),
        ),
        frame(
            "ist-write-qemu-debug-exit",
            exact("deepwyrm_kernel::test_support::x86_64::write_qemu_debug_exit"),
        ),
    ];
    let completion_halt = [
        frame(
            "ist-completion-halt",
            suffix(
                "IST completion halt branch",
                " as deepwyrm_kernel::test_support::transport::CompletionTransport>::halt",
            ),
        ),
        frame(
            "ist-halt-after-completion",
            exact("deepwyrm_kernel::test_support::x86_64::halt_after_completion"),
        ),
    ];

    let audited = |segments: &[&[AuditedStackFrame]]| {
        audited_stack_path(segments).expect("IST terminal stack manifest is exact")
    };
    let panic_paths = [
        audited(&[&handler_prefix, &panic_common, &panic_bounded_text]),
        audited(&[&handler_prefix, &panic_common, &panic_optional_u32_argument]),
        audited(&[&handler_prefix, &panic_common, &panic_optional_u32]),
        audited(&[&handler_prefix, &panic_common, &panic_address_argument]),
        audited(&[&handler_prefix, &panic_common, &panic_address]),
        audited(&[
            &handler_prefix,
            &panic_common,
            &panic_address_padding,
            &fmt_padding_branch,
        ]),
    ];
    let completion_paths = [
        audited(&[&handler_prefix, &completion_common, &completion_encode_hex]),
        audited(&[&handler_prefix, &completion_common, &completion_checksum]),
        audited(&[&handler_prefix, &completion_common, &completion_serial]),
        audited(&[&handler_prefix, &completion_common, &completion_drain]),
        audited(&[&handler_prefix, &completion_common, &completion_debug_exit]),
        audited(&[&handler_prefix, &completion_common, &completion_halt]),
    ];
    let panic_bound = audited_stack_upper_bound(&panic_paths);
    let completion_bound = audited_stack_upper_bound(&completion_paths);
    let panic_bytes = panic_bound.bytes;
    let completion_bytes = completion_bound.bytes;
    let measured_chain = panic_bytes.max(completion_bytes);
    let max_frame_count = audited_stack_upper_bound(&[panic_bound, completion_bound]).frame_count;
    let return_address_bytes = max_frame_count * size_of::<u64>();
    let used = measured_chain + return_address_bytes + IST_ENTRY_BYTES;
    assert!(
        used + REQUIRED_SPARE_BYTES <= IST_STACK_BYTES,
        "{selector} IST stack bound exceeds 16 KiB: panic={panic_bytes} completion={completion_bytes} \
         entry={IST_ENTRY_BYTES} depth={max_frame_count} returns={return_address_bytes} \
         required-spare={REQUIRED_SPARE_BYTES}"
    );
    eprintln!(
        "{selector} IST stack panic={panic_bytes} completion={completion_bytes} \
         entry={IST_ENTRY_BYTES} depth={max_frame_count} returns={return_address_bytes} used={used} \
         required-spare={REQUIRED_SPARE_BYTES} spare={}",
        IST_STACK_BYTES - used
    );
}
