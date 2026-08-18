use super::*;

pub(crate) fn validate_production_ist_stack_margin(sizes: &[StackSize], disassembly: &str) {
    const IST_STACK_BYTES: usize = 16 * 1024;
    const REQUIRED_SPARE_BYTES: usize = 4 * 1024;
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
            "production-ist-exception-dispatch",
            exact("dw_x86_64_exception_dispatch"),
        ),
        frame(
            "production-ist-report-early-exception",
            contains_plain(
                "production IST early exception report",
                "arch::x86_64::exceptions::report_early_exception::<",
            ),
        ),
        frame(
            "production-ist-serial-exception-reporter",
            suffix(
                "production IST serial exception reporter",
                " as deepwyrm_kernel::arch::x86_64::exceptions::EarlyExceptionReporter>::report_and_halt",
            ),
        ),
    ];
    let hardware_byte = suffix(
        "production IST COM1 hardware byte",
        ">::write_hardware_byte",
    );
    let port_read = suffix(
        "production IST COM1 port read",
        " as deepwyrm_kernel::debug::PortIo>::read_u8",
    );
    let panic_common = [
        frame(
            "production-ist-emit-early-panic-record",
            exact("deepwyrm_kernel::debug::emit_early_panic_record"),
        ),
        frame(
            "production-ist-emit-panic-record",
            contains_plain(
                "production IST panic record emission",
                "debug::emit_panic_record::<",
            ),
        ),
        frame(
            "production-ist-render-panic-record",
            contains_plain(
                "production IST panic record rendering",
                "debug::render_panic_record::<",
            ),
        ),
        frame(
            "production-ist-panic-output-guard",
            exact("<deepwyrm_kernel::debug::OutputGuard>::acquire"),
        ),
    ];
    let bounded_text = [
        frame(
            "production-ist-write-limited",
            contains_plain(
                "production IST bounded panic field",
                "debug::write_limited::<",
            ),
        ),
        frame(
            "production-ist-com1-formatted-bytes",
            suffix("production IST COM1 formatted bytes", ">::write_bytes"),
        ),
        frame("production-ist-com1-hardware-byte", hardware_byte),
        frame("production-ist-com1-port-read", port_read),
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
    let optional_u32 = [
        frame(
            "production-ist-write-optional-u32",
            contains_plain(
                "production IST optional u32 rendering",
                "debug::write_optional_u32::<",
            ),
        ),
        frame("production-ist-com1-write-fmt-u32", fmt_write),
        frame("production-ist-com1-spec-write-fmt-u32", fmt_spec),
        frame("production-ist-fmt-arguments-u32", fmt_arguments),
        frame("production-ist-core-fmt-write-u32", fmt_core_write),
        frame(
            "production-ist-u32-display",
            fixed_x86_64_stack_frame(disassembly, "<u32 as core::fmt::Display>::fmt"),
        ),
        frame("production-ist-u32-pad-integral", fmt_pad_integral),
        frame("production-ist-u32-write-prefix", fmt_write_prefix),
        frame("production-ist-com1-write-str-u32", fmt_write_str),
        frame(
            "production-ist-com1-formatted-u32-bytes",
            suffix("production IST COM1 formatted u32 bytes", ">::write_bytes"),
        ),
        frame("production-ist-com1-u32-hardware-byte", hardware_byte),
        frame("production-ist-com1-u32-port-read", port_read),
    ];
    let address = [
        frame(
            "production-ist-write-address",
            contains_plain(
                "production IST address rendering",
                "debug::write_address::<",
            ),
        ),
        frame("production-ist-com1-write-fmt-address", fmt_write),
        frame("production-ist-com1-spec-write-fmt-address", fmt_spec),
        frame("production-ist-fmt-arguments-address", fmt_arguments),
        frame("production-ist-core-fmt-write-address", fmt_core_write),
        frame(
            "production-ist-u64-lower-hex",
            fixed_x86_64_stack_frame(disassembly, "<u64 as core::fmt::LowerHex>::fmt"),
        ),
        frame("production-ist-address-pad-integral", fmt_pad_integral),
        frame("production-ist-address-write-prefix", fmt_write_prefix),
        frame("production-ist-com1-write-str-address", fmt_write_str),
        frame(
            "production-ist-com1-formatted-address-bytes",
            suffix(
                "production IST COM1 formatted address bytes",
                ">::write_bytes",
            ),
        ),
        frame("production-ist-com1-address-hardware-byte", hardware_byte),
        frame("production-ist-com1-address-port-read", port_read),
    ];
    let address_padding = [
        frame(
            "production-ist-write-address-padding",
            contains_plain(
                "production IST address rendering",
                "debug::write_address::<",
            ),
        ),
        frame("production-ist-com1-write-fmt-address-padding", fmt_write),
        frame(
            "production-ist-com1-spec-write-fmt-address-padding",
            fmt_spec,
        ),
        frame(
            "production-ist-fmt-arguments-address-padding",
            fmt_arguments,
        ),
        frame(
            "production-ist-core-fmt-write-address-padding",
            fmt_core_write,
        ),
        frame(
            "production-ist-u64-lower-hex-padding",
            fixed_x86_64_stack_frame(disassembly, "<u64 as core::fmt::LowerHex>::fmt"),
        ),
        frame(
            "production-ist-address-pad-integral-padding",
            fmt_pad_integral,
        ),
    ];
    let halt = [frame(
        "production-ist-halt-forever",
        exact("deepwyrm_kernel::arch::x86_64::exceptions::halt_forever"),
    )];
    let audited = |segments: &[&[AuditedStackFrame]]| {
        audited_stack_path(segments).expect("production IST terminal stack manifest is exact")
    };
    let panic_paths = [
        audited(&[&handler_prefix, &panic_common, &bounded_text]),
        audited(&[&handler_prefix, &panic_common, &optional_u32]),
        audited(&[&handler_prefix, &panic_common, &address]),
        audited(&[
            &handler_prefix,
            &panic_common,
            &address_padding,
            &fmt_padding_branch,
        ]),
    ];
    let halt_path = audited(&[&handler_prefix, &halt]);
    let panic_bound = audited_stack_upper_bound(&panic_paths);
    let panic_bytes = panic_bound.bytes;
    let measured_chain = panic_bytes.max(halt_path.bytes);
    let max_frame_count = audited_stack_upper_bound(&[panic_bound, halt_path]).frame_count;
    let return_address_bytes = max_frame_count * size_of::<u64>();
    let used = measured_chain + return_address_bytes + IST_ENTRY_BYTES;
    assert!(
        used + REQUIRED_SPARE_BYTES <= IST_STACK_BYTES,
        "production IST stack bound exceeds 16 KiB: panic={panic_bytes} halt={} \
         entry={IST_ENTRY_BYTES} depth={max_frame_count} returns={return_address_bytes} \
         required-spare={REQUIRED_SPARE_BYTES}",
        halt_path.bytes
    );
    eprintln!(
        "production IST stack panic={panic_bytes} halt={} entry={IST_ENTRY_BYTES} \
         depth={max_frame_count} returns={return_address_bytes} used={used} \
         required-spare={REQUIRED_SPARE_BYTES} spare={}",
        halt_path.bytes,
        IST_STACK_BYTES - used
    );
}
