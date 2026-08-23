#[allow(dead_code)]
#[path = "../build.rs"]
mod kernel_build;

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn source(relative: &str) -> String {
    fs::read_to_string(root().join(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

#[test]
fn h2_h3_build_and_idt_own_exactly_the_reserved_fixed_ipi_entries() {
    let build = source("build.rs");
    for evidence in [
        "src/arch/x86_64/ipi_entry.S",
        "deepwyrm-x86_64-ipi-entry.o",
        "assemble_source(&ipi_entry_path, &ipi_entry_object, layout)?",
        "ipi_entry_object.as_path()",
    ] {
        assert!(
            build.contains(evidence),
            "IPI build path omitted `{evidence}`"
        );
    }

    let idt = source("src/arch/x86_64/idt.rs");
    for (vector, handler) in [
        ("SMP_RENDEZVOUS_VECTOR", "handlers.rendezvous_ipi"),
        ("TLB_SHOOTDOWN_VECTOR", "handlers.tlb_shootdown_ipi"),
    ] {
        let assignment = format!("entries[usize::from({vector})]");
        let start = idt.find(&assignment).expect("fixed IPI IDT assignment");
        let body = &idt[start..];
        let end = body.find(';').expect("fixed IPI IDT assignment end");
        let body = &body[..=end];
        assert!(body.contains("InterruptGate::kernel_interrupt"));
        assert!(body.contains(handler));
        assert!(body.contains("None, selector"));
    }
    assert!(idt.contains("const INTERRUPT_GATE_PRESENT_RING0: u8 = 0x8e"));
}

#[test]
fn h2_h3_ipi_entry_source_preserves_every_gpr_and_conditionally_normalizes_gs() {
    let assembly = source("src/arch/x86_64/ipi_entry.S");
    let body = assembly
        .split_once(".macro IPI_ENTRY")
        .expect("fixed IPI entry macro")
        .1
        .split_once(".endm")
        .expect("fixed IPI entry macro end")
        .0;
    for register in [
        "%rax", "%rbx", "%rcx", "%rdx", "%rsi", "%rdi", "%rbp", "%r8", "%r9", "%r10", "%r11",
        "%r12", "%r13", "%r14", "%r15",
    ] {
        assert!(
            body.contains(&format!("pushq {register}")),
            "fixed IPI entry omitted save {register}"
        );
        assert!(
            body.contains(&format!("popq {register}")),
            "fixed IPI entry omitted restore {register}"
        );
    }
    assert!(body.contains("movq 128(%rsp), %rax"));
    assert!(body.contains("testb $3, %al"));
    assert_eq!(body.matches("swapgs").count(), 2);
    assert!(body.contains("andq $-16, %rsp"));
    assert!(body.contains("callq \\dispatch"));
    assert!(body.contains("iretq"));
    assert!(assembly.contains(
        "IPI_ENTRY dw_x86_64_rendezvous_ipi_entry, dw_x86_64_rendezvous_ipi_dispatch, rendezvous_ipi"
    ));
    assert!(assembly.contains(
        "IPI_ENTRY dw_x86_64_tlb_shootdown_ipi_entry, dw_x86_64_tlb_shootdown_ipi_dispatch, tlb_shootdown_ipi"
    ));
}

#[test]
fn h2_h3_receive_seam_eois_before_capability_free_protocol_callbacks() {
    let ipi = source("src/arch/x86_64/ipi.rs");
    let dispatch = ipi
        .split_once("fn dispatch(vector: LiveIpiVector)")
        .expect("fixed IPI Rust dispatch")
        .1
        .split_once("dw_x86_64_rendezvous_ipi_dispatch")
        .expect("fixed IPI Rust dispatch end")
        .0;
    let eoi = dispatch.find("transport.eoi").expect("EOI trampoline call");
    let handler = dispatch
        .find("handlers.rendezvous")
        .expect("rendezvous callback");
    assert!(
        eoi < handler,
        "EOI must precede a possibly waiting stop callback"
    );
    assert!(dispatch.contains("halt_without_return()"));
    assert!(ipi.contains("rendezvous: fn()"));
    assert!(ipi.contains("tlb_shootdown: fn()"));
    for forbidden in [
        "crate::memory",
        "crate::syscall",
        "crate::task",
        "finalize_current",
        "schedule_current",
    ] {
        assert!(
            !ipi.contains(forbidden),
            "fixed IPI seam acquired forbidden authority `{forbidden}`"
        );
    }
}

#[test]
fn h2_h3_production_assembly_object_retains_both_exact_returning_entries() {
    let clang = env::var_os("DEEPWYRM_CLANG").unwrap_or_else(|| "clang".into());
    let objdump =
        env::var_os("DEEPWYRM_LLVM_OBJDUMP").unwrap_or_else(|| OsString::from("llvm-objdump"));
    if !tool_available(&clang) || !tool_available(&objdump) {
        eprintln!("skipping fixed IPI artifact probe: clang or llvm-objdump unavailable");
        return;
    }

    let layout_source = source("arch/x86_64/layout.toml");
    let layout = kernel_build::Layout::parse(&layout_source).expect("parse kernel layout");
    let object = env::temp_dir().join(format!("deepwyrm-h23-ipi-entry-{}.o", std::process::id()));
    kernel_build::assemble_source(&root().join("src/arch/x86_64/ipi_entry.S"), &object, layout)
        .expect("assemble fixed IPI entries through the production build helper");

    let output = Command::new(&objdump)
        .args(["-dr", "--no-show-raw-insn"])
        .arg(&object)
        .output()
        .expect("inspect fixed IPI object");
    assert!(output.status.success());
    let disassembly = String::from_utf8(output.stdout).expect("objdump output is UTF-8");
    for (entry, dispatch) in [
        (
            "dw_x86_64_rendezvous_ipi_entry",
            "dw_x86_64_rendezvous_ipi_dispatch",
        ),
        (
            "dw_x86_64_tlb_shootdown_ipi_entry",
            "dw_x86_64_tlb_shootdown_ipi_dispatch",
        ),
    ] {
        let body = function_body(&disassembly, entry);
        assert_eq!(body.matches("pushq").count(), 15);
        assert_eq!(body.matches("popq").count(), 15);
        assert_eq!(body.matches("swapgs").count(), 2);
        assert_eq!(body.matches("iretq").count(), 1);
        assert_eq!(body.matches(dispatch).count(), 2);
        assert!(body.contains("movq\t0x80(%rsp), %rax"));
        assert!(body.contains("testb\t$0x3, %al"));
    }
    let _ = fs::remove_file(object);
}

fn tool_available(program: &OsStr) -> bool {
    Command::new(program)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn function_body<'a>(disassembly: &'a str, symbol: &str) -> &'a str {
    let marker = format!("<{symbol}>:");
    let body = disassembly
        .split_once(&marker)
        .unwrap_or_else(|| panic!("missing disassembly for `{symbol}`"))
        .1;
    body.split_once("\n\n").map_or(body, |(body, _)| body)
}
