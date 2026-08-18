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
fn e4_exception_assembly_copies_old_rsp_ss_only_for_cpl3() {
    let assembly = source("src/arch/x86_64/exceptions.S");
    let common = assembly
        .split_once(".Lexception_common:")
        .expect("exception common entry")
        .1
        .split_once("dw_x86_64_apic_error_entry:")
        .expect("exception common terminator")
        .0;
    assert!(common.contains("movq 32(%rsp), %rax"));
    assert!(common.contains("testb $3, %al"));
    assert!(common.contains("movq 56(%rsp), %rax"));
    assert!(common.contains("copied old SS"));
    assert!(common.contains("copied old RSP"));
    assert!(common.contains(".Lexception_kernel_origin:"));
}

#[test]
fn e4_exception_rust_requires_exact_kernel_or_user_selectors() {
    let rust = source("src/arch/x86_64/exceptions.rs");
    assert!(rust.contains("KERNEL_CODE_SELECTOR"));
    assert!(rust.contains("USER_CODE_SELECTOR"));
    assert!(rust.contains("USER_DATA_SELECTOR"));
    assert!(rust.contains("ExceptionOrigin::Kernel"));
    assert!(rust.contains("ExceptionOrigin::User"));
    assert!(rust.contains("dispatch_bound_user_exception(record)"));
    assert!(rust.contains("Self::NonMaskableInterrupt | Self::DoubleFault | Self::MachineCheck"));
    assert!(rust.contains("native_exception_type().unwrap_or(DW_EXCEPTION_NONE)"));
}

#[test]
fn cpl3_entry_requires_exception_runtime_binding() {
    let live = source("src/arch/x86_64/syscall/live.rs");
    let exceptions = source("src/arch/x86_64/exceptions.rs");
    assert!(
        live.contains("exception_binding: &crate::arch::x86_64::exceptions::UserExceptionBinding")
    );
    assert!(live.contains("user_exception_binding_is_current(exception_binding)"));
    assert!(exceptions.contains("bind_user_exception_handler"));
    assert!(exceptions.contains("compare_exchange("));
}

#[test]
fn e4_exception_assembly_remains_freestanding() {
    let clang = "/usr/lib/llvm/22/bin/clang-22";
    if Command::new(clang).arg("--version").output().is_err() {
        return;
    }
    let output =
        std::env::temp_dir().join(format!("deepwyrm-e4-exceptions-{}.o", std::process::id()));
    let status = Command::new(clang)
        .args([
            "--no-default-config",
            "--target=x86_64-unknown-none",
            "-ffreestanding",
            "-fno-pic",
            "-mno-red-zone",
            "-c",
        ])
        .arg(root().join("src/arch/x86_64/exceptions.S"))
        .arg("-o")
        .arg(&output)
        .status()
        .expect("run clang for E4 exception assembly");
    assert!(status.success());
    let _ = fs::remove_file(output);
}
