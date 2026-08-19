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
fn syscall_entry_swaps_to_kernel_gs_before_touching_user_rsp_or_gs_state() {
    let assembly = source("src/arch/x86_64/syscall_entry.S");
    let entry = assembly
        .split_once("dw_x86_64_syscall_entry:")
        .expect("syscall entry symbol")
        .1;
    let swap = entry.find("    swapgs").expect("entry SWAPGS");
    let first_gs = entry
        .find("movq %rsp, %gs:E4_GS_STAGED_USER_RSP")
        .expect("first trusted GS access");
    let switch = entry
        .find("movq %gs:E4_GS_ENTRY_STACK_TOP, %rsp")
        .expect("trusted GS stack switch");
    assert!(swap < first_gs && first_gs < switch);
    let before = &entry[..switch];
    assert!(before.contains("movq %rcx, %gs:E4_GS_STAGED_USER_RIP"));
    assert!(before.contains("movq %r11, %gs:E4_GS_STAGED_USER_RFLAGS"));
    assert!(!before.contains("pushq") && !before.contains("(%rsp)"));
}

#[test]
fn syscall_entry_uses_iretq_with_balanced_swapgs_and_no_sysret() {
    let assembly = source("src/arch/x86_64/syscall_entry.S");
    let lowered = assembly.to_ascii_lowercase();
    assert!(!lowered.contains("sysret"));
    assert_eq!(assembly.match_indices("    swapgs").count(), 3);
    assert_eq!(assembly.match_indices("    swapgs\n    iretq").count(), 2);
    assert!(assembly.match_indices("iretq").count() >= 2);
    assert!(assembly.contains("pushq $0x2b"));
    assert!(assembly.contains("pushq $0x33"));
    assert!(assembly.contains("xorl %ecx, %ecx"));
    assert!(assembly.contains("xorl %r11d, %r11d"));
}

#[test]
fn raw_frame_and_gs_offsets_are_source_locked() {
    let assembly = source("src/arch/x86_64/syscall_entry.S");
    for marker in [
        ".equ E4_GS_ENTRY_STACK_TOP,       0",
        ".equ E4_GS_CURRENT_STACK_TOP,     8",
        ".equ E4_GS_BINDING_GENERATION,   16",
        ".equ E4_GS_STAGED_USER_RSP,      24",
        ".equ E4_SC_USER_RIP,             104",
        ".equ E4_SC_BINDING_GENERATION,   128",
        ".equ E4_SC_RETURN_AUTHORIZED,    136",
        ".equ E4_SC_FRAME_SIZE,           144",
    ] {
        assert!(
            assembly.contains(marker),
            "missing assembly marker {marker}"
        );
    }
}

#[test]
fn msr_policy_matches_e0_and_return_requires_explicit_authorization() {
    let msr = source("src/arch/x86_64/syscall/msr.rs");
    let live = source("src/arch/x86_64/syscall/live.rs");
    let frame = source("src/arch/x86_64/syscall/frame.rs");
    let native = source("src/syscall/native.rs");
    assert!(msr.contains("pub(crate) const E4_FMASK: u64 = 0x001f_7700"));
    assert!(msr.contains("star: u64::from(KERNEL_CODE_SELECTOR.bits()) << 32"));
    assert!(msr.contains("gs_base: entry_state_base"));
    assert!(msr.contains("kernel_gs_base: 0"));
    assert!(msr.contains("CR4_FSGSBASE"));
    assert!(live.contains("CPUID_SYSCALL_SYSRET: u32 = 1 << 11"));
    assert!(live.contains("pub(crate) unsafe fn bind_syscall_runtime"));
    assert!(live.contains("pub(crate) unsafe fn bind_native_syscall_runtime"));
    assert!(live.contains("unsafe { dispatch_bound_runtime(frame) }"));
    assert!(live.contains("syscall_runtime_binding_is_current(syscall_binding)"));
    assert!(!live.contains("frame.set_status(DW_STATUS_NOT_SUPPORTED)"));
    assert!(!live.contains("authorize_return("));
    assert!(native.contains("pub(crate) fn dispatch_frame"));
    assert!(native.contains("runtime.authorize_return("));
    assert!(frame.contains("pub(crate) fn authorize_return"));
}

#[test]
fn e5_fp_simd_unavailable_policy_is_enforced_at_every_user_boundary() {
    let live = source("src/arch/x86_64/syscall/live.rs");
    let msr = source("src/arch/x86_64/syscall/msr.rs");
    let exceptions = source("src/arch/x86_64/exceptions.rs");

    assert!(msr.contains("CR0_TASK_SWITCHED"));
    assert!(msr.contains("cr0 | CR0_TASK_SWITCHED"));
    assert!(live.contains("enforce_live_fp_simd_unavailable()?"));
    assert!(live.contains("live_fp_simd_unavailable_is_enforced()"));
    assert!(
        live.match_indices("!live_fp_simd_unavailable_is_enforced()")
            .count()
            >= 3
    );
    assert!(exceptions.contains("ExceptionVector::DeviceNotAvailable"));
    assert!(exceptions.contains("ExceptionDisposition::UserFatal"));
}

#[test]
fn syscall_assembly_is_freestanding_and_calls_only_the_rust_dispatch() {
    let clang = "/usr/lib/llvm/22/bin/clang-22";
    if Command::new(clang).arg("--version").output().is_err() {
        return;
    }
    let output = std::env::temp_dir().join(format!("deepwyrm-e4-syscall-{}.o", std::process::id()));
    let status = Command::new(clang)
        .args([
            "--no-default-config",
            "--target=x86_64-unknown-none",
            "-ffreestanding",
            "-fno-pic",
            "-mno-red-zone",
            "-c",
        ])
        .arg(root().join("src/arch/x86_64/syscall_entry.S"))
        .arg("-o")
        .arg(&output)
        .status()
        .expect("run clang for E4 syscall assembly");
    assert!(status.success());
    let _ = fs::remove_file(output);
}

#[test]
fn production_installs_syscall_boundary_only_after_deep_root_activation() {
    let kernel = source("src/lib.rs");
    let activation = kernel
        .find("arch::x86_64::mm::activate_bootstrap_deep_paging(")
        .expect("Deep-owned paging activation");
    let install = kernel
        .find("arch::x86_64::syscall::install_syscall_boundary()")
        .expect("E4 syscall installation");
    assert!(activation < install);
}

#[test]
fn e5_live_user_pins_guard_actual_atomic_write_batches() {
    let access = source("src/arch/x86_64/mm/activation/user_access.rs");
    assert!(access.contains("self.target.pins"));
    assert!(access.contains("begin_mutation(start, end - start)"));
    assert!(access.contains(".apply(writes, invalidations)"));
    let reserve = access
        .find("begin_mutation(start, end - start)")
        .expect("E5 mutation reservation");
    let apply = access
        .find(".apply(writes, invalidations)")
        .expect("atomic live target apply");
    assert!(reserve < apply);
}

#[test]
fn e5_live_usercopy_exact_copy_is_bound_to_the_pinned_range() {
    let access = source("src/arch/x86_64/mm/activation/user_access.rs");

    assert!(access.contains("fn assert_exact_copy_range"));
    assert_eq!(
        access
            .match_indices("self.assert_exact_copy_range(range,")
            .count(),
        2
    );
    assert!(access.contains("range, self.range"));
    assert!(access.contains("Some(range.byte_len())"));
}

#[test]
fn e5_user_return_validation_is_bound_to_the_target_process() {
    let activation = source("src/arch/x86_64/mm/activation.rs");
    let access = source("src/arch/x86_64/mm/activation/user_access.rs");
    let adapters = source("src/syscall/adapters.rs");

    assert!(activation.contains("process: crate::task::ProcessKey"));
    assert!(activation.contains("process,"));
    assert!(access.contains("pub(super) process: crate::task::ProcessKey"));
    assert!(access.contains("ProcessUserReturnMappingValidation"));
    assert!(access.contains("self.process"));
    assert!(adapters.contains("mappings.process_key() != target_process"));
}

#[test]
fn e7_smoke_runtime_uses_live_e5_syscall_and_return_authority() {
    let runtime = source("src/arch/x86_64/mm/activation/test_support/e7.rs");
    let kernel = source("src/lib.rs");
    let build = source("build.rs");

    let user = source("tests/userspace/e7_task_smoke.S");
    assert!(user.contains("movw $0x2b, %ax"));
    assert!(user.contains("movw %ax, %gs"));

    for marker in [
        "current_process_address_space(self.process)",
        "crate::syscall::abi_get_info(",
        "crate::syscall::process_exit(",
        "Some(SchedulerThreadState::Running)",
        "frame.authorize_return(current_binding_generation, &mut mappings)",
        "bind_native_syscall_runtime(&raw mut runtime)",
        "ValidatedUserReturn::initial(context, &mut mappings)",
        "enter_validated_user(",
        "self.finish_task_release(thread_final)",
        "self.finish_task_release(process_final)",
        "self.finish_task_release(root_final)",
    ] {
        assert!(runtime.contains(marker), "E7 runtime omitted `{marker}`");
    }
    assert!(kernel.contains("test if test.is_task_userspace()"));
    let activation = kernel
        .find("activate_bootstrap_deep_paging(")
        .expect("Deep-owned paging activation");
    let task_dispatch = kernel
        .find("run_task_guest_test(active_paging)")
        .expect("E7 post-activation dispatch");
    assert!(activation < task_dispatch);
    assert!(build.contains("cargo:rustc-cfg=deepwyrm_e7_guest"));
}
