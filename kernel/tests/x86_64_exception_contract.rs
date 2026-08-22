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
fn g5_user_faults_and_invalid_returns_share_structured_terminal_reaper_handoff() {
    let live = source("src/arch/x86_64/syscall/live.rs");
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");

    assert!(live.contains("runtime.user_exception(record);"));
    assert!(live.contains("runtime.invalid_return(error);"));
    assert!(live.contains("handoff_to_terminal_reaper::<R>(context)"));
    assert!(live.contains("binding.user_exception_handler"));
    assert!(primordial.contains("process_unhandled_exception("));
    assert!(primordial.contains("bind_native_runtime_user_exception_handler()"));
    assert!(!primordial.contains("primordial userspace exception:"));
    assert!(!primordial.contains("invalid primordial userspace return:"));
}

#[test]
fn g5_primordial_selectors_have_exact_post_teardown_oracles() {
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");

    for evidence in [
        "G5PrimordialExpectation::BlockingCleanup",
        "FServiceOperationOwner::GenericWait",
        "FServiceOperationOwner::AtomicWait",
        "NativeSuspendPlan::IdleCurrent",
        "NativeIdleSuspendPoll::ResumeCurrent",
        "DW_STATUS_TIMED_OUT",
        "G5PrimordialExpectation::UserException",
        "DW_EXCEPTION_ILLEGAL_INSTRUCTION, 6",
        "G5PrimordialExpectation::InvalidReturn",
        "DW_EXCEPTION_GENERAL_PROTECTION, 1",
        "DW_TERMINATION_UNHANDLED_EXCEPTION",
        "PrimordialCompletionError::UnhandledException",
    ] {
        assert!(
            primordial.contains(evidence),
            "primordial G5 oracle omitted {evidence}"
        );
    }

    let terminate = primordial
        .split_once("fn terminate_current(&mut self) -> !")
        .expect("primordial terminal handoff")
        .1;
    let completion = terminate
        .find("let completion = complete_primordial_launch(self);")
        .expect("structured completion after reaper reclaim");
    let oracle = terminate
        .find("self.g5_probe.accepts_completion(&completion)")
        .expect("G5 post-completion oracle");
    assert!(completion < oracle);
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

#[test]
fn f3_timer_interrupt_is_returning_preserves_gprs_and_normalizes_user_gs() {
    let assembly = source("src/arch/x86_64/exceptions.S");
    let body = assembly
        .split_once("dw_x86_64_apic_timer_entry:")
        .expect("F3 timer entry")
        .1
        .split_once("dw_x86_64_apic_error_entry:")
        .expect("timer entry terminator")
        .0;
    for register in [
        "%rax", "%rbx", "%rcx", "%rdx", "%rsi", "%rdi", "%rbp", "%r8", "%r9", "%r10", "%r11",
        "%r12", "%r13", "%r14", "%r15",
    ] {
        assert!(
            body.contains(&format!("pushq {register}")),
            "timer entry omitted save {register}"
        );
        assert!(
            body.contains(&format!("popq {register}")),
            "timer entry omitted restore {register}"
        );
    }
    assert!(body.contains("movq 128(%rsp), %rax"));
    assert!(body.contains("testb $3, %al"));
    assert_eq!(body.match_indices("swapgs").count(), 2);
    assert!(body.contains("callq dw_x86_64_timer_interrupt_dispatch"));
    assert!(body.contains("iretq"));
    assert!(!body.contains("dw_x86_64_terminal_interrupt_dispatch"));
}

#[test]
fn f3_spurious_apic_interrupt_returns_without_eoi_or_rust_dispatch() {
    let assembly = source("src/arch/x86_64/exceptions.S");
    let body = assembly
        .split_once("dw_x86_64_apic_spurious_entry:")
        .expect("spurious entry")
        .1
        .split_once(".Lterminal_interrupt_common:")
        .expect("terminal common after spurious")
        .0;
    assert!(body.contains("iretq"));
    assert!(!body.contains("callq"));
    assert!(!body.contains("dw_x86_64_terminal_interrupt_dispatch"));
}

#[test]
fn f3_irq_lock_disables_interrupts_before_spin_ownership_and_restores_after_drop() {
    let irq = source("src/sync/irq.rs");
    let disable = irq
        .find("let interrupts_were_enabled = disable_and_save_interrupts();")
        .unwrap();
    let lock = irq.find("let inner = self.inner.lock();").unwrap();
    assert!(disable < lock);
    let release = irq.find("drop(self.inner.take());").unwrap();
    let restore = irq
        .find("restore_interrupts(self.interrupts_were_enabled);")
        .unwrap();
    assert!(release < restore);
    assert!(irq.contains("\"cli\""));
    assert!(irq.contains("\"sti\""));
}

#[test]
fn f3_lapic_leaf_is_supervisor_rw_nx_and_uncacheable() {
    let activation = source("src/arch/x86_64/mm/activation.rs");
    let apic_live = source("src/arch/x86_64/apic_live.rs");
    let time_live = source("src/time/live.rs");
    assert!(activation.contains("fn install_mmio_frame"));
    assert!(activation.contains("| WRITE_THROUGH"));
    assert!(activation.contains("| CACHE_DISABLE"));
    assert!(activation.contains("| NO_EXECUTE"));
    let method = activation.split_once("fn install_mmio_frame").unwrap().1;
    let method = method.split_once("fn validate_location").unwrap().0;
    assert!(!method.contains("| USER"));
    assert!(apic_live.contains("const IA32_PAT: u32 = 0x277"));
    assert!(apic_live.contains("((pat >> 24) as u8) == PAT_UNCACHEABLE"));
    assert!(time_live.contains("if !lapic_pat_entry_is_uncacheable()"));
}

#[test]
fn daybreak_time_init_faults_before_first_irreversible_effect_and_never_advertises_retry() {
    let live = source("src/time/live.rs");
    let prepare = live
        .find("let plan = match prepare_initialize(active)")
        .unwrap();
    let fault = live
        .find("TIME_STATE.store(TimeInitState::Faulted as u8, Ordering::Release);")
        .unwrap();
    let commit = live
        .find("let state = commit_initialize(active, pm_descriptor, plan)?;")
        .unwrap();
    assert!(prepare < fault && fault < commit);
    let commit_body = live.split_once("fn commit_initialize").unwrap().1;
    assert!(commit_body.contains("install_kernel_mmio_page(plan.frame)"));
    assert!(!commit_body.contains("TimeInitState::Uninitialized"));
    assert!(live.contains("TimeInitState::from_u8(observed) == Some(TimeInitState::Faulted)"));
}
