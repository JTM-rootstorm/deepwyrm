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
    let debug = source("src/debug/mod.rs");
    assert!(rust.contains("KERNEL_CODE_SELECTOR"));
    assert!(rust.contains("USER_CODE_SELECTOR"));
    assert!(rust.contains("USER_DATA_SELECTOR"));
    assert!(rust.contains("ExceptionOrigin::Kernel"));
    assert!(rust.contains("ExceptionOrigin::User"));
    assert!(rust.contains("dispatch_bound_user_exception(record)"));
    assert!(rust.contains("Self::NonMaskableInterrupt | Self::DoubleFault | Self::MachineCheck"));
    assert!(rust.contains("native_exception_type().unwrap_or(DW_EXCEPTION_NONE)"));
    assert!(debug.contains("current_cpu_id_for_diagnostics"));
    assert!(debug.contains("current_cpu_index_for_diagnostics"));
    assert!(debug.contains("record.cpu_id.or(current_cpu_id)"));
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
    assert!(primordial.contains("process_unhandled_exception_on("));
    assert!(primordial.contains("bind_native_runtime_user_exception_handler()"));
    assert!(!primordial.contains("primordial userspace exception:"));
    assert!(!primordial.contains("invalid primordial userspace return:"));
}

#[test]
fn h2_user_exception_stages_before_the_cpu_private_reaper_then_mutates_runtime() {
    let live = source("src/arch/x86_64/syscall/live.rs");

    let user_exception = live
        .split_once("unsafe fn native_runtime_user_exception")
        .expect("H2 user exception entry")
        .1
        .split_once("#[allow(\n    unsafe_code,\n    reason = \"the immutable runtime binding")
        .expect("H2 user exception entry extent")
        .0;
    assert!(
        user_exception.contains("stage_terminal_action(TerminalAction::UserException(record))")
    );
    assert!(user_exception.contains("handoff_to_terminal_reaper::<R>(context)"));
    assert!(
        !user_exception.contains("runtime.user_exception(record)"),
        "the exception entry must abandon the faulting stack before runtime mutation"
    );

    let reaper = live
        .split_once("unsafe extern \"sysv64\" fn native_runtime_terminal_reaper")
        .expect("H2 terminal reaper callback")
        .1
        .split_once("#[allow(\n    unsafe_code,\n    reason = \"the audited assembly boundary")
        .expect("H2 terminal reaper callback extent")
        .0;
    let user_exception = reaper
        .find("runtime.user_exception(record);")
        .expect("reaper delivers staged user exception");
    let terminate = reaper
        .find("runtime.terminate_current()")
        .expect("reaper terminal reclaim");
    assert!(user_exception < terminate);
    assert!(reaper.contains("take_terminal_action()"));
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
        .split_once("fn prepare_terminal_handoff(&mut self) -> PreparedTerminalHandoff")
        .expect("primordial terminal handoff")
        .1
        .split_once("fn reserve_runtime_phase")
        .expect("primordial terminal handoff extent")
        .0;
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
    assert!(body.contains("callq dw_x86_64_timer_pre_iret_gate"));
    assert!(body.contains("iretq"));
    assert!(!body.contains("dw_x86_64_terminal_interrupt_dispatch"));

    let user_origin = body
        .split_once("jz .Lapic_timer_kernel_origin")
        .expect("DW1-B CPL3 timer branch")
        .1
        .split_once(".Lapic_timer_kernel_origin:")
        .expect("DW1-B kernel-origin timer branch")
        .0;
    let dispatch = user_origin
        .find("callq dw_x86_64_timer_interrupt_dispatch")
        .expect("CPL3 timer dispatch");
    let thread_stack = user_origin
        .find("movq %gs:DW_GS_CURRENT_STACK_TOP, %rsp")
        .expect("bound Thread stack selection");
    let copy = user_origin
        .find("rep movsq")
        .expect("complete timer-frame copy");
    let gate = user_origin
        .find("callq dw_x86_64_timer_pre_iret_gate")
        .expect("CPL3 pre-IRET gate");
    let second_swapgs = user_origin.rfind("swapgs").expect("CPL3 return swapgs");
    assert!(dispatch < thread_stack && thread_stack < copy && copy < gate && gate < second_swapgs);
    assert!(user_origin.contains(
        "movq %r12, %rsi\n\
         \x20   movq %gs:DW_GS_CURRENT_STACK_TOP, %rsp\n\
         \x20   testq %rsp, %rsp\n\
         \x20   jz .Lapic_timer_entry_fail\n\
         \x20   subq $DW_TIMER_FRAME_SIZE, %rsp\n\
         \x20   movq %rsp, %rdi\n\
         \x20   movl $(DW_TIMER_FRAME_SIZE / 8), %ecx\n\
         \x20   cld\n\
         \x20   rep movsq\n\
         \x20   movq %rsp, %r12"
    ));

    let kernel_origin = body
        .split_once(".Lapic_timer_kernel_origin:")
        .expect("DW1-B kernel-origin timer branch")
        .1
        .split_once(".Lapic_timer_restore:")
        .expect("DW1-B timer restore")
        .0;
    assert!(kernel_origin.contains("callq dw_x86_64_timer_interrupt_dispatch"));
    assert!(!kernel_origin.contains("dw_x86_64_timer_pre_iret_gate"));
    assert!(!kernel_origin.contains("DW_GS_CURRENT_STACK_TOP"));
    assert!(!kernel_origin.contains("rep movsq"));

    for exact_offset in [
        ".equ DW_TIMER_FRAME_SIZE, 160",
        ".equ DW_TIMER_FRAME_R15, 0",
        ".equ DW_TIMER_FRAME_RAX, 112",
        ".equ DW_TIMER_FRAME_RIP, 120",
        ".equ DW_TIMER_FRAME_CS, 128",
        ".equ DW_TIMER_FRAME_RFLAGS, 136",
        ".equ DW_TIMER_FRAME_RSP, 144",
        ".equ DW_TIMER_FRAME_SS, 152",
        ".equ DW_GS_CURRENT_STACK_TOP, 8",
    ] {
        assert!(assembly.contains(exact_offset), "missing {exact_offset}");
    }
}

#[test]
fn dw1b_timer_return_validation_is_fail_closed_before_resume_or_rearm() {
    let live = source("src/arch/x86_64/syscall/live.rs");
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    let expiry = primordial
        .rsplit_once("fn publish_quantum_expiry(")
        .expect("live facade quantum-expiry publisher")
        .1
        .split_once("fn prepare_quantum(")
        .expect("live facade quantum-expiry publisher extent")
        .0;
    assert!(expiry.contains("runtime.switch_cpu(self.cpu);"));
    assert!(!expiry.contains("runtime.select_cpu(self.cpu);"));
    assert!(expiry.contains("runtime.publish_quantum_expiry(ticket)"));

    let gate = live
        .split_once("unsafe fn native_runtime_timer_pre_iret")
        .expect("DW1-B timer pre-IRET handler")
        .1
        .split_once("pub(crate) unsafe extern \"sysv64\" fn dw_x86_64_timer_pre_iret_gate")
        .expect("DW1-B timer pre-IRET handler extent")
        .0;
    let validate = gate
        .find("runtime.authorize_timer_return(frame)")
        .expect("validate interrupted CPL3 return frame");
    let stop = gate
        .find("poll_timer_return_stop(context)")
        .expect("remote Stop precedence poll");
    let boundary = gate
        .find("validate_live_syscall_boundary()")
        .expect("revalidate the exact current-CPU runtime binding");
    let prepare = gate
        .find("runtime.prepare_preemption()")
        .expect("prepare preemptive switch");
    let resume = gate
        .find("runtime.resume_timer_preemption(frame)")
        .expect("resume selected timer continuation");
    let post_switch_stop = gate[resume..]
        .find("poll_timer_return_stop(context)")
        .expect("post-switch Stop poll after physical handoff")
        + resume;
    let rearm = gate
        .find("arm_current_normal_quantum()")
        .expect("arm fresh selected-thread quantum");
    assert!(
        stop < validate
            && stop < boundary
            && boundary < validate
            && validate < prepare
            && prepare < resume
            && resume < post_switch_stop
            && post_switch_stop < rearm
    );
    assert!(gate.contains("poll_timer_return_stop(context)"));
    assert!(gate.contains("runtime.has_reschedule_request()"));

    let frame = source("src/arch/x86_64/syscall/frame.rs");
    assert!(frame.contains("pub(crate) struct RawCpl3TimerReturnFrame"));
    assert!(frame.contains("size_of::<RawCpl3TimerReturnFrame>() == 160"));
    assert!(frame.contains("self.cs != USER_CODE_SELECTOR"));
    assert!(frame.contains("self.ss != USER_DATA_SELECTOR"));
    assert!(frame.contains("sanitize_user_rflags(self.rflags)"));
}

#[test]
fn dw1b_syscall_return_accounts_due_budget_before_preemption_and_rearm() {
    let live = source("src/arch/x86_64/syscall/live.rs");
    let service = live
        .split_once("fn service_syscall_return_preemption")
        .expect("DW1-B syscall return preemption service")
        .1
        .split_once("fn switch_kernel_context")
        .expect("DW1-B syscall return preemption extent")
        .0;
    let stop = service
        .find("poll_timer_return_stop(*context)")
        .expect("remote Stop precedence poll");
    let due = service
        .find("service_current_scheduler_quantum_deadline()")
        .expect("IF-clear due-budget service");
    let request = service
        .find("runtime.has_reschedule_request()")
        .expect("exact scheduler request observation");
    let prepare = service
        .find("runtime.prepare_preemption()")
        .expect("normal preemption preparation");
    let resume = service
        .find("runtime.resume_syscall_preemption(frame)")
        .expect("acknowledged syscall continuation resume");
    let post_switch_stop = service
        .rfind("poll_timer_return_stop(*context)")
        .expect("post-switch Stop poll after physical handoff");
    let rearm = service
        .rfind("arm_current_normal_quantum()")
        .expect("selected execution quantum preparation");
    assert!(
        stop < due
            && due < request
            && request < prepare
            && prepare < resume
            && resume < post_switch_stop
            && post_switch_stop < rearm
    );
    let switched = service
        .split_once("switch_kernel_context(plan)")
        .expect("syscall-return physical switch")
        .1;
    assert!(!switched.contains("frame.rebind_after_kernel_resume"));

    let arm = live
        .split_once("fn arm_current_normal_quantum()")
        .expect("DW1-B normal quantum helper")
        .1
        .split_once("fn poll_timer_return_stop")
        .expect("DW1-B normal quantum helper extent")
        .0;
    assert!(arm.contains("if let Some(ticket)"));
    assert!(arm.contains("arm_scheduler_quantum(ticket)"));
    assert!(!arm.contains("CpuIndex::BOOTSTRAP"));

    let scheduler = source("src/task/scheduler.rs");
    assert!(scheduler.contains("next_quantum_generation: [u64; H2_SCHEDULER_CPU_CAPACITY]"));
    assert!(scheduler.contains("self.next_quantum_generation[cpu.index()]"));

    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    let authorize = primordial
        .split_once("fn authorize_timer_return(")
        .expect("DW1-C2 timer-return authorization")
        .1
        .split_once("unsafe fn prepare_preemption")
        .expect("DW1-C2 timer-return authorization extent")
        .0;
    assert!(!authorize.contains("CpuIndex::BOOTSTRAP"));

    let adapters = source("src/syscall/adapters.rs");
    assert!(adapters.contains("pending_quantum_cancellation"));
    assert!(adapters.contains("state.cancelled_quantum()"));
    assert!(
        primordial.contains("self.stage_local_scheduler_quantum_cancellation(cancelled_quantum)")
    );
    assert!(primordial.contains("deferred.cancelled_quantum()"));
    assert!(primordial.contains("crate::time::cancel_scheduler_quantum(ticket)"));
    assert!(primordial.contains("stop_running_claim_on(claim)"));

    let detached_cancel = primordial
        .split_once("fn drain_quantum_cancellation_detached(&mut self)")
        .expect("DW1-C2 detached physical cancellation")
        .1
        .split_once("fn synchronize_scheduler_current_detached")
        .expect("DW1-C2 detached physical cancellation extent")
        .0;
    let take = detached_cancel
        .find("take_local_scheduler_quantum_cancellation()")
        .expect("take exact transition ticket under runtime authority");
    let cancel = detached_cancel
        .find("crate::time::cancel_scheduler_quantum(ticket)")
        .expect("cancel exact physical source without runtime authority");
    let commit = detached_cancel
        .find("runtime.commit_local_scheduler_quantum_cancellation(ticket)")
        .expect("revalidate cancellation under runtime authority");
    assert!(take < cancel && cancel < commit);

    let suspend = primordial
        .rsplit_once("unsafe fn prepare_suspend<'owner>(")
        .expect("runtime facade suspend path")
        .1
        .split_once("unsafe fn poll_idle_suspend")
        .expect("runtime facade suspend path extent")
        .0;
    let unlock = suspend
        .find("};")
        .expect("runtime authority lock scope ends");
    let drain = suspend
        .find("self.drain_quantum_cancellation_detached()")
        .expect("suspend drains exact quantum after lock release");
    assert!(unlock < drain);

    let time = source("src/time/live.rs");
    let monotonic = time
        .split_once("pub(crate) fn monotonic_now()")
        .expect("DW1-C2 monotonic sample path")
        .1
        .split_once("pub(crate) fn timer_service_is_healthy")
        .expect("DW1-C2 monotonic sample path extent")
        .0;
    assert!(monotonic.contains("installed_current_cpu_index()? == CpuIndex::BOOTSTRAP"));
    assert!(monotonic.contains("BSP_TIMER_SERVICE"));
    assert!(monotonic.contains("sample_clock_now()?"));

    let clear = scheduler
        .split_once("fn clear_preemption_on(")
        .expect("DW1-C2 exact quantum transition cancellation")
        .1
        .split_once("fn mint_quantum_on(")
        .expect("DW1-C2 exact quantum transition cancellation extent")
        .0;
    assert!(clear.contains("let cancelled = self.quantum[cpu.index()].take()"));
    assert!(clear.contains("cancelled"));
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
        .find("let committed = commit_initialize(active, pm_descriptor, plan)?;")
        .unwrap();
    assert!(prepare < fault && fault < commit);
    let commit_body = live.split_once("fn commit_initialize").unwrap().1;
    assert!(commit_body.contains("install_kernel_mmio_page(plan.frame)"));
    assert!(!commit_body.contains("TimeInitState::Uninitialized"));
    assert!(live.contains("TimeInitState::from_u8(observed) == Some(TimeInitState::Faulted)"));
}
