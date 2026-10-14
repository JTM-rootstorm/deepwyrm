#[path = "support/host_tools.rs"]
mod host_tools;

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

/// Text test: the user-fault and invalid-return routing is target-only live wiring (live.rs, primordial.rs) that no host test compiles.
#[test]
fn g5_user_faults_and_invalid_returns_share_structured_terminal_reaper_handoff() {
    let live = source("src/arch/x86_64/syscall/live.rs");
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");

    assert!(live.contains("runtime.user_exception(record);"));
    assert!(live.contains("runtime.invalid_return(error);"));
    assert!(live.contains("handoff_to_terminal_reaper::<R>(context)"));
    assert!(live.contains("binding.user_exception_handler"));
    // S2K-3.1: the live exception path is the facade's remote-stop-aware
    // termination; the carrier's direct copy that called
    // `process_unhandled_exception_on` was never reached and is deleted.
    assert!(primordial.contains("crate::syscall::prepare_process_unhandled_exception("));
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
        .find("R::terminate_current(DivergentCarrier::from_mut(runtime))")
        .expect("reaper terminal reclaim");
    assert!(user_exception < terminate);
    assert!(reaper.contains("take_terminal_action()"));
}

/// Text test: the G5 completion oracle runs only on the target-only primordial terminal path.
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

    // The live terminal path: the facade's detached handoff and its helpers,
    // through `finish_primordial_terminal_handoff`.
    let terminate = primordial
        .split_once("fn prepare_terminal_retirement_state(")
        .expect("primordial terminal handoff")
        .1
        .split_once("fn reserve_runtime_phase")
        .expect("primordial terminal handoff extent")
        .0;
    let completion = terminate
        .find("let completion = complete_primordial_launch(self);")
        .expect("structured completion after reaper reclaim");
    let oracle = terminate
        .find("self.core.g5_probe.accepts_completion(&completion)")
        .expect("G5 post-completion oracle");
    assert!(completion < oracle);
}

#[test]
fn e4_exception_assembly_remains_freestanding() {
    let clang = host_tools::clang();
    let output =
        std::env::temp_dir().join(format!("deepwyrm-e4-exceptions-{}.o", std::process::id()));
    let status = Command::new(&clang)
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
fn every_user_entry_consumes_a_quantum_that_expires_during_arming() {
    let time = source("src/time/live.rs");
    let arm = time
        .split_once("pub(crate) fn arm_scheduler_quantum(")
        .unwrap()
        .1
        .split_once("pub(crate) fn cancel_scheduler_quantum(")
        .unwrap()
        .0;
    let publish = arm.find("publish_current_quantum_expiry(due)").unwrap();
    let return_expiry = arm.find("Ok(due.is_some())").unwrap();
    assert!(publish < return_expiry);

    let live = source("src/arch/x86_64/syscall/live.rs");
    for (start, end) in [
        (
            "unsafe fn native_runtime_timer_pre_iret",
            "pub(crate) unsafe extern \"sysv64\" fn dw_x86_64_timer_pre_iret_gate",
        ),
        (
            "fn service_syscall_return_preemption",
            "fn switch_kernel_context",
        ),
    ] {
        let gate = live.split_once(start).unwrap().1.split_once(end).unwrap().0;
        let retry = gate.find("loop {").unwrap();
        let consume = gate.find("runtime.prepare_preemption()").unwrap();
        let arm = gate
            .find("let expired_during_arm = arm_current_normal_quantum();")
            .unwrap();
        let done = gate.find("if !expired_during_arm {").unwrap();
        assert!(retry < consume && consume < arm && arm < done);
        assert!(gate[done..].contains("break;"));
        assert!(!gate[..done].contains("break;") && !gate.contains("return;"));
    }
    let assembly = source("src/arch/x86_64/syscall_entry.S");
    let initial = assembly
        .split_once("dw_x86_64_iret_to_user:")
        .unwrap()
        .1
        .split_once(".size dw_x86_64_iret_to_user")
        .unwrap()
        .0;
    // Text test: the order of assembly reads, the RSP pivot and pushes is invisible to Rust
    // types and host tests. The context may sit in the stack top the frame overwrites (the
    // first-run path keeps it there), so all 18 fields are read before the pivot and first push.
    let pivot = initial
        .find("movq %gs:E4_GS_CURRENT_STACK_TOP, %rsp")
        .unwrap();
    let before_pivot = &initial[..pivot];
    for field in [
        "R15",
        "R14",
        "R13",
        "R12",
        "RBP",
        "RBX",
        "R9",
        "R8",
        "R10",
        "RDX",
        "RSI",
        "RDI",
        "RAX",
        "RCX",
        "R11",
        "USER_RIP",
        "USER_RFLAGS",
        "USER_RSP",
    ] {
        assert_eq!(
            before_pivot
                .matches(&format!("E4_UR_{field}(%r12)"))
                .count(),
            1,
            "context field {field} must be read exactly once before the pivot"
        );
    }
    assert!(!before_pivot.contains("push") && !before_pivot.contains("(%rsp)"));
    assert!(
        !initial[pivot..].contains("E4_UR_"),
        "no context read after the pivot"
    );
    let source_read = initial.find("movq E4_UR_R12(%r12), %r12").unwrap();
    let iret_frame = initial.find("pushq $0x2b").unwrap();
    assert!(source_read < pivot && pivot < iret_frame);
    let iret_words: Vec<_> = initial[pivot..]
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pushq "))
        .take(5)
        .collect();
    assert_eq!(
        iret_words,
        [
            "$0x2b",
            "%gs:E4_GS_STAGED_USER_RSP",
            "%gs:E4_GS_STAGED_USER_RFLAGS",
            "$0x33",
            "%gs:E4_GS_STAGED_USER_RIP"
        ]
    );
    let frame = initial.find("pushq %rax").unwrap();
    let gate = initial.find("callq dw_x86_64_timer_pre_iret_gate").unwrap();
    let entry = initial.find("    iretq").unwrap();
    assert!(pivot < frame && frame < gate && gate < entry);
    let saved: Vec<_> = initial[frame..gate]
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pushq "))
        .collect();
    assert_eq!(
        saved,
        [
            "%rax", "%rbx", "%rcx", "%rdx", "%rsi", "%rdi", "%rbp", "%r8", "%r9", "%r10", "%r11",
            "%r12", "%r13", "%r14", "%r15"
        ]
    );
    let restored: Vec<_> = initial[gate..entry]
        .lines()
        .filter_map(|line| line.trim().strip_prefix("popq "))
        .collect();
    assert_eq!(restored, saved.into_iter().rev().collect::<Vec<_>>());
    assert_eq!(initial[..gate].matches("    pushq ").count(), 20);
    assert!(initial[gate..entry].contains("    swapgs"));
}

#[test]
fn quantum_clock_is_sampled_only_inside_synchronized_preparation() {
    let live = source("src/arch/x86_64/syscall/live.rs");
    let prepare = live
        .split_once("unsafe fn native_runtime_prepare_quantum<")
        .unwrap()
        .1
        .split_once("pub(crate) fn publish_current_quantum_expiry(")
        .unwrap()
        .0;
    assert!(prepare.contains(".prepare_quantum(|| crate::time::monotonic_now()"));
    let arm = live
        .split_once("fn arm_current_normal_quantum()")
        .unwrap()
        .1
        .split_once("fn poll_timer_return_stop")
        .unwrap()
        .0;
    assert!(!arm.contains("monotonic_now"));
    assert!(arm.contains("(binding.prepare_quantum_handler)(binding.context)"));

    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    let carrier = primordial.split_once("fn prepare_quantum(").unwrap().1;
    let carrier = carrier.split_once("fn has_reschedule_request").unwrap().0;
    assert!(carrier.contains("sample_now_ns: impl FnOnce() -> u64"));
    assert_eq!(carrier.matches("sample_now_ns()").count(), 1);
    let sample = carrier.find("let now_ns = sample_now_ns();").unwrap();
    let prepare = carrier
        .find(".prepare_quantum_if_needed_on(self.cpu, now_ns)")
        .unwrap();
    assert!(sample < prepare);
    let facade = primordial.rsplit_once("fn prepare_quantum(").unwrap().1;
    let facade = facade.split_once("fn has_reschedule_request").unwrap().0;
    assert!(!facade.contains("sample_now_ns()"));
    assert!(facade.contains(".with_synchronized_runtime_at_safe_point(|runtime| {"));
    assert!(facade.contains("runtime.prepare_quantum(sample_now_ns)"));
    let synchronized = primordial
        .split_once("fn with_synchronized_runtime_at_safe_point<T>(")
        .unwrap()
        .1
        .split_once("fn service_q35_retirement_at_bsp_safe_point")
        .unwrap()
        .0;
    assert!(
        synchronized
            .find("let mut runtime = guard.on(&mut self.owned);")
            .unwrap()
            < synchronized.find("Ok(operation(&mut runtime))").unwrap()
    );

    let execution = source("src/task/execution.rs");
    let prepare = execution
        .split_once("pub(crate) fn prepare_quantum_if_needed_on(")
        .unwrap()
        .1
        .split_once("pub(crate) fn publish_quantum_expiry(")
        .unwrap()
        .0;
    assert!(prepare.contains(".prepare_quantum_if_needed_on(cpu, now_ns)"));
    assert!(!prepare.contains("sample_now_ns"));

    let scheduler = source("src/task/scheduler.rs");
    let prepare = scheduler
        .split_once("pub(crate) fn prepare_quantum_if_needed_on(")
        .unwrap()
        .1
        .split_once("pub(crate) fn publish_quantum_expiry(")
        .unwrap()
        .0;
    let lock = prepare.find("let mut state = self.state.lock();").unwrap();
    let existing = prepare
        .find("if state.quantum[cpu.index()].is_some()")
        .unwrap();
    let mint = prepare
        .find("state.mint_quantum_on(cpu, claim, now_ns)")
        .unwrap();
    assert!(lock < existing && existing < mint);
    assert!(!prepare.contains("sample_now_ns"));
}

#[test]
fn dw1b_timer_return_validation_is_fail_closed_before_resume_or_rearm() {
    let live = source("src/arch/x86_64/syscall/live.rs");
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    // S2K-6: the per-CPU quantum-expiry publisher, not the facade, publishes under its own
    // runtime-authority handle.
    let expiry = primordial
        .split_once("crate::syscall::native::NativeQuantumExpiry\n    for QuantumExpiryPublisher")
        .expect("primordial quantum-expiry publisher")
        .1
        .split_once("\n}\n")
        .expect("primordial quantum-expiry publisher extent")
        .0;
    assert!(!expiry.contains("notify_completed_switch_runnable"));
    let runtime_lock = expiry.find("let guard = self.runtime.lock();").unwrap();
    let publish = expiry
        .find("guard.core.shared.execution.publish_quantum_expiry(ticket)")
        .unwrap();
    assert!(runtime_lock < publish);

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

/// Text test: the quantum and timer-return paths are target-only (live.rs, primordial.rs); no host test compiles them.
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
    let post_switch_stop = resume
        + service[resume..]
            .find("poll_timer_return_stop(*context)")
            .expect("post-switch Stop poll after physical handoff");
    let rearm = service
        .rfind("arm_current_normal_quantum()")
        .expect("selected execution quantum preparation");
    let post_rearm_stop = service
        .rfind("poll_timer_return_stop(*context)")
        .expect("post-switch Stop poll after physical handoff");
    assert!(
        stop < due
            && due < request
            && request < prepare
            && prepare < resume
            && resume < post_switch_stop
            && post_switch_stop < rearm
            && rearm < post_rearm_stop
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
        .split_once("\n    }\n")
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
        .split_once("fn finish_scheduler_root_switch_detached(")
        .expect("DW1-C2 detached physical cancellation extent")
        .0;
    let take = detached_cancel
        .find("take_local_scheduler_quantum_cancellation()")
        .expect("take exact transition ticket under runtime authority");
    let cancel = detached_cancel
        .find("cancel_scheduler_quantum_guard_free(ticket, self.runtime.guard_free())")
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
    assert!(clear.contains("let cancelled_quantum = self.quantum[cpu.index()].take()"));
    assert!(clear.contains("let published_expiry = self.need_resched[cpu.index()].take()"));
    assert!(clear.contains("cancelled_quantum.is_none() || published_expiry.is_none()"));
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

/// Every `asm!` block in `kernel/src`, as `(file, template, options)`.
fn kernel_asm_blocks() -> Vec<(String, String, String)> {
    fn visit(directory: &std::path::Path, blocks: &mut Vec<(String, String, String)>) {
        let mut entries: Vec<_> = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                visit(&path, blocks);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "rs") {
                continue;
            }
            let text = fs::read_to_string(&path).unwrap();
            let file = path
                .strip_prefix(root())
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let mut rest = text.as_str();
            while let Some(start) = rest.find("asm!(") {
                let body = &rest[start + "asm!(".len()..];
                let mut depth = 1_usize;
                let mut in_string = false;
                let mut end = body.len();
                for (index, character) in body.char_indices() {
                    match character {
                        '"' => in_string = !in_string,
                        '(' if !in_string => depth += 1,
                        ')' if !in_string => {
                            depth -= 1;
                            if depth == 0 {
                                end = index;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let block = &body[..end];
                let template = block
                    .split('"')
                    .skip(1)
                    .step_by(2)
                    .collect::<Vec<_>>()
                    .join("; ");
                let options = block
                    .split_once("options(")
                    .map_or("", |(_, options)| options.split(')').next().unwrap_or(""))
                    .to_owned();
                blocks.push((file.clone(), template, options));
                rest = &body[end..];
            }
        }
    }
    let mut blocks = Vec::new();
    visit(&root().join("src"), &mut blocks);
    blocks
}

/// Text test: whether an interrupt-flag change is a compiler memory barrier is an inline-asm
/// option, which no host test or type can observe.
///
/// Enabling or disabling interrupts orders the memory an interrupt handler shares with the
/// interrupted code, so such a block must not claim `nomem`. The only exception is a terminal
/// `cli; hlt`, after which no code runs. `KNOWN` lists sites outside the S2K lane that were
/// reported to the coordinator; each must still exist, so a fix forces its removal here.
#[test]
fn interrupt_flag_changes_are_compiler_barriers() {
    const KNOWN: [(&str, &str); 2] = [
        ("src/arch/x86_64/mod.rs", "cli"),
        ("src/arch/x86_64/power.rs", "sti; hlt"),
    ];
    let blocks = kernel_asm_blocks();
    let toggles_if = |template: &str| {
        template
            .split([';', '\n'])
            .any(|instruction| matches!(instruction.trim(), "sti" | "cli"))
    };
    let mut claimed = Vec::new();
    for (file, template, options) in &blocks {
        if !toggles_if(template) || !options.contains("nomem") {
            continue;
        }
        if template == "cli; hlt" {
            continue;
        }
        claimed.push((file.as_str(), template.as_str()));
    }
    let mut unexpected = claimed.clone();
    unexpected.retain(|site| !KNOWN.contains(site));
    assert!(
        unexpected.is_empty(),
        "interrupt-flag changes that claim `nomem`: {unexpected:?}"
    );
    for known in KNOWN {
        assert!(
            claimed.contains(&known),
            "{known:?} no longer claims `nomem`; remove it from KNOWN"
        );
    }
    assert!(
        blocks
            .iter()
            .any(|(file, template, _)| file == "src/time/live/probes.rs"
                && template == "sti; hlt; cli"),
        "the scan must see the probe's idle halt"
    );
    for template in ["pushfq; pop {}; cli", "sti"] {
        assert!(
            blocks
                .iter()
                .any(|(file, found, _)| file == "src/sync/irq.rs" && found == template),
            "the scan must see the IRQ lock's `{template}`"
        );
    }
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
