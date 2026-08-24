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
        ".equ E4_GS_TERMINAL_REAPER_TOP,  48",
        ".equ E4_GS_CPU_INDEX,            56",
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
    assert!(live.contains("unsafe fn publish_syscall_runtime"));
    assert!(!live.contains("pub(crate) unsafe fn bind_syscall_runtime"));
    assert!(live.contains("Pin<&'runtime mut R>"));
    assert!(live.contains("pub(crate) unsafe fn enter_native_syscall_runtime"));
    assert!(live.contains("struct NativeSyscallRuntimeEntry<"));
    assert!(!live.contains("struct SyscallRuntimeBinding"));
    assert!(!live.contains("fn bind_native_syscall_runtime"));
    assert!(live.contains("unsafe { dispatch_bound_runtime(frame) }"));
    assert!(!live.contains("syscall_runtime_binding_is_current"));
    assert!(!live.contains("frame.set_status(DW_STATUS_NOT_SUPPORTED)"));
    assert!(!live.contains("frame.authorize_return("));
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
fn i1_bsp_scratch_is_usable_for_acpi_and_mmio_before_syscall_install() {
    let kernel = source("src/lib.rs");
    let activation = kernel
        .find("activate_bootstrap_deep_paging(")
        .expect("Deep root activation");
    let acpi = kernel
        .find("AcpiScratchReader::new(&mut active_paging, &boot_info)")
        .expect("post-activation ACPI scratch reader");
    let mmio = kernel
        .find("time::initialize(&mut active_paging, pm_timer)")
        .expect("post-activation MMIO scratch use");
    let syscall = kernel
        .find("arch::x86_64::syscall::install_syscall_boundary()")
        .expect("later SYSCALL install");
    assert!(activation < acpi && acpi < mmio && mmio < syscall);
}

#[test]
fn i1_native_adapter_phases_revalidate_exact_identity_after_guard_free_work() {
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    let stationary = source("src/arch/x86_64/syscall/stationary_runtime.rs");

    assert!(stationary.contains("struct RuntimePhaseReservation"));
    assert!(stationary.contains("pub(crate) fn revalidate("));
    assert!(stationary.contains("pub(crate) fn abort(self)"));
    assert!(primordial.contains("prepare_address_region_mutation("));
    assert!(primordial.contains("address_region_map_prepared_model("));
    assert!(primordial.contains("address_region_unmap_prepared("));
    let services = source("src/syscall/f_services.rs");
    assert!(services.contains("struct PreparedFServiceDispatch"));
    assert!(services.contains("fn dispatch_prepared<"));
    assert!(
        services.contains("prepared\n            .begin(current_thread, current_root_generation)")
    );
    assert!(!services.contains("struct FServiceDispatchCommit"));
    assert!(services.contains("The enclosing native runtime phase owns the only"));
    assert!(primordial.contains(".prepare_dispatch(request, self.thread, root_generation)"));
    assert!(primordial.contains("self.services.dispatch_prepared("));
    assert!(primordial.contains("let phase = self.reserve_runtime_phase();"));
    assert!(primordial.contains("self.assert_guard_free_external_work();"));
    assert!(primordial.contains("self.commit_runtime_phase(phase);"));

    let handle = primordial
        .split_once("fn handle(&mut self, request: NativeSyscallRequest)")
        .expect("native handler")
        .1;
    let reserve = handle
        .find("let phase = self.reserve_runtime_phase();")
        .unwrap();
    let guard_free = handle
        .find("self.assert_guard_free_external_work();")
        .unwrap();
    let commit = handle.find("self.commit_runtime_phase(phase);").unwrap();
    assert!(reserve < guard_free && guard_free < commit);

    for adapter in ["fn map_memory(", "fn unmap_memory(", "fn exit_process("] {
        let adapter = primordial.split_once(adapter).expect("staged adapter").1;
        let reserve = adapter
            .find("let phase = self.reserve_runtime_phase();")
            .unwrap();
        let guard_free = adapter
            .find("self.assert_guard_free_external_work();")
            .unwrap();
        let commit = adapter.find("self.commit_runtime_phase(phase);").unwrap();
        assert!(reserve < guard_free && guard_free < commit, "{adapter}");
    }

    for external_boundary in ["fn precommit_exact_stop(", "fn rendezvous_stop("] {
        let boundary = primordial
            .split_once(external_boundary)
            .expect("guard-free divergent boundary")
            .1;
        assert!(boundary.contains("self.assert_guard_free_external_work();"));
    }
}

#[test]
fn i1_post_ack_carrier_never_reuses_a_retired_frame_for_late_holdsafe() {
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    let continuation = primordial
        .split_once("fn prepare_after_rendezvous_stop(&mut self) -> PreparedCarrierEntry")
        .expect("post-ack carrier continuation")
        .1
        .split_once("fn terminate_exception")
        .expect("post-ack carrier continuation end")
        .0;
    assert!(continuation.contains("complete_switch_on(stopped_claim)"));
    assert!(continuation.contains("self.drain_staged_rendezvous_cleanup();"));
    assert!(continuation.contains("terminal_reaper_next_on(self.cpu)"));

    let idle = primordial
        .split_once("fn enter_idle_scheduler(&mut self) -> !")
        .expect("kernel-root idle path")
        .1
        .split_once("unsafe fn prepare_suspend")
        .expect("kernel-root idle path end")
        .0;
    assert!(idle.contains("MailboxNotification::HoldSafe(_) => {}"));
    assert!(idle.contains("service_current_rendezvous_latch()"));
    assert!(idle.contains("kernel-root idle carrier received an unexpected stop request"));
    let rescan = idle
        .split_once("IdleWakeError::RescanRequired")
        .expect("kernel-root idle rescan path")
        .1;
    assert!(rescan.contains("cancel_current_idle("));
    assert!(rescan.contains("service_current_rendezvous_latch()"));

    let precommit = primordial
        .split_once("fn precommit_exact_stop(")
        .expect("remote-stop precommit")
        .1;
    let stage = precommit
        .find("self.stage_rendezvous_cleanup();")
        .expect("cleanup staging");
    let consume_reaper = precommit
        .find("self\n            .rendezvous_reaper\n            .take()")
        .expect("irreversible reaper witness consume");
    assert!(stage < consume_reaper);
    let finalizers = primordial
        .split_once("fn drain_finalizers(&mut self)")
        .expect("post-ack finalizer drain")
        .1
        .split_once("fn prove_registry_capacity")
        .expect("finalizer drain extent")
        .0;
    assert!(finalizers.contains("while !self.cleanup.is_empty()"));
    assert!(finalizers.contains("crate::syscall::complete_wait_wakes("));
}

#[test]
fn i1_remote_termination_waits_guard_free_for_exact_ack_before_reclaim() {
    let live = source("src/arch/x86_64/syscall/live.rs");
    let trampoline = live
        .split_once("unsafe fn native_runtime_trampoline")
        .expect("native runtime trampoline")
        .1;
    let usercopy_drop = trampoline.find("drop(usercopy_window)").unwrap();
    let completion = trampoline
        .find("runtime.complete_remote_stop(frame, current_binding_generation())")
        .unwrap();
    assert!(usercopy_drop < completion);

    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    let dispatch = primordial
        .split_once("impl<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> NativeSyscallHandler")
        .expect("live carrier dispatch")
        .1
        .split_once("impl<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>\n    crate::syscall::native::NativeRendezvousRuntime")
        .expect("live carrier dispatch extent")
        .0;
    assert!(dispatch.contains("publish_live_remote_stop(identity, ())"));
    assert!(dispatch.contains("let mut runtime = self.runtime.lock();"));
    assert!(primordial.contains("fn stopped_service_state_is_quiescent(&self)"));
    assert!(primordial.contains("self.services.operation_owner(self.thread)"));
    assert!(primordial.contains("self.wait_controls[self.cpu.index()].is_clear()"));
    let initiator = primordial
        .split_once("fn complete_remote_stop(")
        .expect("remote-stop initiator")
        .1
        .split_once("fn authorize_return(")
        .expect("remote-stop initiator extent")
        .0;
    let await_ack = initiator.find("await_live_remote_stop(deferred)").unwrap();
    let reclaim = initiator
        .find("runtime.complete_process_termination(")
        .unwrap();
    assert!(await_ack < reclaim);
    assert!(initiator.contains("permits[cpu_index] = Some(permit)"));

    let adapters = source("src/syscall/adapters.rs");
    assert!(adapters.contains("prepare_process_terminate("));
    assert!(adapters.contains("complete_prepared_process_termination_after_remote_stops"));
    assert!(adapters.contains("retire_exit_pins_after_remote_stops("));

    let execution = source("src/task/execution.rs");
    assert!(execution.contains("acknowledged_remote_stop"));
    assert!(execution.contains("remote-stop permit named a Thread still owned by the scheduler"));
}

#[test]
fn i1_idle_suspend_stop_handoffs_after_idle_cleanup_instead_of_halting() {
    let live = source("src/arch/x86_64/syscall/live.rs");
    let idle_suspend = live
        .split_once("crate::syscall::native::NativeSuspendPlan::IdleCurrent =>")
        .expect("idle-suspend path")
        .1;

    assert_eq!(
        idle_suspend
            .match_indices("stage_rendezvous_action(RendezvousAction(request))")
            .count(),
        2
    );
    assert_eq!(
        idle_suspend
            .match_indices("handoff_to_rendezvous_reaper(context)")
            .count(),
        2
    );
    let finish = idle_suspend
        .find("crate::arch::x86_64::idle::finish_current_idle(halt)")
        .expect("post-hlt idle finish");
    let post_halt_latch = idle_suspend[finish..]
        .find("service_current_rendezvous_latch()")
        .expect("post-hlt latch consume");
    let post_halt_handoff = idle_suspend[finish..]
        .find("handoff_to_rendezvous_reaper(context)")
        .expect("post-hlt reaper handoff");
    assert!(post_halt_latch < post_halt_handoff);
    assert!(!idle_suspend.contains("live D carrier safe-point/reaper join has not yet"));
}

#[test]
fn i1_replacement_carrier_treats_prior_holdsafe_as_a_reclaim_gate_not_a_stop() {
    let live = source("src/arch/x86_64/syscall/live.rs");
    let gate = live
        .split_once("unsafe fn native_runtime_rendezvous_gate")
        .expect("CPL3 pre-IRET gate")
        .1
        .split_once("unsafe fn native_runtime_rendezvous_reaper")
        .expect("gate extent")
        .0;
    assert!(gate.contains("MailboxNotification::HoldSafe(_) => 0"));
    assert!(!gate.contains(
        "Stop(request)\n        | crate::arch::x86_64::rendezvous::MailboxNotification::HoldSafe"
    ));

    let trampoline = live
        .split_once("unsafe fn native_runtime_trampoline")
        .expect("native trampoline")
        .1
        .split_once("crate::syscall::native::SyscallControl::ReturnToCaller")
        .expect("post-dispatch gate extent")
        .0;
    assert!(trampoline.contains("MailboxNotification::HoldSafe(_) => {}"));
    assert!(trampoline.contains("MailboxNotification::Stop(request) =>"));
}

#[test]
fn e5_live_user_pins_guard_actual_atomic_write_batches() {
    let access = source("src/arch/x86_64/mm/activation/user_access.rs");
    assert!(access.contains("self.target.pins"));
    assert!(access.contains("begin_mutation(self.address_space, start, end - start)"));
    assert!(access.contains(".apply(writes, invalidations)"));
    let reserve = access
        .find("begin_mutation(self.address_space, start, end - start)")
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
        "current_process_address_space(&self.active_root, self.process)",
        "crate::syscall::abi_get_info(",
        "crate::syscall::process_exit_on(",
        "Some(SchedulerThreadState::Running)",
        "frame.authorize_return(current_binding_generation, &mut mappings)",
        "validate_target_continuation_roundtrip()",
        "core::pin::pin!(runtime)",
        "enter_native_syscall_runtime(",
        "runtime.as_mut(),",
        "ValidatedUserReturn::initial(context, &mut mappings)",
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

#[test]
fn i1_live_process_exit_retires_the_current_cpu_carrier() {
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");
    let adapters = source("src/syscall/adapters.rs");

    assert!(runtime.contains("crate::syscall::process_exit_on("));
    assert!(runtime.contains("self.cpu,"));
    assert!(adapters.contains("current_cpu: crate::cpu::CpuIndex"));
    assert!(adapters.contains("DeferredCurrentRetirement::Handoff"));
    assert!(adapters.contains("cpu: current_cpu"));
    assert!(runtime.contains("complete_deferred_current_reclaim_on("));
    assert!(adapters.contains("retire_exit_pins_defer_current_on(cpu"));
}

#[test]
fn i1_live_context_switch_acknowledges_from_the_destination_carrier() {
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");

    assert!(runtime.contains("fn complete_physical_switch_handoff(&self)"));
    assert!(runtime.contains(".complete_switch_on(outgoing)"));
    assert!(runtime.contains(
        "runtime.switch_cpu(self.cpu);\n            runtime.complete_physical_switch_handoff();\n            runtime.prepare_fresh_user_entry()"
    ));
    assert!(
        runtime.contains("runtime.switch_cpu(self.cpu);\n        runtime.resume_suspended(frame);")
    );
}

#[test]
fn i1_live_wait_suspension_uses_the_physical_current_cpu() {
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");
    let services = source("src/syscall/f_services.rs");
    let waits = source("src/wait/engine.rs");

    assert!(runtime.contains("self.thread,\n                        self.cpu,"));
    assert!(services.contains("wait_many_syscall_on("));
    assert!(services.contains("wait_one_syscall_on("));
    assert!(services.contains("current_cpu,"));
    assert!(waits.contains("prepare_block_current_on(cpu, thread)"));
    assert!(waits.contains("cancel_block_on(cpu, block)"));
    assert!(waits.contains("commit_block_on(cpu, block)"));
}

#[test]
fn f2_syscall_frame_moves_to_thread_stack_before_rust_dispatch() {
    let assembly = source("src/arch/x86_64/syscall_entry.S");
    let entry = assembly
        .split_once("dw_x86_64_syscall_entry:")
        .expect("syscall entry symbol")
        .1;
    let thread_stack = entry
        .find("movq %gs:E4_GS_CURRENT_STACK_TOP, %rsp")
        .expect("current Thread stack switch");
    let reserve = entry[thread_stack..]
        .find("subq $E4_SC_FRAME_SIZE, %rsp")
        .map(|offset| thread_stack + offset)
        .expect("Thread-owned syscall-frame reservation");
    let copy = entry.find("rep movsq").expect("entry-frame copy");
    let dispatch = entry
        .find("callq dw_x86_64_syscall_dispatch")
        .expect("Rust syscall dispatch");
    assert!(thread_stack < reserve && reserve < copy && copy < dispatch);
    assert!(entry[..dispatch].contains("movl $(E4_SC_FRAME_SIZE / 8), %ecx"));
    assert!(entry[..dispatch].contains("movq %rsp, %r12"));
}

#[test]
fn f12_terminal_control_abandons_the_retiring_stack_before_runtime_reclaim() {
    let assembly = source("src/arch/x86_64/syscall_entry.S");
    let handoff = assembly
        .split_once("dw_x86_64_terminal_reaper_handoff:")
        .expect("terminal reaper handoff symbol")
        .1
        .split_once(".size dw_x86_64_terminal_reaper_handoff")
        .expect("terminal reaper handoff extent")
        .0;
    let clear_if = handoff.find("    cli").expect("terminal CLI");
    let gs_base = handoff
        .find("movl $IA32_GS_BASE, %ecx")
        .expect("kernel GS-base selection");
    let kernel_gs_base = handoff
        .find("movl $IA32_KERNEL_GS_BASE, %ecx")
        .expect("unswapped CPL3 exception GS-base selection");
    let switch = handoff
        .find("movq E4_GS_TERMINAL_REAPER_TOP(%rax), %rsp")
        .expect("CPU-private terminal stack switch");
    let align = handoff
        .find("andq $-16, %rsp")
        .expect("SysV stack alignment");
    let callback = handoff.find("callq *%r9").expect("noreturn Rust callback");
    let trap = handoff.find("    ud2").expect("callback return trap");
    assert!(
        clear_if < gs_base
            && gs_base < kernel_gs_base
            && kernel_gs_base < switch
            && switch < align
            && align < callback
            && callback < trap
    );
    assert!(!handoff.contains("retq"));
    assert!(!handoff.contains("E4_GS_CURRENT_STACK_TOP"));
    assert!(!handoff.contains("__dw_terminal_reaper_stack_top"));

    let live = source("src/arch/x86_64/syscall/live.rs");
    let terminal_arm = live
        .split_once("SyscallControl::TerminateCurrent =>")
        .expect("terminal syscall control arm")
        .1
        .split_once("SyscallControl::SuspendCurrent =>")
        .expect("terminal syscall control arm extent")
        .0;
    assert!(terminal_arm.contains("handoff_to_terminal_reaper::<R>(context)"));
    assert!(!terminal_arm.contains("terminate_current()"));
}

#[test]
fn h2_syscall_entry_and_native_runtime_carriers_are_fixed_per_cpu() {
    let live = source("src/arch/x86_64/syscall/live.rs");
    let runtime_binding = source("src/arch/x86_64/syscall/runtime_binding.rs");
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    let arch = source("src/arch/x86_64/mod.rs");

    assert!(live.contains("[EntryStateStorage; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT]"));
    assert!(live.contains("install_syscall_boundary_for_slot("));
    assert!(live.contains("cpu_index_for_entry_state_address"));
    assert!(live.contains("super::msr::IA32_KERNEL_GS_BASE"));
    assert!(arch.contains("migrate_bsp_to_runtime_slot0_after_deep_paging"));
    assert!(arch.contains("initialize_ap_runtime_slot"));
    assert!(arch.contains("RuntimeCpuDescriptorLifecycle::Online"));
    assert!(live.contains(
        "static RUNTIME_STATE: [AtomicU8; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT]"
    ));
    assert!(live.contains(
        "static RUNTIME: [RuntimeStorage; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT]"
    ));
    assert!(live.contains("let cpu_index = current_cpu_index_for_diagnostics()?;"));
    assert!(live.contains("RUNTIME_CARRIER_CLAIMS.claim(cpu_index, context)"));
    assert!(runtime_binding.contains("owners: SpinMutex<[usize; SLOTS]>"));
    assert!(runtime_binding.contains("owners.contains(&address)"));
    assert!(runtime_binding.contains("RuntimeCarrierClaimError::ContextAlreadyClaimed"));
    assert!(live.contains("RuntimeCarrierLifecycles"));
    assert!(live.contains("bind_native_runtime_carrier_for_slot"));
    assert!(live.contains("release_native_runtime_carrier_for_slot"));
    assert!(live.contains("RuntimeCarrierLifecycle::Executing"));
    assert!(!live.contains("EntryBindingError::NonBootstrapCpu"));

    let shared = primordial
        .split_once("struct PrimordialRuntimeShared")
        .expect("stationary shared runtime")
        .1
        .split_once("impl crate::time::DeadlineWakeTarget")
        .expect("stationary shared runtime extent")
        .0;
    for authority in ["execution:", "channels:", "events:", "timers:", "waits:"] {
        assert!(
            shared.contains(authority),
            "shared runtime omitted {authority}"
        );
    }
    for exclusive in [
        "active:",
        "registry:",
        "memory:",
        "tasks:",
        "services:",
        "regions:",
    ] {
        assert!(
            !shared.contains(exclusive),
            "unsynchronized {exclusive} leaked into the shared runtime"
        );
    }
    assert!(primordial.contains("struct PrimordialRuntimeCarrier"));
    assert!(primordial.contains("struct RuntimeCarrierFacade"));
    assert!(primordial.contains("struct RuntimeAuthorityLock"));
    assert!(primordial.contains("struct PerCpuLiveCarrier"));
    assert!(primordial.contains("initialize_per_cpu_live_carriers()"));
    assert!(primordial.contains("bind_runtime_carrier_facades(facades.as_mut())"));
    assert!(primordial.contains("release_runtime_carrier_facades()"));
    assert!(primordial.contains("runtime.select_cpu(self.cpu)"));
    assert!(primordial.contains("runtime.prepare_fresh_user_entry()"));
    assert!(primordial.contains("enter_bound_validated_user(&state, stack)"));
    assert!(!primordial.contains("reject_entry"));
}

#[test]
fn i1_stationary_foundation_keeps_authority_and_carrier_boundaries_explicit() {
    let stationary = source("src/arch/x86_64/syscall/stationary_runtime.rs");
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");

    for authority in [
        "struct RuntimeCore",
        "registry: REGISTRY",
        "memory: MEMORY",
        "tasks: TASKS",
        "spaces: SPACES",
        "regions: REGIONS",
        "struct PagingAuthority",
        "struct ThreadServiceSlots",
        "struct PerCpuStaging",
        "fn assert_clear",
    ] {
        assert!(
            stationary.contains(authority),
            "missing stationary {authority}"
        );
    }
    assert!(stationary.contains("stationary authority nesting on CPU"));
    assert!(stationary.contains("assert_clear_on"));
    assert!(stationary.contains("prepare_on"));
    assert!(stationary.contains("ThreadServiceSlotError::StaleLease"));
    assert!(primordial.contains("struct PerCpuLiveCarrier"));
    assert!(primordial.contains("initialize_per_cpu_live_carriers"));
    assert!(primordial.contains("0..crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT"));
    assert!(primordial.contains("local: &'static PerCpuLiveCarrier"));
    assert!(primordial.contains("bind_runtime_carrier_facades(facades.as_mut())"));
    assert!(primordial.contains("release_runtime_carrier_facades()"));
    assert!(!primordial.contains("reject_entry"));
}

#[test]
fn i1_runtime_join_keeps_cpu_identity_and_dispatch_release_separate() {
    let live = source("src/arch/x86_64/syscall/live.rs");
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    let execution = source("src/task/execution.rs");

    assert!(live.contains("RuntimeCarrierLifecycle::Executing"));
    assert!(live.contains("release_native_runtime_carrier_for_slot(cpu)"));
    assert!(live.contains("runtime_binding() -> Option<RuntimeBindingState>"));
    assert!(live.contains("!= Some(RuntimeCarrierLifecycle::Executing)"));
    assert!(primordial.contains("current_thread_on(self.cpu)"));
    assert!(primordial.contains("prepare_process_root_selection(self.cpu"));
    assert!(primordial.contains("terminal_reaper_next_on(self.cpu)"));
    assert!(primordial.contains("schedule_next_on(self.cpu)"));
    assert!(primordial.contains("begin_execution(cpu_index)"));
    assert!(primordial.contains("idle::enable_live_cpu(cpu)"));
    assert!(execution.contains("pub(crate) fn terminal_reaper_next_on"));
    assert!(!primordial.contains("bind_parked_runtime_carriers"));
}

#[test]
fn i1_ap_and_rendezvous_fresh_entries_bind_the_selected_thread_stack_before_cpl3() {
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    for (start, end) in [
        ("fn rendezvous_stop(", "fn complete_remote_stop("),
        (
            "fn enter_idle_scheduler(&mut self) -> !",
            "unsafe fn prepare_suspend",
        ),
    ] {
        let path = primordial
            .split_once(start)
            .expect("fresh-entry path")
            .1
            .split_once(end)
            .expect("fresh-entry path extent")
            .0;
        let fresh = path
            .split_once("Entry::Fresh { state, stack }")
            .expect("fresh-entry branch")
            .1;
        let bind = fresh
            .find("bind_current_thread_stack(stack)")
            .expect("selected stack binding");
        let enter = fresh
            .find("enter_bound_validated_user(&state, stack)")
            .expect("CPL3 entry");
        assert!(bind < enter, "fresh CPL3 entry preceded its stack binding");
    }
}

#[test]
fn f2_kernel_context_switch_is_sysv_only_and_separate_from_user_return() {
    let assembly = source("src/arch/x86_64/kernel_context.S");
    for marker in [
        "pushfq",
        "pushq %rbx",
        "pushq %rbp",
        "pushq %r12",
        "pushq %r13",
        "pushq %r14",
        "pushq %r15",
        "movq %rsp, (%rdi)",
        "movq %rsi, %rsp",
        "popq %r15",
        "popq %rbx",
        "popfq",
        "retq",
    ] {
        assert!(assembly.contains(marker), "kernel switch omitted {marker}");
    }
    let lowered = assembly.to_ascii_lowercase();
    for forbidden in [
        "    iretq",
        "    sysret",
        "    swapgs",
        "    wrmsr",
        "    rdmsr",
    ] {
        assert!(
            !lowered.contains(forbidden),
            "kernel switch contains {forbidden}"
        );
    }
    let build = source("build.rs");
    assert!(build.contains("src/arch/x86_64/kernel_context.S"));
    assert!(build.contains("deepwyrm-x86_64-kernel-context.o"));
}

#[test]
fn f2_runtime_binding_is_retained_by_divergent_entry_and_suspension_drops_short_reborrows() {
    let live = source("src/arch/x86_64/syscall/live.rs");
    let native = source("src/syscall/native.rs");
    let divergent_entry_api = live
        .split_once("pub(crate) unsafe fn enter_native_syscall_runtime")
        .expect("native runtime entry API")
        .1
        .split_once("impl<")
        .expect("private divergent entry implementation")
        .0;
    assert!(divergent_entry_api.contains(") -> ! {"));
    assert!(live.contains("NativeSyscallRuntimeEntry<'runtime, R>"));
    assert!(live.contains("runtime: Pin<&'runtime mut R>"));
    assert!(live.contains("Pin<&'runtime mut R>"));
    assert!(live.contains("let entry = NativeSyscallRuntimeEntry { runtime };"));
    assert!(live.contains("unsafe { entry.enter(state, stack, exception_binding) }"));
    assert!(live.contains("Pin::get_unchecked_mut(self.runtime.as_mut())"));
    assert!(!live.contains("SyscallRuntimeBinding"));
    assert!(!live.contains("bind_native_syscall_runtime"));
    assert!(live.contains("let control = {"));
    assert!(live.contains("runtime.prepare_suspend(frame)"));
    assert!(live.contains("execute_kernel_switch(plan)"));
    assert!(live.contains("frame.rebind_after_kernel_resume(generation)"));
    assert!(live.contains("runtime.resume_suspended(frame)"));
    assert!(native.contains("SuspendCurrent"));
    assert!(native.contains(") -> SyscallControl"));
    assert!(!native.contains("runtime.reschedule()"));
}

#[test]
fn i1_live_wait_control_is_owned_by_each_physical_cpu_carrier() {
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");
    let services = source("src/syscall/f_services.rs");

    assert!(runtime.contains(
        "wait_controls: [NativeWaitControl; crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT]"
    ));
    assert!(runtime.contains("&mut self.wait_controls[self.cpu.index()]"));
    assert!(runtime.contains(".all(NativeWaitControl::is_clear)"));
    assert!(
        !services.contains("control: NativeWaitControl,"),
        "shared F-service state must not own one cross-CPU suspension handoff"
    );
}

#[test]
fn i1_syscall_entry_polls_remote_stop_before_usercopy_or_dispatch() {
    let live = source("src/arch/x86_64/syscall/live.rs");
    let trampoline = live
        .split_once("unsafe fn native_runtime_trampoline<")
        .expect("native runtime trampoline")
        .1
        .split_once("fn switch_kernel_context(")
        .expect("native runtime trampoline terminator")
        .0;
    let stop_poll = trampoline
        .find("take_current_notification_at_safe_point()")
        .expect("entry mailbox safe point");
    let usercopy = trampoline
        .find("NativeUsercopyWindow::enter_current()")
        .expect("usercopy entry");
    let dispatch = trampoline
        .find("dispatch_frame(runtime, frame")
        .expect("native dispatch");
    assert!(stop_poll < usercopy && usercopy < dispatch);
    assert!(
        trampoline
            .match_indices("take_current_notification_at_safe_point()")
            .count()
            >= 3,
        "entry, post-dispatch, and rendezvous-control seams must poll the authoritative mailbox"
    );
    let usercopy_drop = trampoline.find("drop(usercopy_window)").unwrap();
    let post_dispatch_poll = trampoline[usercopy_drop..]
        .find("take_current_notification_at_safe_point()")
        .unwrap()
        + usercopy_drop;
    let latched_poll = trampoline
        .find("service_current_rendezvous_latch()")
        .unwrap();
    assert!(usercopy_drop < post_dispatch_poll && post_dispatch_poll < latched_poll);
}

#[test]
fn daybreak_switch_plan_brands_execution_owner_through_every_suspend_facade() {
    let context = source("src/arch/x86_64/context.rs");
    let execution = source("src/task/execution.rs");
    let native = source("src/syscall/native.rs");
    let adapters = source("src/syscall/adapters.rs");
    let services = source("src/syscall/f_services.rs");
    let live = source("src/arch/x86_64/syscall/live.rs");

    assert!(context.contains("pub(crate) struct KernelSwitchPlan<'owner>"));
    assert!(context.contains("_owner: PhantomData<&'owner ()>"));
    assert!(context.contains("_owner: &'owner Owner"));
    assert!(context.contains("fn into_switch(self) -> (*mut u64, u64)"));
    assert!(context.contains("execute_kernel_switch(plan: KernelSwitchPlan<'_>)"));

    assert!(execution.contains("&'owner self,"));
    assert!(
        execution
            .match_indices("KernelSwitchPlan<'owner>, ExecutionSwitchError")
            .count()
            >= 5
    );
    assert!(execution.contains("KernelSwitchPlan::new(\n                    self,"));
    assert!(execution.contains("KernelSwitchPlan::new_initial(\n                self,"));

    assert!(native.contains("pub(crate) enum NativeSuspendPlan<'owner>"));
    assert!(native.contains("pub(crate) enum NativeIdleSuspendPoll<'owner>"));
    assert!(native.contains("fn prepare_suspend<'owner>("));
    assert!(native.contains("unsafe fn prepare_suspend<'owner>("));
    assert!(native.contains(") -> NativeSuspendPlan<'owner>;"));
    assert!(native.contains("fn poll_idle_suspend<'owner>("));
    assert!(native.contains("unsafe fn poll_idle_suspend<'owner>("));
    assert!(native.contains(") -> NativeIdleSuspendPoll<'owner>;"));

    assert!(adapters.contains("pub(crate) unsafe fn prepare_suspend<"));
    assert!(adapters.contains("pub(crate) unsafe fn poll_idle<"));
    assert!(adapters.contains("pub(crate) unsafe fn prepare_wait_suspend_plan<"));
    assert!(adapters.contains("pub(crate) unsafe fn poll_wait_idle_suspend<"));
    assert!(adapters.contains("Result<NativeSuspendPlan<'owner>, WaitSuspendError>"));
    assert!(adapters.contains("Result<NativeIdleSuspendPoll<'owner>, WaitSuspendError>"));
    assert!(services.contains("pub(crate) unsafe fn prepare_suspend<"));
    assert!(services.contains("pub(crate) unsafe fn poll_idle_suspend<"));
    assert!(services.contains("Result<NativeSuspendPlan<'owner>, WaitSuspendError>"));
    assert!(services.contains("Result<NativeIdleSuspendPoll<'owner>, WaitSuspendError>"));
    assert!(live.contains("KernelSwitchPlan<'_>)"));
    assert!(live.contains("unsafe { runtime.prepare_suspend(frame) }"));
    assert!(live.contains("unsafe { runtime.poll_idle_suspend(frame) }"));
    assert!(live.contains("execute_kernel_switch(plan)"));
}

#[test]
fn daybreak_production_execution_exposes_no_raw_safe_continuation_seed() {
    let execution = source("src/task/execution.rs");
    assert!(!execution.contains("pub(crate) fn seed_kernel_continuation("));
    assert!(execution.contains("#[cfg(test)]"));
    assert!(execution.contains("pub(crate) fn seed_test_kernel_continuation("));
    let context = source("src/arch/x86_64/context.rs");
    assert!(context.contains("validate_initial_kernel_continuation_frame"));
    assert!(context.contains("INITIAL_KERNEL_CONTINUATION_RFLAGS"));
}

#[test]
fn f9_zero_count_wake_still_validates_address_key_and_output_before_dispatch() {
    let runtime = source("src/arch/x86_64/mm/activation/test_support/f9.rs");
    let adapters = source("src/syscall/adapters.rs");
    let wake = adapters
        .split_once("pub(crate) fn atomic_wake_with")
        .expect("generic atomic wake transaction")
        .1
        .split_once("pub(crate) fn clock_get")
        .expect("generic atomic wake transaction terminator")
        .0;
    let address_pin = wake.find("pin_address(user, address)").unwrap();
    let key = wake.find("resolve_key(address, &pin)").unwrap();
    let output_range = wake.find("user_range(").unwrap();
    let output_pin = wake
        .find("user.preflight_owned_output(output_range)")
        .unwrap();
    let dispatch = wake.find("wake(key, count)").unwrap();
    assert!(
        address_pin < key
            && key < output_range
            && output_range < output_pin
            && output_pin < dispatch
    );
    assert!(
        !wake[..dispatch].contains("count == 0"),
        "count zero must not bypass address/key/output validation"
    );
    assert!(
        runtime.contains("crate::syscall::atomic_wake_with("),
        "F9 target runtime must use the host-tested atomic wake transaction"
    );
}
