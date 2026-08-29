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
    assert_eq!(assembly.match_indices("    swapgs").count(), 5);
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
fn common_terminal_retry_paths_use_an_unconditionally_imported_status() {
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    assert!(
        !primordial
            .contains("#[cfg(deepwyrm_dw1c_evidence)]\nuse deepwyrm_abi::DW_STATUS_WOULD_BLOCK;")
    );
    let abi_import = primordial
        .split_once("use deepwyrm_abi::{")
        .expect("common primordial ABI import")
        .1
        .split_once("};")
        .expect("end of common primordial ABI import")
        .0;
    assert!(abi_import.contains("DW_STATUS_WOULD_BLOCK"));

    for helper in [
        "prepare_remote_process_termination",
        "prepare_remote_task_group_termination",
        "prepare_remote_thread_termination",
    ] {
        let helper = primordial
            .split_once(&format!("fn {helper}("))
            .unwrap_or_else(|| panic!("missing common terminal helper {helper}"))
            .1;
        let helper = helper
            .split_once("\n    fn ")
            .map_or(helper, |(body, _)| body);
        assert!(
            helper.contains(
                "NativeSyscallResult::returning(\n                    DW_STATUS_WOULD_BLOCK,"
            ),
            "{helper} lost its ordinary retry status"
        );
    }
}

#[test]
fn dw1c_token7_channel_flight_is_capacity_only_and_post_authority() {
    let adapters = source("src/syscall/adapters.rs");
    let send = adapters
        .split_once("pub(crate) fn channel_send_from_thread<")
        .expect("threaded Channel send adapter")
        .1
        .split_once("pub(crate) fn channel_receive<")
        .expect("threaded Channel send extent")
        .0;
    let would_block = send
        .find("error == ChannelError::WouldBlock")
        .expect("token-7 requires capacity failure");
    let release = send[would_block..]
        .find("release_lookup_pin(registry, pin, cleanup);")
        .map(|offset| would_block + offset)
        .expect("Channel send releases lookup pin");
    let observe = send[release..]
        .find(".observe_token7_full_send(")
        .map(|offset| release + offset)
        .expect("token-7 full-send observer");
    assert!(would_block < release && release < observe);
    assert!(send.contains("tracks_token7_actor(current_process, thread)"));
    assert!(!send[..observe].contains("ChannelError::PeerClosed"));

    let wait = source("src/wait/engine.rs");
    let exact = wait
        .split_once("fn exact_writable_channel(&self)")
        .expect("token-7 exact wait helper")
        .1
        .split_once("pub(crate) fn select_ready")
        .expect("token-7 exact wait helper extent")
        .0;
    assert!(exact.contains("if self.len != 1"));
    assert!(exact.contains("item.desired == DW_SIGNAL_WRITABLE"));
    let commit = wait.find(".commit_published_block_on(cpu, block)").unwrap();
    let block_observe = wait.find(".observe_token7_writable_block(").unwrap();
    assert!(commit < block_observe);

    let receive = adapters
        .split_once("fn complete_wait_wakes_with_channel_drain<")
        .expect("provenance-preserving wake helper")
        .1;
    let success = receive.find("Ok(()) => {").unwrap();
    let wake_observe = receive.find(".observe_token7_peer_drain_wake(").unwrap();
    let stale = receive
        .find("Err(SchedulerError::StaleBlockToken) => {}")
        .unwrap();
    let prior_winner = receive
        .find("Ok(false) | Err(crate::task::BlockedOperationError::StaleReservation)")
        .unwrap();
    assert!(success < wake_observe && wake_observe < stale && wake_observe < prior_winner);
    assert!(adapters.contains("Some(drained_peer)"));
}

#[test]
fn address_region_adapter_source_contract_tracks_the_private_module() {
    let facade = source("src/syscall/adapters.rs");
    let address_region = source("src/syscall/adapters/address_region.rs");

    assert!(facade.contains("mod address_region;"));
    assert!(facade.contains("pub(crate) use address_region::{"));
    for marker in [
        "fn queue_mapping_releases",
        "pub(crate) fn decode_map_args",
        "pub(crate) fn address_region_map_prepared_model",
        "pub(crate) fn address_region_unmap_prepared",
        "pub(crate) fn address_region_protect_prepared",
    ] {
        assert!(
            address_region.contains(marker),
            "private address-region adapter module is missing {marker}"
        );
        assert!(
            !facade.contains(marker),
            "address-region implementation marker remains duplicated in the facade: {marker}"
        );
    }
}

#[test]
fn i1_post_ack_carrier_never_reuses_a_retired_frame_for_late_holdsafe() {
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    let continuation = primordial
        .split_once("fn prepare_after_rendezvous_stop(&mut self) -> PreparedRendezvousNext")
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
    assert!(primordial.contains("fn await_remote_stop_permits("));
    let await_ack = primordial.find("await_live_remote_stop(deferred)").unwrap();
    let await_call = initiator
        .find("let permits = await_remote_stop_permits(pending.deferred)")
        .unwrap();
    let authority_lock = initiator[await_call..]
        .find("let mut runtime = self.runtime.lock();")
        .map(|offset| await_call + offset)
        .unwrap();
    let reclaim = initiator
        .find("runtime.complete_process_termination(")
        .unwrap();
    let helper = primordial.find("fn await_remote_stop_permits(").unwrap();
    assert!(helper < await_ack);
    assert!(await_call < authority_lock);
    assert!(authority_lock < reclaim);
    assert!(primordial.contains("permits[cpu_index] = Some(permit)"));

    let adapters = source("src/syscall/adapters.rs");
    assert!(adapters.contains("prepare_process_terminate("));
    assert!(adapters.contains("complete_prepared_process_termination_after_remote_stops"));
    assert!(adapters.contains("execution.quiesce_terminal_threads(effects.pins.thread_keys())"));
    assert!(adapters.contains("retire_quiesced_exit_pins_after_remote_stops("));

    let execution = source("src/task/execution.rs");
    assert!(execution.contains("acknowledged_remote_stop"));
    assert!(execution.contains("scheduler_pre_retired"));
    assert!(
        execution.contains("terminal Thread retained multiple scheduler retirement authorities")
    );
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
        3
    );
    assert_eq!(
        idle_suspend
            .match_indices("handoff_to_rendezvous_reaper(context)")
            .count(),
        3
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
    assert!(adapters.contains("retire_quiesced_exit_pins_defer_current_after_remote_stops_on("));
}

#[test]
fn i1_live_context_switch_acknowledges_from_the_destination_carrier() {
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");

    assert!(runtime.contains("fn complete_physical_switch_handoff(&mut self)"));
    assert!(runtime.contains(".complete_switch_on(outgoing)"));
    let fresh = runtime
        .rsplit_once("fn enter_scheduled_fresh_thread(&mut self) -> !")
        .expect("live fresh-thread entry")
        .1
        .split_once("fn publish_scheduler_idle")
        .expect("live fresh-thread entry boundary")
        .0;
    let fresh_ack = fresh
        .find("runtime.complete_physical_switch_handoff()")
        .unwrap();
    let fresh_sync = fresh
        .find("self.synchronize_scheduler_current_detached();")
        .unwrap();
    let fresh_notify = fresh
        .find("crate::task::notify_completed_switch_runnable(publication);")
        .unwrap();
    let fresh_prepare = fresh
        .find("runtime.prepare_fresh_user_entry_synchronized()")
        .unwrap();
    assert!(fresh_sync < fresh_ack && fresh_ack < fresh_notify && fresh_notify < fresh_prepare);
    let resume = runtime
        .split_once("fn resume_suspended(")
        .expect("live suspended-resume facade")
        .1;
    assert!(resume.contains("runtime.switch_cpu(self.cpu);"));
    assert!(resume.contains("runtime.resume_suspended(frame)"));

    let direct_invalid = runtime
        .split_once("fn invalid_return(&mut self, error:")
        .expect("direct invalid-return terminal path")
        .1
        .split_once("fn user_exception(")
        .expect("direct user-exception boundary")
        .0;
    let direct_ack = direct_invalid
        .find("self.complete_physical_switch_handoff()")
        .expect("direct invalid-return switch acknowledgement");
    let direct_sync = direct_invalid
        .find("self.synchronize_scheduler_current();")
        .expect("direct invalid-return scheduler synchronization");
    let direct_terminal = direct_invalid
        .find("self.terminate_exception(")
        .expect("direct invalid-return termination");
    let direct_notify = direct_invalid
        .find("crate::task::notify_completed_switch_runnable(publication);")
        .expect("direct invalid-return Runnable notification");
    assert!(
        direct_sync < direct_ack && direct_ack < direct_notify && direct_notify < direct_terminal
    );

    let remote_terminal = runtime
        .split_once("fn terminate_exception_with_remote_stops(")
        .expect("remote terminal exception path")
        .1
        .split_once("fn intercept_wyr1_evidence_raw(")
        .expect("remote terminal exception boundary")
        .0;
    let remote_switch = remote_terminal
        .find("runtime.switch_cpu(self.cpu);")
        .expect("remote terminal CPU restoration");
    let remote_ack = remote_terminal
        .find("runtime.complete_physical_switch_handoff()")
        .expect("remote terminal switch acknowledgement");
    let remote_sync = remote_terminal
        .find("self.synchronize_scheduler_current_at_safe_point_detached()")
        .expect("remote terminal scheduler safe-point synchronization");
    let remote_prepare = remote_terminal
        .find("runtime.prepare_remote_process_exception(exception)")
        .expect("remote terminal preparation");
    let remote_notify = remote_terminal
        .find("crate::task::notify_completed_switch_runnable(published);")
        .expect("remote terminal Runnable notification");
    let remote_wait = remote_terminal
        .find("await_remote_stop_permits(pending.deferred)")
        .expect("remote terminal acknowledgement wait");
    let remote_final_sync = remote_terminal
        .rfind("self.synchronize_scheduler_current_detached();")
        .expect("remote terminal post-acknowledgement synchronization");
    let remote_complete = remote_terminal
        .find("runtime.complete_process_termination(")
        .expect("remote terminal completion");
    assert!(
        remote_sync < remote_switch
            && remote_switch < remote_ack
            && remote_ack < remote_notify
            && remote_notify < remote_prepare
            && remote_prepare < remote_wait
            && remote_wait < remote_final_sync
            && remote_final_sync < remote_complete
    );
}

#[test]
fn i2_suspended_resume_gives_remote_stop_priority_under_scheduler_authority() {
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");
    let live = source("src/arch/x86_64/syscall/live.rs");

    let resume = runtime
        .rsplit_once("fn resume_suspended(")
        .expect("live suspended-resume facade")
        .1
        .split_once("\n    }\n}")
        .expect("live suspended-resume facade terminator")
        .0;
    let authority = resume.find("self.runtime.lock()").unwrap();
    let carrier = resume.find("runtime.switch_cpu(self.cpu)").unwrap();
    let acknowledgement = resume
        .find("runtime.complete_physical_switch_handoff()")
        .unwrap();
    let synchronization = resume
        .find("self.synchronize_scheduler_current_at_safe_point_detached()")
        .unwrap();
    let terminal = resume
        .find("NativeResumeOutcome::TerminateCurrent")
        .unwrap();
    let runnable = resume
        .find("crate::task::notify_completed_switch_runnable(publication);")
        .unwrap();
    let mailbox = resume
        .find("take_current_notification_at_safe_point()")
        .unwrap();
    let current = resume.find("runtime.resume_suspended(frame)").unwrap();
    assert!(
        authority < carrier
            && carrier < terminal
            && terminal < synchronization
            && synchronization < acknowledgement
            && acknowledgement < runnable
            && runnable < mailbox
            && mailbox < current
    );
    assert!(resume.contains("NativeResumeOutcome::ServiceRendezvous"));

    let suspended = live
        .split_once("SyscallControl::SuspendCurrent =>")
        .expect("suspended syscall trampoline")
        .1
        .split_once("SyscallControl::CompleteRemoteStop")
        .expect("suspended syscall trampoline terminator")
        .0;
    let outcome = suspended.find("runtime.resume_suspended(frame)").unwrap();
    let rebind = suspended
        .find("current_runtime_context::<R>()")
        .expect("destination runtime carrier rebind");
    let frame_rebind = suspended
        .find("frame.rebind_after_kernel_resume(generation)")
        .expect("resumed frame generation rebind");
    let handoff = suspended[outcome..]
        .find("handoff_to_rendezvous_reaper(context)")
        .unwrap()
        + outcome;
    let authorize = suspended
        .find("runtime.authorize_return(frame, generation)")
        .unwrap();
    assert!(rebind < outcome && outcome < frame_rebind && frame_rebind < authorize);
    assert!(outcome < handoff);
    let rendezvous = suspended
        .split_once("NativeResumeOutcome::ServiceRendezvous")
        .expect("remote rendezvous outcome")
        .1
        .split_once("NativeResumeOutcome::TerminateCurrent")
        .expect("remote rendezvous outcome extent")
        .0;
    assert!(!rendezvous.contains("rebind_after_kernel_resume"));
}

#[test]
fn i2_terminal_reclaim_handoff_is_owned_by_the_exact_physical_cpu() {
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");
    let live = source("src/arch/x86_64/syscall/live.rs");

    assert!(
        runtime.contains(
            "deferred_currents: [Option<crate::task::DeferredCurrentExecutionResources>;"
        )
    );
    assert!(runtime.contains("self.deferred_currents[self.cpu.index()]"));
    assert!(runtime.contains("deferred_currents: core::array::from_fn(|_| None)"));
    assert!(
        !runtime
            .contains("deferred_current: Option<crate::task::DeferredCurrentExecutionResources>")
    );
    assert!(runtime.contains("NativeResumeOutcome::TerminateCurrent"));

    let suspended = live
        .split_once("SyscallControl::SuspendCurrent =>")
        .expect("suspended syscall trampoline")
        .1
        .split_once("SyscallControl::CompleteRemoteStop")
        .expect("suspended syscall trampoline terminator")
        .0;
    let terminal = suspended
        .find("NativeResumeOutcome::TerminateCurrent")
        .unwrap();
    let handoff = suspended[terminal..]
        .find("handoff_to_terminal_reaper::<R>(context)")
        .unwrap()
        + terminal;
    let stage = suspended[terminal..]
        .find("stage_terminal_action(TerminalAction::CompleteCurrent)")
        .unwrap()
        + terminal;
    let authorize = suspended
        .find("runtime.authorize_return(frame, generation)")
        .unwrap();
    let rebind = suspended
        .find("frame.rebind_after_kernel_resume(generation)")
        .unwrap();
    assert!(authorize < terminal && rebind < terminal);
    assert!(terminal < stage && stage < handoff);
}

#[test]
fn i2_live_selector_owns_bounded_test_only_runtime_capacity() {
    let build = source("build.rs");
    let activation = source("src/arch/x86_64/mm/activation.rs");
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");

    assert!(build.contains("cargo:rustc-check-cfg=cfg(deepwyrm_i2_stress)"));
    assert!(build.contains("selector == \"smp-runtime-stress\""));
    assert!(build.contains("cargo:rustc-cfg=deepwyrm_i2_stress"));
    assert!(activation.contains("const LIVE_ADDRESS_SPACE_CAPACITY: usize = 3;"));
    assert!(
        activation.contains(
            "#[cfg(deepwyrm_wrcap_relay)]\nconst LIVE_ADDRESS_SPACE_CAPACITY: usize = 4;"
        )
    );
    assert!(
        activation.contains(
            "#[cfg(deepwyrm_wyr1_evidence)]\nconst LIVE_ADDRESS_SPACE_CAPACITY: usize = 4;"
        )
    );
    assert!(
        activation
            .contains("#[cfg(deepwyrm_i2_stress)]\nconst LIVE_ADDRESS_SPACE_CAPACITY: usize = 6;")
    );
    assert!(
        activation.contains(
            "#[cfg(deepwyrm_dw1b_evidence)]\nconst LIVE_ADDRESS_SPACE_CAPACITY: usize = 5;"
        )
    );
    assert!(activation.contains(
        "#[cfg(deepwyrm_wyr1b_evidence)]\nconst LIVE_ADDRESS_SPACE_CAPACITY: usize = 8;"
    ));
    assert!(
        runtime.contains(
            "#[cfg(all(deepwyrm_i2_stress, not(deepwyrm_wrcap_relay)))]\nconst USERSPACE_CHAIN_PROCESSES: usize = 6;"
        )
    );
    assert!(runtime.contains("const USERSPACE_CHAIN_PROCESSES: usize = 3;"));
    assert!(
        runtime
            .contains("#[cfg(deepwyrm_wrcap_relay)]\nconst USERSPACE_CHAIN_PROCESSES: usize = 4;")
    );
    assert!(
        runtime.contains(
            "#[cfg(deepwyrm_wyr1_evidence)]\nconst USERSPACE_CHAIN_PROCESSES: usize = 4;"
        )
    );
    assert!(runtime.contains("#[cfg(deepwyrm_wrcap_relay)]\nconst TASK_GROUPS: usize = 2;"));
    assert!(runtime.contains("#[cfg(deepwyrm_wrcap_relay)]\nconst MEMORY_OBJECTS: usize = 12;"));
    assert!(runtime.contains("#[cfg(deepwyrm_wrcap_relay)]\nconst MEMORY_LEASES: usize = 13;"));
    assert!(runtime.contains("#[cfg(deepwyrm_wrcap_relay)]\nconst WAITERS: usize = 6;"));
    assert!(runtime.contains(
        "#[cfg(deepwyrm_wrcap_relay)]\nconst CHANNEL_PAIRS: usize = USERSPACE_CHAIN_PROCESSES;"
    ));
    assert!(runtime.contains("#[cfg(deepwyrm_wrcap_relay)]\nconst REGISTRY_OBJECTS: usize = 48;"));
    assert!(runtime.contains("const PRIMORDIAL_BOOTFS_MAX_PAGES: usize = 17;"));
    assert!(runtime.contains(
        "#[cfg(deepwyrm_wyr1b_evidence)]\nconst PRIMORDIAL_BOOTFS_MAX_PAGES: usize = parse_wyr1b_bootfs_pages();"
    ));
    assert!(
        runtime.contains(
            "#[cfg(all(deepwyrm_i2_stress, not(deepwyrm_wrcap_relay)))]\nconst PRIMORDIAL_BOOTFS_MAX_PAGES: usize = 32;"
        )
    );
    assert!(
        runtime.contains(
            "#[cfg(deepwyrm_wrcap_relay)]\nconst PRIMORDIAL_BOOTFS_MAX_PAGES: usize = 39;"
        )
    );
    assert!(runtime.contains(
        "#[cfg(deepwyrm_wyr1_evidence)]\nconst PRIMORDIAL_BOOTFS_MAX_PAGES: usize = 128;"
    ));
}

#[test]
fn live_return_boundary_publishes_final_release_effects_before_userspace_resume() {
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");
    let dispatch = runtime
        .find("impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> NativeSyscallHandler")
        .expect("live native handler");
    let return_boundary = runtime[dispatch..]
        .find("if result.control == SyscallControl::ReturnToCaller")
        .expect("normal syscall return finalizer boundary");
    let drain = runtime[dispatch..]
        .find("self.drain_finalizers()")
        .expect("normal syscall return drains finalizers");
    let result_return = runtime[dispatch..]
        .find("\n        result\n")
        .expect("native handler result return");

    assert!(return_boundary < drain && drain < result_return);
}

#[test]
fn syscall_return_preemption_revokes_authorization_immediately_before_switch() {
    let live = source("src/arch/x86_64/syscall/live.rs");
    let frame = source("src/arch/x86_64/syscall/frame.rs");
    let service = live
        .split_once("fn service_syscall_return_preemption<")
        .expect("syscall-return preemption service")
        .1
        .split_once("fn switch_kernel_context(")
        .expect("syscall-return preemption extent")
        .0;

    assert!(
        service.contains(
            "frame.revoke_authorized_return();\n            switch_kernel_context(plan);"
        )
    );
    let revoke = service.find("frame.revoke_authorized_return()").unwrap();
    let switch = service.find("switch_kernel_context(plan)").unwrap();
    let resume = service
        .find("runtime.resume_syscall_preemption(frame)")
        .unwrap();
    assert!(revoke < switch && switch < resume);

    let revoke_method = frame
        .split_once("pub(crate) fn revoke_authorized_return(&mut self)")
        .expect("return authorization revocation")
        .1
        .split_once("pub(crate) fn authorize_return")
        .expect("revocation extent")
        .0;
    assert!(revoke_method.contains("self.return_authorized = 0;"));
    assert!(frame.contains("current_binding_generation == 0 || self.return_authorized != 0"));
}

#[test]
fn live_timer_expiry_is_bound_and_serviced_only_from_carrier_safe_points() {
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");

    assert!(runtime.contains("impl crate::time::TimerExpiryTarget for PrimordialRuntimeShared"));
    assert!(runtime.contains("crate::time::bind_timer_expiry_target(target)"));
    assert!(runtime.contains("fn service_pending_timer_expiries_on_bootstrap(&mut self)"));
    assert!(runtime.contains("general Timer expiry service escaped CPU0 ownership"));
    assert!(runtime.contains(".expire(token, &self.shared.waits)"));
    assert!(runtime.contains("timer_expiries:\n        IrqSpinMutex<"));
    assert_eq!(
        runtime
            .matches("runtime.service_pending_timer_expiries_on_bootstrap();")
            .count(),
        2
    );
    assert!(
        runtime
            .matches("self.cpu == crate::cpu::CpuIndex::BOOTSTRAP")
            .count()
            >= 2
    );
}

#[test]
fn i2_live_dispatch_covers_every_stress_payload_syscall_family() {
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");
    let adapters = source("src/syscall/adapters.rs");
    let address_region = source("src/syscall/adapters/address_region.rs");

    assert!(runtime.contains("NativeSyscallRequest::AddressRegionProtect"));
    assert!(runtime.contains("fn protect_memory("));
    assert!(runtime.contains("crate::syscall::address_region_protect_prepared("));
    assert!(address_region.contains("pub(crate) fn address_region_protect_prepared<"));
    for family in [
        "NativeSyscallRequest::HandleClose",
        "NativeSyscallRequest::HandleDuplicate",
        "NativeSyscallRequest::ObjectGetInfoV1",
        "NativeSyscallRequest::TaskGroupCreate",
        "NativeSyscallRequest::TaskGroupTerminate",
        "NativeSyscallRequest::MemoryObjectCreate",
        "NativeSyscallRequest::AddressRegionMap",
        "NativeSyscallRequest::AddressRegionUnmap",
        "NativeSyscallRequest::AddressRegionProtect",
        "NativeSyscallRequest::ProcessTerminate",
        "NativeSyscallRequest::ProcessExit",
    ] {
        assert!(runtime.contains(family), "live carrier omitted {family}");
    }
    assert!(runtime.contains("fn prepare_remote_task_group_termination("));
    assert!(runtime.contains("fn complete_task_group_termination("));
    assert!(runtime.contains("PendingRemoteTermination::TaskGroup"));
    assert!(adapters.contains("pub(crate) fn prepare_task_group_terminate<"));
    assert!(
        adapters.contains(
            "pub(crate) fn complete_prepared_task_group_termination_after_remote_stops_on<"
        )
    );
    assert!(runtime.contains("crate::syscall::process_unhandled_exception_on("));
    assert!(adapters.contains("pub(crate) fn process_unhandled_exception_on<"));
    assert!(
        runtime.contains(
            "crate::syscall::complete_prepared_process_termination_after_remote_stops_on("
        )
    );
}

#[test]
fn i1_terminal_child_without_local_work_rejoins_the_idle_scheduler() {
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");

    assert!(runtime.contains("enum PreparedTerminalHandoff"));
    assert!(runtime.contains("if retired_process != self.primordial_process"));
    assert!(runtime.contains("self.finish_inactive_process_teardown("));
    assert!(runtime.contains("PreparedTerminalHandoff::IdleScheduler"));
    assert!(runtime.contains("enter_bound_idle_scheduler()"));
    let terminal = runtime
        .split_once("fn prepare_terminal_handoff(")
        .expect("terminal handoff")
        .1
        .split_once("fn terminate_exception(")
        .expect("terminal handoff terminator")
        .0;
    let primordial_unmap = terminal
        .find("self.unmap_primordial_userspace(&proof)")
        .unwrap();
    let next_selection = terminal.find("terminal_reaper_next_on(self.cpu)").unwrap();
    assert!(primordial_unmap < next_selection);
    let no_successor = terminal
        .split_once(
            "if retiring_wyr1_primordial {\n            // A permanent supervisor may already be Running on another CPU",
        )
        .expect("WYR1 no-successor branch")
        .1
        .split_once("\n        if retired_process != self.primordial_process {")
        .expect("ordinary no-successor branch")
        .0;
    let kernel_root = no_successor
        .find("enter_kernel_execution_root(previous)")
        .unwrap();
    let retirement = no_successor
        .find("self.finish_quiesced_process_root_retirement(")
        .unwrap();
    assert!(kernel_root < retirement);
    assert!(!no_successor.contains("self.unmap_primordial_userspace("));
    assert!(!no_successor.contains("self.finish_inactive_process_teardown("));
    assert!(!terminal.contains("terminal idle safe-root"));
}

#[test]
fn wyr1_terminal_child_after_primordial_retirement_uses_its_current_root() {
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");
    let terminal = runtime
        .split_once("fn prepare_terminal_handoff(")
        .expect("terminal handoff")
        .1
        .split_once("fn terminate_exception(")
        .expect("terminal handoff terminator")
        .0;
    let retired_child = terminal
        .split_once("if retired_process != self.primordial_process && primordial_retired {")
        .expect("WYR1 retired-primordial child branch")
        .1
        .split_once("\n        if retired_process != self.primordial_process {")
        .expect("legacy retained-primordial child branch")
        .0;
    let retirement_fact = terminal
        .split_once("let primordial_retired = match")
        .expect("WYR1 primordial retirement fact")
        .1
        .split_once("if retired_process != self.primordial_process && primordial_retired {")
        .expect("WYR1 retired-primordial child branch")
        .0;
    let unmap = retired_child.find("self.unmap_current_userspace(").unwrap();
    let kernel_root = retired_child
        .find("enter_kernel_execution_root(previous)")
        .unwrap();
    let retirement = retired_child
        .find("self.finish_quiesced_process_root_retirement(")
        .unwrap();
    let idle = retired_child.find("self.local.record_idle()").unwrap();
    let reporter_guard = retired_child.find("if retiring_reporter {").unwrap();
    let reporter_info = retired_child
        .find(".process_info(retired_process)")
        .unwrap();
    let reporter_failure = retired_child
        .find("crate::test_support::complete_fail(detail)")
        .unwrap();

    assert!(reporter_guard < reporter_info);
    assert!(reporter_info < reporter_failure);
    assert!(reporter_failure < unmap);
    assert!(retired_child.contains("if info.application_code == 0"));
    assert!(retired_child.contains("supervisor_evidence_detail(0xd014)"));
    assert!(runtime.contains("return 0x2510_0000 | case;"));
    assert!(runtime.contains("return 0x2710_0000 | case;"));
    assert!(unmap < kernel_root);
    assert!(kernel_root < retirement);
    assert!(retirement < idle);
    assert!(
        retirement_fact.contains("Ok(None) | Err(crate::task::TaskError::InvalidTask) => true")
    );
    assert!(retirement_fact.contains("Ok(Some(_)) => false"));
    assert!(retirement_fact.contains("supervisor_evidence_detail(0xd00d)"));
    assert!(!retired_child.contains("prepare_process_root_selection("));
    assert!(!retired_child.contains("self.primordial_address_space"));
}

#[test]
fn wyr1_primordial_completion_failures_have_variant_specific_details() {
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");
    let diagnostic = source("src/arch/x86_64/mm/activation/primordial_diagnostic.rs");
    let terminal = runtime
        .split_once("fn prepare_terminal_handoff(&mut self) -> PreparedTerminalHandoff")
        .expect("terminal handoff")
        .1
        .split_once("fn reserve_runtime_phase")
        .expect("terminal handoff extent")
        .0;

    assert!(terminal.contains("if let Err(error) = validate_primordial_retirement_facts(self)"));
    assert!(terminal.contains("let terminal_info = self.g5_probe.terminal_info;"));
    assert!(terminal.contains("complete_fail(primordial_completion_detail("));
    assert!(terminal.contains("                    error,\n                    terminal_info,"));
    assert!(!terminal.contains("supervisor_evidence_detail(0xd001)"));

    for mapping in [
        "PrimordialCompletionError::MalformedReady => 0xd200",
        "PrimordialCompletionError::ObserveExit(code) => 0xd300 | (code & 0xff)",
        "PrimordialCompletionError::NonzeroExit(code) => 0xd400 | (code & 0xff)",
        "PrimordialCompletionError::UnhandledException => 0xd500",
        "PrimordialCompletionError::AuthorizedTermination => 0xd600",
        "PrimordialCompletionError::NotQuiescent(code) => 0xd700 | (code & 0xff)",
    ] {
        assert!(
            runtime.contains(mapping),
            "missing completion detail mapping {mapping}"
        );
    }
    for mapping in [
        "ChannelError::Capacity => 0x7100_0011",
        "ChannelError::InvalidArgument => 0x7100_0012",
        "ChannelError::InvalidEndpoint => 0x7100_0013",
        "ChannelError::StalePair => 0x7100_0014",
        "ChannelError::WouldBlock => 0x7100_0015",
        "ChannelError::PeerClosed => 0x7100_0016",
        "ChannelError::BufferTooSmall => 0x7100_0017",
        "ChannelError::AccessDenied => 0x7100_0018",
        "ChannelError::FinalizationMismatch => 0x7100_0019",
    ] {
        assert!(
            runtime.contains(mapping),
            "missing Channel mapping {mapping}"
        );
    }
    assert!(runtime.contains("0xe000"));
    assert!(runtime.contains("primordial_receive_failure_tag(code) << 8"));
    assert!(runtime.contains("primordial_terminal_summary(terminal_info)"));
    assert!(diagnostic.contains("application_code == 0xaf01_0002"));
    assert!(diagnostic.contains("application_code & 0xffff_0000 == 0xaf11_0000"));
    assert!(diagnostic.contains("0x20 | (application_code & 0x1f)"));
    let b400_terminal = diagnostic
        .find("application_code & 0xff00_0000 == 0xb400_0000")
        .expect("B400 structured terminal summary");
    let generic_bootstrap = diagnostic
        .find("application_code & 0xf000_0000 == 0xb000_0000")
        .expect("generic bootstrap summary");
    assert!(b400_terminal < generic_bootstrap);
    assert!(diagnostic.contains("let reason = (application_code >> 18) & 0x0f;"));
    assert!(diagnostic.contains("let exception_type = (application_code >> 14) & 0x0f;"));
    assert!(diagnostic.contains("(reason << 4) | exception_type"));
    assert!(diagnostic.contains("0x80 | (application_code & 0x3f)"));
    let terminal_summary = diagnostic
        .split_once("pub(super) fn primordial_terminal_summary(")
        .expect("primordial terminal summary")
        .1
        .split_once("#[cfg(test)]")
        .expect("terminal summary extent")
        .0;
    let gp = terminal_summary
        .find("info.exception_type == DW_EXCEPTION_GENERAL_PROTECTION")
        .expect("GP detail summary");
    let other_exception = terminal_summary
        .find("info.exception_type.0 > 0x0f")
        .expect("other exception summary");
    assert!(gp < other_exception);
    assert!(terminal_summary.contains("let detail = if info.detail > 0x1f"));
    assert!(terminal_summary.contains("0xc0 | detail"));
    assert!(terminal_summary.contains("info.exception_type.0 > 0x0f"));
    assert!(terminal_summary.contains("0xe0 | exception_type"));
    assert!(terminal_summary.contains("return 0xfc;"));
    assert!(terminal_summary.contains("0xfd"));
    assert!(terminal_summary.contains("return 0xff;"));
    assert!(!terminal_summary.contains("        0xfe\n"));
    assert!(runtime.contains("primordial_completion_case(error, terminal_info)"));
}

#[test]
fn final_external_thread_completion_retires_pins_before_process_root_teardown() {
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");
    let completion = runtime
        .split_once("fn complete_thread_termination(")
        .expect("Thread termination completion")
        .1
        .split_once("fn finish_terminal_adapter_resources")
        .expect("Thread completion boundary")
        .0;

    let preserve = completion
        .find("let exited_process = prepared.exited_process();")
        .expect("prepared final-Process identity");
    let retire = completion
        .find("complete_prepared_thread_termination_after_remote_stops_on(")
        .expect("remote-stop pin retirement");
    let resources = completion
        .find("self.finish_terminal_adapter_resources(")
        .expect("terminal resource completion");
    let external_guard = completion
        .find("exited_process.filter(|target| *target != self.process)")
        .expect("external final-Process guard");
    let teardown = completion
        .find("self.finish_inactive_process_teardown(")
        .expect("inactive final-Process teardown");

    assert!(preserve < retire && retire < resources);
    assert!(resources < external_guard && external_guard < teardown);
    assert!(completion.contains("control == SyscallControl::ReturnToCaller"));
}

#[test]
fn i1_live_wait_suspension_uses_the_physical_current_cpu() {
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");
    let services = source("src/syscall/f_services.rs");
    let adapters = source("src/syscall/adapters.rs");
    let waits = source("src/wait/engine.rs");

    assert!(runtime.contains("self.thread,\n                        self.cpu,"));
    assert!(services.contains("wait_many_syscall_on("));
    assert!(services.contains("wait_one_syscall_on("));
    assert!(services.contains("current_cpu,"));
    assert!(waits.contains("prepare_block_current_on(cpu, thread)"));
    assert!(waits.contains("cancel_block_on(cpu, block)"));
    assert!(waits.contains("commit_published_block_on(cpu, block)"));
    assert!(runtime.contains("self.services.prepare_suspend_on("));
    assert!(runtime.contains("self.services.poll_idle_suspend_on("));
    assert!(services.contains("control.prepare_suspend_on(cpu"));
    assert!(services.contains("control.poll_idle_on(cpu"));
    assert!(adapters.contains("schedule_from_idle_on(cpu, suspended)"));
    assert!(adapters.contains("prepare_blocking_kernel_switch_on("));
    assert!(adapters.contains("prepare_idle_blocking_kernel_switch_on("));
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
    let preserve_kernel_orientation = handoff
        .find("jnz .Le4_reaper_entry_state")
        .expect("syscall-origin GS preservation branch");
    let kernel_gs_base = handoff
        .find("movl $IA32_KERNEL_GS_BASE, %ecx")
        .expect("unswapped CPL3 exception GS-base selection");
    let reject_empty_exception = handoff[kernel_gs_base..]
        .find("jz .Le4_entry_fail")
        .map(|offset| kernel_gs_base + offset)
        .expect("empty exception GS pair rejection");
    let normalize_exception = handoff
        .find("    swapgs")
        .expect("exception-origin GS normalization");
    let normalized_entry = handoff
        .find(".Le4_reaper_entry_state:")
        .expect("normalized terminal entry label");
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
            && gs_base < preserve_kernel_orientation
            && preserve_kernel_orientation < kernel_gs_base
            && kernel_gs_base < reject_empty_exception
            && reject_empty_exception < normalize_exception
            && normalize_exception < normalized_entry
            && normalized_entry < switch
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
fn reaper_handoffs_normalize_exception_gs_before_strict_revalidation() {
    let assembly = source("src/arch/x86_64/syscall_entry.S");
    let live = source("src/arch/x86_64/syscall/live.rs");

    assert!(live.contains("program_and_verify(&mut access, plan)"));
    assert!(live.contains("verify(&mut LiveMsrAccess, plan)"));
    assert!(!live.contains("verify_live_boundary"));

    for (symbol, label) in [
        (
            "dw_x86_64_terminal_reaper_handoff:",
            ".Le4_reaper_entry_state:",
        ),
        (
            "dw_x86_64_rendezvous_reaper_handoff:",
            ".Le1_reaper_entry_state:",
        ),
    ] {
        let body = assembly
            .split_once(symbol)
            .expect("reaper handoff symbol")
            .1
            .split_once(".size ")
            .expect("reaper handoff extent")
            .0;
        let gs = body
            .find("movl $IA32_GS_BASE, %ecx")
            .expect("kernel-origin GS read");
        let preserve_kernel = body
            .find(&format!("jnz {}", label.trim_end_matches(':')))
            .expect("kernel-origin preservation branch");
        let kernel_gs = body
            .find("movl $IA32_KERNEL_GS_BASE, %ecx")
            .expect("exception-origin GS read");
        let reject_empty = body[kernel_gs..]
            .find("jz .Le4_entry_fail")
            .map(|offset| kernel_gs + offset)
            .expect("empty reversed pair rejection");
        let swap = body.find("    swapgs").expect("GS normalization");
        let normalized = body.find(label).expect("normalized entry label");
        let stack = body
            .find("movq E4_GS_TERMINAL_REAPER_TOP(%rax), %rsp")
            .expect("reaper stack pivot");
        assert!(gs < preserve_kernel && preserve_kernel < kernel_gs);
        assert!(kernel_gs < reject_empty && reject_empty < swap);
        assert!(swap < normalized && normalized < stack);
        assert_eq!(body.match_indices("    swapgs").count(), 1);
    }
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
    assert!(
        primordial.contains("release_runtime_carrier_facades(shared, runtime_ref, admissions)")
    );
    assert!(primordial.contains("runtime.switch_cpu(self.cpu)"));
    assert!(primordial.contains("runtime.prepare_fresh_user_entry_synchronized()"));
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
    assert!(
        primordial.contains("release_runtime_carrier_facades(shared, runtime_ref, admissions)")
    );
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
fn dw1c1_ap_carriers_cross_generation_bound_scheduler_admission_before_dispatch() {
    let live = source("src/arch/x86_64/syscall/live.rs");
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    let admission = source("src/task/scheduler/carrier_admission.rs");
    let scheduler = source("src/task/scheduler.rs");

    assert!(live.contains("bind_running_native_runtime_carrier_for_slot"));
    assert!(primordial.contains("prepare_runtime_carrier_admission(facades_mut)"));
    assert!(primordial.contains("normalize_bootstrap_carrier(&mut facades_mut[0])"));
    assert!(primordial.contains("publish_ap_carrier_ready"));
    assert!(primordial.contains("carrier_ticket_is_schedulable(ticket)"));
    assert!(primordial.contains("commit_ap_schedulable(ticket, resources, ||"));
    assert!(primordial.contains("idle::enable_live_cpu(cpu).is_ok()"));
    assert!(primordial.contains("let revalidated ="));
    assert!(primordial.contains("carrier_resource_tuple("));
    assert!(primordial.contains("live_rendezvous_handler_is_bound()"));
    assert!(primordial.contains("live_idle_wake_is_enabled(cpu)"));
    assert!(primordial.contains("ap_scheduler_timer_is_masked(cpu)"));
    assert!(primordial.contains("fail_live_carrier_admission("));
    assert!(admission.contains("CarrierAdmissionLifecycle::Preparing"));
    assert!(admission.contains("CarrierAdmissionLifecycle::CarrierReady"));
    assert!(admission.contains("CarrierAdmissionLifecycle::Schedulable"));
    assert!(admission.contains("Irreversible boundary"));
    assert!(scheduler.contains("SchedulerError::CarrierUnavailable"));

    let release_runtime = primordial
        .find("release_native_runtime_carrier_for_slot(cpu)")
        .expect("AP runtime release");
    let release_cpu = primordial[release_runtime..]
        .find("begin_execution(cpu_index)")
        .map(|offset| release_runtime + offset)
        .expect("AP CPU release");
    let await_ready = primordial[release_cpu..]
        .find("CarrierAdmissionLifecycle::CarrierReady")
        .map(|offset| release_cpu + offset)
        .expect("AP readiness acknowledgement wait");
    let idle_commit = primordial[await_ready..]
        .find("commit_ap_schedulable(ticket, resources")
        .map(|offset| await_ready + offset)
        .expect("AP scheduler admission commit");
    assert!(release_runtime < release_cpu);
    assert!(release_cpu < await_ready);
    assert!(await_ready < idle_commit);
    let final_revalidation = primordial[await_ready..idle_commit]
        .find("let revalidated =")
        .map(|offset| await_ready + offset)
        .expect("final live tuple revalidation");
    assert!(await_ready < final_revalidation);
    assert!(final_revalidation < idle_commit);
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
    assert!(context.contains("fn into_switch(self) -> (*mut u64, KernelStackBounds, u64)"));
    assert!(context.contains("execute_kernel_switch(plan: KernelSwitchPlan<'_>)"));
    assert!(
        context.contains("switch_owned_kernel_context(current_rsp_out, next_rsp, current_stack)")
    );

    let switch_assembly = source("src/arch/x86_64/kernel_context.S");
    let owned = switch_assembly
        .split_once("dw_x86_64_switch_owned_kernel_context:")
        .expect("owned switch entry")
        .1
        .split_once("dw_x86_64_switch_kernel_context:")
        .expect("raw switch entry")
        .0;
    for exact in [
        "subq $56, %r8",
        "cmpq %rdx, %r8",
        "addq $8, %r8",
        "cmpq %rcx, %r8",
        "jmp dw_x86_64_switch_kernel_context",
    ] {
        assert!(owned.contains(exact), "owned switch omitted {exact}");
    }

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
fn dw1c1_root_switches_are_move_only_prepare_execute_commit_transactions() {
    let bindings = source("src/arch/x86_64/mm/activation/address_space.rs");
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    let rendezvous = source("src/arch/x86_64/rendezvous.rs");

    for exact in [
        "prepare_selection_switch",
        "commit_selection_switch",
        "prepare_kernel_execution_root_switch",
        "commit_kernel_execution_root_switch",
        "prepare_from_kernel_execution_root_switch",
        "commit_from_kernel_execution_root_switch",
        "PreparedKernelRootEntry",
        "ExecutedKernelRootEntry",
    ] {
        assert!(
            bindings.contains(exact),
            "detached root contract omitted {exact}"
        );
    }
    assert!(primordial.contains("root_switch_flights:"));
    assert!(primordial.contains("fn cancel_scheduler_root_switch("));
    assert!(primordial.contains("fn cancel_stop_root_switch("));
    assert!(primordial.contains("fn cancel_ap_kernel_root_entry("));

    let detached = primordial
        .split_once("fn synchronize_scheduler_current_detached")
        .expect("detached scheduler root switch")
        .1
        .split_once("fn enter_ap_kernel_root_detached")
        .expect("AP kernel-root entry boundary")
        .0;
    let prepare = detached
        .find("runtime.prepare_scheduler_root_switch()")
        .unwrap();
    let execute = detached.find("prepared.execute()").unwrap();
    let commit = detached
        .find("runtime.commit_scheduler_root_switch(executed)")
        .unwrap();
    assert!(prepare < execute && execute < commit);
    assert!(detached[prepare..execute].contains("let Some(prepared)"));

    let stop = primordial
        .split_once("fn rendezvous_stop(")
        .expect("live rendezvous stop")
        .1
        .split_once("impl<'roles")
        .expect("rendezvous implementation terminator")
        .0;
    let stop_prepare = stop.find("runtime.prepare_rendezvous_stop").unwrap();
    let stop_execute = stop.find("root_switch.execute()").unwrap();
    let stop_commit = stop.find("runtime.commit_rendezvous_stop").unwrap();
    assert!(stop_prepare < stop_execute && stop_execute < stop_commit);
    assert!(rendezvous.contains("prepare_stop_at_safe_point"));
    assert!(rendezvous.contains("commit_prepared_stop_at_safe_point"));
}

#[test]
fn dw1c_detach_commits_its_root_flight_without_ordinary_cpu_reselection() {
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    let detach = primordial
        .split_once("fn enter_idle_scheduler(&mut self) -> !")
        .expect("live idle scheduler")
        .1
        .split_once("if !self.admission_entered")
        .expect("AP admission boundary")
        .0;
    let prepare = detach
        .find("runtime.prepare_terminal_kernel_root_switch()")
        .expect("detach prepares its root-switch flight");
    let execute = detach[prepare..]
        .find("prepared.execute()")
        .map(|offset| prepare + offset)
        .expect("detach executes its root-switch flight");
    let commit = detach[execute..]
        .find("runtime.commit_terminal_kernel_root_switch(executed)")
        .map(|offset| execute + offset)
        .expect("detach commits its root-switch flight");

    assert!(prepare < execute && execute < commit);
    assert!(
        !detach[execute..commit].contains("runtime.switch_cpu(self.cpu)"),
        "the executed root-switch flight must reselect its authenticated CPU"
    );
}

#[test]
fn dw1c1_ap_carrier_enters_its_exact_kernel_root_before_ready_publication() {
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    let idle = primordial
        .split_once("fn enter_idle_scheduler(&mut self) -> !")
        .expect("live idle carrier")
        .1;
    let root = idle.find("self.enter_ap_kernel_root_detached()").unwrap();
    let resources = idle.find("carrier_resource_tuple(").unwrap();
    let ready = idle.find("publish_ap_carrier_ready(").unwrap();
    assert!(root < resources && resources < ready);
    assert!(primordial.contains("runtime.prepare_ap_kernel_root_entry()"));
    assert!(primordial.contains("runtime.commit_ap_kernel_root_entry(executed)"));
    assert!(primordial.contains("CarrierActiveRoot::Kernel(kernel)"));
}

#[test]
fn dw1c1_terminal_handoff_executes_every_root_switch_outside_the_runtime_guard() {
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    for exact in [
        "enum PreparedTerminalStep",
        "fn prepare_terminal_handoff_detached(",
        "fn prepare_terminal_kernel_root_switch(",
        "fn commit_terminal_kernel_root_switch(",
        "fn prepare_terminal_primordial_root_switch(",
        "fn commit_terminal_primordial_root_switch(",
        "TerminalKernelContinuation::EnterPrimordialPublisher",
        "TerminalKernelContinuation::FinishGenericChild",
    ] {
        assert!(
            primordial.contains(exact),
            "terminal transaction omitted {exact}"
        );
    }

    let facade = primordial
        .rsplit_once("fn terminate_current(&mut self) -> !")
        .expect("runtime facade terminal path")
        .1
        .split_once("fn enter_scheduled_fresh_thread")
        .expect("runtime facade terminal boundary")
        .0;
    assert!(facade.contains("runtime.prepare_terminal_handoff_detached()"));
    assert!(!facade.contains("runtime.prepare_terminal_handoff()"));
    for commit in [
        "runtime.commit_scheduler_root_switch(executed)",
        "runtime.commit_terminal_kernel_root_switch(executed)",
        "runtime.commit_terminal_primordial_root_switch(executed)",
    ] {
        let execute = facade.find("prepared.execute()").unwrap();
        let commit = facade.find(commit).unwrap();
        assert!(
            execute < commit,
            "terminal root commit preceded detached execute"
        );
        assert!(
            facade[execute..commit].contains("let mut runtime = self.runtime.lock()"),
            "terminal root commit did not reacquire serialized authority"
        );
        let reacquire = facade[execute..commit]
            .rfind("let mut runtime = self.runtime.lock()")
            .unwrap()
            + execute;
        assert!(
            !facade[reacquire..commit].contains("runtime.switch_cpu(self.cpu)"),
            "terminal root commit bypassed its exact in-flight selector"
        );
    }
    for cancel in [
        "runtime.cancel_scheduler_root_switch(failure)",
        "runtime.cancel_terminal_kernel_root_switch(failure)",
        "runtime.cancel_terminal_primordial_root_switch(failure)",
    ] {
        let cancel = facade.find(cancel).unwrap();
        let reacquire = facade[..cancel]
            .rfind("let mut runtime = self.runtime.lock()")
            .unwrap();
        assert!(!facade[reacquire..cancel].contains("runtime.switch_cpu(self.cpu)"));
    }
    assert!(primordial.contains("self.select_root_switch_flight(executed.flight)"));
    assert!(primordial.contains("self.select_root_switch_flight(failure.flight)"));
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
