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
    let clang = host_tools::clang();
    let output = std::env::temp_dir().join(format!("deepwyrm-e4-syscall-{}.o", std::process::id()));
    let status = Command::new(&clang)
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
        .find("AcpiScratchReader::new(&mut active_paging, boot_info)")
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
    assert!(
        primordial
            .contains(".prepare_dispatch(request, self.own.scheduled().thread, root_generation)")
    );
    assert!(primordial.contains("self.core.services.dispatch_prepared("));
    assert!(primordial.contains("let phase = self.reserve_runtime_phase();"));
    assert!(primordial.contains("self.commit_runtime_phase(phase);"));

    // The carrier's handler, not the facade's (which comes first in the file). S2K-3 removed the
    // runtime guard-free check the reservation used to bracket: it could never fire (S2K design
    // §2.4 finding 1), and the `GuardFree` token now keeps physical boundaries out of the guard.
    // The reservation order stays pinned until D1 makes it live.
    let handle = primordial
        .split_once(
            "fn handle(&mut self, request: NativeSyscallRequest) -> crate::syscall::native::ReturnReady {",
        )
        .expect("carrier native handler")
        .1
        .split_once("\n    }\n")
        .expect("carrier native handler extent")
        .0;
    let reserve = handle
        .find("let phase = self.reserve_runtime_phase();")
        .unwrap();
    let commit = handle.find("self.commit_runtime_phase(phase);").unwrap();
    assert!(reserve < commit);

    for adapter in ["fn map_memory(", "fn unmap_memory(", "fn exit_process("] {
        let adapter = primordial.split_once(adapter).expect("staged adapter").1;
        let reserve = adapter
            .find("let phase = self.reserve_runtime_phase();")
            .unwrap();
        let commit = adapter.find("self.commit_runtime_phase(phase);").unwrap();
        assert!(reserve < commit, "{adapter}");
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

/// Text test: the post-acknowledgement carrier continuation is target-only primordial.rs code.
#[test]
fn i1_post_ack_carrier_never_reuses_a_retired_frame_for_late_holdsafe() {
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    let continuation = primordial
        .split_once("fn prepare_after_rendezvous_stop(&mut self) -> PreparedRendezvousNext")
        .expect("post-ack carrier continuation")
        .1
        .split_once("\n    }\n")
        .expect("post-ack carrier continuation end")
        .0;
    assert!(continuation.contains("complete_switch_on(stopped_claim)"));
    assert!(continuation.contains("self.drain_staged_rendezvous_cleanup();"));
    assert!(continuation.contains("terminal_reaper_next_on(self.cpu())"));

    let idle = primordial
        .split_once("fn enter_idle_scheduler(this: DivergentCarrier<'_, Self>) -> !")
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
        .find("self\n            .core\n            .rendezvous_reaper\n            .take()")
        .expect("irreversible reaper witness consume");
    assert!(stage < consume_reaper);
    let finalizers = primordial
        .split_once("fn drain_finalizers(&mut self)")
        .expect("post-ack finalizer drain")
        .1
        .split_once("fn prove_registry_capacity")
        .expect("finalizer drain extent")
        .0;
    assert!(finalizers.contains("while let Some(release) = self.core.cleanup.pop()"));
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
    assert!(dispatch.contains("let mut guard = self.runtime.lock();"));
    assert!(primordial.contains("fn stopped_service_state_is_quiescent(&self)"));
    assert!(primordial.contains(".operation_owner(self.own.scheduled().thread)"));
    assert!(primordial.contains("self.own.wait_control.is_clear()"));
    // The wait-before-reacquire order is static since S2K-3: `await_remote_stop_permits` takes a
    // `GuardFree` token, which the facade cannot mint while it holds the runtime guard, and the
    // reclaim is a carrier method, which only a guard reaches.
    assert!(primordial.contains("fn await_remote_stop_permits("));
    assert!(primordial.contains("    _guard_free: GuardFree<'_>,\n) -> ["));
    let await_ack = primordial.find("await_live_remote_stop(deferred)").unwrap();
    let helper = primordial.find("fn await_remote_stop_permits(").unwrap();
    assert!(helper < await_ack);
    assert!(primordial.contains("permits[cpu_index] = Some(permit)"));

    let adapters = source("src/syscall/adapters.rs");
    assert!(adapters.contains("prepare_process_terminate("));
    assert!(adapters.contains("complete_prepared_process_termination_after_remote_stops"));
    assert!(adapters.contains("execution.quiesce_terminal_threads(pins.thread_keys())"));
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
    assert!(runtime.contains("self.cpu(),"));
    assert!(adapters.contains("current_cpu: crate::cpu::CpuIndex"));
    assert!(adapters.contains("DeferredCurrentRetirement::Handoff"));
    assert!(adapters.contains("cpu: current_cpu"));
    assert!(runtime.contains("complete_deferred_current_reclaim_on("));
    assert!(adapters.contains("retire_quiesced_exit_pins_defer_current_after_remote_stops_on("));
}

/// Text test: switch acknowledgement ordering is target-only facade code in primordial.rs.
#[test]
fn i1_live_context_switch_acknowledges_from_the_destination_carrier() {
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");

    assert!(runtime.contains("fn complete_physical_switch_handoff(&mut self)"));
    assert!(runtime.contains(".complete_switch_on(outgoing)"));
    let fresh = runtime
        .rsplit_once("fn enter_scheduled_fresh_thread(this: DivergentCarrier<'_, Self>) -> !")
        .expect("live fresh-thread entry")
        .1
        .split_once("fn publish_scheduler_idle")
        .expect("live fresh-thread entry boundary")
        .0;
    let fresh_ack = fresh
        .find("runtime.complete_physical_switch_handoff()")
        .unwrap();
    let fresh_sync = fresh
        .find("if !this.synchronize_scheduler_current_at_safe_point_detached() {")
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
    assert!(resume.contains("let mut runtime = guard.on(&mut self.owned);"));
    assert!(resume.contains("runtime.resume_suspended(frame)"));

    // The facade's invalid return takes the remote-stop-aware terminal path
    // pinned below. (The carrier's direct copy, never reached, is deleted.)
    let invalid = runtime
        .split_once("fn invalid_return(&mut self, error:")
        .expect("live invalid-return terminal path")
        .1
        .split_once("fn user_exception(")
        .expect("live user-exception boundary")
        .0;
    assert!(invalid.contains("self.terminate_exception_with_remote_stops("));

    let remote_terminal = runtime
        .split_once("fn terminate_exception_with_remote_stops(")
        .expect("remote terminal exception path")
        .1
        .split_once("fn intercept_wyr1_evidence_raw(")
        .expect("remote terminal exception boundary")
        .0;
    let remote_switch = remote_terminal
        .find("let mut runtime = guard.on(&mut self.owned);")
        .expect("remote terminal carrier for this CPU");
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
        .find("await_remote_stop_permits(pending.deferred, self.runtime.guard_free())")
        .expect("remote terminal acknowledgement wait");
    let remote_final_sync = remote_terminal
        .rfind("self.synchronize_scheduler_current_after_remote_stops_detached();")
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

    let remote_completion = runtime
        .split_once("fn complete_remote_stop(")
        .expect("remote-stop completion facade")
        .1
        .split_once("fn authorize_return(")
        .expect("remote-stop completion boundary")
        .0;
    assert_eq!(
        remote_completion
            .matches("self.synchronize_scheduler_current_after_remote_stops_detached();")
            .count(),
        3
    );
    for completion in [
        "runtime.complete_process_termination(",
        "runtime.complete_task_group_termination(",
        "runtime.complete_thread_termination(",
    ] {
        let wait = remote_completion
            .find("await_remote_stop_permits(pending.deferred, self.runtime.guard_free())")
            .unwrap();
        let sync = remote_completion[wait..]
            .find("self.synchronize_scheduler_current_after_remote_stops_detached();")
            .unwrap()
            + wait;
        let complete = remote_completion[sync..].find(completion).unwrap() + sync;
        assert!(wait < sync && sync < complete);
    }

    let post_ack_helper = runtime
        .split_once("fn synchronize_scheduler_current_after_remote_stops_detached(")
        .expect("post-ack scheduler synchronization helper")
        .1
        .split_once("fn synchronize_scheduler_current_at_safe_point_detached(")
        .expect("post-ack scheduler synchronization boundary")
        .0;
    let suspended = post_ack_helper
        .find(".suspended_claim_on(self.cpu)")
        .unwrap();
    let physical = post_ack_helper
        .find("suspended.thread(),\n                            runtime.own.scheduled().thread")
        .unwrap();
    let prepare = post_ack_helper
        .find(".prepare_scheduler_root_switch()")
        .unwrap();
    let terminal = post_ack_helper
        .find(".terminal_scheduler_current_on(&runtime.core.tasks, self.cpu)")
        .unwrap();
    let terminal_owner = post_ack_helper
        .find("terminal,\n                                runtime.own.scheduled().thread")
        .unwrap();
    let process_root = post_ack_helper.find("active_root.process(),").unwrap();
    assert!(suspended < physical && physical < terminal && terminal < terminal_owner);
    assert!(terminal_owner < process_root && process_root < prepare);
    assert!(post_ack_helper.contains("None => runtime.prepare_scheduler_root_switch(),"));
    assert!(!post_ack_helper.contains("lost its physical scheduler claim"));
}

#[test]
fn i1_detached_scheduler_sync_honors_terminal_stop_publication() {
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");
    let live = source("src/arch/x86_64/syscall/live.rs");
    let syscall = source("src/arch/x86_64/syscall.rs");

    // S2K-6 ([DIVERGENT] in live.rs): each detached scheduler-root entry runs the safe-point
    // synchronization and, on a published Stop, the rendezvous handoff in its own frame, not
    // behind a `&mut self` helper.
    let stop_arm = "if !this.synchronize_scheduler_current_at_safe_point_detached() {";
    assert_eq!(
        runtime.matches(stop_arm).count(),
        3,
        "every detached scheduler-root entry must share Stop arbitration"
    );
    for entry in runtime.split(stop_arm).skip(1) {
        let handoff = entry.split_once('}').expect("detached Stop arm").0;
        assert!(handoff.contains("handoff_current_rendezvous_from_carrier("));
        assert!(handoff.contains("carrier.release()"));
        assert!(!handoff.contains("runtime.prepare_scheduler_root_switch()"));
    }
    assert!(!runtime.contains("fn synchronize_scheduler_current_detached("));

    let safe = runtime
        .split_once("fn synchronize_scheduler_current_at_safe_point_detached(")
        .expect("safe-point scheduler synchronization")
        .1
        .split_once("fn with_synchronized_runtime_at_safe_point")
        .expect("safe-point scheduler synchronization boundary")
        .0;
    let mailbox = safe
        .find("take_current_notification_at_safe_point()")
        .expect("preparation-time Stop arbitration");
    let barrier = safe
        .find("terminal_scheduler_current_on(&runtime.core.tasks, self.cpu)")
        .expect("terminal Stop publication barrier");
    let prepare = safe
        .find("runtime.prepare_scheduler_root_switch()")
        .expect("scheduler-root preparation");
    assert!(mailbox < barrier && barrier < prepare);

    let handoff = live
        .split_once("pub(crate) fn handoff_current_rendezvous_from_carrier(_release: super::CarrierRelease<'_>) -> !")
        .expect("detached carrier rendezvous handoff")
        .1
        .split_once("/// Called by the CPL3-origin e1 assembly boundary")
        .expect("detached carrier rendezvous handoff boundary")
        .0;
    let take = handoff
        .find("take_current_notification_at_safe_point()")
        .expect("exact Stop acquisition");
    let stage = handoff
        .find("stage_rendezvous_action(RendezvousAction(request))")
        .expect("exact Stop staging");
    let pivot = handoff
        .find("handoff_to_rendezvous_reaper(core::ptr::null_mut())")
        .expect("dedicated reaper pivot");
    assert!(take < stage && stage < pivot);
    assert!(syscall.contains("handoff_current_rendezvous_from_carrier"));
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
    let carrier = resume.find("= guard.on(&mut self.owned)").unwrap();
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
    assert!(!resume.contains("let no_current"));
    assert!(
        resume.contains(
            "suspended.thread(),\n                        runtime.own.scheduled().thread"
        )
    );
    assert!(resume.contains("suspended.thread(),\n                        deferred.thread()"));

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

/// Text test: that the suspended trampoline stages the terminal action before its reaper handoff
/// is control flow in the target-only trampoline, which no type orders.
#[test]
fn i2_terminal_reclaim_handoff_is_owned_by_the_exact_physical_cpu() {
    // The deferred current is owner-only by type since S2K-6 (TSV row 72): it lives in the
    // CPU's `CpuSharedState` slot, which only that CPU's owner can borrow mutably (see
    // `cpu_slots_mutate_only_through_their_owner` in `kernel/tests/root_switch_ui.rs`).
    let live = source("src/arch/x86_64/syscall/live.rs");

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
    assert!(activation.contains(
        "#[cfg(deepwyrm_wyr1d_evidence)]\nconst LIVE_ADDRESS_SPACE_CAPACITY: usize = 8;"
    ));
    assert!(
        activation.contains(
            "#[cfg(deepwyrm_dw1e_evidence)]\nconst LIVE_ADDRESS_SPACE_CAPACITY: usize = 8;"
        )
    );
    assert!(runtime.contains(
        "#[cfg(any(\n    deepwyrm_wyr1c_evidence,\n    deepwyrm_wyr1d_evidence,\n    deepwyrm_wyr1e_evidence,\n    deepwyrm_dw1e_evidence\n))]\nconst _: () = assert!(super::LIVE_ADDRESS_SPACE_CAPACITY >= USERSPACE_CHAIN_PROCESSES);"
    ));
    assert!(
        runtime.contains(
            "#[cfg(all(deepwyrm_i2_stress, not(deepwyrm_wrcap_relay)))]\nconst USERSPACE_CHAIN_PROCESSES: usize = 6;"
        )
    );
    assert!(runtime.contains("const USERSPACE_CHAIN_PROCESSES: usize = 3;"));
    assert!(
        runtime.contains(
            "#[cfg(deepwyrm_dw1d_evidence)]\nconst USERSPACE_CHAIN_PROCESSES: usize = 4;"
        )
    );
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
    // F3A.6y. Production derives this from the producer's measured archive
    // rather than pinning the Wave 4 literal; the other arms below still pin
    // their own forms, which is what keeps this selector's 32 distinct from
    // production's derived value.
    assert!(
        runtime.contains(
            "const PRIMORDIAL_BOOTFS_MAX_PAGES: usize = parse_production_bootfs_pages();"
        )
    );
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
fn the_production_product_selects_its_own_resource_geometry() {
    // DW1-F/WYR1-F F2A. Every capacity arm below used to key off an evidence
    // cfg, so the freestanding kernel that selects no guest test fell through
    // to the bootstrap-era DW0 geometry -- three Processes, one TaskGroup, ten
    // MemoryObjects, four wait registrations -- and could not instantiate the
    // frozen six-role WYR1-F product. Each arm is asserted by its exact text
    // because the failure is silent: the wrong arm compiles, links, and
    // produces an artifact whose shortfall appears only at boot.
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");
    for (name, field) in [
        ("REGISTRY_OBJECTS", "registry"),
        ("MEMORY_OBJECTS", "memory"),
        ("MEMORY_LEASES", "mappings"),
        ("USERSPACE_CHAIN_PROCESSES", "identities"),
        ("CHANNEL_PAIRS", "channel_pairs"),
        ("WAITERS", "waits"),
        ("TASK_GROUPS", "identities"),
        ("HANDLES", "handles"),
    ] {
        let arm = format!(
            "#[cfg(deepwyrm_production_product)]\nconst {name}: usize = super::production_resource_geometry::SELECTED.{field};"
        );
        assert!(runtime.contains(&arm), "missing production arm for {name}");
    }
    // The bootstrap-era arm must exclude the production product, or both arms
    // apply and the build breaks -- which is the loud outcome, but the
    // exclusion is what makes the production arm reachable at all.
    assert_eq!(
        runtime
            .matches("#[cfg(not(any(\n    deepwyrm_production_product,")
            .count(),
        8
    );
    // The ninth is the ten-handle drift guard, whose exclusion sits at the end
    // of its list rather than the start.
    assert_eq!(
        runtime
            .matches("    deepwyrm_production_product,\n)))]\nconst _: [(); 10] = [(); HANDLES];")
            .count(),
        1
    );
    assert!(
        runtime.contains("#[cfg(deepwyrm_production_product)]\nconst _: [(); 48] = [(); HANDLES];")
    );
    // The ledger is consulted, not restated: the arms name the selected
    // capacity rather than literals, so a demand change cannot drift from the
    // number the kernel links.
    assert!(!runtime.contains(
        "#[cfg(deepwyrm_production_product)]\nconst USERSPACE_CHAIN_PROCESSES: usize = 16;"
    ));

    let geometry = source("src/arch/x86_64/mm/activation/production_resource_geometry.rs");
    assert!(geometry.contains("const _: () = assert!(fits(SELECTED));"));
    assert!(geometry.contains(
        "const _: () = assert!(SELECTED.identities <= crate::memory::kernel_stack::E3_THREAD_STACK_COUNT);"
    ));
    assert!(geometry.contains("const _: () = assert!(SELECTED.evidence == 0);"));

    let activation = source("src/arch/x86_64/mm/activation.rs");
    assert!(activation.contains(
        "#[cfg(deepwyrm_production_product)]\nconst LIVE_ADDRESS_SPACE_CAPACITY: usize = production_resource_geometry::SELECTED.identities;"
    ));

    // The instrumented half of the same reconciliation. Since F3A.7k the
    // selector-35 siblings select the WYR1-F fairness ledger, and Wyrmroot's
    // WYR1-F receipt records `kernel_resource_geometry = "wyr1f-fairness"` with
    // a 64-handle, 192-entry, sixty-four-identity table. Wyrmroot cannot read
    // these arms, so they are asserted here, and a change to them fails in
    // this repository first. The arms name the ledger rather than literals,
    // and the ledger holds the figures.
    let squeezed: String = runtime.chars().filter(|c| !c.is_whitespace()).collect();
    for (name, field) in [
        ("USERSPACE_CHAIN_PROCESSES", "identities"),
        ("TASK_GROUPS", "identities"),
        ("HANDLES", "handles"),
        ("REGISTRY_OBJECTS", "registry"),
        ("MEMORY_OBJECTS", "memory"),
        ("MEMORY_LEASES", "mappings"),
        ("CHANNEL_PAIRS", "channel_pairs"),
    ] {
        assert!(
            squeezed.contains(&format!(
                "#[cfg(deepwyrm_wyr1f_fairness_evidence)]const{name}:usize=super::wyr1f_fairness_resource_geometry::SELECTED.{field};"
            )),
            "{name} does not select the fairness ledger"
        );
    }
    let fairness = source("src/arch/x86_64/mm/activation/wyr1f_fairness_resource_geometry.rs");
    for figure in ["handles: 64,", "identities: 64,", "registry: 192,"] {
        assert!(
            fairness.contains(figure),
            "fairness ledger no longer says {figure}"
        );
    }
    assert!(activation.contains(
        "#[cfg(deepwyrm_wyr1f_fairness_evidence)]\nconst LIVE_ADDRESS_SPACE_CAPACITY: usize = wyr1f_fairness_resource_geometry::SELECTED.identities;"
    ));
    let build = source("build.rs");
    assert!(build.contains("!wyr1e8 && selector == Some(WYR1F_CLOSURE_SELECTOR)"));
    // Without the emission, selector 35 falls back to the thirty-two-handle
    // arms and every gate still compiles.
    // The same condition also guards the supervisor-evidence relay, so any
    // guarded block may be the one that carries the emission.
    assert!(
        build
            .match_indices("if wyr1f_fairness_selected(Some(selector.as_str()), wyr1e8) {")
            .any(|(at, _)| build[at..].lines().nth(1).is_some_and(|line| {
                line.trim() == "println!(\"cargo:rustc-cfg=deepwyrm_wyr1f_fairness_evidence\");"
            })),
        "the closure selector no longer emits the fairness cfg"
    );
}

#[test]
fn live_uart_selectors_provision_overlapping_control_and_temt_timers() {
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");

    assert!(runtime.contains(
        "#[cfg(not(any(\n    deepwyrm_i2_stress,\n    deepwyrm_dw1e_evidence,\n    deepwyrm_wyr1d_evidence,\n    deepwyrm_wyr1e_evidence,\n    deepwyrm_production_product\n)))]\nconst TIMERS: usize = 1;"
    ));
    assert!(runtime.contains(
        "#[cfg(any(\n    deepwyrm_i2_stress,\n    deepwyrm_dw1e_evidence,\n    deepwyrm_wyr1d_evidence,\n    deepwyrm_wyr1e_evidence,\n    deepwyrm_production_product\n))]\nconst TIMERS: usize = 2;"
    ));
    assert!(runtime.contains(
        "#[cfg(any(\n    deepwyrm_dw1e_evidence,\n    deepwyrm_wyr1d_evidence,\n    deepwyrm_wyr1e_evidence,\n    deepwyrm_production_product\n))]\nconst _: [(); 2] = [(); TIMERS];"
    ));
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

    let statements: Vec<_> = service.lines().map(str::trim).collect();
    assert!(statements.windows(2).any(|pair| pair
        == [
            "frame.revoke_authorized_return();",
            "switch_kernel_context(plan);"
        ]));
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
    assert!(runtime.contains(".expire(token, &self.core.shared.waits)"));
    assert!(runtime.contains("timer_expiries:\n        IrqSpinMutex<"));
    // D1 commits 5 and 6 add the family-A and family-B preparation holds,
    // which service CPU0's timer expiries exactly like the ordinary hold.
    assert_eq!(
        runtime
            .matches("runtime.service_pending_timer_expiries_on_bootstrap();")
            .count(),
        6
    );
    let shared_carrier = runtime
        .split_once(
            "impl<'runtime, 'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>\n    NativeSyscallFrameRuntime\n    for RuntimeCarrierFacade",
        )
        .expect("shared native carrier callbacks")
        .1;
    let timer_return = shared_carrier
        .split_once("fn has_reschedule_request(&mut self) -> bool {")
        .expect("shared native carrier reschedule callback")
        .1
        .split_once("fn authorize_timer_return")
        .expect("shared native carrier reschedule callback extent")
        .0;
    let expiry_service = timer_return
        .find("runtime.service_pending_timer_expiries_on_bootstrap();")
        .expect("timer-return expiry service");
    let reschedule = timer_return
        .find("runtime.has_reschedule_request()")
        .expect("timer-return reschedule decision");
    assert!(expiry_service < reschedule);
    let idle_scheduler = shared_carrier
        .split_once("fn enter_idle_scheduler(this: DivergentCarrier<'_, Self>) -> !")
        .expect("shared native carrier idle scheduler")
        .1
        .split_once("unsafe fn prepare_suspend")
        .expect("shared native carrier idle scheduler extent")
        .0;
    let idle_expiry_service = idle_scheduler
        .find("runtime.service_pending_timer_expiries_on_bootstrap();")
        .expect("kernel-root idle expiry service");
    let idle_schedule = idle_scheduler
        .find(".schedule_next_on(this.cpu)")
        .expect("kernel-root idle scheduler decision");
    assert!(idle_scheduler.contains("this.cpu == crate::cpu::CpuIndex::BOOTSTRAP"));
    assert!(idle_expiry_service < idle_schedule);
    assert!(idle_scheduler.contains(
        ".current\n            };\n            crate::task::drain_runnable_work_notifications();"
    ));
    assert!(
        runtime
            .matches("self.cpu == crate::cpu::CpuIndex::BOOTSTRAP")
            .count()
            >= 2
    );
}

#[test]
fn q35_external_entry_binds_the_selector_runtime_and_live_eoi_targets() {
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    let external = source("src/arch/x86_64/external_interrupt.rs");
    let ipi = source("src/arch/x86_64/ipi.rs");
    let live_time = source("src/time/live.rs");

    let publish = primordial
        .split_once("fn publish_runtime_shared(")
        .expect("primordial shared-runtime publication")
        .1
        .split_once("impl crate::arch::x86_64::external_interrupt::Q35ExternalInterruptHandler")
        .expect("primordial q35 handler boundary")
        .0;
    assert!(publish.contains("bind_q35_external_interrupt_handler(target)"));

    let handler = primordial
        .split_once("impl crate::arch::x86_64::external_interrupt::Q35ExternalInterruptHandler")
        .expect("primordial q35 handler")
        .1
        .split_once("fn complete_q35_handler_after_eoi")
        .expect("primordial post-EOI callback boundary")
        .0;
    assert!(handler.contains("complete_q35_handler_after_eoi,"));

    let handler_binding = external
        .split_once("pub(crate) fn bind_q35_external_interrupt_handler<")
        .expect("generic q35 handler binding")
        .1
        .split_once("unsafe fn dispatch_handler<")
        .expect("generic q35 handler trampoline boundary")
        .0;
    assert!(handler_binding.contains("dispatch: dispatch_handler::<T>,"));

    let time_initialize = live_time
        .split_once("pub(crate) fn initialize<")
        .expect("live-time initialization")
        .1
        .split_once("struct TimeInitPlan")
        .expect("live-time plan boundary")
        .0;
    assert!(time_initialize.contains("bind_live_ipi_transport(&LIVE_IPI_TRANSPORT)"));

    let transport_binding = ipi
        .split_once("pub(crate) fn bind_live_ipi_transport<")
        .expect("generic live IPI binding")
        .1
        .split_once("unsafe fn transport_send<")
        .expect("generic live IPI send boundary")
        .0;
    assert!(transport_binding.contains("eoi: transport_eoi::<T>,"));
}

/// Text test: live dispatch coverage is target-only primordial.rs wiring (D1 builds a host router).
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
    assert!(runtime.contains("crate::syscall::prepare_process_unhandled_exception("));
    assert!(adapters.contains("pub(crate) fn prepare_process_unhandled_exception<"));
    assert!(
        runtime.contains(
            "crate::syscall::complete_prepared_process_termination_after_remote_stops_on("
        )
    );
}

/// Text test: the terminal handoff is target-only primordial.rs code until the D2 terminal engine.
#[test]
fn i1_terminal_child_without_local_work_rejoins_the_idle_scheduler() {
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");

    assert!(runtime.contains("enum PreparedTerminalHandoff"));
    assert!(runtime.contains("if retirement.retired_process != self.core.primordial_process"));
    assert!(runtime.contains("self.finish_inactive_process_teardown("));
    assert!(runtime.contains("PreparedTerminalHandoff::IdleScheduler"));
    assert!(runtime.contains("syscall::enter_bound_idle_scheduler(carrier.release())"));
    // The live terminal path (S2K-3.1 re-anchored it off the carrier's
    // never-reached copy): retirement state, the detached handoff and its
    // continuations.
    let terminal = runtime
        .split_once("fn prepare_terminal_retirement_state(")
        .expect("terminal handoff")
        .1
        .split_once("fn reserve_runtime_phase")
        .expect("terminal handoff terminator")
        .0;
    let primordial_unmap = terminal
        .find("self.unmap_primordial_userspace(&proof)")
        .unwrap();
    let next_selection = terminal
        .find("terminal_reaper_next_on(self.cpu())")
        .unwrap();
    assert!(primordial_unmap < next_selection);
    // With no successor, a retiring WYR1 primordial enters the kernel root
    // first and is retired only by that root switch's continuation.
    let no_successor = terminal
        .split_once("if retirement.retiring_wyr1_primordial {")
        .expect("WYR1 no-successor branch")
        .1
        .split_once("\n        }\n")
        .expect("WYR1 no-successor branch end")
        .0;
    assert!(no_successor.contains("self.prepare_terminal_kernel_root_switch()"));
    assert!(no_successor.contains("TerminalKernelContinuation::RetireWyr1Primordial(retirement)"));
    let retire = terminal
        .split_once("TerminalKernelContinuation::RetireWyr1Primordial(mut retirement) =>")
        .expect("WYR1 primordial kernel-root continuation")
        .1
        .split_once("TerminalKernelContinuation::RetireWyr1Child")
        .expect("WYR1 primordial kernel-root continuation end")
        .0;
    assert!(retire.contains("self.finish_quiesced_process_root_retirement("));
    assert!(!retire.contains("self.unmap_primordial_userspace("));
    assert!(!retire.contains("self.finish_inactive_process_teardown("));
    assert!(!terminal.contains("terminal idle safe-root"));
}

/// Text test: the terminal handoff is target-only primordial.rs code until the D2 terminal engine.
#[test]
fn wyr1_terminal_child_after_primordial_retirement_uses_its_current_root() {
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");
    // The live terminal path (re-anchored by S2K-3.1, as above).
    let terminal = runtime
        .split_once("fn prepare_terminal_retirement_state(")
        .expect("terminal handoff")
        .1
        .split_once("fn reserve_runtime_phase")
        .expect("terminal handoff terminator")
        .0;
    let retired_child = terminal
        .split_once(
            "if retirement.retired_process != self.core.primordial_process && primordial_retired {",
        )
        .expect("WYR1 retired-primordial child branch")
        .1
        .split_once("\n        if retirement.retired_process != self.core.primordial_process {")
        .expect("legacy retained-primordial child branch")
        .0;
    let retirement_fact = terminal
        .split_once("let primordial_retired = match")
        .expect("WYR1 primordial retirement fact")
        .1
        .split_once(
            "if retirement.retired_process != self.core.primordial_process && primordial_retired {",
        )
        .expect("WYR1 retired-primordial child branch")
        .0;
    let unmap = retired_child.find("self.unmap_current_userspace(").unwrap();
    let kernel_root = retired_child
        .find("self.prepare_terminal_kernel_root_switch()")
        .unwrap();
    let reporter_guard = retired_child.find("if retiring_reporter {").unwrap();
    let reporter_info = retired_child
        .find(".process_info(retirement.retired_process)")
        .unwrap();
    let reporter_failure = retired_child
        .find("crate::test_support::complete_fail(detail)")
        .unwrap();
    // The root is retired, and the CPU idles, only in the kernel-root
    // switch's continuation, after the CR3 switch the facade executes.
    let continuation = terminal
        .split_once("TerminalKernelContinuation::RetireWyr1Child {\n                retirement,")
        .expect("WYR1 child kernel-root continuation")
        .1
        .split_once("TerminalKernelContinuation::EnterPrimordialPublisher")
        .expect("WYR1 child kernel-root continuation end")
        .0;
    let retirement = continuation
        .find("self.finish_quiesced_process_root_retirement(")
        .unwrap();
    let idle = continuation
        .find("self.owned.physically_executing.record_idle()")
        .unwrap();

    assert!(reporter_guard < reporter_info);
    assert!(reporter_info < reporter_failure);
    assert!(reporter_failure < unmap);
    assert!(retired_child.contains("if info.application_code == 0"));
    assert!(retired_child.contains("supervisor_evidence_detail(0xd014)"));
    assert!(retired_child.contains("TerminalKernelContinuation::RetireWyr1Child {"));
    assert!(runtime.contains("return 0x2510_0000 | case;"));
    assert!(runtime.contains("return 0x2710_0000 | case;"));
    assert!(unmap < kernel_root);
    assert!(retirement < idle);
    assert!(
        retirement_fact.contains("Ok(None) | Err(crate::task::TaskError::InvalidTask) => true")
    );
    assert!(retirement_fact.contains("Ok(Some(_)) => false"));
    assert!(retirement_fact.contains("supervisor_evidence_detail(0xd00d)"));
    assert!(!retired_child.contains("prepare_process_root_selection("));
    assert!(!retired_child.contains("self.core.primordial_address_space"));
}

/// Text test: the completion-failure details are emitted only on the target-only terminal path.
#[test]
fn wyr1_primordial_completion_failures_have_variant_specific_details() {
    let runtime = source("src/arch/x86_64/mm/activation/primordial.rs");
    let diagnostic = source("src/arch/x86_64/mm/activation/primordial_diagnostic.rs");
    // The live terminal path (re-anchored by S2K-3.1 off the carrier's
    // never-reached copy, which alone formatted the detail call over lines).
    let terminal = runtime
        .split_once("fn prepare_terminal_retirement_state(")
        .expect("terminal handoff")
        .1
        .split_once("fn reserve_runtime_phase")
        .expect("terminal handoff extent")
        .0;

    assert!(terminal.contains(
        "if retiring_wyr1_primordial && let Err(error) = validate_primordial_retirement_facts(self)"
    ));
    assert!(terminal.contains("let terminal_info = self.core.g5_probe.terminal_info;"));
    assert!(terminal.contains("complete_fail(primordial_completion_detail(error, terminal_info))"));
    assert!(!terminal.contains("supervisor_evidence_detail(0xd001)"));

    for mapping in [
        "PrimordialCompletionError::MalformedReady(_) => 0xd200",
        "PrimordialCompletionError::ObserveExit(code) => 0xd300 | (code & 0xff)",
        "PrimordialCompletionError::NonzeroExit(code) => 0xd400 | (code & 0xff)",
        "PrimordialCompletionError::UnhandledException => 0xd500",
        "PrimordialCompletionError::AuthorizedTermination => 0xd600",
        "PrimordialCompletionError::NotQuiescent(code, _) => 0xd700 | (code & 0xff)",
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
        .find("exited_process.filter(|target| *target != self.own.scheduled().process)")
        .expect("external final-Process guard");
    let teardown = completion
        .find("self.finish_inactive_process_teardown(")
        .expect("inactive final-Process teardown");

    assert!(preserve < retire && retire < resources);
    assert!(resources < external_guard && external_guard < teardown);
    assert!(completion.contains("control == SyscallControl::ReturnToCaller"));
}

/// Text test: the F-service, wait-engine and adapter seams take the suspension CPU as a
/// `CpuIndex` argument, a value no type ties to the physical CPU. (The primordial carrier's CPU is
/// static since S2K-6, TSV row 85: `PrimordialRuntimeCarrier::cpu` is its `CpuOwner`'s, with no
/// field to reselect.)
#[test]
fn i1_live_wait_suspension_uses_the_physical_current_cpu() {
    let services = source("src/syscall/f_services.rs");
    let adapters = source("src/syscall/adapters.rs");
    let waits = source("src/wait/engine.rs");

    assert!(services.contains("wait_many_syscall_on("));
    assert!(services.contains("wait_one_syscall_on("));
    assert!(services.contains("current_cpu,"));
    assert!(waits.contains("prepare_block_current_on(cpu, thread)"));
    assert!(waits.contains("cancel_block_on(cpu, block)"));
    assert!(waits.contains("commit_published_block_on(cpu, block)"));
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

    // Text test: which authorities the stationary shared runtime holds is a field list no type
    // orders.
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
    // The primordial per-CPU binding is static since S2K-6 (TSV row 89): each facade holds its
    // CPU's runtime-authority handle (minted once, not Clone) and its `CpuOwnedState`, whose
    // `CpuOwner` (minted once, unforgeable, not Clone) is the only key to that CPU's slot and the
    // only source of its carrier's CPU. See `kernel/tests/root_switch_ui.rs`.
}

/// Text test: facade binding and per-CPU carrier publication are target-only live wiring in
/// primordial.rs, which no host test compiles.
#[test]
fn i1_stationary_foundation_keeps_authority_and_carrier_boundaries_explicit() {
    let stationary = source("src/arch/x86_64/syscall/stationary_runtime.rs");
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");

    // S2K-1 deleted the never-instantiated RuntimeCore/PagingAuthority family
    // and S2K-3 its guard-depth check; the reservation remains.
    assert!(stationary.contains("struct RuntimePhaseReservation"));
    assert!(primordial.contains("struct PhysicallyExecuting {"));
    assert!(primordial.contains("    physically_executing: PhysicallyExecuting,"));
    assert!(primordial.contains("    owned: CpuOwnedState,"));
    assert!(
        primordial
            .contains("let live_cpu_count = bind_runtime_carrier_facades(facades, publishers);")
    );
    assert!(primordial.contains(
        "release_runtime_carrier_facades(\n        shared,\n        unsafe { &mut (*facades.as_ptr()).runtime },"
    ));
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
    assert!(primordial.contains("current_thread_on(self.cpu())"));
    // D1 commit 3: the CPU is read before P is taken beneath the guard.
    assert!(primordial.contains(
        "let cpu = self.cpu();\n        let prepared = self\n            .paging\n            .lock()\n            .prepare_process_root_selection(cpu, process, address_space)"
    ));
    assert!(primordial.contains("terminal_reaper_next_on(self.cpu())"));
    assert!(primordial.contains("schedule_next_on(this.cpu)"));
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
    assert!(primordial.contains("prepare_runtime_carrier_admission(facades, live_cpu_count)"));
    assert!(primordial.contains("#[cfg(deepwyrm_dw1c_evidence)]\n    assert_eq!("));
    assert!(primordial.contains("for cpu_index in 1..live_cpu_count {"));
    assert!(primordial.contains("normalize_bootstrap_carrier(facades)"));
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

/// Text test: Stacked/Tree Borrows validity of the published facade pointers is invisible to the
/// type system and to host tests (the pinned toolchains ship no Miri), and `enter` is target-only.
#[test]
fn f1_facades_are_reached_only_through_their_published_pointers() {
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    let enter = primordial
        .split_once("pub(super) fn enter(")
        .expect("primordial enter")
        .1;
    // S2K-4: the runtime lives in permanent storage, not on `enter`'s boot-stack frame.
    assert!(
        !enter.contains("core::pin::pin!("),
        "a runtime object is pinned on the boot stack"
    );
    // S2K stage 4: it is built in place there, so no whole-lock temporary exists on that frame.
    assert!(enter.contains("PRIMORDIAL_RUNTIME_AUTHORITY.init_in_place("));
    assert!(
        !enter.contains("RuntimeAuthorityLock::new("),
        "the runtime authority is built as a temporary and then moved"
    );
    // The storage's one `&'static mut` is consumed once into the base pointer; nothing after it
    // re-derives a reference to the array or a facade, and CPU0 enters through the published
    // pointer itself.
    let base_anchor = "core::ptr::NonNull::from(PRIMORDIAL_FACADES.init(facades))";
    let base = enter
        .find(base_anchor)
        .expect("one base pointer from the facade storage");
    let after = &enter[base + base_anchor.len()..];
    for forbidden in [
        "get_unchecked_mut",
        "Pin::new_unchecked",
        "facades.as_mut()",
        "facades_mut",
        "&mut facades[",
        "enter_native_syscall_runtime(",
        "PRIMORDIAL_FACADES",
    ] {
        assert!(
            !after.contains(forbidden),
            "a published facade is re-borrowed after publication: {forbidden}"
        );
    }
    assert!(
        after.contains("let live_cpu_count = bind_runtime_carrier_facades(facades, publishers);")
    );
    assert!(after.contains("enter_published_native_syscall_runtime(\n            facades,"));
    let bind = primordial
        .split_once("fn bind_runtime_carrier_facades<")
        .expect("facade publication")
        .1
        .split_once("\n}\n")
        .expect("facade publication extent")
        .0;
    assert!(bind.contains("let carrier = unsafe { facades.add(cpu_index) };"));
    assert!(!bind.contains("get_unchecked_mut") && !bind.contains("Pin::new_unchecked"));
}

/// Text test: how the target-only divergent entry retains its carrier is visible to no host test.
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
    // F1 (S2K): the divergent entry retains the carrier as the raw pointer it was published with,
    // taken once from the caller's pin, so no `&mut` is retagged over the published address.
    assert!(divergent_entry_api.contains("runtime: core::pin::Pin<&'runtime mut R>"));
    assert!(live.contains("    runtime: core::ptr::NonNull<R>,\n"));
    assert!(live.contains("let entry = NativeSyscallRuntimeEntry {\n        runtime,\n"));
    assert!(live.contains("unsafe { entry.enter(state, stack, exception_binding) }"));
    assert!(live.contains("let context = self.runtime.as_ptr();"));
    assert!(!live.contains("Pin::get_unchecked_mut(self.runtime.as_mut())"));
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

/// Text test: that the shared F-service state holds no wait control is the absence of a field in
/// a host type, which no positive type fact states.
#[test]
fn i1_live_wait_control_is_owned_by_each_physical_cpu_carrier() {
    // Each CPU's wait control is owner-only by type since S2K-6 (TSV row 96): it lives in the
    // CPU's `CpuSharedState` slot, which only that CPU's owner can borrow mutably (see
    // `cpu_slots_mutate_only_through_their_owner` in `kernel/tests/root_switch_ui.rs`).
    let services = source("src/syscall/f_services.rs");
    assert!(
        !services.contains("control: NativeWaitControl,"),
        "shared F-service state must not own one cross-CPU suspension handoff"
    );
}

/// Text test: the two post-dispatch mailbox rechecks are control flow inside the target-only
/// trampoline, which no type orders. (The entry poll before usercopy is static since S2K-3: the
/// usercopy window takes the `SafePointClear` only `poll_entry_safe_point` mints.)
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
    let usercopy = trampoline
        .find("NativeUsercopyWindow::enter_current(safe_point)")
        .expect("usercopy entry");
    let dispatch = trampoline
        .find("dispatch_frame(runtime, frame")
        .expect("native dispatch");
    assert!(usercopy < dispatch);
    assert!(
        trampoline
            .match_indices("take_current_notification_at_safe_point()")
            .count()
            >= 2,
        "post-dispatch and rendezvous-control seams must poll the authoritative mailbox"
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

/// Text test: that the AP revalidates its private resources after entering its kernel root and
/// before publishing ready is control flow in the target-only facade. (Entering the root before
/// the ready publication is static since S2K D5: the publication takes the executing state only
/// the entry's commit mints.)
#[test]
fn dw1c1_ap_carrier_enters_its_exact_kernel_root_before_ready_publication() {
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    let idle = primordial
        .split_once("fn enter_idle_scheduler(this: DivergentCarrier<'_, Self>) -> !")
        .expect("live idle carrier")
        .1
        .split_once("\n    }\n")
        .expect("live idle carrier extent")
        .0;
    let root = idle
        .find("let executing = this.enter_ap_kernel_root_detached();")
        .unwrap();
    let resources = idle.find("carrier_resource_tuple(").unwrap();
    let ready = idle
        .find("publish_ap_carrier_ready(ticket, resources, executing)")
        .unwrap();
    assert!(root < resources && resources < ready);
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
        .rsplit_once("fn terminate_current(this: DivergentCarrier<'_, Self>) -> !")
        .expect("runtime facade terminal path")
        .1
        .split_once("fn enter_scheduled_fresh_thread")
        .expect("runtime facade terminal boundary")
        .0;
    assert!(facade.contains("runtime.prepare_terminal_handoff_detached()"));
    assert!(!facade.contains("runtime.prepare_terminal_handoff()"));
    // Every terminal root switch runs outside the runtime guard, and every commit after it under
    // a reacquired guard: static since S2K-3 (`execute` takes a `GuardFree` token and the commits
    // are carrier methods; see `kernel/tests/root_switch_ui.rs`). No commit can reselect a CPU
    // either, since S2K-6 (TSV row 103's residual): a carrier is built only for its owner's CPU,
    // with no CPU field to reselect, and the flight's commit checks the flight's CPU and
    // generation against that carrier.
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

/// Text test (D1 commit 5, design §11.2.3 family A): `AbiGetInfo` and
/// `ClockGet` are served by the facade with their usercopy outside every
/// runtime-authority hold. P is taken alone through a `GuardFree`, from a
/// copied root identity that is revalidated before the walk. The facade is
/// target-only, so its routing is pinned here; the type facts are UI cases.
#[test]
fn family_a_usercopy_runs_guard_free() {
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    let helper = primordial
        .split_once("    fn handle_guard_free_usercopy(")
        .expect("family-A facade helper")
        .1
        .split_once("\n    }\n")
        .expect("family-A facade helper extent")
        .0;
    assert!(helper.contains(
        "NativeSyscallRequest::AbiGetInfo { .. } | NativeSyscallRequest::ClockGet { .. }"
    ));
    let prepare = helper
        .find("runtime.prepare_guard_free_usercopy()")
        .expect("guarded preparation");
    let copy = helper
        .find("self.paging.guard_free_access(self.runtime.guard_free())")
        .expect("guard-free P access");
    let walk = helper
        .find("paging.usercopy_process_address_space(root, process)")
        .expect("revalidated copied root");
    let commit = helper
        .find("runtime.commit_runtime_phase(phase);")
        .expect("phase commit");
    assert!(prepare < copy && copy < walk && walk < commit);
    assert!(primordial.contains(
        "let handled = match self\n                .handle_guard_free_usercopy(request)\n                .or_else(|| self.handle_deferred_output(request))\n            {"
    ));
    assert!(primordial.contains(
        "NativeSyscallRequest::AbiGetInfo { .. } => {\n                unreachable!(\"AbiGetInfo must be served guard-free by the CPU-local facade\")"
    ));
}

/// Text test (D1 commit 6, design §11.2.3 family B): eight single-output
/// syscalls pin their output before the runtime authority, run the unchanged
/// adapter under it against a `DeferredUserOutput`, and copy the recorded
/// bytes out after it, with no runtime lock held for either copy step.
#[test]
fn family_b_outputs_are_pinned_before_and_written_after_the_hold() {
    let primordial = source("src/arch/x86_64/mm/activation/primordial.rs");
    let helper = primordial
        .split_once("    fn handle_deferred_output(")
        .expect("family-B facade helper")
        .1
        .split_once("\n    }\n")
        .expect("family-B facade helper extent")
        .0;
    for request in [
        "NativeSyscallRequest::HandleDuplicate { out_handle, .. }",
        "NativeSyscallRequest::TaskGroupCreate { out_handle, .. }",
        "NativeSyscallRequest::ThreadCreate { out_thread, .. }",
        "NativeSyscallRequest::DeviceResourceClaim { out_resource, .. }",
        "NativeSyscallRequest::DevicePioRead { out_value, .. }",
        "NativeSyscallRequest::InterruptCreate { out_interrupt, .. }",
        "NativeSyscallRequest::EventCreate { out_event, .. }",
        "NativeSyscallRequest::TimerCreate { out_timer, .. }",
    ] {
        assert!(helper.contains(request), "family B omits {request}");
    }
    let prepare = helper
        .find("runtime.prepare_guard_free_usercopy()")
        .expect("guarded preparation");
    let pin = helper
        .find("user.preflight_owned_output(range)")
        .expect("early owned preflight");
    let run = helper
        .find("runtime.run_deferred_output(request, &mut deferred);")
        .expect("guarded adapter run");
    let copy = helper
        .find(".commit_owned_output(output, bytes)")
        .expect("guard-free copy-out");
    assert!(prepare < pin && pin < run && run < copy);
    // The adapter's preflight succeeds only if the early one pinned the range.
    assert!(helper.contains(
        "DeferredUserOutput::new(\n            pinned.as_ref().map(|(range, _)| *range),\n        );"
    ));
    assert_eq!(
        helper
            .matches("self.paging.guard_free_access(self.runtime.guard_free())")
            .count(),
        2,
        "both copy steps take P alone"
    );
    assert!(
        primordial
            .contains("\"family-B requests are served by the CPU-local facade's deferred output\"")
    );
}
