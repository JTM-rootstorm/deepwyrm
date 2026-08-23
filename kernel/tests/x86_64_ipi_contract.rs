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
        .find("RENDEZVOUS_HANDLER.get()")
        .expect("rendezvous callback");
    assert!(
        eoi < handler,
        "EOI must precede a possibly waiting stop callback"
    );
    assert!(dispatch.contains("halt_without_return()"));
    assert!(ipi.contains("bind_live_rendezvous_handler(handler: fn())"));
    assert!(ipi.contains("bind_live_tlb_shootdown_handler(handler: fn())"));
    assert!(ipi.contains("static RENDEZVOUS_HANDLER: BindingSlot<fn()>"));
    assert!(ipi.contains("static TLB_SHOOTDOWN_HANDLER: BindingSlot<fn()>"));
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
fn h4_remote_deadline_mutation_notifies_only_the_bsp_timer_service_over_e1() {
    let live = source("src/time/live.rs");
    for evidence in [
        "static BSP_TIMER_SERVICE: TimerServiceSignal",
        ".publish()",
        "send_live_ipi(bsp.local_apic_id, LiveIpiVector::Rendezvous)",
        "BSP_TIMER_SERVICE.fail_transport()",
        "match BSP_TIMER_SERVICE.take()",
        "installed_current_cpu_index() == Ok(CpuIndex::BOOTSTRAP)",
        "bind_live_rendezvous_handler(live_rendezvous_handler)",
    ] {
        assert!(
            live.contains(evidence),
            "H4 BSP timer-service dispatch omitted `{evidence}`"
        );
    }

    let request = live
        .split_once("fn request_bsp_timer_service()")
        .expect("H4 BSP timer-service request")
        .1
        .split_once("fn service_bsp_timer_request()")
        .expect("H4 BSP timer-service request extent")
        .0;
    assert!(request.contains("LiveIpiVector::Rendezvous"));
    assert!(!request.contains("LiveIpiVector::TlbShootdown"));
    assert!(
        request
            .matches("BSP_TIMER_SERVICE.fail_transport()")
            .count()
            >= 3
    );
    assert!(request.contains("Err(error) => {"));
    assert!(request.contains("let Some(bsp) ="));

    let ap_init = live
        .split_once("pub(crate) fn initialize_ap_local_apic")
        .expect("AP local-APIC initializer")
        .1
        .split_once("pub(crate) fn send_bsp_ipi")
        .expect("AP local-APIC initializer extent")
        .0;
    assert!(ap_init.contains("configure_one_shot_timer"));
    assert!(!ap_init.contains("program_one_shot_timer"));

    let apic = source("src/arch/x86_64/apic.rs");
    let masked_timer = apic
        .split_once("pub fn configure_one_shot_timer")
        .expect("masked one-shot configuration")
        .1
        .split_once("pub fn start_timer_calibration")
        .expect("masked one-shot configuration extent")
        .0;
    assert!(masked_timer.contains("APIC_LVT_MASKED"));
    assert!(masked_timer.contains("APIC_TIMER_INITIAL_COUNT, 0"));

    let service = source("src/time/service.rs");
    for evidence in [
        "pending: AtomicBool",
        "faulted: AtomicBool",
        "self.pending.store(true, Ordering::Release)",
        "self.faulted.store(true, Ordering::Release)",
        "self.pending.swap(false, Ordering::AcqRel)",
        "self.ensure_healthy()?",
    ] {
        assert!(
            service.contains(evidence),
            "H4 ambiguous timer transport guard omitted `{evidence}`"
        );
    }
    let timer_dispatch = live
        .split_once("pub(crate) extern \"sysv64\" fn dw_x86_64_timer_interrupt_dispatch()")
        .expect("BSP timer dispatch")
        .1
        .split_once("fn read_pm_timer")
        .expect("BSP timer dispatch extent")
        .0;
    let health = timer_dispatch
        .find("BSP_TIMER_SERVICE.ensure_healthy()")
        .expect("global timer-service fault check");
    let queue = timer_dispatch
        .find("state.interrupt()")
        .expect("deadline queue interrupt service");
    assert!(health < queue);
}

#[test]
fn h4_idle_publication_brackets_rescan_and_uses_only_coalesced_e1_wake() {
    let idle = source("src/arch/x86_64/idle.rs");
    for evidence in [
        "RendezvousMailbox",
        "self.mailboxes[index].publish_wake()",
        "faulted: AtomicBool",
        "self.faulted.store(true, Ordering::Release)",
        "super::ipi::LiveIpiVector::Rendezvous",
        "CPU_PREPARING",
        "CPU_HALTED",
        "finish_transition(halt.cpu, halt.generation, CPU_HALTED, CPU_ACTIVE)",
    ] {
        assert!(idle.contains(evidence), "H4 idle seam omitted `{evidence}`");
    }
    assert!(!idle.contains("LiveIpiVector::TlbShootdown"));
    assert!(idle.contains("for offset in 1..CPU_CAPACITY"));
    assert!(idle.contains("publish_affine_runnable(publisher, owner)"));
    let live_notify = idle
        .split_once("pub(crate) fn notify_runnable_work(affinity: Option<CpuIndex>)")
        .expect("live runnable notifier")
        .1
        .split_once("pub(crate) fn take_current_notification()")
        .expect("live runnable notifier extent")
        .0;
    assert_eq!(live_notify.matches("fail_transport_and_halt()").count(), 4);
    let transport_fault = idle
        .split_once("fn fail_transport_and_halt()")
        .expect("idle transport-fault handler")
        .1
        .split_once("#[cfg(test)]")
        .expect("idle transport-fault handler extent")
        .0;
    assert!(transport_fault.contains("LIVE_IDLE_WAKE.fail_transport()"));

    let live_syscall = source("src/arch/x86_64/syscall/live.rs");
    let suspension = live_syscall
        .split_once("crate::syscall::native::NativeSuspendPlan::IdleCurrent => loop")
        .expect("native idle-suspend loop")
        .1
        .split_once("let generation = current_binding_generation()")
        .expect("native idle-suspend loop extent")
        .0;
    let prepare = suspension.find("prepare_current_idle()").unwrap();
    let poll = suspension.find("runtime.poll_idle_suspend(frame)").unwrap();
    let commit = suspension.find("commit_current_idle(idle)").unwrap();
    let halt = suspension.find("wait_for_suspend_interrupt()").unwrap();
    let finish = suspension.find("finish_current_idle(halt)").unwrap();
    assert!(prepare < poll && poll < commit && commit < halt && halt < finish);
    assert_eq!(suspension.matches("cancel_current_idle(idle)").count(), 2);
    assert!(suspension.contains("SYSCALL FMASK keeps IF clear"));

    let wait = live_syscall
        .split_once("fn wait_for_suspend_interrupt()")
        .expect("architectural idle halt")
        .1
        .split_once("dw_x86_64_first_run_thread_entry")
        .expect("architectural idle halt extent")
        .0;
    assert!(wait.contains("core::arch::asm!(\"sti\", \"hlt\", \"cli\""));
    let msr = source("src/arch/x86_64/syscall/msr.rs");
    assert!(msr.contains("pub(crate) const E4_FMASK: u64 = 0x001f_7700"));
    assert_ne!(
        0x001f_7700_u64 & (1 << 9),
        0,
        "FMASK must clear IF on SYSCALL"
    );

    let time_live = source("src/time/live.rs");
    let timer_dispatch = time_live
        .split_once("pub(crate) extern \"sysv64\" fn dw_x86_64_timer_interrupt_dispatch()")
        .unwrap()
        .1
        .split_once("fn read_pm_timer")
        .unwrap()
        .0;
    assert!(timer_dispatch.contains("live_idle_wake_is_healthy()"));

    let execution = source("src/task/execution.rs");
    assert!(
        execution.contains("let affinity = self.scheduler.wake_with_affinity(key)?;\n        super::notify_runnable_work(affinity);")
    );
    assert!(
        execution.contains("super::notify_runnable_work(None);\n        self.completed = true;")
    );
    let scheduler = source("src/task/scheduler.rs");
    assert!(scheduler.contains("let affinity = entry.continuation_cpu;"));
    assert!(scheduler.contains("complete_switch_on_with_runnable_publication"));
}

#[test]
fn h2_live_transport_has_stationary_cpu_slots_and_lock_free_receive_eoi() {
    let live = source("src/time/live.rs");
    for evidence in [
        "static LOCAL_APIC_SLOTS: [PerCpuLocalApicSlot; CPU_CAPACITY]",
        "current_cpu_index_for_diagnostics()",
        "CpuIndex::new",
        "IrqSpinMutex<Option<LiveLocalApicOwner>>",
        "bind_live_ipi_transport(&LIVE_IPI_TRANSPORT)",
        "IpiOperation::Fixed",
        "const XAPIC_EOI_REGISTER: u32 = 0x0b0",
    ] {
        assert!(
            live.contains(evidence),
            "live IPI transport omitted `{evidence}`"
        );
    }

    let eoi = live
        .split_once("fn end_of_interrupt(&self) -> Result<(), LiveTimeError>")
        .expect("lock-free per-CPU EOI")
        .1
        .split_once("static LOCAL_APIC_SLOTS")
        .expect("per-CPU EOI extent")
        .0;
    assert!(eoi.contains("self.identity()"));
    assert!(eoi.contains("XAPIC_EOI_REGISTER, 0"));
    assert!(!eoi.contains("self.owner.lock()"));

    let time_state = live
        .split_once("struct LiveTimeState")
        .expect("live time state")
        .1
        .split_once("impl LiveTimeState")
        .expect("live time state extent")
        .0;
    assert!(!time_state.contains("apic: LocalApic"));
    assert!(!time_state.contains("registers: LiveXApicMmio"));
}

#[test]
fn h2_bsp_timer_and_ap_idle_publish_in_fail_closed_order() {
    let live = source("src/time/live.rs");
    let initialize = live
        .split_once("pub(crate) fn initialize<'root")
        .expect("live time initializer")
        .1
        .split_once("struct TimeInitPlan")
        .expect("live time initializer extent")
        .0;
    let slot = initialize
        .find("LOCAL_APIC_SLOTS[CpuIndex::BOOTSTRAP.index()].publish")
        .expect("BSP LAPIC slot publication");
    let transport = initialize
        .find("bind_live_ipi_transport(&LIVE_IPI_TRANSPORT)")
        .expect("live IPI transport publication");
    let time = initialize
        .find("publish(committed.time)")
        .expect("time service publication");
    assert!(slot < transport && transport < time);

    let ap_init = live
        .split_once("pub(crate) fn initialize_ap_local_apic")
        .expect("AP local APIC initializer")
        .1
        .split_once("pub(crate) fn send_bsp_ipi")
        .expect("AP local APIC initializer extent")
        .0;
    let masked = ap_init
        .find("configure_one_shot_timer")
        .expect("masked AP timer setup");
    let publish = ap_init
        .find("LOCAL_APIC_SLOTS[cpu.index()].publish")
        .expect("AP LAPIC publication");
    let ready = ap_init
        .find("current_cpu_ipi_transport_ready(cpu_index)")
        .expect("AP transport readiness check");
    assert!(masked < publish && publish < ready);
    assert!(live.contains("installed_current_cpu_index()? != CpuIndex::BOOTSTRAP"));
    assert!(live.contains("installed_current_cpu_index() != Ok(CpuIndex::BOOTSTRAP)"));
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
