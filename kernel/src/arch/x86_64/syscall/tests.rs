extern crate std;

use core::mem::{offset_of, size_of};

use super::frame::*;
use super::msr::*;
use crate::task::{SavedThreadContext, ThreadStartState};

struct Mapping {
    executable: bool,
    writable_stack: bool,
}

impl UserReturnMappingValidation for Mapping {
    fn executable_at(&mut self, _instruction_pointer: u64) -> bool {
        self.executable
    }

    fn writable_byte_below(&mut self, _stack_pointer: u64) -> bool {
        self.writable_stack
    }
}

#[test]
fn e4_user_flag_reconstruction_is_exact() {
    assert_eq!(SAFE_USER_RFLAGS_MASK, 0x0020_0cd5);
    assert_eq!(REQUIRED_USER_RFLAGS, 0x202);
    assert_eq!(sanitize_user_rflags(u64::MAX), 0x0020_0ed7);
    assert_eq!(sanitize_user_rflags(0), 0x202);
}

#[test]
fn e4_raw_frames_have_fixed_offsets() {
    assert_eq!(size_of::<PerCpuEntryState>(), 64);
    assert_eq!(offset_of!(PerCpuEntryState, entry_stack_top), 0);
    assert_eq!(offset_of!(PerCpuEntryState, current_kernel_stack_top), 8);
    assert_eq!(offset_of!(PerCpuEntryState, binding_generation), 16);
    assert_eq!(offset_of!(PerCpuEntryState, staged_user_rsp), 24);
    assert_eq!(offset_of!(PerCpuEntryState, staged_user_rip), 32);
    assert_eq!(offset_of!(PerCpuEntryState, staged_user_rflags), 40);
    assert_eq!(offset_of!(PerCpuEntryState, reserved), 48);
    assert_eq!(size_of::<RawUserReturnContext>(), 18 * 8);
    assert_eq!(offset_of!(RawUserReturnContext, r15), 0);
    assert_eq!(offset_of!(RawUserReturnContext, rax), 96);
    assert_eq!(offset_of!(RawUserReturnContext, rcx), 104);
    assert_eq!(offset_of!(RawUserReturnContext, r11), 112);
    assert_eq!(offset_of!(RawUserReturnContext, user_rip), 120);
    assert_eq!(offset_of!(RawUserReturnContext, user_rflags), 128);
    assert_eq!(offset_of!(RawUserReturnContext, user_rsp), 136);

    assert_eq!(size_of::<RawSyscallFrame>(), 18 * 8);
    assert_eq!(offset_of!(RawSyscallFrame, r15), 0);
    assert_eq!(offset_of!(RawSyscallFrame, r9), 48);
    assert_eq!(offset_of!(RawSyscallFrame, r10), 64);
    assert_eq!(offset_of!(RawSyscallFrame, rax), 96);
    assert_eq!(offset_of!(RawSyscallFrame, user_rip), 104);
    assert_eq!(offset_of!(RawSyscallFrame, user_rflags), 112);
    assert_eq!(offset_of!(RawSyscallFrame, user_rsp), 120);
    assert_eq!(offset_of!(RawSyscallFrame, binding_generation), 128);
    assert_eq!(offset_of!(RawSyscallFrame, return_authorized), 136);

    assert_eq!(size_of::<RawCpl3TimerReturnFrame>(), 160);
    assert_eq!(offset_of!(RawCpl3TimerReturnFrame, r15), 0);
    assert_eq!(offset_of!(RawCpl3TimerReturnFrame, rax), 112);
    assert_eq!(offset_of!(RawCpl3TimerReturnFrame, rip), 120);
    assert_eq!(offset_of!(RawCpl3TimerReturnFrame, cs), 128);
    assert_eq!(offset_of!(RawCpl3TimerReturnFrame, rflags), 136);
    assert_eq!(offset_of!(RawCpl3TimerReturnFrame, rsp), 144);
    assert_eq!(offset_of!(RawCpl3TimerReturnFrame, ss), 152);
}

fn timer_frame() -> RawCpl3TimerReturnFrame {
    RawCpl3TimerReturnFrame {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rbp: 0,
        rdi: 0,
        rsi: 0,
        rdx: 0,
        rcx: 0,
        rbx: 0,
        rax: 0,
        rip: 0x4000,
        cs: USER_CODE_SELECTOR,
        rflags: u64::MAX,
        rsp: 0x8000,
        ss: USER_DATA_SELECTOR,
    }
}

#[test]
fn dw1b_timer_return_requires_exact_selectors_mappings_and_sanitized_flags() {
    let mut mappings = Mapping {
        executable: true,
        writable_stack: true,
    };
    let mut frame = timer_frame();
    frame.validate_and_sanitize(&mut mappings).unwrap();
    assert_eq!(frame.rflags, sanitize_user_rflags(u64::MAX));

    for invalid in [0x23, 0x3b] {
        let mut frame = timer_frame();
        frame.cs = invalid;
        assert_eq!(
            frame.validate_and_sanitize(&mut mappings),
            Err(UserReturnError::InvalidSelector)
        );
    }
    let mut frame = timer_frame();
    frame.ss = 0x23;
    assert_eq!(
        frame.validate_and_sanitize(&mut mappings),
        Err(UserReturnError::InvalidSelector)
    );

    let mut no_execute = Mapping {
        executable: false,
        writable_stack: true,
    };
    assert_eq!(
        timer_frame().validate_and_sanitize(&mut no_execute),
        Err(UserReturnError::InstructionNotExecutable)
    );
    let mut no_stack = Mapping {
        executable: true,
        writable_stack: false,
    };
    assert_eq!(
        timer_frame().validate_and_sanitize(&mut no_stack),
        Err(UserReturnError::StackNotWritable)
    );
}

#[test]
fn initial_user_return_uses_sysv_startup_registers() {
    let start =
        ThreadStartState::from_validated_user_state(0x4000_1000, 0x5000_2000, 0x1111, 0x2222);
    let context = SavedThreadContext::initial(start);
    let mut mappings = Mapping {
        executable: true,
        writable_stack: true,
    };
    let validated = ValidatedUserReturn::initial(context, &mut mappings).unwrap();
    let raw = validated.raw();
    assert_eq!(raw.rdi, 0x1111);
    assert_eq!(raw.rsi, 0x2222);
    assert_eq!(raw.user_rip, 0x4000_1000);
    assert_eq!(raw.user_rsp, 0x5000_2000);
    assert_eq!(raw.user_rflags, 0x202);
}

#[test]
fn return_validation_requires_both_mapping_facts() {
    let start = ThreadStartState::from_validated_user_state(0x4000, 0x8000, 0, 0);
    let context = SavedThreadContext::initial(start);
    let mut no_execute = Mapping {
        executable: false,
        writable_stack: true,
    };
    assert_eq!(
        ValidatedUserReturn::initial(context, &mut no_execute),
        Err(UserReturnError::InstructionNotExecutable)
    );
    let mut no_stack = Mapping {
        executable: true,
        writable_stack: false,
    };
    assert_eq!(
        ValidatedUserReturn::initial(context, &mut no_stack),
        Err(UserReturnError::StackNotWritable)
    );
}

#[test]
fn raw_syscall_extracts_deepwyrm_register_order() {
    let frame =
        RawSyscallFrame::synthetic(0x10021, [1, 2, 3, 4, 5, 6], 0x4000, 0x8000, u64::MAX, 7);
    assert!(frame.validates_entry());
    let (number, arguments) = frame.request().unwrap();
    assert_eq!(number.0, 0x10021);
    assert_eq!(arguments.as_array(), [1, 2, 3, 4, 5, 6]);
}

#[test]
fn syscall_return_stays_unapproved_until_mapping_and_generation_match() {
    let mut frame = RawSyscallFrame::synthetic(1, [0; 6], 0x4000, 0x8000, u64::MAX, 9);
    let mut mappings = Mapping {
        executable: true,
        writable_stack: true,
    };
    assert_eq!(
        frame.authorize_return(8, &mut mappings),
        Err(UserReturnError::BindingChanged)
    );
    assert!(frame.authorize_return(9, &mut mappings).is_ok());
    assert_eq!(frame.user_rflags, sanitize_user_rflags(u64::MAX));
    assert_eq!(frame.return_authorized, SYSCALL_RETURN_AUTHORIZED);
}

#[derive(Default)]
struct FakeMsr {
    values: std::collections::BTreeMap<u32, u64>,
    writes: std::vec::Vec<(u32, u64)>,
}

impl SyscallMsrAccess for FakeMsr {
    type Error = ();

    fn read(&mut self, msr: u32) -> Result<u64, Self::Error> {
        Ok(*self.values.get(&msr).unwrap_or(&0))
    }

    fn write(&mut self, msr: u32, value: u64) -> Result<(), Self::Error> {
        self.values.insert(msr, value);
        self.writes.push((msr, value));
        Ok(())
    }
}

#[test]
fn e4_msr_plan_is_exact_and_preserves_efer() {
    let plan = SyscallMsrPlan::new(0x500, 0xffff_ffff_8000_1000, 0xffff_ffff_8000_2000).unwrap();
    assert_eq!(plan.efer, 0x501);
    assert_eq!(plan.star, 0x0000_0008_0000_0000);
    assert_eq!(plan.lstar, 0xffff_ffff_8000_1000);
    assert_eq!(plan.fmask, 0x001f_7700);
    assert_eq!(plan.fs_base, 0);
    assert_eq!(plan.gs_base, 0xffff_ffff_8000_2000);
    assert_eq!(plan.kernel_gs_base, 0);
}

#[test]
fn e4_msr_programming_enables_sce_last_and_verifies_readback() {
    let plan = SyscallMsrPlan::new(0x100, 0xffff_ffff_8000_1000, 0xffff_ffff_8000_2000).unwrap();
    let mut access = FakeMsr::default();
    program_and_verify(&mut access, plan).unwrap();
    assert_eq!(access.writes.last(), Some(&(IA32_EFER, plan.efer)));
    assert_eq!(access.writes.len(), 7);
    verify(&mut access, plan).unwrap();

    access.values.insert(IA32_FMASK, 0);
    assert!(matches!(
        verify(&mut access, plan),
        Err(SyscallMsrProgramError::Readback {
            msr: IA32_FMASK,
            ..
        })
    ));
}

#[test]
fn e4_live_boundary_accepts_only_the_two_exact_gs_orientations() {
    let plan = SyscallMsrPlan::new(0x100, 0xffff_ffff_8000_1000, 0xffff_ffff_8000_2000).unwrap();
    let mut access = FakeMsr::default();
    program_and_verify(&mut access, plan).unwrap();

    verify_live_boundary(&mut access, plan).unwrap();

    access.values.insert(IA32_GS_BASE, 0);
    access.values.insert(IA32_KERNEL_GS_BASE, plan.gs_base);
    verify_live_boundary(&mut access, plan).unwrap();
    assert!(matches!(
        verify(&mut access, plan),
        Err(SyscallMsrProgramError::Readback {
            msr: IA32_GS_BASE,
            ..
        })
    ));

    for (gs_base, kernel_gs_base) in [
        (0, 0),
        (plan.gs_base, plan.gs_base),
        (plan.gs_base, 0x1000),
        (0x1000, 0),
        (0, 0x1000),
        (0x1000, plan.gs_base),
    ] {
        access.values.insert(IA32_GS_BASE, gs_base);
        access.values.insert(IA32_KERNEL_GS_BASE, kernel_gs_base);
        assert!(
            verify_live_boundary(&mut access, plan).is_err(),
            "malformed GS pair ({gs_base:#x}, {kernel_gs_base:#x}) was accepted"
        );
    }
}

#[test]
fn e4_live_boundary_keeps_every_non_gs_msr_exact() {
    let plan = SyscallMsrPlan::new(0x100, 0xffff_ffff_8000_1000, 0xffff_ffff_8000_2000).unwrap();
    let mut access = FakeMsr::default();
    program_and_verify(&mut access, plan).unwrap();

    for msr in [IA32_STAR, IA32_LSTAR, IA32_FMASK, IA32_FS_BASE, IA32_EFER] {
        let expected = plan.expected(msr).unwrap();
        access.values.insert(msr, expected ^ 1);
        assert!(matches!(
            verify_live_boundary(&mut access, plan),
            Err(SyscallMsrProgramError::Readback {
                msr: observed_msr,
                ..
            }) if observed_msr == msr
        ));
        access.values.insert(msr, expected);
    }
}

#[test]
fn e5_cr0_normalization_sets_only_task_switched() {
    for value in [0, u64::MAX, 0x1234_5678_9abc_def0, CR0_TASK_SWITCHED] {
        let normalized = normalize_cr0_for_e5(value);
        assert_ne!(normalized & CR0_TASK_SWITCHED, 0);
        assert_eq!(normalized & !CR0_TASK_SWITCHED, value & !CR0_TASK_SWITCHED);
    }
}

#[test]
fn e4_cr4_normalization_clears_only_fsgsbase() {
    for value in [0, u64::MAX, 0x1234_5678_9abc_def0, CR4_FSGSBASE] {
        let normalized = normalize_cr4_for_e4(value);
        assert_eq!(normalized & CR4_FSGSBASE, 0);
        assert_eq!(normalized & !CR4_FSGSBASE, value & !CR4_FSGSBASE);
    }
}

#[test]
fn hostile_user_rsp_is_entry_data_not_a_kernel_invariant_failure() {
    let mut frame = RawSyscallFrame::synthetic(1, [0; 6], 0x4000, u64::MAX, 0x202, 4);
    assert!(frame.validates_entry());
    let mut mappings = Mapping {
        executable: true,
        writable_stack: true,
    };
    assert_eq!(
        frame.authorize_return(4, &mut mappings),
        Err(UserReturnError::NonCanonicalUserAddress)
    );
}

#[test]
fn dwstatus_is_sign_extended_into_rax() {
    let mut frame = RawSyscallFrame::synthetic(1, [0; 6], 0x4000, 0x8000, 0x202, 1);
    frame.set_status(deepwyrm_abi::DW_STATUS_NOT_SUPPORTED);
    assert_eq!(frame.rax, (-14_i64) as u64);
}

#[test]
fn suspended_frame_rebinds_only_before_return_authorization() {
    let mut frame = RawSyscallFrame::synthetic(1, [0; 6], 0x4000, 0x8000, 0x202, 9);
    let mut mappings = Mapping {
        executable: true,
        writable_stack: true,
    };
    assert_eq!(
        frame.rebind_after_kernel_resume(0),
        Err(UserReturnError::BindingChanged)
    );
    assert!(frame.rebind_after_kernel_resume(10).is_ok());
    assert_eq!(frame.binding_generation(), 10);
    assert!(frame.authorize_return(10, &mut mappings).is_ok());
    assert_eq!(
        frame.rebind_after_kernel_resume(11),
        Err(UserReturnError::BindingChanged)
    );
}

#[test]
fn dw1_a_idle_accounting_is_bound_to_successful_halted_publication() {
    fn assert_live_boundary(source: &str, commit_marker: &str, wait_marker: &str) {
        let commit = source
            .find(commit_marker)
            .expect("live idle path must commit its architecture generation");
        let source = &source[commit..];
        let rescan = source
            .find("IdleWakeError::RescanRequired")
            .expect("live idle path must preserve the RescanRequired branch");
        let rescan_continue = source[rescan..]
            .find("continue;")
            .map(|offset| rescan + offset)
            .expect("RescanRequired must return to the scheduler scan");
        let publish = source
            .find("publish_scheduler_idle(started_at_ns)")
            .expect("successful HALTED publication must begin scheduler idle accounting");
        let wait = source
            .find(wait_marker)
            .expect("published scheduler idle accounting must precede the physical halt");
        let physical_finish = source
            .find("finish_current_idle(halt)")
            .expect("the exact HALTED generation must finish after return");
        let accounting_finish = source
            .find("finish_scheduler_idle(idle_accounting, finished_at_ns)")
            .expect("the matching scheduler idle token must close after HALTED completion");

        assert!(rescan < rescan_continue);
        assert!(rescan_continue < publish);
        assert!(publish < wait);
        assert!(wait < physical_finish);
        assert!(physical_finish < accounting_finish);
    }

    assert_live_boundary(
        include_str!("live.rs"),
        "commit_current_idle(idle)",
        "wait_for_suspend_interrupt();",
    );
    let primordial = include_str!("../mm/activation/primordial.rs");
    let commit = primordial
        .find("commit_current_idle(idle)")
        .expect("AP idle path must commit its architecture generation");
    let primordial = &primordial[commit..];
    let publish = primordial
        .find("publish_scheduler_idle(started_at_ns)")
        .expect("successful AP HALTED publication must begin scheduler idle accounting");
    let wait = primordial
        .find("core::arch::asm!(\"sti\", \"hlt\", \"cli\"")
        .expect("AP scheduler idle accounting must precede the physical halt");
    let physical_finish = primordial
        .find("finish_current_idle(halt)")
        .expect("the AP HALTED generation must finish after return");
    let accounting_finish = primordial
        .find("finish_scheduler_idle(idle_accounting, finished_at_ns)")
        .expect("the matching AP scheduler idle token must close after HALTED completion");
    let rescan = primordial
        .find("IdleWakeError::RescanRequired")
        .expect("AP idle path must preserve the RescanRequired branch");
    assert!(publish < wait);
    assert!(wait < physical_finish);
    assert!(physical_finish < accounting_finish);
    assert!(accounting_finish < rescan);
    assert!(!primordial[rescan..].contains("publish_scheduler_idle"));
}
