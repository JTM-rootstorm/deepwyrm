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
    let plan = SyscallMsrPlan::new(
        0x500,
        0xffff_ffff_8000_1000,
        0xffff_ffff_8000_3000,
        0xffff_ffff_8000_2000,
        None,
    )
    .unwrap();
    assert_eq!(plan.efer, 0x501);
    assert_eq!(plan.star, 0x0000_0008_0000_0000);
    assert_eq!(plan.lstar, 0xffff_ffff_8000_1000);
    assert_eq!(plan.fmask, 0x001f_7700);
    assert_eq!(plan.fs_base, 0);
    assert_eq!(plan.gs_base, 0xffff_ffff_8000_2000);
    assert_eq!(plan.kernel_gs_base, 0);
    assert_eq!(plan.cstar, 0xffff_ffff_8000_3000);
    assert_eq!(plan.sysenter_cs, 0);
    assert_eq!(plan.tsc_aux, None);
    assert_eq!(plan.expected(IA32_TSC_AUX), None);
}

fn plan_with_tsc_aux(tsc_aux: Option<u64>) -> SyscallMsrPlan {
    SyscallMsrPlan::new(
        0x100,
        0xffff_ffff_8000_1000,
        0xffff_ffff_8000_3000,
        0xffff_ffff_8000_2000,
        tsc_aux,
    )
    .unwrap()
}

/// DW2 §13.13 part d: a CPU with RDTSCP or RDPID gets its slot plus one in
/// IA32_TSC_AUX, written before SCE is enabled and read back.
#[test]
fn tsc_aux_is_programmed_and_verified_where_the_cpu_has_it() {
    let plan = plan_with_tsc_aux(Some(3));
    assert_eq!(plan.expected(IA32_TSC_AUX), Some(3));
    let mut access = FakeMsr::default();
    program_and_verify(&mut access, plan).unwrap();
    assert_eq!(access.writes.len(), 12);
    assert_eq!(access.writes.first(), Some(&(IA32_TSC_AUX, 3)));
    assert_eq!(access.writes.last(), Some(&(IA32_EFER, plan.efer)));
    verify(&mut access, plan).unwrap();
}

/// A wrong TSC_AUX, another CPU's identity or zero, fails verification.
#[test]
fn a_wrong_tsc_aux_fails_verification() {
    let plan = plan_with_tsc_aux(Some(2));
    let mut access = FakeMsr::default();
    program_and_verify(&mut access, plan).unwrap();
    for wrong in [0, 1, 3] {
        access.values.insert(IA32_TSC_AUX, wrong);
        assert_eq!(
            verify(&mut access, plan),
            Err(SyscallMsrProgramError::Readback {
                msr: IA32_TSC_AUX,
                expected: 2,
                observed: wrong,
            })
        );
    }
    access.values.insert(IA32_TSC_AUX, 2);
    verify(&mut access, plan).unwrap();
}

/// Records every MSR read, so a test can show one is never touched.
#[derive(Default)]
struct ReadLog {
    msr: FakeMsr,
    reads: std::vec::Vec<u32>,
}

impl SyscallMsrAccess for ReadLog {
    type Error = ();

    fn read(&mut self, msr: u32) -> Result<u64, Self::Error> {
        self.reads.push(msr);
        self.msr.read(msr)
    }

    fn write(&mut self, msr: u32, value: u64) -> Result<(), Self::Error> {
        self.msr.write(msr, value)
    }
}

/// On a CPU without RDTSCP and RDPID the MSR does not exist: the plan
/// neither writes nor reads it, whatever a read would return.
#[test]
fn a_cpu_without_the_feature_neither_writes_nor_reads_tsc_aux() {
    let plan = plan_with_tsc_aux(None);
    let mut access = ReadLog::default();
    program_and_verify(&mut access, plan).unwrap();
    access.msr.values.insert(IA32_TSC_AUX, 7);
    verify(&mut access, plan).unwrap();
    assert!(
        access
            .msr
            .writes
            .iter()
            .all(|&(msr, _)| msr != IA32_TSC_AUX)
    );
    assert!(!access.reads.contains(&IA32_TSC_AUX));
    assert_eq!(access.msr.writes.len(), 11);
}

/// Zero means "not installed", so no plan may install it.
#[test]
fn a_zero_tsc_aux_identity_is_refused() {
    assert_eq!(
        SyscallMsrPlan::new(
            0x100,
            0xffff_ffff_8000_1000,
            0xffff_ffff_8000_3000,
            0xffff_ffff_8000_2000,
            Some(0),
        ),
        Err(SyscallMsrPlanError::ZeroCpuIdentity)
    );
}

/// The CPUID decision: the MSR exists with RDTSCP or RDPID; RDPID is used
/// only where reported; a leaf above its maximum is not consulted.
#[test]
fn tsc_aux_support_follows_cpuid() {
    let none = TscAuxSupport {
        msr: false,
        rdpid: false,
    };
    let rdtscp_only = TscAuxSupport {
        msr: true,
        rdpid: false,
    };
    let rdpid = TscAuxSupport {
        msr: true,
        rdpid: true,
    };
    assert_eq!(tsc_aux_support(7, 0, 0x8000_0001, 0), none);
    assert_eq!(
        tsc_aux_support(7, 0, 0x8000_0001, CPUID_RDTSCP),
        rdtscp_only
    );
    assert_eq!(tsc_aux_support(7, CPUID_RDPID, 0x8000_0001, 0), rdpid);
    assert_eq!(
        tsc_aux_support(7, CPUID_RDPID, 0x8000_0008, CPUID_RDTSCP),
        rdpid
    );
    // Leaf 7 or 0x8000_0001 not reported: its register is ignored.
    assert_eq!(
        tsc_aux_support(6, CPUID_RDPID, 0x8000_0000, CPUID_RDTSCP),
        none
    );
    assert_eq!(
        tsc_aux_support(6, CPUID_RDPID, 0x8000_0001, CPUID_RDTSCP),
        rdtscp_only
    );
}

/// DW2 §13.13 part d: an RDPID value names slot `value - 1` only when it is
/// in range and that slot is installed; otherwise the GS pair answers.
#[test]
fn an_rdpid_value_names_a_cpu_only_when_valid_and_installed() {
    let all_installed = |_slot: usize| true;
    // A valid value.
    assert_eq!(cpu_index_from_tsc_aux(1, 4, all_installed), Some(0));
    assert_eq!(cpu_index_from_tsc_aux(4, 4, all_installed), Some(3));
    // Zero: no slot installed on this CPU.
    assert_eq!(cpu_index_from_tsc_aux(0, 4, all_installed), None);
    // Out of range.
    assert_eq!(cpu_index_from_tsc_aux(5, 4, all_installed), None);
    assert_eq!(cpu_index_from_tsc_aux(u64::MAX, 4, all_installed), None);
    // A slot not installed.
    assert_eq!(cpu_index_from_tsc_aux(3, 4, |slot| slot != 2), None);
    assert_eq!(cpu_index_from_tsc_aux(2, 4, |slot| slot != 2), Some(1));
    // The installed test is asked only of the slot named, and never out of range.
    let mut asked = std::vec::Vec::new();
    assert_eq!(
        cpu_index_from_tsc_aux(9, 4, |slot| {
            asked.push(slot);
            true
        }),
        None
    );
    assert!(asked.is_empty());
}

#[test]
fn e4_msr_programming_enables_sce_last_and_verifies_readback() {
    let plan = SyscallMsrPlan::new(
        0x100,
        0xffff_ffff_8000_1000,
        0xffff_ffff_8000_3000,
        0xffff_ffff_8000_2000,
        None,
    )
    .unwrap();
    let mut access = FakeMsr::default();
    program_and_verify(&mut access, plan).unwrap();
    assert_eq!(access.writes.last(), Some(&(IA32_EFER, plan.efer)));
    assert_eq!(access.writes.len(), 11);
    for msr in [IA32_SYSENTER_CS, IA32_SYSENTER_ESP, IA32_SYSENTER_EIP] {
        assert!(access.writes.contains(&(msr, 0)), "{msr:#x}");
    }
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
fn e4_live_validation_requires_strict_kernel_gs_orientation() {
    let plan = SyscallMsrPlan::new(
        0x100,
        0xffff_ffff_8000_1000,
        0xffff_ffff_8000_3000,
        0xffff_ffff_8000_2000,
        None,
    )
    .unwrap();
    let mut access = FakeMsr::default();
    program_and_verify(&mut access, plan).unwrap();

    access.values.insert(IA32_GS_BASE, 0);
    access.values.insert(IA32_KERNEL_GS_BASE, plan.gs_base);
    assert!(matches!(
        verify(&mut access, plan),
        Err(SyscallMsrProgramError::Readback {
            msr: IA32_GS_BASE,
            ..
        })
    ));

    access.values.insert(IA32_GS_BASE, plan.gs_base);
    access.values.insert(IA32_KERNEL_GS_BASE, 0);
    verify(&mut access, plan).unwrap();

    for msr in [
        IA32_STAR,
        IA32_LSTAR,
        IA32_FMASK,
        IA32_EFER,
        IA32_CSTAR,
        IA32_SYSENTER_CS,
        IA32_SYSENTER_ESP,
        IA32_SYSENTER_EIP,
    ] {
        let expected = plan.expected(msr).unwrap();
        access.values.insert(msr, expected ^ 1);
        assert!(matches!(
            verify(&mut access, plan),
            Err(SyscallMsrProgramError::Readback {
                msr: observed_msr,
                ..
            }) if observed_msr == msr
        ));
        access.values.insert(msr, expected);
    }
}

#[test]
fn a_thread_fs_base_is_user_state_not_a_boundary_invariant() {
    let plan = SyscallMsrPlan::new(
        0x100,
        0xffff_ffff_8000_1000,
        0xffff_ffff_8000_3000,
        0xffff_ffff_8000_2000,
        None,
    )
    .unwrap();
    let mut access = FakeMsr::default();
    program_and_verify(&mut access, plan).unwrap();
    assert!(access.writes.contains(&(IA32_FS_BASE, 0)));
    for fs_base in [0x7fff_0000_1000, 0x1000, 0] {
        access.values.insert(IA32_FS_BASE, fs_base);
        verify(&mut access, plan).unwrap();
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
fn authorized_frame_rebind_requires_explicit_revocation() {
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
    frame.revoke_authorized_return();
    assert_eq!(frame.test_return_authorized(), 0);
    assert!(frame.rebind_after_kernel_resume(11).is_ok());
    assert_eq!(frame.binding_generation(), 11);
    assert!(frame.authorize_return(11, &mut mappings).is_ok());
}
