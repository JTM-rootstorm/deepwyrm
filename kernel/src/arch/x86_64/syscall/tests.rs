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
    fn executable_at(&self, _instruction_pointer: u64) -> bool {
        self.executable
    }

    fn writable_byte_below(&self, _stack_pointer: u64) -> bool {
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
}

#[test]
fn initial_user_return_uses_sysv_startup_registers() {
    let start =
        ThreadStartState::from_validated_user_state(0x4000_1000, 0x5000_2000, 0x1111, 0x2222);
    let context = SavedThreadContext::initial(start);
    let validated = ValidatedUserReturn::initial(
        context,
        &Mapping {
            executable: true,
            writable_stack: true,
        },
    )
    .unwrap();
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
    assert_eq!(
        ValidatedUserReturn::initial(
            context,
            &Mapping {
                executable: false,
                writable_stack: true,
            },
        ),
        Err(UserReturnError::InstructionNotExecutable)
    );
    assert_eq!(
        ValidatedUserReturn::initial(
            context,
            &Mapping {
                executable: true,
                writable_stack: false,
            },
        ),
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
    let mappings = Mapping {
        executable: true,
        writable_stack: true,
    };
    assert_eq!(
        frame.authorize_return(8, &mappings),
        Err(UserReturnError::BindingChanged)
    );
    assert!(frame.authorize_return(9, &mappings).is_ok());
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
    assert_eq!(
        frame.authorize_return(
            4,
            &Mapping {
                executable: true,
                writable_stack: true,
            },
        ),
        Err(UserReturnError::NonCanonicalUserAddress)
    );
}

#[test]
fn dwstatus_is_sign_extended_into_rax() {
    let mut frame = RawSyscallFrame::synthetic(1, [0; 6], 0x4000, 0x8000, 0x202, 1);
    frame.set_status(deepwyrm_abi::DW_STATUS_NOT_SUPPORTED);
    assert_eq!(frame.rax, (-14_i64) as u64);
}
