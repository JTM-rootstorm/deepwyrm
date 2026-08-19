#![cfg_attr(
    not(all(target_os = "none", target_arch = "x86_64")),
    allow(
        dead_code,
        reason = "E4 MSR plans are host-tested before target installation consumes them"
    )
)]

//! Pure planning and verification for the DW0-E4 SYSCALL MSR set.

use super::super::gdt::KERNEL_CODE_SELECTOR;

pub(crate) const IA32_EFER: u32 = 0xc000_0080;
pub(crate) const IA32_STAR: u32 = 0xc000_0081;
pub(crate) const IA32_LSTAR: u32 = 0xc000_0082;
pub(crate) const IA32_FMASK: u32 = 0xc000_0084;
pub(crate) const IA32_FS_BASE: u32 = 0xc000_0100;
pub(crate) const IA32_GS_BASE: u32 = 0xc000_0101;
pub(crate) const IA32_KERNEL_GS_BASE: u32 = 0xc000_0102;

pub(crate) const EFER_SCE: u64 = 1;
pub(crate) const E4_FMASK: u64 = 0x001f_7700;
pub(crate) const CR0_TASK_SWITCHED: u64 = 1 << 3;
pub(crate) const CR4_FSGSBASE: u64 = 1 << 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SyscallMsrPlan {
    pub(crate) efer: u64,
    pub(crate) star: u64,
    pub(crate) lstar: u64,
    pub(crate) fmask: u64,
    pub(crate) fs_base: u64,
    pub(crate) gs_base: u64,
    pub(crate) kernel_gs_base: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SyscallMsrPlanError {
    NonCanonicalKernelAddress,
    ZeroKernelAddress,
}

pub(crate) const fn normalize_cr0_for_e5(cr0: u64) -> u64 {
    cr0 | CR0_TASK_SWITCHED
}

pub(crate) const fn normalize_cr4_for_e4(cr4: u64) -> u64 {
    cr4 & !CR4_FSGSBASE
}

impl SyscallMsrPlan {
    pub(crate) fn new(
        current_efer: u64,
        lstar: u64,
        gs_base: u64,
    ) -> Result<Self, SyscallMsrPlanError> {
        if lstar == 0 || gs_base == 0 {
            return Err(SyscallMsrPlanError::ZeroKernelAddress);
        }
        if !is_upper_canonical(lstar) || !is_upper_canonical(gs_base) {
            return Err(SyscallMsrPlanError::NonCanonicalKernelAddress);
        }
        Ok(Self {
            efer: current_efer | EFER_SCE,
            star: u64::from(KERNEL_CODE_SELECTOR.bits()) << 32,
            lstar,
            fmask: E4_FMASK,
            fs_base: 0,
            gs_base,
            kernel_gs_base: 0,
        })
    }

    pub(crate) const fn expected(self, msr: u32) -> Option<u64> {
        match msr {
            IA32_EFER => Some(self.efer),
            IA32_STAR => Some(self.star),
            IA32_LSTAR => Some(self.lstar),
            IA32_FMASK => Some(self.fmask),
            IA32_FS_BASE => Some(self.fs_base),
            IA32_GS_BASE => Some(self.gs_base),
            IA32_KERNEL_GS_BASE => Some(self.kernel_gs_base),
            _ => None,
        }
    }
}

const fn is_upper_canonical(address: u64) -> bool {
    address >= 0xffff_8000_0000_0000
}

pub(crate) trait SyscallMsrAccess {
    type Error;

    fn read(&mut self, msr: u32) -> Result<u64, Self::Error>;
    fn write(&mut self, msr: u32, value: u64) -> Result<(), Self::Error>;
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum SyscallMsrProgramError<E> {
    Access(E),
    Readback {
        msr: u32,
        expected: u64,
        observed: u64,
    },
}

pub(crate) fn program_and_verify<A: SyscallMsrAccess>(
    access: &mut A,
    plan: SyscallMsrPlan,
) -> Result<(), SyscallMsrProgramError<A::Error>> {
    // Program every dependent base/target before SCE becomes live.
    for (msr, value) in [
        (IA32_STAR, plan.star),
        (IA32_LSTAR, plan.lstar),
        (IA32_FMASK, plan.fmask),
        (IA32_FS_BASE, plan.fs_base),
        (IA32_GS_BASE, plan.gs_base),
        (IA32_KERNEL_GS_BASE, plan.kernel_gs_base),
        (IA32_EFER, plan.efer),
    ] {
        access
            .write(msr, value)
            .map_err(SyscallMsrProgramError::Access)?;
    }
    verify(access, plan)
}

pub(crate) fn verify<A: SyscallMsrAccess>(
    access: &mut A,
    plan: SyscallMsrPlan,
) -> Result<(), SyscallMsrProgramError<A::Error>> {
    for msr in [
        IA32_STAR,
        IA32_LSTAR,
        IA32_FMASK,
        IA32_FS_BASE,
        IA32_GS_BASE,
        IA32_KERNEL_GS_BASE,
        IA32_EFER,
    ] {
        let observed = access.read(msr).map_err(SyscallMsrProgramError::Access)?;
        let expected = plan.expected(msr).expect("verified MSR belongs to plan");
        if observed != expected {
            return Err(SyscallMsrProgramError::Readback {
                msr,
                expected,
                observed,
            });
        }
    }
    Ok(())
}
