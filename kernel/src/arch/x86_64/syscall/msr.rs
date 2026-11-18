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
pub(crate) const IA32_CSTAR: u32 = 0xc000_0083;
pub(crate) const IA32_SYSENTER_CS: u32 = 0x174;
pub(crate) const IA32_SYSENTER_ESP: u32 = 0x175;
pub(crate) const IA32_SYSENTER_EIP: u32 = 0x176;
/// The value RDTSCP and RDPID return beside the time stamp (RDTSCP) or alone
/// (RDPID). The kernel keeps the CPU's slot plus one in it (DW2 M8 step 3d,
/// §13.13 part d), so zero means "no slot installed on this CPU". A program
/// can read it, through RDTSCP or RDPID, and cannot write it: WRMSR is
/// privileged. It exists only on a CPU that reports RDTSCP or RDPID.
pub(crate) const IA32_TSC_AUX: u32 = 0xc000_0103;

pub(crate) const EFER_SCE: u64 = 1;
pub(crate) const E4_FMASK: u64 = 0x001f_7700;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SyscallMsrPlan {
    pub(crate) efer: u64,
    pub(crate) star: u64,
    pub(crate) lstar: u64,
    pub(crate) fmask: u64,
    pub(crate) fs_base: u64,
    pub(crate) gs_base: u64,
    pub(crate) kernel_gs_base: u64,
    /// Compatibility-mode SYSCALL's target (AMD). No user code segment can
    /// enter compatibility mode today, so it is a stub that halts; the i386
    /// contract (root `I386_EXECUTION_MODE_CONTRACT.md`) replaces it before
    /// one can.
    pub(crate) cstar: u64,
    /// Zero, with the SYSENTER stack and target: Intel's SYSENTER, which
    /// works from 64-bit user mode too, then raises #GP(0), an ordinary user
    /// fault, instead of entering ring 0 wherever firmware left these.
    pub(crate) sysenter_cs: u64,
    /// The CPU's slot plus one, for IA32_TSC_AUX (DW2 §13.13 part d), or
    /// `None` on a CPU without RDTSCP and RDPID, where the MSR does not exist
    /// and is neither written nor verified. Decided once per CPU, at its
    /// install.
    pub(crate) tsc_aux: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SyscallMsrPlanError {
    NonCanonicalKernelAddress,
    ZeroKernelAddress,
    /// A TSC_AUX identity of zero, which means "not installed".
    ZeroCpuIdentity,
}

impl SyscallMsrPlan {
    pub(crate) fn new(
        current_efer: u64,
        lstar: u64,
        cstar: u64,
        entry_state_base: u64,
        tsc_aux: Option<u64>,
    ) -> Result<Self, SyscallMsrPlanError> {
        if lstar == 0 || cstar == 0 || entry_state_base == 0 {
            return Err(SyscallMsrPlanError::ZeroKernelAddress);
        }
        if tsc_aux == Some(0) {
            return Err(SyscallMsrPlanError::ZeroCpuIdentity);
        }
        if !is_upper_canonical(lstar)
            || !is_upper_canonical(cstar)
            || !is_upper_canonical(entry_state_base)
        {
            return Err(SyscallMsrPlanError::NonCanonicalKernelAddress);
        }
        Ok(Self {
            efer: current_efer | EFER_SCE,
            star: u64::from(KERNEL_CODE_SELECTOR.bits()) << 32,
            lstar,
            fmask: E4_FMASK,
            fs_base: 0,
            // Installation runs in CPL0. Keep the kernel entry-state base active
            // until the first IRET helper swaps it behind IA32_KERNEL_GS_BASE.
            // Every later SYSCALL begins with SWAPGS before consuming GS.
            gs_base: entry_state_base,
            kernel_gs_base: 0,
            cstar,
            sysenter_cs: 0,
            tsc_aux,
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
            IA32_CSTAR => Some(self.cstar),
            IA32_SYSENTER_CS => Some(self.sysenter_cs),
            IA32_SYSENTER_ESP | IA32_SYSENTER_EIP => Some(0),
            IA32_TSC_AUX => self.tsc_aux,
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
    // The CPU's identity first, where the CPU has the MSR: it is not read as
    // an identity until the slot is installed, after the readback below.
    if let Some(tsc_aux) = plan.tsc_aux {
        access
            .write(IA32_TSC_AUX, tsc_aux)
            .map_err(SyscallMsrProgramError::Access)?;
    }
    // Program every dependent base/target before SCE becomes live.
    for (msr, value) in [
        (IA32_STAR, plan.star),
        (IA32_LSTAR, plan.lstar),
        (IA32_FMASK, plan.fmask),
        (IA32_FS_BASE, plan.fs_base),
        (IA32_GS_BASE, plan.gs_base),
        (IA32_KERNEL_GS_BASE, plan.kernel_gs_base),
        (IA32_CSTAR, plan.cstar),
        (IA32_SYSENTER_CS, plan.sysenter_cs),
        (IA32_SYSENTER_ESP, 0),
        (IA32_SYSENTER_EIP, 0),
        (IA32_EFER, plan.efer),
    ] {
        access
            .write(msr, value)
            .map_err(SyscallMsrProgramError::Access)?;
    }
    verify(access, plan)
}

/// Checks every boundary MSR except IA32_FS_BASE, which installation zeroes
/// but which is then per-Thread user state (`thread_set_fs_base`, D1).
/// IA32_TSC_AUX is checked only where the plan has it.
pub(crate) fn verify<A: SyscallMsrAccess>(
    access: &mut A,
    plan: SyscallMsrPlan,
) -> Result<(), SyscallMsrProgramError<A::Error>> {
    let tsc_aux = plan.tsc_aux.map(|_| IA32_TSC_AUX);
    for msr in [
        IA32_STAR,
        IA32_LSTAR,
        IA32_FMASK,
        IA32_GS_BASE,
        IA32_KERNEL_GS_BASE,
        IA32_CSTAR,
        IA32_SYSENTER_CS,
        IA32_SYSENTER_ESP,
        IA32_SYSENTER_EIP,
        IA32_EFER,
    ]
    .into_iter()
    .chain(tsc_aux)
    {
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

/// What a CPU's CPUID says of IA32_TSC_AUX (DW2 §13.13 part d).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TscAuxSupport {
    /// The MSR exists: the CPU reports RDTSCP or RDPID.
    pub(crate) msr: bool,
    /// The CPU reports RDPID, so the kernel may read its CPU index with it.
    pub(crate) rdpid: bool,
}

/// CPUID leaf 0x8000_0001 EDX bit 27: RDTSCP.
pub(crate) const CPUID_RDTSCP: u32 = 1 << 27;
/// CPUID leaf 7 subleaf 0 ECX bit 22: RDPID.
pub(crate) const CPUID_RDPID: u32 = 1 << 22;

/// Decides [`TscAuxSupport`] from CPUID: `max_basic` is leaf 0's EAX,
/// `leaf7_ecx` leaf 7 subleaf 0's ECX, `max_extended` leaf 0x8000_0000's EAX
/// and `extended_edx` leaf 0x8000_0001's EDX. A leaf above its maximum is not
/// reported, so its register is not consulted.
pub(crate) const fn tsc_aux_support(
    max_basic: u32,
    leaf7_ecx: u32,
    max_extended: u32,
    extended_edx: u32,
) -> TscAuxSupport {
    let rdpid = max_basic >= 7 && leaf7_ecx & CPUID_RDPID != 0;
    let rdtscp = max_extended >= 0x8000_0001 && extended_edx & CPUID_RDTSCP != 0;
    TscAuxSupport {
        msr: rdpid || rdtscp,
        rdpid,
    }
}

/// The CPU index an RDPID value names (DW2 §13.13 part d), or `None` for
/// the GS-pair lookup to answer instead. `value` is slot plus one, so it
/// names slot `value - 1` only if it is in `1..=slot_count` and that slot is
/// installed (`installed`, asked only of a slot in range). Zero, a value out
/// of range and a slot not yet installed all fall back: a CPU that has not
/// installed its own boundary holds zero (each CPU zeroes the MSR at its
/// entry), and a value naming a slot not yet installed cannot be trusted.
pub(crate) fn cpu_index_from_tsc_aux(
    value: u64,
    slot_count: usize,
    installed: impl FnOnce(usize) -> bool,
) -> Option<usize> {
    let slot = usize::try_from(value).ok()?.checked_sub(1)?;
    (slot < slot_count && installed(slot)).then_some(slot)
}
