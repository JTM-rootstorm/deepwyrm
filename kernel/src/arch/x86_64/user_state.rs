//! Per-thread user register state the kernel does not keep in the syscall
//! frame: x87/SSE/AVX state and the FS base (toolchain requests D1 and D2,
//! `Plans/DW0_E0_TASK_SYSCALL_CONTRACT.md` §6.6).
//!
//! The kernel itself stays soft-float, so the FP registers and the FS base a
//! CPU holds always belong to the user Thread that last ran there. A Thread
//! saves both into its own kernel stack frame just before it switches away
//! and restores them when that frame resumes (`syscall/live.rs`
//! `switch_kernel_context`); a fresh Thread enters user mode with the
//! architectural initial FP state and FS base 0. Kernel carriers (idle,
//! reapers) never touch either, so state survives them untouched.
//!
//! The save format is chosen once, by the bootstrap CPU, and every other CPU
//! must arrive at the same one: XSAVE over x87, SSE and (when present) AVX, or
//! FXSAVE where the CPU has no XSAVE. Wider components (AVX-512, AMX) are left
//! out of XCR0, which keeps the save area within [`FP_AREA_BYTES`]. CPUs must
//! also agree on MXCSR_MASK, since a Thread's MXCSR moves with it.
//!
//! The DS, ES, FS and GS selectors travel with the same state: user code can
//! load them, so they are saved and restored per Thread too, and a fresh
//! Thread starts with all four null.

pub(crate) const CR0_MONITOR_COPROCESSOR: u64 = 1 << 1;
pub(crate) const CR0_EMULATION: u64 = 1 << 2;
pub(crate) const CR0_TASK_SWITCHED: u64 = 1 << 3;
pub(crate) const CR0_NUMERIC_ERROR: u64 = 1 << 5;

pub(crate) const CR4_DEBUGGING_EXTENSIONS: u64 = 1 << 3;
pub(crate) const CR4_PAGE_SIZE_EXTENSIONS: u64 = 1 << 4;
pub(crate) const CR4_PAE: u64 = 1 << 5;
pub(crate) const CR4_MACHINE_CHECK: u64 = 1 << 6;
pub(crate) const CR4_PGE: u64 = 1 << 7;
pub(crate) const CR4_OSFXSR: u64 = 1 << 9;
pub(crate) const CR4_OSXMMEXCPT: u64 = 1 << 10;
pub(crate) const CR4_UMIP: u64 = 1 << 11;
pub(crate) const CR4_LA57: u64 = 1 << 12;
pub(crate) const CR4_VMXE: u64 = 1 << 13;
pub(crate) const CR4_SMXE: u64 = 1 << 14;
pub(crate) const CR4_FSGSBASE: u64 = 1 << 16;
pub(crate) const CR4_PCIDE: u64 = 1 << 17;
pub(crate) const CR4_OSXSAVE: u64 = 1 << 18;
pub(crate) const CR4_SMEP: u64 = 1 << 20;
pub(crate) const CR4_SMAP: u64 = 1 << 21;

/// The CR4 bits kept from firmware or the loader: paging and machine-check
/// controls, supervisor protections, and VMX/SMX enables, which only CPL0
/// instructions use (clearing them inside VMX or SMX operation would fault).
/// Every other bit is cleared. That keeps firmware from handing user code a
/// per-CPU register the kernel does not switch per Thread (PKRU through PKE,
/// CET state, Key Locker, user interrupts, RDPMC through PCE) and from
/// changing how kernel entry works (FRED, LASS, LAM). Application processors
/// start from CR4 = PAE, so this also makes the bootstrap CPU match them.
pub(crate) const CR4_KEPT: u64 = CR4_DEBUGGING_EXTENSIONS
    | CR4_PAGE_SIZE_EXTENSIONS
    | CR4_PAE
    | CR4_MACHINE_CHECK
    | CR4_PGE
    | CR4_UMIP
    | CR4_LA57
    | CR4_VMXE
    | CR4_SMXE
    | CR4_PCIDE
    | CR4_SMEP
    | CR4_SMAP;

pub(crate) const XCR0_X87: u64 = 1 << 0;
pub(crate) const XCR0_SSE: u64 = 1 << 1;
pub(crate) const XCR0_AVX: u64 = 1 << 2;

/// Bytes of the legacy FXSAVE region plus the XSAVE header.
pub(crate) const XSAVE_LEGACY_AND_HEADER_BYTES: u32 = 576;
/// Save-area size every Thread's switch frame reserves.
pub(crate) const FP_AREA_BYTES: usize = 1024;

pub(crate) const INITIAL_FCW: u16 = 0x037f;
pub(crate) const INITIAL_MXCSR: u32 = 0x1f80;

const CPUID1_EDX_FXSR: u32 = 1 << 24;
const CPUID1_EDX_SSE: u32 = 1 << 25;
const CPUID1_EDX_SSE2: u32 = 1 << 26;
const CPUID1_ECX_XSAVE: u32 = 1 << 26;
const CPUID1_ECX_AVX: u32 = 1 << 28;

/// How this kernel saves user FP state on every CPU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FpSaveMode {
    Fxsave,
    Xsave { xcr0: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FpPolicyError {
    /// The CPU lacks FXSR, SSE or SSE2, which the SysV x86-64 psABI assumes.
    MissingSse2,
    /// CPUID claims XSAVE but not x87 and SSE state in XCR0's supported mask.
    XsaveWithoutLegacyState,
    /// The XSAVE area for the chosen XCR0 does not fit [`FP_AREA_BYTES`].
    AreaTooLarge,
    /// This CPU would choose a different save mode than the bootstrap CPU.
    ModeMismatch,
    /// This CPU accepts different MXCSR bits than the bootstrap CPU.
    MxcsrMaskMismatch,
}

/// The CPUID bits the save-mode decision reads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CpuFpFeatures {
    pub(crate) leaf1_ecx: u32,
    pub(crate) leaf1_edx: u32,
    /// CPUID.(EAX=0DH,ECX=0):EDX:EAX, the XCR0 bits the CPU supports. Zero
    /// when the CPU has no XSAVE.
    pub(crate) xcr0_supported: u64,
}

pub(crate) const fn plan_fp_mode(features: CpuFpFeatures) -> Result<FpSaveMode, FpPolicyError> {
    let legacy = CPUID1_EDX_FXSR | CPUID1_EDX_SSE | CPUID1_EDX_SSE2;
    if features.leaf1_edx & legacy != legacy {
        return Err(FpPolicyError::MissingSse2);
    }
    if features.leaf1_ecx & CPUID1_ECX_XSAVE == 0 {
        return Ok(FpSaveMode::Fxsave);
    }
    let required = XCR0_X87 | XCR0_SSE;
    if features.xcr0_supported & required != required {
        return Err(FpPolicyError::XsaveWithoutLegacyState);
    }
    let mut xcr0 = required;
    if features.leaf1_ecx & CPUID1_ECX_AVX != 0 && features.xcr0_supported & XCR0_AVX != 0 {
        xcr0 |= XCR0_AVX;
    }
    Ok(FpSaveMode::Xsave { xcr0 })
}

/// Checks CPUID.(EAX=0DH,ECX=0):EBX, the area size for the XCR0 now set.
pub(crate) const fn xsave_area_fits(enabled_size: u32) -> Result<(), FpPolicyError> {
    if enabled_size < XSAVE_LEGACY_AND_HEADER_BYTES || enabled_size as usize > FP_AREA_BYTES {
        return Err(FpPolicyError::AreaTooLarge);
    }
    Ok(())
}

/// CR0 for user FP: native x87 errors, no emulation, no lazy trap.
pub(crate) const fn normalize_cr0_for_user_fp(cr0: u64) -> u64 {
    (cr0 | CR0_MONITOR_COPROCESSOR | CR0_NUMERIC_ERROR) & !(CR0_EMULATION | CR0_TASK_SWITCHED)
}

/// CR4 for user FP: the [`CR4_KEPT`] bits as found, FXSAVE/SSE and SIMD
/// exceptions on, OSXSAVE exactly when the mode uses XSAVE, and everything
/// else off, including RD/WR{FS,GS}BASE (user code must never write GS; the
/// FS base changes only through `thread_set_fs_base`) and PKE.
pub(crate) const fn normalize_cr4_for_user_fp(cr4: u64, mode: FpSaveMode) -> u64 {
    let base = (cr4 & CR4_KEPT) | CR4_OSFXSR | CR4_OSXMMEXCPT;
    match mode {
        FpSaveMode::Fxsave => base,
        FpSaveMode::Xsave { .. } => base | CR4_OSXSAVE,
    }
}

/// CPUID.(EAX=7,ECX=0):EDX: the IA32_ARCH_CAPABILITIES MSR exists.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) const CPUID7_EDX_ARCH_CAPABILITIES: u32 = 1 << 29;
/// IA32_ARCH_CAPABILITIES.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) const MSR_ARCH_CAPABILITIES: u32 = 0x10a;
/// IA32_ARCH_CAPABILITIES: the CPU is not affected by rogue data cache load
/// (Meltdown).
pub(crate) const ARCH_CAPABILITIES_RDCL_NO: u64 = 1 << 0;

/// Whether a CPU keeps supervisor-only pages from user code under
/// speculation, which the direct map relies on: every root maps all of
/// allocator RAM, and Deepwyrm has no KPTI (DW2 M2 review R1; Mike,
/// 2026-11-12: refuse affected CPUs). Only Intel CPUs are affected, and an
/// Intel CPU is accepted only when it reports RDCL_NO.
/// `arch_capabilities` is `None` when the CPU has no such MSR.
pub(crate) const fn cpu_resists_rogue_data_cache_load(
    intel: bool,
    arch_capabilities: Option<u64>,
) -> bool {
    match arch_capabilities {
        _ if !intel => true,
        Some(capabilities) => capabilities & ARCH_CAPABILITIES_RDCL_NO != 0,
        None => false,
    }
}

/// CPUID.(EAX=7,ECX=0):EBX: supervisor-mode execution prevention.
pub(crate) const CPUID7_EBX_SMEP: u32 = 1 << 7;
/// CPUID.(EAX=7,ECX=0):EBX: supervisor-mode access prevention.
pub(crate) const CPUID7_EBX_SMAP: u32 = 1 << 20;

/// The CR4 supervisor protections a CPU whose leaf-7 EBX is `leaf7_ebx`
/// runs with (DW2 M2): SMEP and SMAP, each when the CPU has it. The kernel
/// never executes or touches user pages: it copies user memory through the
/// direct map, so it never needs STAC, and AC stays clear.
pub(crate) const fn supervisor_protections(leaf7_ebx: u32) -> u64 {
    let mut protections = 0;
    if leaf7_ebx & CPUID7_EBX_SMEP != 0 {
        protections |= CR4_SMEP;
    }
    if leaf7_ebx & CPUID7_EBX_SMAP != 0 {
        protections |= CR4_SMAP;
    }
    protections
}

/// Whether `cr4` holds every one of `protections`.
pub(crate) const fn cr4_enforces_supervisor_protections(cr4: u64, protections: u64) -> bool {
    cr4 & protections == protections
}

pub(crate) const fn cr0_enforces_user_fp(cr0: u64) -> bool {
    cr0 & (CR0_EMULATION | CR0_TASK_SWITCHED) == 0
        && cr0 & (CR0_MONITOR_COPROCESSOR | CR0_NUMERIC_ERROR)
            == CR0_MONITOR_COPROCESSOR | CR0_NUMERIC_ERROR
}

pub(crate) const fn cr4_enforces_user_fp(cr4: u64, mode: FpSaveMode) -> bool {
    cr4 == normalize_cr4_for_user_fp(cr4, mode)
}

/// MXCSR_MASK when FXSAVE reports zero: every bit but DAZ.
pub(crate) const DEFAULT_MXCSR_MASK: u32 = 0xffbf;

/// The MXCSR bits user code may set on this CPU, from FXSAVE's MXCSR_MASK.
pub(crate) const fn effective_mxcsr_mask(reported: u32) -> u32 {
    if reported == 0 {
        DEFAULT_MXCSR_MASK
    } else {
        reported
    }
}

/// What every CPU must agree on before user code runs: the save format,
/// and the MXCSR bits user code may set. A Thread may migrate, so a CPU
/// that accepted fewer MXCSR bits would fault restoring another's state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FpPolicy {
    pub(crate) mode: FpSaveMode,
    pub(crate) mxcsr_mask: u32,
}

const POLICY_PUBLISHED: u64 = 1 << 63;
const POLICY_FXSAVE: u64 = 1 << 62;

/// One non-zero word per policy, so CPUs can agree through one atomic:
/// bit 63 marks it published, bit 62 selects FXSAVE, bits 32..40 hold XCR0
/// (only x87, SSE and AVX are ever enabled) and bits 0..32 the MXCSR mask.
pub(crate) const fn encode_policy(policy: FpPolicy) -> u64 {
    let mode = match policy.mode {
        FpSaveMode::Fxsave => POLICY_FXSAVE,
        FpSaveMode::Xsave { xcr0 } => (xcr0 & 0xff) << 32,
    };
    POLICY_PUBLISHED | mode | policy.mxcsr_mask as u64
}

pub(crate) const fn decode_policy(word: u64) -> Option<FpPolicy> {
    if word & POLICY_PUBLISHED == 0 {
        return None;
    }
    let mode = if word & POLICY_FXSAVE != 0 {
        FpSaveMode::Fxsave
    } else {
        FpSaveMode::Xsave {
            xcr0: (word >> 32) & 0xff,
        }
    };
    Some(FpPolicy {
        mode,
        mxcsr_mask: word as u32,
    })
}

/// Checks this CPU's policy against the word another CPU already published.
pub(crate) const fn agrees_with_published(
    published: u64,
    policy: FpPolicy,
) -> Result<FpPolicy, FpPolicyError> {
    let Some(other) = decode_policy(published) else {
        return Err(FpPolicyError::ModeMismatch);
    };
    let same_mode = match (other.mode, policy.mode) {
        (FpSaveMode::Fxsave, FpSaveMode::Fxsave) => true,
        (FpSaveMode::Xsave { xcr0: a }, FpSaveMode::Xsave { xcr0: b }) => a == b,
        _ => false,
    };
    if !same_mode {
        Err(FpPolicyError::ModeMismatch)
    } else if other.mxcsr_mask != policy.mxcsr_mask {
        Err(FpPolicyError::MxcsrMaskMismatch)
    } else {
        Ok(policy)
    }
}

/// Is `value` an FS base a Thread may hold? Only lower-half canonical
/// addresses: a non-canonical one would fault the kernel's WRMSR, and the
/// kernel half is no business of user TLS.
pub(crate) const fn is_valid_user_fs_base(value: u64) -> bool {
    value < 0x0000_8000_0000_0000
}

/// A save area. The XSAVE header (bytes 512..576) must be zero apart from
/// what XSAVE itself writes, so every area starts zeroed.
#[derive(Clone)]
#[repr(C, align(64))]
pub(crate) struct FpArea(pub(crate) [u8; FP_AREA_BYTES]);

impl FpArea {
    pub(crate) const fn zeroed() -> Self {
        Self([0; FP_AREA_BYTES])
    }

    /// The architectural initial state as one image both restore forms
    /// accept: FCW 0x037F, an empty x87 stack, MXCSR 0x1F80 with every
    /// exception masked, zero registers, and an XSAVE header whose
    /// XSTATE_BV of zero puts every component in its initial configuration.
    pub(crate) const fn initial() -> Self {
        let mut bytes = [0; FP_AREA_BYTES];
        let fcw = INITIAL_FCW.to_le_bytes();
        bytes[0] = fcw[0];
        bytes[1] = fcw[1];
        let mxcsr = INITIAL_MXCSR.to_le_bytes();
        bytes[24] = mxcsr[0];
        bytes[25] = mxcsr[1];
        bytes[26] = mxcsr[2];
        bytes[27] = mxcsr[3];
        Self(bytes)
    }
}

/// Selectors a fresh Thread starts with in DS, ES, FS and GS: null.
pub(crate) const INITIAL_SELECTORS: [u16; 4] = [0; 4];

/// Everything a suspended Thread keeps of its user register state that the
/// syscall frame does not: FP/SIMD state, the FS base, and the DS, ES, FS
/// and GS selectors, which user code may load and which would otherwise
/// carry over to the next Thread on the CPU.
#[derive(Clone)]
#[repr(C, align(64))]
pub(crate) struct SavedUserState {
    pub(crate) fp: FpArea,
    pub(crate) fs_base: u64,
    /// DS, ES, FS, GS.
    pub(crate) selectors: [u16; 4],
}

impl SavedUserState {
    /// A save target: the FP area must start zeroed.
    pub(crate) const fn for_save() -> Self {
        Self {
            fp: FpArea::zeroed(),
            fs_base: 0,
            selectors: [0; 4],
        }
    }

    /// The state a Thread that has never run starts with.
    pub(crate) const fn initial() -> Self {
        Self {
            fp: FpArea::initial(),
            fs_base: 0,
            selectors: INITIAL_SELECTORS,
        }
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod live {
    use core::sync::atomic::{AtomicU64, Ordering};

    use super::{
        CpuFpFeatures, FpArea, FpPolicy, FpPolicyError, FpSaveMode, SavedUserState,
        agrees_with_published, decode_policy, effective_mxcsr_mask, encode_policy, plan_fp_mode,
        xsave_area_fits,
    };

    const IA32_FS_BASE: u32 = 0xc000_0100;
    const IA32_GS_BASE: u32 = 0xc000_0101;

    static FP_POLICY: AtomicU64 = AtomicU64::new(0);
    static INITIAL_STATE: SavedUserState = SavedUserState::initial();
    /// What the x87 scrub before each restore loads; see
    /// [`dw_x86_64_user_state_restore`].
    static X87_SCRUB_WORD: u32 = 0;

    fn cpu_fp_features() -> CpuFpFeatures {
        use core::arch::x86_64::{__cpuid, __cpuid_count};
        let leaf1 = __cpuid(1);
        let xcr0_supported = if leaf1.ecx & (1 << 26) != 0 && __cpuid(0).eax >= 0xd {
            let leaf_d = __cpuid_count(0xd, 0);
            (u64::from(leaf_d.edx) << 32) | u64::from(leaf_d.eax)
        } else {
            0
        };
        CpuFpFeatures {
            leaf1_ecx: leaf1.ecx,
            leaf1_edx: leaf1.edx,
            xcr0_supported,
        }
    }

    /// The save mode this CPU's CPUID allows. Reads CPUID only.
    pub(crate) fn plan_local_fp_mode() -> Result<FpSaveMode, FpPolicyError> {
        plan_fp_mode(cpu_fp_features())
    }

    /// Reads this CPU's MXCSR_MASK and checks `mode` and the mask against the
    /// policy the first CPU published, publishing it if this is the first.
    ///
    /// # Safety
    ///
    /// CPL0, with CR4.OSFXSR already set on this CPU.
    #[allow(unsafe_code, reason = "FXSAVE is the only way to read MXCSR_MASK")]
    pub(crate) unsafe fn agree_on_fp_policy(mode: FpSaveMode) -> Result<FpPolicy, FpPolicyError> {
        let mut area = FpArea::zeroed();
        // SAFETY: forwarded from this function's contract; `area` is a 64-byte-aligned local.
        unsafe { dw_x86_64_user_state_probe(&mut area) };
        let reported = u32::from_le_bytes([area.0[28], area.0[29], area.0[30], area.0[31]]);
        let policy = FpPolicy {
            mode,
            mxcsr_mask: effective_mxcsr_mask(reported),
        };
        let word = encode_policy(policy);
        match FP_POLICY.compare_exchange(0, word, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Ok(policy),
            Err(published) => agrees_with_published(published, policy),
        }
    }

    /// The save mode every CPU agreed on, once one CPU published it.
    pub(crate) fn current_fp_mode() -> Option<FpSaveMode> {
        decode_policy(FP_POLICY.load(Ordering::Acquire)).map(|policy| policy.mode)
    }

    fn published_mode() -> FpSaveMode {
        current_fp_mode().unwrap_or_else(|| halt_forever())
    }

    #[allow(
        unsafe_code,
        reason = "user state used before any CPU chose a save mode is terminal with interrupts disabled"
    )]
    fn halt_forever() -> ! {
        loop {
            // SAFETY: [ASM] CLI then HLT; neither touches memory or the stack.
            unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
        }
    }

    /// Writes XCR0 for an XSAVE mode and checks the resulting area size.
    ///
    /// # Safety
    ///
    /// CPL0 with CR4.OSXSAVE already set on this CPU.
    #[allow(
        unsafe_code,
        reason = "XSETBV is the only way to enable XSAVE state components"
    )]
    pub(crate) unsafe fn install_xcr0(mode: FpSaveMode) -> Result<(), FpPolicyError> {
        let FpSaveMode::Xsave { xcr0 } = mode else {
            return Ok(());
        };
        // SAFETY: [ASM] CPL0 and CR4.OSXSAVE per the contract; `plan_fp_mode` keeps `xcr0` within
        // the CPU's supported mask with x87 and SSE set, which XSETBV requires.
        unsafe {
            core::arch::asm!(
                "xsetbv",
                in("ecx") 0u32,
                in("eax") xcr0 as u32,
                in("edx") (xcr0 >> 32) as u32,
                options(nomem, nostack, preserves_flags)
            );
        }
        xsave_area_fits(core::arch::x86_64::__cpuid_count(0xd, 0).ebx)
    }

    /// FXSAVEs this CPU's registers into `area`, for its MXCSR_MASK field.
    /// Changes no register.
    ///
    /// # Safety
    ///
    /// CPL0 with CR4.OSFXSR set.
    #[allow(unsafe_code, reason = "FXSAVE into a local area to read MXCSR_MASK")]
    #[inline(never)]
    #[unsafe(no_mangle)]
    pub(crate) unsafe extern "sysv64" fn dw_x86_64_user_state_probe(area: &mut FpArea) {
        // SAFETY: [ASM] `area` is 64-byte-aligned and at least 512 bytes; FXSAVE only stores.
        unsafe {
            core::arch::asm!(
                "fxsave64 [{}]",
                in(reg) area.0.as_mut_ptr(),
                options(nostack, preserves_flags)
            );
        }
    }

    /// Saves the running Thread's FP state, FS base and DS/ES/FS/GS
    /// selectors into `state`.
    ///
    /// # Safety
    ///
    /// CPL0 on a CPU that installed the user FP policy; `state.fp` is zeroed.
    #[allow(
        unsafe_code,
        reason = "XSAVE/FXSAVE, RDMSR of the user FS base and selector reads at the context-switch boundary"
    )]
    #[inline(never)]
    #[unsafe(no_mangle)]
    pub(crate) unsafe extern "sysv64" fn dw_x86_64_user_state_save(state: &mut SavedUserState) {
        let pointer = state.fp.0.as_mut_ptr();
        match published_mode() {
            // SAFETY: [ASM] `pointer` is a 64-byte-aligned, writable area of `FP_AREA_BYTES`.
            FpSaveMode::Fxsave => unsafe {
                core::arch::asm!("fxsave64 [{}]", in(reg) pointer, options(nostack, preserves_flags));
            },
            // SAFETY: [ASM] as above; `install_xcr0` proved the enabled area fits.
            FpSaveMode::Xsave { xcr0 } => unsafe {
                core::arch::asm!(
                    "xsave64 [{}]",
                    in(reg) pointer,
                    in("eax") xcr0 as u32,
                    in("edx") (xcr0 >> 32) as u32,
                    options(nostack, preserves_flags)
                );
            },
        }
        let low: u32;
        let high: u32;
        // SAFETY: [ASM] IA32_FS_BASE exists on every x86-64 CPU.
        unsafe {
            core::arch::asm!(
                "rdmsr",
                in("ecx") IA32_FS_BASE,
                out("eax") low,
                out("edx") high,
                options(nomem, nostack, preserves_flags)
            );
        }
        state.fs_base = (u64::from(high) << 32) | u64::from(low);
        let (ds, es, fs, gs): (u16, u16, u16, u16);
        // SAFETY: [ASM] reading a segment register has no side effect.
        unsafe {
            core::arch::asm!(
                "mov {ds:x}, ds",
                "mov {es:x}, es",
                "mov {fs:x}, fs",
                "mov {gs:x}, gs",
                ds = out(reg) ds,
                es = out(reg) es,
                fs = out(reg) fs,
                gs = out(reg) gs,
                options(nomem, nostack, preserves_flags)
            );
        }
        state.selectors = [ds, es, fs, gs];
    }

    /// Restores a state saved by [`dw_x86_64_user_state_save`], or the
    /// initial state.
    ///
    /// Before the FP restore it runs FNCLEX, EMMS and an FILD of a fixed
    /// kernel word. AMD CPUs without CPUID Fn8000_0008h:EBX[2] (XSaveErPtr)
    /// restore the x87 FIP, FDP and FOP only when the saved FSW.ES is set, so
    /// without the scrub a Thread would see the last x87 instruction and data
    /// addresses of whichever Thread ran before it (CVE-2006-1056; Linux's
    /// `X86_BUG_FXSAVE_LEAK`). After the scrub, such a CPU shows every Thread
    /// the same fixed kernel addresses instead. Other CPUs restore all three
    /// fields, so the scrub costs a few cycles and changes nothing; it runs
    /// unconditionally so every boot exercises it.
    ///
    /// # Safety
    ///
    /// CPL0 on a CPU that installed the user FP policy, with IF clear;
    /// `state` was written by the save above on a CPU under the same policy,
    /// or is the initial state.
    #[allow(
        unsafe_code,
        reason = "selector loads, x87 scrub, XRSTOR/FXRSTOR and WRMSR of the user FS base at the context-switch boundary"
    )]
    #[inline(never)]
    #[unsafe(no_mangle)]
    pub(crate) unsafe extern "sysv64" fn dw_x86_64_user_state_restore(state: &SavedUserState) {
        let [ds, es, fs, gs] = state.selectors;
        // Selectors first: loading FS also loads an FS base, which the WRMSR below then replaces.
        // SAFETY: [ASM] each value was read back from a Thread that loaded it at CPL3, so it is
        // null or names a DPL3 data or readable code descriptor, and every CPU's GDT has the same
        // non-system layout (`gdt::GlobalDescriptorTable::new`); loading it at CPL0 cannot fault.
        // The initial selectors are null. DS and ES bases are ignored in 64-bit mode.
        unsafe {
            core::arch::asm!(
                "mov ds, {ds:x}",
                "mov es, {es:x}",
                "mov fs, {fs:x}",
                ds = in(reg) ds,
                es = in(reg) es,
                fs = in(reg) fs,
                options(nostack, preserves_flags)
            );
        }
        // Loading GS replaces the active GS base, which in the kernel is this CPU's entry record
        // (or, for an unswapped CPL3 exception origin, the user's base of zero). Read it first and
        // write it back, so the load is correct in either orientation. Skip it when GS already
        // holds the value, which is the common case.
        // SAFETY: [ASM] as above for the selector value; RDMSR/WRMSR of IA32_GS_BASE write back
        // the exact value just read, which is canonical. IF is clear per the contract, so only an
        // NMI can observe the brief window, and NMI is terminal.
        unsafe {
            core::arch::asm!(
                "mov {current:x}, gs",
                "cmp {current:x}, {gs:x}",
                "je 2f",
                "rdmsr",
                "mov gs, {gs:x}",
                "wrmsr",
                "2:",
                gs = in(reg) gs,
                current = out(reg) _,
                in("ecx") IA32_GS_BASE,
                out("eax") _,
                out("edx") _,
                options(nostack)
            );
        }
        let pointer = state.fp.0.as_ptr();
        match published_mode() {
            // SAFETY: [ASM] FNCLEX clears any pending x87 exception, so the next two cannot raise
            // #MF; EMMS empties every tag, so the FILD cannot overflow the stack; loading a 32-bit
            // integer is exact, so it raises nothing. `pointer` is a 64-byte-aligned area the save
            // above wrote, or the initial image, and its MXCSR has only bits the agreed mask allows.
            FpSaveMode::Fxsave => unsafe {
                core::arch::asm!(
                    "fnclex",
                    "emms",
                    "fild dword ptr [rip + {scrub}]",
                    "fxrstor64 [{area}]",
                    area = in(reg) pointer,
                    scrub = sym X87_SCRUB_WORD,
                    options(nostack, preserves_flags)
                );
            },
            // SAFETY: [ASM] as above; the header's reserved bytes are zero because every area
            // starts zeroed and XSAVE writes only XSTATE_BV.
            FpSaveMode::Xsave { xcr0 } => unsafe {
                core::arch::asm!(
                    "fnclex",
                    "emms",
                    "fild dword ptr [rip + {scrub}]",
                    "xrstor64 [{area}]",
                    area = in(reg) pointer,
                    scrub = sym X87_SCRUB_WORD,
                    in("eax") xcr0 as u32,
                    in("edx") (xcr0 >> 32) as u32,
                    options(nostack, preserves_flags)
                );
            },
        }
        let fs_base = state.fs_base;
        // SAFETY: [ASM] `fs_base` came from RDMSR or `thread_set_fs_base`, or is 0, so it is
        // canonical and WRMSR cannot fault.
        unsafe {
            core::arch::asm!(
                "wrmsr",
                in("ecx") IA32_FS_BASE,
                in("eax") fs_base as u32,
                in("edx") (fs_base >> 32) as u32,
                options(nomem, nostack, preserves_flags)
            );
        }
    }

    /// Puts this CPU's user state in a fresh Thread's initial configuration.
    ///
    /// # Safety
    ///
    /// As for [`dw_x86_64_user_state_restore`].
    #[allow(unsafe_code, reason = "loads the static initial state")]
    pub(crate) unsafe fn load_initial_user_state() {
        // SAFETY: the initial state is valid for both restore forms, with null selectors and FS
        // base 0.
        unsafe { dw_x86_64_user_state_restore(&INITIAL_STATE) }
    }

    /// Sets the running Thread's FS base (`thread_set_fs_base`).
    ///
    /// # Safety
    ///
    /// CPL0, on the CPU running the calling Thread, with IF clear;
    /// `fs_base` passed [`super::is_valid_user_fs_base`].
    #[allow(unsafe_code, reason = "WRMSR of the running Thread's FS base")]
    pub(crate) unsafe fn write_current_fs_base(fs_base: u64) {
        // SAFETY: [ASM] the contract keeps `fs_base` canonical.
        unsafe {
            core::arch::asm!(
                "wrmsr",
                in("ecx") IA32_FS_BASE,
                in("eax") fs_base as u32,
                in("edx") (fs_base >> 32) as u32,
                options(nomem, nostack, preserves_flags)
            );
        }
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) use live::{
    agree_on_fp_policy, current_fp_mode, dw_x86_64_user_state_restore, dw_x86_64_user_state_save,
    install_xcr0, load_initial_user_state, plan_local_fp_mode, write_current_fs_base,
};

#[cfg(test)]
#[path = "user_state/tests.rs"]
mod tests;
