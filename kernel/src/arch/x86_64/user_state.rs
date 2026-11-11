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
//! out of XCR0, which keeps the save area within [`FP_AREA_BYTES`].

pub(crate) const CR0_MONITOR_COPROCESSOR: u64 = 1 << 1;
pub(crate) const CR0_EMULATION: u64 = 1 << 2;
pub(crate) const CR0_TASK_SWITCHED: u64 = 1 << 3;
pub(crate) const CR0_NUMERIC_ERROR: u64 = 1 << 5;

pub(crate) const CR4_OSFXSR: u64 = 1 << 9;
pub(crate) const CR4_OSXMMEXCPT: u64 = 1 << 10;
pub(crate) const CR4_FSGSBASE: u64 = 1 << 16;
pub(crate) const CR4_OSXSAVE: u64 = 1 << 18;

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

/// CR4 for user FP: FXSAVE/SSE and SIMD exceptions on, OSXSAVE exactly when
/// the mode uses XSAVE, and RD/WR{FS,GS}BASE kept off (user code must never
/// write GS; the FS base changes only through `thread_set_fs_base`).
pub(crate) const fn normalize_cr4_for_user_fp(cr4: u64, mode: FpSaveMode) -> u64 {
    let base = (cr4 | CR4_OSFXSR | CR4_OSXMMEXCPT) & !CR4_FSGSBASE;
    match mode {
        FpSaveMode::Fxsave => base & !CR4_OSXSAVE,
        FpSaveMode::Xsave { .. } => base | CR4_OSXSAVE,
    }
}

pub(crate) const fn cr0_enforces_user_fp(cr0: u64) -> bool {
    cr0 & (CR0_EMULATION | CR0_TASK_SWITCHED) == 0
        && cr0 & (CR0_MONITOR_COPROCESSOR | CR0_NUMERIC_ERROR)
            == CR0_MONITOR_COPROCESSOR | CR0_NUMERIC_ERROR
}

pub(crate) const fn cr4_enforces_user_fp(cr4: u64, mode: FpSaveMode) -> bool {
    cr4 == normalize_cr4_for_user_fp(cr4, mode)
}

/// One non-zero word per mode, so CPUs can agree through one atomic.
pub(crate) const fn encode_mode(mode: FpSaveMode) -> u64 {
    match mode {
        FpSaveMode::Fxsave => 1 << 63,
        FpSaveMode::Xsave { xcr0 } => xcr0 & !(1 << 63),
    }
}

pub(crate) const fn decode_mode(word: u64) -> Option<FpSaveMode> {
    if word == 0 {
        None
    } else if word == 1 << 63 {
        Some(FpSaveMode::Fxsave)
    } else {
        Some(FpSaveMode::Xsave { xcr0: word })
    }
}

/// Checks this CPU's mode against the word another CPU already published.
pub(crate) const fn agrees_with_published(
    published: u64,
    mode: FpSaveMode,
) -> Result<FpSaveMode, FpPolicyError> {
    if published == encode_mode(mode) {
        Ok(mode)
    } else {
        Err(FpPolicyError::ModeMismatch)
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

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod live {
    use core::sync::atomic::{AtomicU64, Ordering};

    use super::{
        CpuFpFeatures, FpArea, FpPolicyError, FpSaveMode, agrees_with_published, decode_mode,
        encode_mode, plan_fp_mode, xsave_area_fits,
    };

    const IA32_FS_BASE: u32 = 0xc000_0100;

    static FP_MODE: AtomicU64 = AtomicU64::new(0);
    static INITIAL_AREA: FpArea = FpArea::initial();

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

    /// Chooses this CPU's save mode and checks it against the one the first
    /// CPU published. Reads CPUID only.
    pub(crate) fn agree_on_fp_mode() -> Result<FpSaveMode, FpPolicyError> {
        let mode = plan_fp_mode(cpu_fp_features())?;
        let word = encode_mode(mode);
        match FP_MODE.compare_exchange(0, word, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Ok(mode),
            Err(published) => agrees_with_published(published, mode),
        }
    }

    fn published_mode() -> FpSaveMode {
        decode_mode(FP_MODE.load(Ordering::Acquire))
            .unwrap_or_else(|| halt_forever())
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

    /// Saves the running Thread's FP state into `area` and returns its FS base.
    ///
    /// # Safety
    ///
    /// CPL0 on a CPU that installed the user FP policy; `area` is zeroed.
    #[allow(
        unsafe_code,
        reason = "XSAVE/FXSAVE and RDMSR of the user FS base at the context-switch boundary"
    )]
    #[inline(never)]
    #[unsafe(no_mangle)]
    pub(crate) unsafe extern "sysv64" fn dw_x86_64_user_state_save(area: &mut FpArea) -> u64 {
        let pointer = area.0.as_mut_ptr();
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
        (u64::from(high) << 32) | u64::from(low)
    }

    /// Restores FP state saved by [`dw_x86_64_user_state_save`] (or the
    /// initial image) and the FS base.
    ///
    /// # Safety
    ///
    /// CPL0 on a CPU that installed the user FP policy; `area` was written by
    /// the save above on a CPU with the same mode, or is the initial image;
    /// `fs_base` is lower-half canonical.
    #[allow(
        unsafe_code,
        reason = "XRSTOR/FXRSTOR and WRMSR of the user FS base at the context-switch boundary"
    )]
    #[inline(never)]
    #[unsafe(no_mangle)]
    pub(crate) unsafe extern "sysv64" fn dw_x86_64_user_state_restore(area: &FpArea, fs_base: u64) {
        let pointer = area.0.as_ptr();
        match published_mode() {
            // SAFETY: [ASM] `pointer` is a 64-byte-aligned area the save above wrote, or the
            // initial image, whose MXCSR has no reserved bit set.
            FpSaveMode::Fxsave => unsafe {
                core::arch::asm!("fxrstor64 [{}]", in(reg) pointer, options(nostack, preserves_flags));
            },
            // SAFETY: [ASM] as above; the header's reserved bytes are zero because every area
            // starts zeroed and XSAVE writes only XSTATE_BV.
            FpSaveMode::Xsave { xcr0 } => unsafe {
                core::arch::asm!(
                    "xrstor64 [{}]",
                    in(reg) pointer,
                    in("eax") xcr0 as u32,
                    in("edx") (xcr0 >> 32) as u32,
                    options(nostack, preserves_flags)
                );
            },
        }
        // SAFETY: [ASM] the contract keeps `fs_base` canonical, so WRMSR cannot fault.
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
    #[allow(unsafe_code, reason = "loads the static initial image")]
    pub(crate) unsafe fn load_initial_user_state() {
        // SAFETY: the initial image is valid for both restore forms; 0 is canonical.
        unsafe { dw_x86_64_user_state_restore(&INITIAL_AREA, 0) }
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
    agree_on_fp_mode, dw_x86_64_user_state_restore, dw_x86_64_user_state_save, install_xcr0,
    load_initial_user_state, write_current_fs_base,
};

#[cfg(test)]
#[path = "user_state/tests.rs"]
mod tests;
