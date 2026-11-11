use super::*;

const FXSR_SSE_SSE2: u32 = (1 << 24) | (1 << 25) | (1 << 26);
const XSAVE: u32 = 1 << 26;
const AVX: u32 = 1 << 28;

fn features(leaf1_ecx: u32, leaf1_edx: u32, xcr0_supported: u64) -> CpuFpFeatures {
    CpuFpFeatures {
        leaf1_ecx,
        leaf1_edx,
        xcr0_supported,
    }
}

#[test]
fn a_cpu_without_sse2_cannot_run_psabi_user_code() {
    for edx in [0, 1 << 24, (1 << 24) | (1 << 25), (1 << 25) | (1 << 26)] {
        assert_eq!(
            plan_fp_mode(features(XSAVE | AVX, edx, 0x7)),
            Err(FpPolicyError::MissingSse2)
        );
    }
}

#[test]
fn a_cpu_without_xsave_falls_back_to_fxsave() {
    assert_eq!(
        plan_fp_mode(features(AVX, FXSR_SSE_SSE2, 0x7)),
        Ok(FpSaveMode::Fxsave)
    );
}

#[test]
fn xsave_enables_avx_only_when_cpuid_and_xcr0_both_offer_it() {
    assert_eq!(
        plan_fp_mode(features(XSAVE | AVX, FXSR_SSE_SSE2, 0x7)),
        Ok(FpSaveMode::Xsave { xcr0: 0x7 })
    );
    assert_eq!(
        plan_fp_mode(features(XSAVE, FXSR_SSE_SSE2, 0x7)),
        Ok(FpSaveMode::Xsave { xcr0: 0x3 })
    );
    assert_eq!(
        plan_fp_mode(features(XSAVE | AVX, FXSR_SSE_SSE2, 0x3)),
        Ok(FpSaveMode::Xsave { xcr0: 0x3 })
    );
}

#[test]
fn wider_components_stay_out_of_xcr0() {
    // AVX-512 (bits 5-7), PKRU (9) and AMX (17, 18) are supported but not enabled.
    let supported = 0x7 | 0xe0 | (1 << 9) | (1 << 17) | (1 << 18);
    assert_eq!(
        plan_fp_mode(features(XSAVE | AVX, FXSR_SSE_SSE2, supported)),
        Ok(FpSaveMode::Xsave { xcr0: 0x7 })
    );
}

#[test]
fn xsave_without_legacy_components_is_refused() {
    assert_eq!(
        plan_fp_mode(features(XSAVE, FXSR_SSE_SSE2, 0x1)),
        Err(FpPolicyError::XsaveWithoutLegacyState)
    );
}

#[test]
fn the_area_holds_x87_sse_and_avx_but_not_more() {
    assert_eq!(xsave_area_fits(576), Ok(()));
    assert_eq!(xsave_area_fits(832), Ok(()));
    assert_eq!(xsave_area_fits(1024), Ok(()));
    assert_eq!(xsave_area_fits(575), Err(FpPolicyError::AreaTooLarge));
    assert_eq!(xsave_area_fits(2696), Err(FpPolicyError::AreaTooLarge));
}

#[test]
fn cr0_normalization_turns_on_native_fp_and_off_every_trap() {
    for value in [0, u64::MAX, 0x8005_003b, 0x8000_0011] {
        let normalized = normalize_cr0_for_user_fp(value);
        assert!(cr0_enforces_user_fp(normalized));
        let touched = CR0_MONITOR_COPROCESSOR | CR0_EMULATION | CR0_TASK_SWITCHED | CR0_NUMERIC_ERROR;
        assert_eq!(normalized & !touched, value & !touched);
    }
    assert!(!cr0_enforces_user_fp(0x8005_0033 | CR0_TASK_SWITCHED));
    assert!(!cr0_enforces_user_fp(0x8005_0033 | CR0_EMULATION));
    assert!(!cr0_enforces_user_fp(0x8005_0031));
}

#[test]
fn cr4_normalization_follows_the_mode_and_keeps_fsgsbase_off() {
    let xsave = FpSaveMode::Xsave { xcr0: 0x7 };
    for value in [0, u64::MAX, 0x0000_06a0, CR4_FSGSBASE | CR4_OSXSAVE] {
        let fx = normalize_cr4_for_user_fp(value, FpSaveMode::Fxsave);
        assert_eq!(fx & (CR4_OSFXSR | CR4_OSXMMEXCPT), CR4_OSFXSR | CR4_OSXMMEXCPT);
        assert_eq!(fx & (CR4_FSGSBASE | CR4_OSXSAVE), 0);
        assert!(cr4_enforces_user_fp(fx, FpSaveMode::Fxsave));

        let xs = normalize_cr4_for_user_fp(value, xsave);
        assert_eq!(xs & CR4_OSXSAVE, CR4_OSXSAVE);
        assert_eq!(xs & CR4_FSGSBASE, 0);
        assert!(cr4_enforces_user_fp(xs, xsave));

        let touched = CR4_OSFXSR | CR4_OSXMMEXCPT | CR4_FSGSBASE | CR4_OSXSAVE;
        assert_eq!(xs & !touched, value & !touched);
    }
    assert!(!cr4_enforces_user_fp(CR4_OSFXSR | CR4_OSXMMEXCPT, xsave));
    assert!(!cr4_enforces_user_fp(
        CR4_OSFXSR | CR4_OSXMMEXCPT | CR4_FSGSBASE,
        FpSaveMode::Fxsave
    ));
}

#[test]
fn modes_round_trip_through_their_shared_word() {
    for mode in [
        FpSaveMode::Fxsave,
        FpSaveMode::Xsave { xcr0: 0x3 },
        FpSaveMode::Xsave { xcr0: 0x7 },
    ] {
        assert_ne!(encode_mode(mode), 0);
        assert_eq!(decode_mode(encode_mode(mode)), Some(mode));
    }
    assert_eq!(decode_mode(0), None);
    assert_ne!(
        encode_mode(FpSaveMode::Fxsave),
        encode_mode(FpSaveMode::Xsave { xcr0: 0x3 })
    );
}

#[test]
fn only_lower_half_canonical_fs_bases_are_accepted() {
    for value in [0, 0x1000, 0x0000_7fff_ffff_f000, 0x0000_7fff_ffff_ffff] {
        assert!(is_valid_user_fs_base(value));
    }
    for value in [
        0x0000_8000_0000_0000,
        0x1234_5678_0000_0000,
        0xffff_8000_0000_0000,
        u64::MAX,
    ] {
        assert!(!is_valid_user_fs_base(value));
    }
}

#[test]
fn the_initial_image_is_the_architectural_reset_state() {
    let image = FpArea::initial();
    assert_eq!(core::mem::align_of::<FpArea>(), 64);
    assert_eq!(core::mem::size_of::<FpArea>(), FP_AREA_BYTES);
    assert_eq!(u16::from_le_bytes([image.0[0], image.0[1]]), 0x037f);
    assert_eq!(
        u32::from_le_bytes([image.0[24], image.0[25], image.0[26], image.0[27]]),
        0x1f80
    );
    // Abridged tag word: every x87 register empty.
    assert_eq!(image.0[4], 0);
    // XSAVE header: XSTATE_BV and XCOMP_BV zero, reserved bytes zero.
    assert!(image.0[512..576].iter().all(|byte| *byte == 0));
    let set: usize = image.0.iter().filter(|byte| **byte != 0).count();
    assert_eq!(set, 4, "only FCW and MXCSR differ from zero");
    assert!(FpArea::zeroed().0.iter().all(|byte| *byte == 0));
}

#[test]
fn every_cpu_must_choose_the_bootstrap_cpus_mode() {
    let xsave = FpSaveMode::Xsave { xcr0: 0x7 };
    assert_eq!(agrees_with_published(encode_mode(xsave), xsave), Ok(xsave));
    assert_eq!(
        agrees_with_published(encode_mode(FpSaveMode::Fxsave), xsave),
        Err(FpPolicyError::ModeMismatch)
    );
    assert_eq!(
        agrees_with_published(encode_mode(FpSaveMode::Xsave { xcr0: 0x3 }), xsave),
        Err(FpPolicyError::ModeMismatch)
    );
}
