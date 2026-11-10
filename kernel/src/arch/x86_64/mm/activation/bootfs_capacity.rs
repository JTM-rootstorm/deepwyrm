//! Bootfs page measurement for the selector-local capacity checks in
//! `primordial.rs`.
//!
//! Split out of the target-only `primordial.rs` (S2K-0) so that the host
//! `test` build compiles it and its test runs; in `primordial.rs` the test
//! compiled nowhere.

/// Selector 22's (`smp-runtime-stress`) bootfs page ceiling. It sizes the
/// primordial mapping journal and invalidation set, so every single mapping of
/// the whole archive -- the bootstrap's, init0's and the I2 controller's --
/// needs one slot per archive page in one publish.
///
/// The archive carries init0 and the I2 payload. Wyrmroot `fd72ab5` (stage 7)
/// measured 157,936 bytes, 39 pages, past the previous 32-page constant, which
/// failed the bootstrap's bootfs map with `publisher-slots`. 64 keeps bounded
/// headroom; a larger archive fails `enter`'s admission check with detail
/// `0x2210_b001` instead of an opaque NO_RESOURCES.
#[cfg_attr(
    not(any(test, all(deepwyrm_i2_stress, not(deepwyrm_wrcap_relay)))),
    expect(
        dead_code,
        reason = "only selector 22's primordial arm and host tests read it"
    )
)]
pub(super) const I2_STRESS_BOOTFS_MAX_PAGES: usize = 64;

/// The number of 4 KiB pages a bootfs of `byte_len` bytes occupies, rounded
/// up; `None` for an empty archive or a length whose rounding overflows.
pub(super) const fn integration_bootfs_page_count(byte_len: usize) -> Option<usize> {
    if byte_len == 0 {
        return None;
    }
    match byte_len.checked_add(4095) {
        Some(rounded) => Some(rounded / 4096),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed 128-page ceiling (the retired selector 25's) to check the
    /// measurement against a bound.
    const WYR1_BOOTFS_MAX_PAGES: usize = 128;

    #[test]
    fn integration_bootfs_measurement_accepts_selector_local_capacity_and_rejects_larger_inputs() {
        assert_eq!(integration_bootfs_page_count(0), None);
        assert_eq!(integration_bootfs_page_count(1), Some(1));
        assert_eq!(integration_bootfs_page_count(4096), Some(1));
        assert_eq!(integration_bootfs_page_count(4097), Some(2));
        assert_eq!(integration_bootfs_page_count(169_896), Some(42));
        assert_eq!(integration_bootfs_page_count(170_496), Some(42));
        assert_eq!(integration_bootfs_page_count(308_576), Some(76));
        assert_eq!(integration_bootfs_page_count(309_192), Some(76));
        assert_eq!(integration_bootfs_page_count(128 * 4096), Some(128));
        assert!(matches!(
            integration_bootfs_page_count(128 * 4096),
            Some(1..=WYR1_BOOTFS_MAX_PAGES)
        ));
        assert_eq!(integration_bootfs_page_count(128 * 4096 + 1), Some(129));
        assert!(!matches!(
            integration_bootfs_page_count(128 * 4096 + 1),
            Some(1..=WYR1_BOOTFS_MAX_PAGES)
        ));
        assert_eq!(integration_bootfs_page_count(usize::MAX), None);
    }

    /// The 32-page stack mapping is the other user of the primordial journal;
    /// `PRIMORDIAL_MAX_MAPPING_PAGES` takes the larger of the two.
    const PRIMORDIAL_STACK_MAPPING_PAGES: usize =
        crate::boot::primordial::construction::STACK_BYTES as usize / 4096;

    #[test]
    fn selector_22_ceiling_admits_the_measured_stage_7_archive() {
        // Wyrmroot fd72ab5's selector-22 archive, the one that failed with
        // `publisher-slots` against the old 32-page constant.
        const STAGE_7_BOOTFS_BYTES: usize = 157_936;
        let pages = integration_bootfs_page_count(STAGE_7_BOOTFS_BYTES).unwrap();
        assert_eq!(pages, 39);
        assert!(pages > 32, "the regression archive exceeds the old ceiling");
        assert!(matches!(
            integration_bootfs_page_count(STAGE_7_BOOTFS_BYTES),
            Some(1..=I2_STRESS_BOOTFS_MAX_PAGES)
        ));
        const { assert!(I2_STRESS_BOOTFS_MAX_PAGES >= PRIMORDIAL_STACK_MAPPING_PAGES) };
        assert!(!matches!(
            integration_bootfs_page_count(I2_STRESS_BOOTFS_MAX_PAGES * 4096 + 1),
            Some(1..=I2_STRESS_BOOTFS_MAX_PAGES)
        ));
    }

    #[test]
    fn selector_22_arm_reads_the_ceiling_and_admits_bootfs_before_mapping() {
        let primordial = include_str!("primordial.rs");
        assert!(primordial.contains(
            "#[cfg(all(deepwyrm_i2_stress, not(deepwyrm_wrcap_relay)))]\n\
             const PRIMORDIAL_BOOTFS_MAX_PAGES: usize = bootfs_capacity::I2_STRESS_BOOTFS_MAX_PAGES;\n"
        ));
        assert!(!primordial.contains("const PRIMORDIAL_BOOTFS_MAX_PAGES: usize = 32;"));
        // The admission block sits directly after the bootfs copy, so nothing
        // can map the archive before it is checked.
        assert!(primordial.contains(
            "    let bootfs = copy_module(&mut active, modules.bootfs(), &BOOTFS_BYTES, \"bootfs\");\n\
             \x20   #[cfg(all(deepwyrm_i2_stress, not(deepwyrm_wrcap_relay)))]\n\
             \x20   if !matches!(\n\
             \x20       bootfs_capacity::integration_bootfs_page_count(bootfs.len()),\n\
             \x20       Some(1..=PRIMORDIAL_BOOTFS_MAX_PAGES)\n\
             \x20   ) {\n\
             \x20       crate::test_support::complete_fail(0x2210_b001)\n\
             \x20   }\n"
        ));
    }
}
