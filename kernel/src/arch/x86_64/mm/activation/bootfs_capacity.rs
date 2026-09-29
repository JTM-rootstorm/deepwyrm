//! Bootfs page measurement for the selector-local capacity checks in
//! `primordial.rs`.
//!
//! Split out of the target-only `primordial.rs` (S2K-0) so that the host
//! `test` build compiles it and its test runs; in `primordial.rs` the test
//! compiled nowhere.

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

    /// Selector 25's page ceiling: the `deepwyrm_wyr1_evidence` arm of
    /// `PRIMORDIAL_BOOTFS_MAX_PAGES`, which is target-only and so cannot be
    /// named here. The test was written against that arm.
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
}
