use super::*;
extern crate std;
use std::collections::{BTreeMap, BTreeSet};
use std::vec::Vec;

const LIMIT: u64 = 1 << 40;

#[derive(Default)]
struct FakeTables {
    entries: BTreeMap<(u64, usize), u64>,
    zero_exclusive: BTreeSet<u64>,
    claimed: BTreeSet<u64>,
    owned_roots: BTreeSet<u64>,
    invalidated: Vec<u64>,
    fail_read: Option<(u64, usize)>,
    fail_commit_before_write: bool,
    fail_after_claim: Option<usize>,
    fail_after_write: Option<usize>,
    conflict_mutation: Option<usize>,
    conflict_assertion: Option<usize>,
    inject_leaf_ad_bits: bool,
}

impl FakeTables {
    fn entry(&self, table: u64, index: usize) -> u64 {
        *self.entries.get(&(table, index)).unwrap_or(&0)
    }

    fn mark_zero_exclusive(&mut self, frames: &[u64]) {
        self.zero_exclusive.extend(frames.iter().copied());
    }

    fn owned_root() -> Self {
        let mut tables = Self::default();
        tables.owned_roots.insert(0x1000);
        tables.claimed.insert(0x1000);
        tables
    }
}

impl PageTableTransaction for FakeTables {
    type Error = ();

    fn read_entry(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error> {
        if self.fail_read == Some((table.address(), index)) {
            return Err(());
        }
        Ok(self.entry(table.address(), index))
    }

    fn commit(&mut self, plan: &MutationPlan) -> Result<(), CommitError<Self::Error>> {
        if self.fail_commit_before_write {
            return Err(CommitError::Access(()));
        }
        if !self.owned_roots.contains(&plan.root().address())
            || plan
                .leaf_data()
                .is_some_and(|frame| self.claimed.contains(&frame.address()))
        {
            return Err(CommitError::TableClaimRejected);
        }
        for frame in plan.new_tables() {
            if !self.zero_exclusive.contains(&frame.address())
                || self.claimed.contains(&frame.address())
                || self
                    .entries
                    .keys()
                    .any(|(table, _)| *table == frame.address())
                || self.entries.values().any(|entry| {
                    *entry & PRESENT != 0
                        && (*entry & address_mask(root().physical_limit())) == frame.address()
                })
            {
                return Err(CommitError::TableClaimRejected);
            }
        }
        for (index, mutation) in plan.mutations().iter().enumerate() {
            if mutation.table() != plan.root()
                && !self.claimed.contains(&mutation.table().address())
                && !plan.new_tables().contains(&mutation.table())
            {
                return Err(CommitError::TableClaimRejected);
            }
            if self.conflict_mutation == Some(index) {
                return Err(CommitError::JournalConflict);
            }
            let mut actual = self.entry(mutation.table().address(), mutation.index());
            if self.inject_leaf_ad_bits && index + 1 == plan.mutations().len() {
                actual |= ACCESSED | DIRTY;
            }
            if actual & mutation.compare_mask() != mutation.expected() & mutation.compare_mask() {
                return Err(CommitError::JournalConflict);
            }
        }
        for (index, assertion) in plan.assertions().iter().enumerate() {
            if !self.claimed.contains(&assertion.table().address()) {
                return Err(CommitError::TableClaimRejected);
            }
            if self.conflict_assertion == Some(index) {
                return Err(CommitError::JournalConflict);
            }
            let actual = self.entry(assertion.table().address(), assertion.index());
            if actual & assertion.compare_mask() != assertion.expected() & assertion.compare_mask()
            {
                return Err(CommitError::JournalConflict);
            }
        }
        let mut staged_claims = self.claimed.clone();
        let mut staged_entries = self.entries.clone();
        if self.inject_leaf_ad_bits
            && let Some(leaf) = plan.mutations().last()
        {
            let actual = *staged_entries
                .get(&(leaf.table().address(), leaf.index()))
                .unwrap_or(&0);
            staged_entries.insert(
                (leaf.table().address(), leaf.index()),
                actual | ACCESSED | DIRTY,
            );
        }
        for (index, frame) in plan.new_tables().iter().enumerate() {
            staged_claims.insert(frame.address());
            if self.fail_after_claim == Some(index) {
                return Err(CommitError::Access(()));
            }
        }
        for (index, mutation) in plan.mutations().iter().rev().enumerate() {
            let actual = *staged_entries
                .get(&(mutation.table().address(), mutation.index()))
                .unwrap_or(&0);
            let replacement = mutation.replacement() | (actual & mutation.preserve_mask());
            staged_entries.insert((mutation.table().address(), mutation.index()), replacement);
            if self.fail_after_write == Some(index) {
                return Err(CommitError::Access(()));
            }
        }
        self.claimed = staged_claims;
        self.entries = staged_entries;
        self.invalidated.push(plan.page().address());
        Ok(())
    }
}

fn root() -> PageTableRoot {
    // SAFETY: test backends register 0x1000 as their unique owned root.
    #[allow(unsafe_code, reason = "host test establishes fake root ownership")]
    unsafe {
        PageTableRoot::from_owned_root(
            0x1000,
            PagingCapabilities::validate(40, true, true, true).unwrap(),
        )
        .unwrap()
    }
}

fn page() -> VirtualPage {
    VirtualPage::new(0x4000).unwrap()
}

#[test]
fn maps_rewalks_protects_and_unmaps_with_local_invalidation() {
    let mut tables = FakeTables::owned_root();
    tables.mark_zero_exclusive(&[0x2000, 0x3000, 0x4000]);
    root()
        .map_page(
            &mut tables,
            page(),
            0x5000,
            MappingPermissions::USER_READ_WRITE,
            &[0x2000, 0x3000, 0x4000],
        )
        .unwrap();
    assert_eq!(tables.claimed.len(), 4);
    assert_eq!(tables.invalidated, [0x4000]);

    root()
        .protect_page(&mut tables, page(), MappingPermissions::USER_READ_ONLY)
        .unwrap();
    let frame = root().unmap_page(&mut tables, page()).unwrap();
    assert_eq!(frame.address(), 0x5000);
    assert_eq!(tables.invalidated, [0x4000, 0x4000, 0x4000]);
}

#[test]
fn preflight_and_commit_failures_leave_entries_claims_and_tlb_unchanged() {
    for mode in 0..10 {
        let mut tables = FakeTables::owned_root();
        tables.mark_zero_exclusive(&[0x2000, 0x3000, 0x4000]);
        if mode == 0 {
            tables.fail_read = Some((0x1000, page().index(3)));
        } else if mode == 1 {
            tables.fail_commit_before_write = true;
        } else if mode == 2 {
            tables.zero_exclusive.remove(&0x3000);
        } else if mode < 6 {
            tables.fail_after_claim = Some(mode - 3);
        } else {
            tables.fail_after_write = Some(mode - 6);
        }
        let entries = tables.entries.clone();
        let claims = tables.claimed.clone();
        let invalidated = tables.invalidated.clone();
        assert!(
            root()
                .map_page(
                    &mut tables,
                    page(),
                    0x5000,
                    MappingPermissions::USER_READ_WRITE,
                    &[0x2000, 0x3000, 0x4000],
                )
                .is_err()
        );
        assert_eq!(tables.entries, entries);
        assert_eq!(tables.claimed, claims);
        assert_eq!(tables.invalidated, invalidated);
    }

    for conflict in 0..4 {
        let mut tables = FakeTables::owned_root();
        tables.mark_zero_exclusive(&[0x2000, 0x3000, 0x4000]);
        tables.conflict_mutation = Some(conflict);
        let entries = tables.entries.clone();
        let claims = tables.claimed.clone();
        assert!(
            root()
                .map_page(
                    &mut tables,
                    page(),
                    0x5000,
                    MappingPermissions::USER_READ_WRITE,
                    &[0x2000, 0x3000, 0x4000],
                )
                .is_err()
        );
        assert_eq!(tables.entries, entries);
        assert_eq!(tables.claimed, claims);
        assert!(tables.invalidated.is_empty());
    }
}

#[test]
fn rejects_table_leaf_alias_and_never_trusts_a_cached_leaf_path() {
    let mut tables = FakeTables::owned_root();
    tables.mark_zero_exclusive(&[0x2000, 0x3000, 0x4000]);
    assert_eq!(
        root().map_page(
            &mut tables,
            page(),
            0x3000,
            MappingPermissions::USER_READ_ONLY,
            &[0x2000, 0x3000, 0x4000],
        ),
        Err(MapError::InvalidPath)
    );
    assert_eq!(
        root().unmap_page(&mut tables, page()),
        Err(MapError::InvalidPath)
    );
    assert_eq!(
        root().map_page(
            &mut tables,
            page(),
            root().frame().address(),
            MappingPermissions::USER_READ_ONLY,
            &[0x2000, 0x3000, 0x4000],
        ),
        Err(MapError::InvalidPath)
    );
    tables.claimed.insert(0x5000);
    assert_eq!(
        root().map_page(
            &mut tables,
            page(),
            0x5000,
            MappingPermissions::USER_READ_ONLY,
            &[0x2000, 0x3000, 0x4000],
        ),
        Err(MapError::TableClaimRejected)
    );
}

#[test]
fn rejects_noncanonical_aliases_and_cyclic_ancestor_paths() {
    for address in [
        0x0000_8000_0000_0000,
        0xffff_0000_0000_0000,
        0xffff_7fff_ffff_f000,
    ] {
        assert_eq!(
            VirtualPage::new(address),
            Err(AddressError::InvalidVirtualPage(address))
        );
    }

    let mut self_cycle = FakeTables::owned_root();
    self_cycle.entries.insert(
        (0x1000, page().index(3)),
        intermediate_entry(root().frame(), true),
    );
    assert_eq!(
        root().unmap_page(&mut self_cycle, page()),
        Err(MapError::InvalidPath)
    );

    let mut two_node = FakeTables::owned_root();
    two_node.claimed.insert(0x2000);
    two_node.entries.insert(
        (0x1000, page().index(3)),
        intermediate_entry(FrameAddress(0x2000), true),
    );
    two_node.entries.insert(
        (0x2000, page().index(2)),
        intermediate_entry(root().frame(), true),
    );
    assert_eq!(
        root().protect_page(&mut two_node, page(), MappingPermissions::USER_READ_ONLY),
        Err(MapError::InvalidPath)
    );
}

#[test]
fn rejects_page_zero_half_mismatch_wx_and_unreadable_mappings() {
    let mut tables = FakeTables::owned_root();
    assert_eq!(
        root().map_page(
            &mut tables,
            VirtualPage::new(0).unwrap(),
            0x5000,
            MappingPermissions::USER_READ_ONLY,
            &[],
        ),
        Err(MapError::PageZero)
    );
    let wx = MappingPermissions {
        user: true,
        readable: true,
        writable: true,
        executable: true,
    };
    assert_eq!(
        root().map_page(&mut tables, page(), 0x5000, wx, &[]),
        Err(MapError::WritableExecutable)
    );
    let execute_only = MappingPermissions {
        user: true,
        readable: false,
        writable: false,
        executable: true,
    };
    assert_eq!(
        root().map_page(&mut tables, page(), 0x5000, execute_only, &[]),
        Err(MapError::UnsupportedPermission)
    );
}

#[test]
fn rejects_reserved_addresses_and_conflicting_ancestor_flags() {
    let limit = root().physical_limit();
    assert!(FrameAddress::new(limit.exclusive(), limit).is_err());
    assert!(validate_entry_bits((1_u64 << 40) | PRESENT, limit).is_err());

    for conflict in [
        intermediate_entry(FrameAddress(0x2000), false),
        intermediate_entry(FrameAddress(0x2000), true) | HUGE,
    ] {
        let mut tables = FakeTables::owned_root();
        tables.entries.insert((0x1000, page().index(3)), conflict);
        assert_eq!(
            root().map_page(
                &mut tables,
                page(),
                0x5000,
                MappingPermissions::USER_READ_ONLY,
                &[0x3000, 0x4000],
            ),
            Err(MapError::ParentConflict)
        );
    }
}

#[test]
fn protect_preserves_hardware_ad_updates_and_leaf_pat_is_not_huge() {
    let mut tables = FakeTables::owned_root();
    tables.mark_zero_exclusive(&[0x2000, 0x3000, 0x4000]);
    root()
        .map_page(
            &mut tables,
            page(),
            0x5000,
            MappingPermissions::USER_READ_WRITE,
            &[0x2000, 0x3000, 0x4000],
        )
        .unwrap();
    let leaf_key = (0x4000, page().index(0));
    *tables.entries.get_mut(&leaf_key).unwrap() |= HUGE | WRITE_THROUGH | CACHE_DISABLE;
    tables.inject_leaf_ad_bits = true;
    root()
        .protect_page(&mut tables, page(), MappingPermissions::USER_READ_ONLY)
        .unwrap();
    let leaf = tables.entry(leaf_key.0, leaf_key.1);
    assert_eq!(leaf & (ACCESSED | DIRTY), ACCESSED | DIRTY);
    assert_eq!(
        leaf & (HUGE | WRITE_THROUGH | CACHE_DISABLE),
        HUGE | WRITE_THROUGH | CACHE_DISABLE
    );
}

#[test]
fn stale_ancestor_assertion_aborts_without_leaf_or_tlb_change() {
    let mut tables = FakeTables::owned_root();
    tables.mark_zero_exclusive(&[0x2000, 0x3000, 0x4000]);
    root()
        .map_page(
            &mut tables,
            page(),
            0x5000,
            MappingPermissions::USER_READ_WRITE,
            &[0x2000, 0x3000, 0x4000],
        )
        .unwrap();
    tables.conflict_assertion = Some(1);
    let entries = tables.entries.clone();
    let invalidated = tables.invalidated.clone();
    assert_eq!(
        root().protect_page(&mut tables, page(), MappingPermissions::USER_READ_ONLY),
        Err(MapError::CommitConflict)
    );
    assert_eq!(tables.entries, entries);
    assert_eq!(tables.invalidated, invalidated);
}

#[test]
fn guarded_stack_arithmetic_is_checked() {
    let first = VirtualPage::new(0x20_000).unwrap();
    let layout = GuardedStackLayout::new(first, 4).unwrap();
    assert_eq!(layout.guard_low.address(), 0x1f_000);
    assert_eq!(layout.guard_high.address(), 0x24_000);
    assert!(GuardedStackLayout::new(first, u64::MAX).is_err());
}

#[test]
fn capabilities_fail_closed_without_nxe_wp_or_four_level_paging() {
    assert_eq!(
        PagingCapabilities::validate(40, false, true, true),
        Err(AddressError::FourLevelPagingRequired)
    );
    assert_eq!(
        PagingCapabilities::validate(40, true, false, true),
        Err(AddressError::NoExecuteRequired)
    );
    assert_eq!(
        PagingCapabilities::validate(40, true, true, false),
        Err(AddressError::WriteProtectRequired)
    );
    assert_eq!(
        PagingCapabilities::validate(53, true, true, true),
        Err(AddressError::InvalidPhysicalWidth(53))
    );
    assert_eq!(root().physical_limit().exclusive(), LIMIT);
}
