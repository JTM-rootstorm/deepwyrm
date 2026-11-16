//! The grown table in pieces of RAM at one virtual range (DW2 large-memory
//! plan, M7 §12.9): staging and its refusals, adoption from one base and its
//! refusals, the storage invariants, and growth on a memory map with no run
//! as long as the table.

extern crate std;

use super::super::physical::PhysicalAddressLimit;
use super::test_support::{grow_in_leaked_runs, leaked_run};
use super::*;
use std::vec::Vec;

const PAGE: u64 = BASE_PAGE_SIZE;
type Manager = FrameRoleManager<128, 128>;

fn limit() -> PhysicalAddressLimit {
    PhysicalAddressLimit::new(1_u64 << 40).unwrap()
}

/// A manager over one range of `page_count` pages at 1 MiB.
fn manager(page_count: u64) -> Manager {
    let candidate = PageRange::from_page_count(0x10_0000, page_count, limit()).unwrap();
    let allocator = PhysicalFrameAllocator::from_candidates(&[candidate], limit(), []).unwrap();
    Manager::new(allocator).unwrap()
}

/// A manager over `count` ranges of `pages` pages, one page apart.
fn scattered(count: u64, pages: u64) -> Manager {
    let candidates: Vec<_> = (0..count)
        .map(|index| PageRange::from_page_count((1 + index * (pages + 1)) * PAGE, pages, limit()))
        .collect::<Result<_, _>>()
        .unwrap();
    let allocator = PhysicalFrameAllocator::from_candidates(&candidates, limit(), []).unwrap();
    Manager::new(allocator).unwrap()
}

/// What a refused staging or adoption must leave as it found it: the free
/// memory, the boot free list, the free slots in list order, every slot's
/// record, the staged runs, and whether the table is grown.
#[derive(Debug, Eq, PartialEq)]
struct Snapshot {
    available: u64,
    free_ranges: Vec<PageRange>,
    free_slots: Vec<usize>,
    records: Vec<Option<RoleRecord>>,
    staged: Vec<(u64, u64)>,
    grown: bool,
    version: u64,
}

fn snapshot<const R: usize, const C: usize>(roles: &FrameRoleManager<R, C>) -> Snapshot {
    Snapshot {
        available: roles.available_frames(),
        free_ranges: roles.allocator.boot_free_ranges().to_vec(),
        free_slots: (0..roles.free_slot_count)
            .map(|depth| roles.free_slot(depth).unwrap().0)
            .collect(),
        records: (0..roles.roles.len())
            .map(|slot| roles.record_at(slot))
            .collect(),
        staged: roles.staged_growth_parts().collect(),
        grown: roles.roles.is_adopted() || roles.starts.is_some(),
        version: roles.version,
    }
}

#[allow(
    unsafe_code,
    reason = "the host model never dereferences synthetic physical memory"
)]
fn zeroed(roles: &mut Manager) -> ZeroedGrant {
    let allocation = roles.allocate(1).unwrap();
    // SAFETY: the host model never dereferences the synthetic run.
    unsafe { roles.assume_zeroed(allocation) }.unwrap()
}

/// Adopts from a leaked buffer of `pages` pages at `offset` bytes.
#[allow(
    unsafe_code,
    reason = "the host model hands the manager a leaked buffer as the table map"
)]
fn adopt(roles: &mut Manager, pages: u64, offset: usize) -> Result<(), FrameRoleError> {
    // SAFETY: a leaked buffer of at least `pages` pages from `base`, used by
    // nothing else, for ever; a misaligned `base` is refused before any
    // write.
    unsafe { roles.adopt_storage(leaked_run(pages * PAGE + 8).wrapping_add(offset)) }
}

#[test]
fn a_table_grown_from_many_runs_keeps_identities_and_indexes_every_start() {
    let mut roles = manager(3000);
    let owner = roles.create_table_owner().unwrap();
    let root = zeroed(&mut roles);
    let root = roles.prepare_table(root, owner, TableLevel::Pml4).unwrap();
    let root = roles.commit_table(root, None).unwrap();
    let kept = roles.allocate(5).unwrap();

    let (layout, runs) = grow_in_leaked_runs(&mut roles, 7);
    assert!(layout.page_count() > 7);
    assert_eq!(runs.len(), 7);
    assert_eq!(roles.staged_growth_parts().count(), 7);
    let staged: Vec<_> = roles.staged_growth_parts().collect();
    for pair in staged.windows(2) {
        // The spacers keep the runs apart in RAM.
        assert!(pair[0].0 + pair[0].1 * PAGE < pair[1].0);
    }
    assert_eq!(
        staged.iter().map(|(_, pages)| pages).sum::<u64>(),
        layout.page_count()
    );
    assert_eq!(roles.roles.len(), 128 + 3000);
    assert_eq!(roles.validate_allocation(&kept), Ok(()));
    assert_eq!(roles.validate_table_identity(root), Ok(()));
    assert_eq!(roles.check_invariants(), Ok(()));
    for (slot, (start, pages)) in runs.iter().zip(&staged) {
        let record = roles.record_at(*slot).unwrap();
        assert_eq!(record.role, FrameRole::RoleTableStorage);
        assert_eq!(
            (record.range.start, record.range.page_count()),
            (*start, *pages)
        );
    }

    // Tables committed all over memory are found through the start index.
    let mut tables = Vec::new();
    while roles.available_frames() > 0 {
        let page = zeroed(&mut roles);
        let page = roles.prepare_table(page, owner, TableLevel::Pdpt).unwrap();
        tables.push(roles.commit_table(page, Some(root)).unwrap());
    }
    assert!(tables.len() > 2500);
    for table in &tables {
        assert_eq!(
            roles.table_identity(owner, TableLevel::Pdpt, table.physical_start()),
            Ok(*table)
        );
    }
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn staging_refuses_a_full_array_a_foreign_grant_and_a_grown_table() {
    let mut roles: FrameRoleManager<8, 512> = {
        let candidate = PageRange::from_page_count(0x10_0000, 4096, limit()).unwrap();
        let allocator = PhysicalFrameAllocator::from_candidates(&[candidate], limit(), []).unwrap();
        FrameRoleManager::new(allocator).unwrap()
    };
    let mut foreign = manager(16);
    let stranger = foreign.allocate(1).unwrap();
    let before = snapshot(&roles);
    let refused = roles.stage_growth_part(stranger).unwrap_err();
    assert_eq!(refused.error(), FrameRoleError::ForeignManager);
    assert_eq!(snapshot(&roles), before);
    foreign.cancel_allocation(refused.into_grant()).unwrap();

    for _ in 0..MAX_GROWTH_PARTS {
        let grant = roles.allocate(1).unwrap();
        roles.stage_growth_part(grant).unwrap();
    }
    assert_eq!(roles.check_invariants(), Ok(()));
    let grant = roles.allocate(1).unwrap();
    let start = grant.physical_start();
    let before = snapshot(&roles);
    let refused = roles.stage_growth_part(grant).unwrap_err();
    assert_eq!(refused.error(), FrameRoleError::Capacity);
    assert_eq!(snapshot(&roles), before);
    let grant = refused.into_grant();
    assert_eq!(grant.physical_start(), start);
    roles.cancel_allocation(grant).unwrap();
    assert_eq!(roles.check_invariants(), Ok(()));

    // Once grown, nothing more stages.
    let mut roles = manager(512);
    grow_in_leaked_runs(&mut roles, 2);
    let grant = roles.allocate(1).unwrap();
    let before = snapshot(&roles);
    let refused = roles.stage_growth_part(grant).unwrap_err();
    assert_eq!(refused.error(), FrameRoleError::WrongRole);
    assert_eq!(snapshot(&roles), before);
    roles.cancel_allocation(refused.into_grant()).unwrap();
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn adoption_refuses_each_bad_staging_and_changes_nothing() {
    let mut roles = manager(4096);
    let layout = roles.grown_layout().unwrap();
    let total = layout.page_count();
    assert!(total > 4);
    let refuse = |roles: &mut Manager, offset: usize| {
        let before = snapshot(roles);
        assert_eq!(adopt(roles, total, offset), Err(FrameRoleError::WrongRole));
        assert_eq!(snapshot(roles), before);
        assert_eq!(roles.check_invariants(), Ok(()));
    };

    // Nothing staged.
    refuse(&mut roles, 0);
    // Fewer pages than the layout, by one.
    let first = roles.allocate(total - 3).unwrap();
    roles.stage_growth_part(first).unwrap();
    let second = roles.allocate(2).unwrap();
    roles.stage_growth_part(second).unwrap();
    refuse(&mut roles, 0);
    // More pages than the layout, by one.
    let third = roles.allocate(2).unwrap();
    roles.stage_growth_part(third).unwrap();
    refuse(&mut roles, 0);

    // Exactly the layout's pages, but at a base that is not 8-aligned.
    let mut roles = manager(4096);
    let first = roles.allocate(total - 1).unwrap();
    roles.stage_growth_part(first).unwrap();
    let last = roles.allocate(1).unwrap();
    roles.stage_growth_part(last).unwrap();
    refuse(&mut roles, 4);
    // A staged run that is no longer its allocation.
    let (identity, range) = roles.staged[1]
        .as_ref()
        .map(|grant| (grant.identity, grant.range))
        .unwrap();
    let slot = roles.slot(identity).unwrap();
    roles.replace_record(
        slot,
        RoleRecord {
            range,
            role: FrameRole::Zeroed,
        },
    );
    let before = snapshot(&roles);
    assert_eq!(adopt(&mut roles, total, 0), Err(FrameRoleError::WrongRole));
    assert_eq!(snapshot(&roles), before);
    roles.replace_record(
        slot,
        RoleRecord {
            range,
            role: FrameRole::AllocatedUninitialized,
        },
    );
    assert_eq!(adopt(&mut roles, total, 0), Ok(()));
    assert_eq!(roles.check_invariants(), Ok(()));
    // A second adoption.
    refuse(&mut roles, 0);
}

#[test]
fn growth_succeeds_where_no_free_range_holds_the_whole_table() {
    // 96 ranges of 24 pages: the table is longer than any of them.
    let mut roles = scattered(96, 24);
    assert_eq!(roles.largest_free_pages(), 24);
    let layout = roles.grown_layout().unwrap();
    let total = layout.page_count();
    assert!(total > 24);
    // What growth needed before: one run of all of it.
    assert_eq!(
        roles.allocate(total).map(|_| ()),
        Err(FrameRoleError::Physical(
            PhysicalMemoryError::NoFramesAvailable
        ))
    );
    let initial = roles.available_frames();
    // The builder's second pass: the largest run left, at any alignment.
    let mut left = total;
    while left > 0 {
        let grant = roles.allocate_largest_aligned(left, 1).unwrap();
        left -= grant.range.page_count();
        roles.stage_growth_part(grant).unwrap();
    }
    assert!(roles.staged_growth_parts().count() > 1);
    assert_eq!(roles.check_invariants(), Ok(()));
    assert_eq!(adopt(&mut roles, total, 0), Ok(()));
    assert_eq!(roles.check_invariants(), Ok(()));
    assert_eq!(roles.available_frames(), initial - total);
    // The aligned allocation belongs to the boot phase.
    assert_eq!(
        roles.allocate_largest_aligned(1, 1).map(|_| ()),
        Err(FrameRoleError::Physical(
            PhysicalMemoryError::InvalidPageRange
        ))
    );
    let mut held = Vec::new();
    while let Ok(grant) = roles.allocate(3) {
        held.push(grant);
    }
    assert_eq!(roles.check_invariants(), Ok(()));
    for grant in held {
        roles.cancel_allocation(grant).unwrap();
    }
    assert_eq!(roles.available_frames(), initial - total);
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn the_check_finds_table_storage_that_is_not_the_staged_runs() {
    // After growth: a run given the table's role that is not one of them.
    let mut roles = manager(1024);
    grow_in_leaked_runs(&mut roles, 3);
    let stray = roles.allocate(1).unwrap();
    let slot = roles.slot(stray.identity).unwrap();
    roles.replace_record(
        slot,
        RoleRecord {
            range: stray.range,
            role: FrameRole::RoleTableStorage,
        },
    );
    assert_eq!(
        roles.check_invariants(),
        Err(FrameRoleError::InvariantViolation)
    );

    // After growth: a staged run without the table's role.
    let mut roles = manager(1024);
    let (_, runs) = grow_in_leaked_runs(&mut roles, 3);
    let range = roles.record_at(runs[2]).unwrap().range;
    roles.replace_record(
        runs[2],
        RoleRecord {
            range,
            role: FrameRole::AllocatedUninitialized,
        },
    );
    assert_eq!(
        roles.check_invariants(),
        Err(FrameRoleError::InvariantViolation)
    );

    // Before growth: a staged run whose role changed, and a run holding the
    // table's role.
    let mut roles = manager(1024);
    let grant = roles.allocate(4).unwrap();
    roles.stage_growth_part(grant).unwrap();
    assert_eq!(roles.check_invariants(), Ok(()));
    let (identity, range) = roles.staged[0]
        .as_ref()
        .map(|grant| (grant.identity, grant.range))
        .unwrap();
    let slot = roles.slot(identity).unwrap();
    for role in [FrameRole::Zeroed, FrameRole::RoleTableStorage] {
        roles.replace_record(slot, RoleRecord { range, role });
        assert_eq!(
            roles.check_invariants(),
            Err(FrameRoleError::InvariantViolation)
        );
    }
    roles.replace_record(
        slot,
        RoleRecord {
            range,
            role: FrameRole::AllocatedUninitialized,
        },
    );
    assert_eq!(roles.check_invariants(), Ok(()));

    // A gap in the staging array.
    let grant = roles.allocate(1).unwrap();
    roles.stage_growth_part(grant).unwrap();
    let first = roles.staged[0].take().unwrap();
    assert_eq!(
        roles.check_invariants(),
        Err(FrameRoleError::InvariantViolation)
    );
    roles.staged[0] = Some(first);
    assert_eq!(roles.check_invariants(), Ok(()));
}
