//! DW2 §10.9: a handle-less on-demand object's pages are released once no
//! live lease covers them and every removal of their translations has been
//! acknowledged, and not before.

use super::*;
use crate::memory::object::{MappingFinalReleases, ReleaseStep};
use crate::object::ObjectId;

const PAGE: u64 = BASE_PAGE_SIZE;

impl Fixture {
    fn object(&self) -> ObjectId {
        self.owner.as_ref().expect("the owner is still held").id()
    }

    /// Unmaps `[at, at + byte_len)` and returns the releases unsettled, as a
    /// family-G transaction holds them while its shootdown is pending.
    fn unmap_held(&mut self, at: u64, byte_len: u64) -> MappingFinalReleases {
        let mut publisher = Self::publisher(
            &mut self.roles,
            self.root,
            &self.page_tables,
            &mut self.candidates,
            &self.region,
            &mut self.target,
        );
        self.region
            .unmap(
                &mut self.objects,
                &mut self.registry,
                &mut publisher,
                at,
                byte_len,
            )
            .unwrap_or_else(|failure| panic!("unmap failed: {:?}", failure.error()))
    }

    /// Settles held releases, as the shootdown's acknowledgement does. None
    /// of these tests releases an object's last reference.
    fn settle(&mut self, releases: MappingFinalReleases) {
        assert!(
            releases.settle_locally(&mut self.registry).is_empty(),
            "no release in these tests is final"
        );
    }

    /// Commits `pages` and charges the object for its index, as admitted
    /// touches do.
    fn commit_charged(&mut self, object: ObjectId, pages: &[u64]) {
        for &page in pages {
            self.commit(page);
        }
        let frames = self.roles.on_demand_frames(self.backing).unwrap();
        self.registry.set_charge_pages(object, frames).unwrap();
    }

    /// The live drain's release step: notices that cannot release are
    /// dropped, the first that can does one step.
    fn drain_step(&mut self) -> Option<ReleaseStep> {
        self.drain_step_within(crate::memory::object::RELEASE_STEP_ENTRIES)
    }

    fn drain_step_within(&mut self, budget: u64) -> Option<ReleaseStep> {
        while let Some(notice) = self.registry.pop_memory_notice() {
            let Some(object) = notice else {
                continue;
            };
            match self.objects.release_unmapped_step_within(
                &mut self.registry,
                &mut self.roles,
                object,
                budget,
            ) {
                ReleaseStep::Idle => continue,
                step @ ReleaseStep::Done { .. } => return Some(step),
                step @ ReleaseStep::More { .. } => {
                    self.registry.requeue_memory_notice(object);
                    return Some(step);
                }
            }
        }
        None
    }

    fn committed(&self, page: u64) -> bool {
        self.roles
            .on_demand_commit_cost(self.backing, page)
            .unwrap()
            == 0
    }

    fn weight(&self, object: ObjectId) -> u64 {
        self.registry.charge(object).unwrap().1
    }

    /// Drops the owner, leaving the object to its leases and `kept`.
    fn drop_owner(&mut self) {
        let owner = self.owner.take().expect("an owner");
        assert_eq!(self.registry.release_internal(owner).unwrap(), None);
    }
}

#[test]
fn a_partial_unmap_frees_its_pages_only_after_its_shootdown_settles() {
    let mut fixture = Fixture::new();
    let object = fixture.object();
    fixture.change(ALIAS, SPAN, None).unwrap();
    fixture.commit_charged(object, &[0, 1, 2, 3]);
    let charged = fixture.weight(object);
    fixture.drop_owner();
    // The alias's pages are all still covered by the mapping at START.
    assert_eq!(fixture.drain_step(), Some(ReleaseStep::Done { freed: 0 }));

    // Shrinking the START lease moves its pin to the pieces: only the
    // coverage pin keeps the release from running while the removal of
    // page 1's translation is unacknowledged (second review, B-1).
    let held = fixture.unmap_held(START + PAGE, PAGE);
    assert_eq!(fixture.drain_step(), None);
    assert_eq!(
        fixture
            .objects
            .release_unmapped_step(&mut fixture.registry, &mut fixture.roles, object),
        ReleaseStep::Idle
    );
    assert!(fixture.committed(1));

    fixture.settle(held);
    assert_eq!(fixture.drain_step(), Some(ReleaseStep::Done { freed: 1 }));
    assert!(!fixture.committed(1));
    for page in [0, 2, 3] {
        assert!(fixture.committed(page), "page {page} is still mapped");
    }
    assert_eq!(fixture.weight(object), charged - 1);
    assert_eq!(fixture.objects.released_hull(object), None);
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

#[test]
fn an_alias_keeps_the_pages_it_covers() {
    let mut fixture = Fixture::new();
    let object = fixture.object();
    fixture.commit_charged(object, &[0, 1, 2, 3]);
    fixture.drop_owner();
    let held = fixture.unmap_held(ALIAS, SPAN);
    assert_eq!(fixture.drain_step(), None, "the alias's pin is held");
    fixture.settle(held);
    assert_eq!(fixture.drain_step(), Some(ReleaseStep::Done { freed: 0 }));
    for page in 0..PAGES {
        assert!(fixture.committed(page));
    }
    fixture.change(START, 2 * PAGE, None).unwrap();
    assert_eq!(fixture.drain_step(), Some(ReleaseStep::Done { freed: 2 }));
    assert_eq!(
        (0..PAGES)
            .map(|page| fixture.committed(page))
            .collect::<Vec<_>>(),
        [false, false, true, true]
    );
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

#[test]
fn closing_the_last_handle_releases_pages_unmapped_while_it_was_open() {
    let mut fixture = Fixture::new();
    let object = fixture.object();
    let owner = fixture.owner.take().unwrap();
    let handle = fixture.registry.internal_into_handle(owner).unwrap();
    fixture.commit_charged(object, &[0, 1, 2, 3]);
    fixture.change(ALIAS, SPAN, None).unwrap();
    fixture.change(START + 2 * PAGE, 2 * PAGE, None).unwrap();
    // A handle can map or commit the pages again: nothing is released.
    assert_eq!(fixture.drain_step(), None);
    assert!(fixture.committed(3));
    assert_eq!(fixture.registry.release_handle(handle).unwrap(), None);
    assert_eq!(fixture.drain_step(), Some(ReleaseStep::Done { freed: 2 }));
    assert_eq!(
        (0..PAGES)
            .map(|page| fixture.committed(page))
            .collect::<Vec<_>>(),
        [true, true, false, false]
    );
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

#[test]
fn a_dma_style_reference_holds_the_pages_until_it_goes() {
    let mut fixture = Fixture::new();
    let object = fixture.object();
    // A DMA mapping holds one internal reference and no lease.
    let device = fixture
        .registry
        .retain_internal(fixture.owner.as_ref().unwrap())
        .unwrap();
    fixture.commit_charged(object, &[0, 1, 2, 3]);
    fixture.drop_owner();
    fixture.change(ALIAS, SPAN, None).unwrap();
    fixture.change(START + 2 * PAGE, 2 * PAGE, None).unwrap();
    assert_eq!(fixture.drain_step(), None);
    assert!(fixture.committed(2));
    assert_eq!(fixture.registry.release_internal(device).unwrap(), None);
    assert_eq!(fixture.drain_step(), Some(ReleaseStep::Done { freed: 2 }));
    assert!(!fixture.committed(2) && !fixture.committed(3));
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

#[test]
fn a_rolled_back_unmap_releases_its_coverage_pin() {
    let mut fixture = Fixture::new();
    let object = fixture.object();
    let before = fixture.registry.live_reference_counts(object);
    fixture.target.fail_apply = true;
    // A shrink: the lease's pin moves to the smaller lease, so the
    // transaction retains a coverage pin before it publishes.
    assert!(fixture.change(START, PAGE, None).is_err());
    fixture.target.fail_apply = false;
    assert_eq!(fixture.registry.live_reference_counts(object), before);
    assert_eq!(fixture.objects.released_hull(object), None);
}

#[test]
fn a_step_on_a_finalizing_object_does_nothing() {
    let mut fixture = Fixture::new();
    let object = fixture.object();
    fixture.commit_charged(object, &[0]);
    fixture.change(ALIAS, SPAN, None).unwrap();
    fixture.drop_owner();
    // The last lease goes: its settlement makes the object final, and its
    // record stays until the cleanup queue finalizes it.
    let held = fixture.unmap_held(START, SPAN);
    let releases = held.settle_locally(&mut fixture.registry);
    assert_eq!(releases.len(), 1);
    assert_eq!(fixture.registry.live_reference_counts(object), None);
    assert!(fixture.objects.released_hull(object).is_some());
    assert_eq!(
        fixture
            .objects
            .release_unmapped_step(&mut fixture.registry, &mut fixture.roles, object),
        ReleaseStep::Idle
    );
    assert!(fixture.committed(0), "finalization, not the step, frees it");
    let finalization = fixture
        .objects
        .take_finalization(releases.into_items().into_iter().flatten().next().unwrap())
        .unwrap();
    assert!(
        crate::memory::object::complete_memory_finalization(
            &mut fixture.registry,
            &mut fixture.roles,
            finalization,
        )
        .is_none()
    );
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

#[test]
fn a_decommit_visits_at_most_its_budget_and_skips_absent_entries() {
    let mut fixture = Fixture::new();
    fixture.commit(0);
    fixture.commit(3);
    // Nothing maps the frames: the test calls the index directly.
    assert_eq!(
        fixture
            .roles
            .decommit_on_demand_range(fixture.backing, 0, PAGES, 1),
        Ok((1, 1, 1))
    );
    assert_eq!(
        fixture
            .roles
            .decommit_on_demand_range(fixture.backing, 1, PAGES, 10),
        Ok((PAGES, 1, 3))
    );
    assert!(!fixture.committed(0) && !fixture.committed(3));
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

#[test]
fn a_hull_larger_than_a_step_is_released_over_several_drains() {
    let mut fixture = Fixture::new();
    let object = fixture.object();
    fixture.commit_charged(object, &[0, 1, 2, 3]);
    let charged = fixture.weight(object);
    fixture.drop_owner();
    fixture.change(ALIAS, SPAN, None).unwrap();
    fixture.change(START + PAGE, 3 * PAGE, None).unwrap();
    // One entry per step: pages 1, 2 and 3 take three drains, the object
    // queued again after each but the last, and page 0 stays mapped.
    assert_eq!(
        fixture.drain_step_within(1),
        Some(ReleaseStep::More { freed: 1 })
    );
    assert_eq!(fixture.objects.released_hull(object), Some((2, PAGES)));
    assert_eq!(
        fixture.drain_step_within(1),
        Some(ReleaseStep::More { freed: 1 })
    );
    assert_eq!(
        fixture.drain_step_within(1),
        Some(ReleaseStep::Done { freed: 1 })
    );
    assert_eq!(fixture.drain_step_within(1), None, "not queued again");
    assert_eq!(
        (0..PAGES)
            .map(|page| fixture.committed(page))
            .collect::<Vec<_>>(),
        [true, false, false, false]
    );
    assert_eq!(fixture.weight(object), charged - 3);
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

#[test]
fn two_unmaps_of_the_same_pages_release_after_both_settle() {
    let mut fixture = Fixture::new();
    let object = fixture.object();
    fixture.commit_charged(object, &[0, 1, 2, 3]);
    fixture.drop_owner();
    let alias = fixture.unmap_held(ALIAS, 2 * PAGE);
    let start = fixture.unmap_held(START, 2 * PAGE);
    fixture.settle(alias);
    // The second unmap's removal is still unacknowledged.
    assert_eq!(fixture.drain_step(), None);
    assert!(fixture.committed(0) && fixture.committed(1));
    fixture.settle(start);
    assert_eq!(fixture.drain_step(), Some(ReleaseStep::Done { freed: 2 }));
    assert_eq!(
        (0..PAGES)
            .map(|page| fixture.committed(page))
            .collect::<Vec<_>>(),
        [false, false, true, true]
    );
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}

#[test]
fn a_protect_removes_no_translation_and_releases_nothing() {
    let mut fixture = Fixture::new();
    let object = fixture.object();
    fixture.commit_charged(object, &[0, 1]);
    let charged = fixture.weight(object);
    fixture.drop_owner();
    // The region has two slots: the alias goes first (its pages stay
    // covered by START), then START splits in two.
    fixture.change(ALIAS, SPAN, None).unwrap();
    assert_eq!(fixture.drain_step(), Some(ReleaseStep::Done { freed: 0 }));
    let before = fixture.registry.live_reference_counts(object);
    fixture.change(START, PAGE, Some(Protection::READ)).unwrap();
    assert_eq!(fixture.objects.released_hull(object), None);
    assert_eq!(fixture.drain_step(), None);
    assert!(fixture.committed(0) && fixture.committed(1));
    assert_eq!(fixture.weight(object), charged);
    // The split's extra lease holds one more pin, and nothing else.
    let after = fixture.registry.live_reference_counts(object);
    assert_eq!(
        after.map(|(handles, internal)| (handles, internal - 1)),
        before
    );
}

#[test]
fn a_decommit_skips_an_absent_node_whole() {
    let mut fixture = Fixture::new();
    // Two levels: the root's entries each cover 512 pages.
    let grant = fixture.roles.allocate_on_demand_backing(1024).unwrap();
    let backing = grant.identity();
    fixture.roles.commit_on_demand_page(backing, 513).unwrap();
    // Page 0's node is absent (one visit skips 512 pages), page 512 is
    // absent under a present node, page 513 is freed.
    assert_eq!(
        fixture.roles.decommit_on_demand_range(backing, 0, 1024, 3),
        Ok((514, 1, 3))
    );
    assert_eq!(fixture.roles.on_demand_commit_cost(backing, 513), Ok(1));
    assert!(fixture.roles.cancel_object_backing(grant).is_ok());
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
}
