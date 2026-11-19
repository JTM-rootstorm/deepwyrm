//! DW2 §13.12 part b: the adapters' companions that say whether a quota
//! refusal is owed, asked through the registry with real finalizing
//! MemoryObjects and an owed backing's reservation.

use super::*;
use deepwyrm_abi::{
    DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND, DW_RIGHT_MAP, DW_RIGHT_READ, DW_RIGHT_WRITE,
    DW_TASK_GROUP_LIMIT_MEMORY_OBJECT, DW_TASK_GROUP_LIMIT_MEMORY_PAGES,
};

type Roles = crate::memory::frame_roles::FrameRoleManager<16, 16>;

struct Fixture {
    registry: ObjectRegistry<32>,
    tasks: Tasks,
    process: ProcessKey,
    roles: Roles,
    memory: MemoryObjectAuthority<4, 4>,
    cleanup: CleanupQueue<32>,
}

/// A process in a job limited to `objects` MemoryObjects and `pages` pages.
fn fixture(objects: u32, pages: u32) -> Fixture {
    let (registry, mut tasks, _root, jobs, process, _) = limited_fixture();
    tasks
        .lower_group_limit(jobs, DW_TASK_GROUP_LIMIT_MEMORY_OBJECT, objects)
        .unwrap();
    tasks
        .lower_group_limit(jobs, DW_TASK_GROUP_LIMIT_MEMORY_PAGES, pages)
        .unwrap();
    let mut roles =
        crate::memory::frame_roles::synthetic_frame_role_manager::<16, 16>(0x40_000, 16);
    roles.set_index_memory(std::boxed::Box::leak(
        std::boxed::Box::<OnDemandIndexModel>::default(),
    ));
    Fixture {
        registry,
        tasks,
        process,
        roles,
        memory: MemoryObjectAuthority::new(),
        cleanup: CleanupQueue::new(),
    }
}

impl Fixture {
    /// Creates an on-demand MemoryObject, charged its one root page.
    fn create(&mut self) -> DwHandle {
        let pages = 1_u64 << 10;
        let out = DwUserAddress(BASE + 0x100);
        let range = output_range(out, 8, 8).unwrap();
        let early = self.roles.allocate_on_demand_backing(pages);
        let mut access = DeferredMemoryObjectAccess::new(
            crate::memory::usercopy::DeferredUserOutput::new(Some(range)),
            pages,
            Some(early.map_err(|_| deepwyrm_abi::DW_STATUS_NO_MEMORY)),
        );
        let status = memory_object_create_owned(
            &mut access,
            &mut self.registry,
            &mut self.memory,
            &mut self.tasks,
            self.process,
            pages * 4096,
            DW_MEMORY_OBJECT_CREATE_FLAG_ON_DEMAND.0,
            DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0),
            out,
            &mut self.cleanup,
        );
        let (output, unused) = access.into_parts();
        assert!(unused.is_none());
        assert_eq!(status, DW_STATUS_SUCCESS);
        DwHandle(u64::from_le_bytes(
            output.written().unwrap().try_into().unwrap(),
        ))
    }

    /// The object behind `handle`.
    fn object(&mut self, handle: DwHandle) -> crate::object::ObjectId {
        memory_object_commit_target(
            &mut self.registry,
            &mut self.tasks,
            &self.memory,
            self.process,
            handle,
            0,
            4096,
            DW_RIGHT_MAP,
        )
        .unwrap()
        .unwrap()
        .1
    }

    /// Closes `handle`: its object is finalizing, its release queued and
    /// not yet run, so it still counts against the job.
    fn close(&mut self, handle: DwHandle) {
        assert_eq!(
            handle_close(
                &mut self.registry,
                &mut self.tasks,
                self.process,
                handle,
                &mut self.cleanup,
            ),
            DW_STATUS_SUCCESS
        );
    }

    /// Runs every queued finalization to its end.
    fn finalize(&mut self) {
        while let Some(release) = self.cleanup.pop() {
            let finalization = self.memory.take_finalization(release).unwrap();
            assert!(
                crate::memory::object::complete_memory_finalization(
                    &mut self.registry,
                    &mut self.roles,
                    finalization
                )
                .is_none()
            );
        }
    }

    fn create_allowed(&self, pages: u64) -> bool {
        memory_object_quota_allows(&self.registry, &self.tasks, self.process, pages)
    }

    fn create_owed(&self, pages: u64) -> bool {
        memory_object_refusal_owed(&self.registry, &self.tasks, self.process, pages)
    }
}

/// §13.10's measurement in small: a job whose MemoryObject count is full of
/// closed, finalizing objects is owed; one whose objects are live is
/// refused; and a create is owed only if its pages are owed too.
#[test]
fn a_create_refused_by_finalizing_objects_is_owed_and_by_live_ones_is_not() {
    let mut fixture = fixture(2, 4);
    let first = fixture.create();
    let second = fixture.create();
    // Two of two counted, both live: refused, and not owed.
    assert!(!fixture.create_allowed(1));
    assert!(!fixture.create_owed(1));
    // One closed and finalizing: still refused, now owed.
    fixture.close(first);
    assert!(!fixture.create_allowed(1));
    assert_eq!(
        fixture.registry.finalizing_objects_of(
            fixture
                .tasks
                .charge_tag(fixture.process)
                .unwrap()
                .groups()
                .next()
                .unwrap(),
            crate::task::quota::object_class(deepwyrm_abi::DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap()
        ),
        1
    );
    assert!(fixture.create_owed(1));
    // Both classes are asked: two root pages are charged, one finalizing.
    // Three pages refuse (2 + 3 > 4) and would fit with it gone (1 + 3);
    // four would not (1 + 4 > 4), so the create is not owed though its
    // object is.
    assert!(fixture.create_owed(3));
    assert!(!fixture.create_owed(4));
    // Finalized: one of two counted, one page charged; nothing refuses, so
    // nothing is owed.
    fixture.finalize();
    assert!(fixture.create_allowed(1));
    assert!(!fixture.create_owed(1));
    // The page class alone: 1 + 4 > 4 with nothing finalizing.
    assert!(!fixture.create_allowed(4));
    assert!(!fixture.create_owed(4));
    fixture.close(second);
    fixture.finalize();
}

/// An owed backing's reservation (an abandoned create's frames, freed by
/// owed steps) counts as finalizing: a commit or fault refused for it is
/// owed. The together form counts the first charge's pages in a group both
/// tags share, and is owed only if each refusing half is.
#[test]
fn a_commit_or_fault_refused_by_an_owed_backing_is_owed() {
    let mut fixture = fixture(8, 10);
    let handle = fixture.create();
    let object = fixture.object(handle);
    let process = fixture.process;
    // The live Process is charged to its job, as a created one is.
    let tag = fixture.tasks.charge_tag(process).unwrap();
    fixture
        .registry
        .set_charge_tag(process.object_id(), tag)
        .unwrap();
    let registry = &mut fixture.registry;
    let tasks = &fixture.tasks;
    // One root page charged, and six pages of an owed backing.
    assert!(registry.reserve_owed_backing_pages(77, tag, 6));
    let single = |registry: &ObjectRegistry<32>, frames| {
        (
            admit_charged_pages(registry, tasks, object, frames).is_ok(),
            charged_pages_refusal_owed(registry, tasks, object, frames),
        )
    };
    // 7 + 3 fits; 7 + 4 refuses and fits with the six gone; 7 + 10 does not.
    assert_eq!(single(registry, 3), (true, false));
    assert_eq!(single(registry, 4), (false, true));
    assert_eq!(single(registry, 10), (false, false));
    let together = |registry: &ObjectRegistry<32>, first: u64, second: u64| {
        let pair = ((object, first), (process.object_id(), second));
        (
            admit_charged_pages_together(registry, tasks, pair.0, pair.1).is_ok(),
            charged_pages_together_refusal_owed(registry, tasks, pair.0, pair.1),
        )
    };
    // Each half fits alone; the sum refuses in the shared job and fits with
    // the six gone (7 + 2 + 2 - 6).
    assert_eq!(together(registry, 2, 2), (false, true));
    // The first half refuses too, and both are owed.
    assert_eq!(together(registry, 4, 1), (false, true));
    // The first half is owed (7 + 5 - 6 fits) and the sum is not
    // (7 + 5 + 6 - 6 > 10): not owed.
    assert_eq!(together(registry, 5, 6), (false, false));
    // Only the second half asks: 7 + 11 - 6 > 10.
    assert_eq!(together(registry, 0, 11), (false, false));
    assert_eq!(together(registry, 1, 2), (true, false));
    // Freed: what refused for the backing is admitted.
    registry.end_owed_backing_reservation(77);
    assert_eq!(single(registry, 4), (true, false));
    assert_eq!(together(registry, 2, 2), (true, false));
    registry
        .set_charge_tag(process.object_id(), crate::task::quota::ChargeTag::EMPTY)
        .unwrap();
    fixture.close(handle);
    fixture.finalize();
}

/// `count` Thread identities, distinct from each other and from every
/// identity of the fixture's registry: a reservation keys on identity
/// alone.
fn threads(count: usize) -> std::vec::Vec<crate::task::ThreadKey> {
    let mut scratch = ObjectRegistry::<{ crate::object::RESERVATION_THREADS + 1 }>::new();
    (0..count)
        .map(|_| {
            let creation = scratch.create(deepwyrm_abi::DW_OBJECT_TYPE_THREAD).unwrap();
            crate::task::ThreadKey::from_object_id(
                scratch.creation_into_handle(creation).unwrap().id(),
            )
        })
        .collect()
}

impl Fixture {
    fn slot_owed(&self, pages: u64) -> bool {
        memory_object_slot_owed(&self.registry, &self.tasks, self.process, pages)
    }

    fn reserve(&mut self, pages: u64, thread: crate::task::ThreadKey) -> bool {
        reserve_memory_object_pages(&mut self.registry, &self.tasks, self.process, pages, thread)
    }

    /// Fills `owed` reservation slots with owed backings keyed from 100,
    /// charged nothing, and the rest with `others`' creates in flight.
    fn fill_slots(&mut self, owed: usize, others: &[crate::task::ThreadKey]) {
        assert_eq!(owed + others.len(), crate::object::RESERVATION_THREADS);
        let empty = crate::task::quota::ChargeTag::EMPTY;
        for key in 0..owed {
            assert!(
                self.registry
                    .reserve_owed_backing_pages(100 + key as u64, empty, 0)
            );
        }
        for &thread in others {
            assert!(self.registry.reserve_pages(thread.object_id(), empty, 0));
        }
    }
}

/// DW2 §13.19 item 1: a create its quota admits that finds every slot held,
/// with an owed backing among the holders, is owed; with every slot held by
/// Threads' creates it is not.
#[test]
fn a_create_finding_every_slot_held_is_owed_only_for_an_owed_backing() {
    let slots = crate::object::RESERVATION_THREADS;
    let ids = threads(slots + 1);
    let creating = ids[slots];

    // Every slot held by owed backings: owed, and the reserve fails.
    let mut job = fixture(8, 64);
    job.fill_slots(slots, &[]);
    assert!(job.create_allowed(1));
    assert!(job.slot_owed(1));
    assert!(!job.reserve(1, creating));
    // Every slot is still an owed backing's: the creating Thread holds none.
    assert!(!job.registry.reservation_slot_free());
    assert_eq!(job.registry.owed_backing_reservations(), slots);

    // 63 by owed backings and one by another Thread's create: owed.
    let mut job = fixture(8, 64);
    job.fill_slots(slots - 1, &ids[..1]);
    assert!(job.slot_owed(1));
    assert!(!job.reserve(1, creating));

    // All 64 by Threads' creates in flight: not owed.
    let mut job = fixture(8, 64);
    job.fill_slots(0, &ids[..slots]);
    assert!(job.create_allowed(1));
    assert!(!job.slot_owed(1));
    assert!(!job.reserve(1, creating));
}

/// A free slot is not owed, and the create reserves it.
#[test]
fn a_create_finding_a_slot_free_is_not_slot_owed() {
    let slots = crate::object::RESERVATION_THREADS;
    let ids = threads(1);
    let mut fixture = fixture(8, 64);
    let empty = crate::task::quota::ChargeTag::EMPTY;
    for key in 0..slots - 1 {
        assert!(
            fixture
                .registry
                .reserve_owed_backing_pages(100 + key as u64, empty, 0)
        );
    }
    assert!(fixture.registry.reservation_slot_free());
    assert!(!fixture.slot_owed(1));
    assert!(fixture.reserve(1, ids[0]));
    assert!(!fixture.registry.reservation_slot_free());
}

/// A create its quota refuses, with every slot held by owed backings, is
/// not slot-owed: the quota's rule decides it. Here the backings are
/// charged to the job, so that rule finds it owed.
#[test]
fn a_create_the_quota_refuses_is_decided_by_the_quota_rule() {
    let slots = crate::object::RESERVATION_THREADS;
    let ids = threads(1);
    let mut fixture = fixture(8, 64);
    let tag = fixture.tasks.charge_tag(fixture.process).unwrap();
    for key in 0..slots {
        assert!(
            fixture
                .registry
                .reserve_owed_backing_pages(100 + key as u64, tag, 1)
        );
    }
    // 64 of 64 pages charged to the owed backings: one more refuses.
    assert!(!fixture.create_allowed(1));
    assert!(!fixture.slot_owed(1));
    assert!(fixture.create_owed(1));
    assert!(!fixture.reserve(1, ids[0]));
    for key in 0..slots {
        fixture
            .registry
            .end_owed_backing_reservation(100 + key as u64);
    }
}

/// Once one owed backing's reservation ends, a slot is free, the create is
/// no longer slot-owed, and the same create reserves.
#[test]
fn a_slot_freed_by_an_owed_backing_admits_the_waiting_create() {
    let slots = crate::object::RESERVATION_THREADS;
    let ids = threads(1);
    let mut fixture = fixture(8, 64);
    fixture.fill_slots(slots, &[]);
    assert!(fixture.slot_owed(1));
    assert!(!fixture.reserve(1, ids[0]));
    fixture.registry.end_owed_backing_reservation(100);
    assert!(fixture.registry.reservation_slot_free());
    assert_eq!(fixture.registry.owed_backing_reservations(), slots - 1);
    assert!(!fixture.slot_owed(1));
    assert!(fixture.reserve(1, ids[0]));
    assert!(!fixture.create_allowed(64));
    fixture.registry.release_reserved_pages(ids[0].object_id());
}
