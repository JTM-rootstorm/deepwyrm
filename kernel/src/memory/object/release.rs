//! The release-on-unmap step (DW2 §10.9 item 5) and the release lists a
//! replace hands back.

use super::*;

/// The pins of the leases a committed replace took out of the page tables.
///
/// Each pin keeps its object alive, so its frames stay allocated, until every
/// CPU has acknowledged the removal: acknowledgement precedes reclamation
/// (H0 §12.6). Releasing a pin at commit, before the shootdown settled, let
/// another holder's last release finalize the object and free frames a remote
/// TLB still mapped (DW2 §10.9 review, finding F1). Family G hands these to
/// [`crate::syscall::HeldReleases`], which releases them on the settlement;
/// a path where no other CPU can hold the translation releases them at once
/// with [`MappingFinalReleases::settle_locally`]. Dropping a non-empty set
/// fails stop.
#[must_use = "unmapped lease pins are released only after their removal is acknowledged"]
#[derive(Debug)]
pub(crate) struct UnmappedLeasePins {
    pins: [Option<InternalRef>; MAX_MAPPING_BATCH],
    count: usize,
}

impl UnmappedLeasePins {
    pub(crate) fn empty() -> Self {
        Self {
            pins: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    fn push(&mut self, pin: InternalRef) {
        assert!(
            self.count < MAX_MAPPING_BATCH,
            "unmapped lease pin batch overflow"
        );
        self.pins[self.count] = Some(pin);
        self.count += 1;
    }

    pub(crate) const fn len(&self) -> usize {
        self.count
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Moves every pin of `other` into this set.
    pub(crate) fn absorb(&mut self, other: &mut Self) {
        for pin in other.take_all() {
            self.push(pin);
        }
    }

    fn take_all(&mut self) -> impl Iterator<Item = InternalRef> + '_ {
        self.count = 0;
        self.pins.iter_mut().filter_map(Option::take)
    }

    /// Releases every pin, handing each final release to `sink`. The caller
    /// guarantees no CPU can still hold a translation of the removed leases.
    pub(crate) fn release<const REGISTRY_OBJECTS: usize>(
        &mut self,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        mut sink: impl FnMut(FinalRelease),
    ) {
        for pin in self.take_all() {
            match registry.release_internal(pin) {
                Ok(Some(final_release)) => sink(final_release),
                Ok(None) => {}
                Err(error) => {
                    panic!(
                        "unmapped lease pin release violated generic object invariants: {error:?}"
                    )
                }
            }
        }
    }
}

impl Drop for UnmappedLeasePins {
    fn drop(&mut self) {
        #[cfg(test)]
        {
            extern crate std;
            // A failing host test unwinds through its pins; a second panic
            // would abort the whole test binary.
            if std::thread::panicking() {
                return;
            }
        }
        if self.count != 0 {
            // The pins are leaked with the panic: their objects stay alive,
            // which is the safe side of the failure.
            panic!("unmapped lease pins were dropped before their removal was acknowledged");
        }
    }
}

#[must_use = "mapping reference releases may contain final MemoryObject cleanup authority"]
#[derive(Debug)]
pub(crate) struct MappingFinalReleases {
    items: [Option<FinalRelease>; MAPPING_FINAL_RELEASE_CAPACITY],
    count: usize,
    unmapped: UnmappedLeasePins,
}

impl MappingFinalReleases {
    pub(crate) fn empty() -> Self {
        Self {
            items: core::array::from_fn(|_| None),
            count: 0,
            unmapped: UnmappedLeasePins::empty(),
        }
    }

    pub(super) fn push_unmapped(&mut self, pin: InternalRef) {
        self.unmapped.push(pin);
    }

    /// Releases the unmapped lease pins now, into this batch. Only for a path
    /// where no other CPU can hold a translation of the removed range: the
    /// teardown of a quiesced Process no CPU is resident on, a rollback of
    /// mappings no CPU has entered, or a host model that publishes no
    /// shootdown. The batch keeps its `2 * BATCH + 1` bound: these pins were
    /// part of it before they were held.
    pub(crate) fn settle_locally<const REGISTRY_OBJECTS: usize>(
        mut self,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
    ) -> Self {
        let mut unmapped = core::mem::replace(&mut self.unmapped, UnmappedLeasePins::empty());
        unmapped.release(registry, |release| self.push(release));
        self
    }

    /// The final releases and the unmapped lease pins, apart.
    pub(crate) fn into_parts(
        self,
    ) -> (
        [Option<FinalRelease>; MAPPING_FINAL_RELEASE_CAPACITY],
        UnmappedLeasePins,
    ) {
        (self.items, self.unmapped)
    }

    pub(super) fn push(&mut self, release: FinalRelease) {
        assert!(
            self.count < MAPPING_FINAL_RELEASE_CAPACITY,
            "mapping final-release batch overflow"
        );
        self.items[self.count] = Some(release);
        self.count += 1;
    }

    pub(crate) const fn len(&self) -> usize {
        self.count
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.count == 0 && self.unmapped.is_empty()
    }

    /// The final releases. Fails stop if unmapped lease pins remain: those
    /// go through [`Self::into_parts`] or [`Self::settle_locally`] first.
    pub(crate) fn into_items(self) -> [Option<FinalRelease>; MAPPING_FINAL_RELEASE_CAPACITY] {
        let (items, unmapped) = self.into_parts();
        drop(unmapped);
        items
    }
}

impl<const OBJECTS: usize, const LEASES: usize> MemoryObjectAuthority<OBJECTS, LEASES> {
    /// One step of releasing an on-demand object's unmapped pages (DW2
    /// §10.9 item 5). Runs under T and P where the cleanup queue drains,
    /// after its pops. The object must be `Live` in the registry, have no
    /// handle and no internal reference beyond its live leases' pins: then
    /// no removal of its translations is unacknowledged and nothing but a
    /// live lease can reach its pages. Frees up to [`RELEASE_STEP_ENTRIES`]
    /// index entries' worth of committed pages in its hull that no live
    /// lease covers, lowering its charge by the pages freed.
    pub(crate) fn release_unmapped_step<
        const REGISTRY_OBJECTS: usize,
        const RANGE_CAPACITY: usize,
        const ROLE_CAPACITY: usize,
    >(
        &mut self,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        roles: &mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
        object: ObjectId,
    ) -> ReleaseStep {
        self.release_unmapped_step_within(registry, roles, object, RELEASE_STEP_ENTRIES)
    }

    /// [`Self::release_unmapped_step`] with an entry budget of `budget`.
    pub(crate) fn release_unmapped_step_within<
        const REGISTRY_OBJECTS: usize,
        const RANGE_CAPACITY: usize,
        const ROLE_CAPACITY: usize,
    >(
        &mut self,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        roles: &mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
        object: ObjectId,
        budget: u64,
    ) -> ReleaseStep {
        let Some(slot) = self
            .objects
            .iter()
            .position(|slot| slot.record.is_some_and(|record| record.object == object))
        else {
            return ReleaseStep::Idle;
        };
        let record = self.objects[slot]
            .record
            .expect("found object slot has a record");
        let (MemoryObjectKind::OnDemand, Some((first, end))) = (record.kind, record.released)
        else {
            return ReleaseStep::Idle;
        };
        let Some((handles, internal)) = registry.live_reference_counts(object) else {
            return ReleaseStep::Idle;
        };
        let leases = self
            .leases
            .iter()
            .flatten_records()
            .filter(|lease| lease.metadata.object_slot == slot)
            .count();
        if handles != 0 || usize::try_from(internal).ok() != Some(leases) {
            return ReleaseStep::Idle;
        }
        let mut cursor = first;
        let mut visited = 0_u64;
        let mut freed = 0_u64;
        while cursor < end && visited < budget {
            let Some((low, high)) = self.next_uncovered(slot, cursor, end) else {
                cursor = end;
                break;
            };
            let (next, pages, entries) = roles
                .decommit_on_demand_range(record.backing, low, high, budget - visited)
                .unwrap_or_else(|error| {
                    panic!("a live on-demand object's index failed to release: {error:?}")
                });
            freed += pages;
            visited += entries;
            cursor = next;
            if entries == 0 {
                break;
            }
        }
        if freed != 0 {
            let (_, weight) = registry
                .charge(object)
                .unwrap_or_else(|error| panic!("a live object lost its charge: {error:?}"));
            let weight = weight
                .checked_sub(freed)
                .expect("an object's weight counts every page it committed");
            registry
                .set_charge_pages(object, weight)
                .unwrap_or_else(|error| panic!("a live object rejected its weight: {error:?}"));
        }
        let record = self.objects[slot]
            .record
            .as_mut()
            .expect("found object slot has a record");
        if cursor >= end {
            record.released = None;
            ReleaseStep::Done { freed }
        } else {
            record.released = Some((cursor, end));
            ReleaseStep::More { freed }
        }
    }

    /// The first run `[low, high)` of object pages at or after `from` and
    /// before `end` that no live lease of the object at `slot` covers.
    fn next_uncovered(&self, slot: usize, from: u64, end: u64) -> Option<(u64, u64)> {
        let covers = || {
            self.leases
                .iter()
                .flatten_records()
                .filter(move |lease| lease.metadata.object_slot == slot)
                .map(|lease| {
                    let first = lease.metadata.range.object_offset / PAGE_SIZE;
                    (first, first + lease.metadata.range.byte_len / PAGE_SIZE)
                })
        };
        let mut low = from;
        while let Some((_, cover_end)) =
            covers().find(|&(cover_first, cover_end)| cover_first <= low && low < cover_end)
        {
            low = cover_end;
        }
        if low >= end {
            return None;
        }
        let high = covers()
            .map(|(cover_first, _)| cover_first)
            .filter(|&cover_first| cover_first > low)
            .fold(end, u64::min);
        Some((low, high))
    }

    #[cfg(test)]
    pub(crate) fn released_hull(&self, object: ObjectId) -> Option<(u64, u64)> {
        self.objects
            .iter()
            .find_map(|slot| slot.record.filter(|record| record.object == object))
            .and_then(|record| record.released)
    }
}
