//! The owed-finalization queue and its steps (DW2 §10.12, §12.11 part 2
//! items 7 and 8).

use super::*;

/// A finalization owed in steps, and how far its index has been freed.
pub(super) struct OwedFinalization {
    finalization: MemoryObjectFinalization,
    cursor: u64,
}

impl<const OBJECTS: usize, const LEASES: usize> MemoryObjectAuthority<OBJECTS, LEASES> {
    /// Whether any finalization is owed (DW2 §10.12): of an object, or of
    /// an abandoned create's backing (DW2 §12.11 part 2 item 7).
    pub(crate) fn finalization_owed(&self) -> bool {
        self.owed_len != 0 || self.backings_len != 0
    }

    /// Queues an abandoned create's backing to be freed in owed steps
    /// after the owed objects (DW2 §12.11 part 2 item 7). The caller has
    /// given it a reservation slot in the same hold.
    ///
    /// # Panics
    ///
    /// If the queue is full: every owed backing holds one of the
    /// registry's [`RESERVATION_THREADS`] slots, so it cannot be.
    pub(crate) fn queue_owed_backing(&mut self, backing: OwedBacking) {
        assert!(
            self.backings_len < RESERVATION_THREADS,
            "every owed backing holds a reservation slot, so no more than RESERVATION_THREADS are owed"
        );
        let index = (self.backings_head + self.backings_len) % RESERVATION_THREADS;
        assert!(
            self.owed_backings[index].is_none(),
            "the owed backings' ring has a free entry past its last"
        );
        self.owed_backings[index] = Some((backing, 0));
        self.backings_len += 1;
    }

    /// How many owed backings are queued.
    pub(crate) fn owed_backing_count(&self) -> usize {
        self.backings_len
    }

    /// Queues the finalization of an on-demand object, or of a page-backed
    /// object whose backing is indexed, to be done in steps (DW2 §10.12
    /// item 1, §12.10 part 2 item 6), in a free slot (the one
    /// `take_finalization` just emptied, at least, is free); any other kind
    /// is returned to be completed at once.
    pub(crate) fn defer_finalization(
        &mut self,
        finalization: MemoryObjectFinalization,
    ) -> Option<MemoryObjectFinalization> {
        if !matches!(
            (finalization.kind, finalization.backing.kind()),
            (MemoryObjectKind::OnDemand, ObjectBackingKind::OnDemand)
                | (
                    MemoryObjectKind::PageBacked,
                    ObjectBackingKind::AllocatorIndexed
                )
        ) {
            return Some(finalization);
        }
        let slot = self
            .objects
            .iter()
            .zip(self.backings.iter())
            .zip(self.owed.iter())
            .position(|((slot, backing), owed)| {
                slot.record.is_none() && backing.is_none() && owed.is_none()
            })
            .expect("the slot a finalization was taken from is free");
        self.owed[slot] = Some(OwedFinalization {
            finalization,
            cursor: 0,
        });
        assert!(self.owed_len < OBJECTS, "one owed entry per slot");
        self.owed_order[(self.owed_head + self.owed_len) % OBJECTS] = slot;
        self.owed_len += 1;
        None
    }

    /// One step of the owed finalizations (DW2 §10.12 item 2), oldest
    /// first: at most `budget` index entries are visited, the budget left
    /// by an object that completes going on to the next (step-6 review R3),
    /// less the root's entries its completion reads.
    /// Each step lowers the object's weight by what it freed of what the
    /// object is charged: an on-demand object's frames, an eager object's
    /// run pages, not its index nodes (DW2 §12.10 part 2 item 8); an
    /// object whose index is empty is completed. Owed backings are served
    /// after the objects from the same budget, each step lowering the
    /// backing's reservation by the run pages it freed; at its index's end
    /// its root is freed and its reservation ends (DW2 §12.11 part 2 items
    /// 7 and 8). `true` if any remain.
    #[cfg(deepwyrm_integrated)]
    pub(crate) fn finalize_owed_step<
        const REGISTRY_OBJECTS: usize,
        const RANGE_CAPACITY: usize,
        const ROLE_CAPACITY: usize,
    >(
        &mut self,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        roles: &mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
        budget: u64,
    ) -> bool {
        self.finalize_owed_step_observed(registry, roles, budget, |_, _, _| {})
    }

    /// The owed slots, oldest first (DW2 §10.19 revision 2: the step report
    /// keys its record of each queued object by its slot).
    pub(crate) fn owed_slots(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.owed_len).map(|index| self.owed_order[(self.owed_head + index) % OBJECTS])
    }

    /// [`Self::finalize_owed_step`], telling `observe` of each object it
    /// worked on: its slot, the frames this step freed of it, and whether
    /// it completed. Only reported; the step is the same.
    #[cfg(deepwyrm_integrated)]
    pub(crate) fn finalize_owed_step_observed<
        const REGISTRY_OBJECTS: usize,
        const RANGE_CAPACITY: usize,
        const ROLE_CAPACITY: usize,
    >(
        &mut self,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        roles: &mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
        budget: u64,
        mut observe: impl FnMut(usize, u64, bool),
    ) -> bool {
        let mut left = budget;
        while left != 0 && self.owed_len != 0 {
            let slot = self.owed_order[self.owed_head];
            let owed = self.owed[slot]
                .as_mut()
                .expect("a queued owed slot holds its finalization");
            let backing = owed.finalization.backing.identity();
            let pages = owed.finalization.backing.byte_len() / PAGE_SIZE;
            let (cursor, freed, visited) = roles
                .release_index_step(backing, owed.cursor, left)
                .unwrap_or_else(|error| panic!("an owed index did not free: {error:?}"));
            owed.cursor = cursor;
            if freed != 0 {
                registry
                    .lower_finalizing_charge_pages(owed.finalization.final_release.id(), freed)
                    .unwrap_or_else(|error| {
                        panic!("an owed object's weight did not fall: {error:?}")
                    });
            }
            left = left.saturating_sub(visited.max(1));
            observe(slot, freed, cursor >= pages);
            if cursor < pages {
                break;
            }
            let owed = self.owed[slot]
                .take()
                .expect("a queued owed slot holds its finalization");
            self.owed_head = (self.owed_head + 1) % OBJECTS;
            self.owed_len -= 1;
            let parent = complete_memory_finalization(registry, roles, owed.finalization);
            assert!(parent.is_none(), "an owed object has no parent");
            // Completion re-reads the root's entries to check the index
            // empty before freeing it: charged in full (second security
            // pass D-2).
            left = left.saturating_sub(crate::memory::frame_roles::INDEX_FANOUT);
        }
        if self.owed_len == 0 {
            self.release_owed_backings(registry, roles, left);
        }
        self.finalization_owed()
    }

    /// The owed backings' share of a finalize step: the loop
    /// [`Self::finalize_owed_step_observed`] runs for objects, with the
    /// backing's reservation in place of an object's charge. Not reported
    /// per backing.
    #[cfg(deepwyrm_integrated)]
    fn release_owed_backings<
        const REGISTRY_OBJECTS: usize,
        const RANGE_CAPACITY: usize,
        const ROLE_CAPACITY: usize,
    >(
        &mut self,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        roles: &mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
        mut left: u64,
    ) {
        while left != 0 && self.backings_len != 0 {
            let (backing, cursor) = self.owed_backings[self.backings_head]
                .as_mut()
                .expect("a queued owed backing is held");
            let pages = backing.pages();
            let key = backing.key();
            let (next, freed, visited) = roles
                .release_index_step(backing.identity(), *cursor, left)
                .unwrap_or_else(|error| panic!("an owed backing did not free: {error:?}"));
            *cursor = next;
            if freed != 0 {
                registry
                    .lower_owed_backing_pages(key, freed)
                    .unwrap_or_else(|error| {
                        panic!("an owed backing's reservation did not fall: {error:?}")
                    });
            }
            left = left.saturating_sub(visited.max(1));
            if next < pages {
                break;
            }
            let (backing, _) = self.owed_backings[self.backings_head]
                .take()
                .expect("a queued owed backing is held");
            self.backings_head = (self.backings_head + 1) % RESERVATION_THREADS;
            self.backings_len -= 1;
            roles
                .release_owed_backing(backing)
                .unwrap_or_else(|_| panic!("an owed backing's root did not free"));
            registry.end_owed_backing_reservation(key);
            // As an object's completion: the root's entries are read.
            left = left.saturating_sub(crate::memory::frame_roles::INDEX_FANOUT);
        }
    }
}
