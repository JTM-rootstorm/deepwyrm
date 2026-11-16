//! An eager backing of many runs allocated, and abandoned, in steps (DW2
//! §12.11 part 2).
//!
//! The first hold ([`FrameRoleManager::begin_backing`]) takes at most
//! [`INDEX_RUN_THRESHOLD`] runs as a chain. If they do not cover the
//! request, an index root is taken in the `EagerBuilding` state and the
//! chain becomes the allocation's remainder. Each building step
//! ([`FrameRoleManager::extend_backing`]) links runs into the index at the
//! object page `linked`: the remainder's tail first, split at [`RUN_CAP`]
//! pages, then runs from the allocator. Linking a run is two passes: the
//! nodes its pages need and lack are taken and zeroed first, the only part
//! that can fail, and given back if one fails; then the nodes are linked,
//! the run's entries written and the run given the `ObjectPage` role. So a
//! run is either wholly in the index or not in it, and the entries stay
//! gapless from page 0 to `linked`.
//!
//! An allocation or backing that will not be used is abandoned: its
//! remainder (at most 16 runs) is freed, and an index with runs linked
//! keeps its root, now `EagerFreeing` with `pages` set to the pages linked,
//! as an [`OwedBacking`] whose runs and nodes the owed finalize step frees.
//! No path a syscall reaches frees an index whole.

use super::chain::ChainRun;
use super::index::{
    BUILD_STEP_PAGES, BUILD_STEP_RUNS, EagerIndex, LINK_MAX_NODES, RUN_CAP, Taken, entry_span,
    node_place,
};
use super::*;

/// One node a run needs and its index lacks, taken and zeroed, not yet
/// linked: its frame, its level and the first object page it covers.
#[derive(Clone, Copy)]
struct NewNode {
    frame: Taken,
    level: u8,
    first: u64,
}

/// Where the next run to link comes from.
enum NextRun {
    /// The remainder's tail run, whole; `before` is the slot of the run
    /// that links to it, or `None` when it is the remainder's head.
    Tail {
        identity: FrameRoleIdentity,
        run: ChainRun,
        before: Option<usize>,
    },
    /// The last [`RUN_CAP`] pages of the remainder's tail run, which is
    /// longer.
    Split { run: ChainRun },
    /// A run from the allocator: the remainder is empty.
    Fresh,
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>
{
    /// One building step of `allocation` (DW2 §12.11 part 2 item 3): links
    /// runs into its index until this call has linked [`BUILD_STEP_RUNS`]
    /// runs or [`BUILD_STEP_PAGES`] pages, or the request is covered; then
    /// the root becomes `EagerAllocated`, one write, and the allocation is
    /// complete. A complete allocation is left as it is.
    ///
    /// On failure (no frames or role slots for a run or a node), the run
    /// being linked is not linked: the index and the remainder are as they
    /// were before it, and the allocation stays valid for abandonment.
    pub(crate) fn extend_backing(
        &mut self,
        allocation: &mut BackingAllocation,
    ) -> Result<(), FrameRoleError> {
        self.extend_backing_within(allocation, BUILD_STEP_RUNS)
    }

    /// [`Self::extend_backing`] stopped after at most `most_runs` runs, so
    /// a host test can hold an allocation part built.
    #[cfg(test)]
    pub(crate) fn extend_backing_runs(
        &mut self,
        allocation: &mut BackingAllocation,
        most_runs: u64,
    ) -> Result<(), FrameRoleError> {
        self.extend_backing_within(allocation, most_runs.min(BUILD_STEP_RUNS))
    }

    fn extend_backing_within(
        &mut self,
        allocation: &mut BackingAllocation,
        most_runs: u64,
    ) -> Result<(), FrameRoleError> {
        if allocation.is_complete() {
            return Ok(());
        }
        let (root_range, root) = self.index_root(allocation.head, RootUse::Building)?;
        if !allocation.indexed || root.pages != allocation.pages {
            return Err(FrameRoleError::WrongRole);
        }
        let index = EagerIndex {
            memory: self.memory()?,
            root: allocation.head,
            node: root_range.start,
            levels: root.levels,
        };
        let mut runs = 0_u64;
        let mut pages = 0_u64;
        while allocation.linked < allocation.pages && runs < most_runs && pages < BUILD_STEP_PAGES {
            pages += self.link_one_run(&index, allocation)?;
            runs += 1;
        }
        if allocation.linked == allocation.pages {
            assert!(
                allocation.remainder.is_none(),
                "an index whose every page is linked has no remainder"
            );
            let slot = self.slot(allocation.head)?;
            self.replace_record(
                slot,
                RoleRecord {
                    range: root_range,
                    role: FrameRole::IndexRoot(IndexRootLink {
                        state: IndexRootState::EagerAllocated,
                        ..root
                    }),
                },
            );
        }
        Ok(())
    }

    /// Links the next run into the index at object page `linked`, and
    /// returns its pages.
    fn link_one_run(
        &mut self,
        index: &EagerIndex,
        allocation: &mut BackingAllocation,
    ) -> Result<u64, FrameRoleError> {
        let place = allocation.linked;
        let next = match &allocation.remainder {
            Some(remainder) => {
                let (identity, run, before) = self.remainder_tail(remainder)?;
                if run.range.page_count() > RUN_CAP {
                    NextRun::Split { run }
                } else {
                    NextRun::Tail {
                        identity,
                        run,
                        before,
                    }
                }
            }
            None => NextRun::Fresh,
        };
        let (slot, identity, range) = match next {
            NextRun::Tail {
                identity,
                run,
                before,
            } => {
                let count = run.range.page_count();
                let nodes = self.take_run_nodes(index, place, count)?;
                // Nothing below can fail: the run leaves the remainder.
                match before {
                    Some(before) => {
                        self.link_next(before, 0);
                        let remainder = allocation
                            .remainder
                            .as_mut()
                            .expect("a tail run came from the remainder");
                        remainder.pages -= count;
                        remainder.runs -= 1;
                    }
                    None => allocation.remainder = None,
                }
                self.link_run_nodes(index, &nodes);
                (run.slot, identity, run.range)
            }
            NextRun::Split { run } => {
                let nodes = self.take_run_nodes(index, place, RUN_CAP)?;
                let fresh = self.next_slot().and_then(|(slot, generation)| {
                    Ok((slot, generation, self.identity(slot, generation)?))
                });
                let (slot, generation, identity) = match fresh {
                    Ok(fresh) => fresh,
                    Err(error) => {
                        self.untake_run_nodes(&nodes);
                        return Err(error);
                    }
                };
                // Nothing below can fail. The tail run keeps its start and
                // its link and gives up its last `RUN_CAP` pages, which
                // become a run of their own.
                let split = run.range.end - RUN_CAP * BASE_PAGE_SIZE;
                self.shorten_run(
                    run.slot,
                    PageRange {
                        start: run.range.start,
                        end: split,
                    },
                );
                let carved = PageRange {
                    start: split,
                    end: run.range.end,
                };
                self.occupy(
                    slot,
                    generation,
                    RoleRecord {
                        range: carved,
                        role: FrameRole::AllocatedUninitialized,
                    },
                );
                allocation
                    .remainder
                    .as_mut()
                    .expect("a split run came from the remainder")
                    .pages -= RUN_CAP;
                self.link_run_nodes(index, &nodes);
                (slot, identity, carved)
            }
            NextRun::Fresh => {
                let left = allocation.pages - place;
                let (slot, generation, identity, range) = self.take_run(left.min(RUN_CAP))?;
                self.occupy(
                    slot,
                    generation,
                    RoleRecord {
                        range,
                        role: FrameRole::AllocatedUninitialized,
                    },
                );
                let nodes = match self.take_run_nodes(index, place, range.page_count()) {
                    Ok(nodes) => nodes,
                    Err(error) => {
                        self.allocator
                            .free_run(range)
                            .expect("a run just taken frees");
                        self.vacate(slot);
                        return Err(error);
                    }
                };
                self.link_run_nodes(index, &nodes);
                (slot, identity, range)
            }
        };
        let count = range.page_count();
        self.write_run_entries(index, identity, place, count, &mut None);
        self.replace_record(
            slot,
            RoleRecord {
                range,
                role: FrameRole::ObjectPage(IndexEntryLink {
                    owner: index.root.raw,
                    place,
                }),
            },
        );
        allocation.linked += count;
        allocation.runs += 1;
        Ok(count)
    }

    /// The remainder's tail run, its identity, and the slot of the run
    /// before it (`None`: the tail is the head), checked to end at the
    /// remainder's pages. A walk of at most [`INDEX_RUN_THRESHOLD`] runs.
    fn remainder_tail(
        &self,
        remainder: &RemainderChain,
    ) -> Result<(FrameRoleIdentity, ChainRun, Option<usize>), FrameRoleError> {
        let mut identity = remainder.head;
        let mut before = None;
        let mut object_page = 0_u64;
        loop {
            let run =
                self.chain_run(remainder.head, identity, object_page, ChainState::Allocated)?;
            match self.link_identity(run.link.next) {
                Some(next) => {
                    before = Some(run.slot);
                    object_page += run.range.page_count();
                    identity = next;
                }
                None if object_page + run.range.page_count() == remainder.pages => {
                    return Ok((identity, run, before));
                }
                None => return Err(FrameRoleError::InvariantViolation),
            }
        }
    }

    /// Shortens the live chain run in `slot` to `range`, which keeps its
    /// start. The start index is keyed by a run's first page, which does
    /// not change, and nothing else is kept per page of a run, so the
    /// record is rewritten in place.
    fn shorten_run(&mut self, slot: usize, range: PageRange) {
        let mut record = self.record_at(slot).expect("a shortened run is live");
        assert!(
            matches!(record.role, FrameRole::BackingAllocated(_))
                && range.start == record.range.start
                && range.start < range.end
                && range.end < record.range.end,
            "a run is shortened only from its end"
        );
        record.range = range;
        self.replace_record(slot, record);
    }

    /// First pass of linking a run of `count` pages at object page `place`
    /// (gapless after it): takes and zeroes every node its pages need and
    /// lack, top level first and in page order within a level. A node of a
    /// level exists exactly when it covers a page below `place`, so those
    /// whose first page lies in `[place, place + count)` are the new ones.
    /// If one fails, those taken are given back.
    fn take_run_nodes(
        &mut self,
        index: &EagerIndex,
        place: u64,
        count: u64,
    ) -> Result<[Option<NewNode>; LINK_MAX_NODES], FrameRoleError> {
        assert!(
            (1..=RUN_CAP).contains(&count),
            "a linked run holds 1 to RUN_CAP pages"
        );
        let end = place + count;
        let mut nodes = [None; LINK_MAX_NODES];
        let mut taken = 0;
        // The root's level is `levels - 1`; the nodes below it.
        for level in (0..index.levels - 1).rev() {
            let span = entry_span(level + 1);
            let mut first = place.div_ceil(span) * span;
            while first < end {
                let role = FrameRole::IndexNode(IndexEntryLink {
                    owner: index.root.raw,
                    place: node_place(first, level),
                });
                match self.take_index_frame(index.memory, role) {
                    Ok(frame) => {
                        nodes[taken] = Some(NewNode {
                            frame,
                            level,
                            first,
                        });
                        taken += 1;
                    }
                    Err(error) => {
                        self.untake_run_nodes(&nodes);
                        return Err(error);
                    }
                }
                first += span;
            }
        }
        Ok(nodes)
    }

    fn untake_run_nodes(&mut self, nodes: &[Option<NewNode>; LINK_MAX_NODES]) {
        for node in nodes.iter().flatten() {
            self.untake_index_frame(node.frame);
        }
    }

    /// Second pass: links each new node into its parent, parents first.
    fn link_run_nodes(&mut self, index: &EagerIndex, nodes: &[Option<NewNode>; LINK_MAX_NODES]) {
        for node in nodes.iter().flatten() {
            let parent_level = node.level + 1;
            let parent = self.node_at(index, node.first, parent_level);
            let entry = ((node.first / entry_span(parent_level)) % INDEX_FANOUT) as usize;
            #[allow(
                unsafe_code,
                reason = "the manager owns its index nodes exclusively under `&mut self`"
            )]
            // SAFETY: `parent` is a node of this index, which the manager
            // owns exclusively under `&mut self`.
            unsafe {
                index.memory.write(parent, entry, node.frame.identity.raw)
            };
        }
    }

    /// Frees an index allocation whole, at any stage (DW2 §12.11 part 2
    /// item 9): its index, every run and node linked, then its remainder.
    /// Nothing changes on a refusal.
    pub(super) fn cancel_index_allocation(
        &mut self,
        allocation: &BackingAllocation,
    ) -> Result<(), FrameRoleError> {
        let (_, root) = self.index_root(allocation.head, RootUse::Unfinished)?;
        let complete = root.state == IndexRootState::EagerAllocated;
        if !allocation.indexed
            || root.pages != allocation.pages
            || complete != allocation.is_complete()
        {
            return Err(FrameRoleError::WrongRole);
        }
        if let Some(remainder) = &allocation.remainder
            && self.chain_totals(remainder.head, ChainState::Allocated)?
                != (remainder.pages, remainder.runs)
        {
            return Err(FrameRoleError::WrongRole);
        }
        self.release_index(allocation.head, RootUse::Unfinished)?;
        if let Some(remainder) = &allocation.remainder {
            self.free_chain(remainder.head, ChainState::Allocated);
        }
        Ok(())
    }

    /// Abandons an allocation that will not become a backing (DW2 §12.11
    /// part 2 item 6), in a hold of bounded length. A chain is freed whole
    /// (at most [`INDEX_RUN_THRESHOLD`] runs unless the manager has no index
    /// memory), as is an index's remainder. An index with nothing linked
    /// has its root freed. An index with runs linked keeps its root, now
    /// being freed with `pages` set to the pages linked (one write, its
    /// levels unchanged), and is returned to be freed in owed steps.
    /// Afterwards nothing resolves the backing.
    pub(crate) fn abandon_backing(&mut self, allocation: BackingAllocation) -> Option<OwedBacking> {
        if !allocation.indexed {
            self.cancel_backing_allocation(allocation)
                .unwrap_or_else(|_| panic!("an abandoned chain allocation frees"));
            return None;
        }
        let head = allocation.head;
        let (range, root) = match self.index_root(head, RootUse::Unfinished) {
            Ok((range, root)) if root.pages == allocation.pages => (range, root),
            Ok(_) | Err(_) => panic!("an abandoned index allocation lost its root"),
        };
        if let Some(remainder) = &allocation.remainder {
            self.release_chain(
                remainder.head,
                ChainState::Allocated,
                remainder.pages,
                remainder.runs,
            )
            .unwrap_or_else(|_| panic!("an abandoned allocation's remainder frees"));
        }
        if allocation.linked == 0 {
            // No run is linked, so no node: the root alone.
            self.release_index(head, RootUse::Unfinished)
                .unwrap_or_else(|_| panic!("an abandoned empty index frees"));
            return None;
        }
        self.begin_owed_release(head, range, root, allocation.linked);
        Some(OwedBacking {
            root: head,
            pages: allocation.linked,
        })
    }

    /// Abandons a backing that will not be used, a create's rolled back
    /// (DW2 §12.11 part 2 item 6): an indexed one's root, `Eager`, is set
    /// to being freed and returned to be freed in owed steps; any other
    /// kind is freed whole, as [`Self::cancel_object_backing`] frees it.
    pub(crate) fn abandon_object_backing(
        &mut self,
        grant: ObjectBackingGrant,
    ) -> Option<OwedBacking> {
        if grant.kind != ObjectBackingKind::AllocatorIndexed {
            self.cancel_object_backing(grant)
                .unwrap_or_else(|_| panic!("an abandoned backing frees"));
            return None;
        }
        let head = grant.identity.0;
        let (range, root) = match self.index_root(head, RootUse::Eager) {
            Ok((range, root))
                if root.state == IndexRootState::Eager && root.pages == grant.pages =>
            {
                (range, root)
            }
            Ok(_) | Err(_) => panic!("an abandoned indexed backing lost its root"),
        };
        self.begin_owed_release(head, range, root, grant.pages);
        Some(OwedBacking {
            root: head,
            pages: grant.pages,
        })
    }

    /// Writes the root of `head` as being freed, with `pages` pages.
    fn begin_owed_release(
        &mut self,
        head: FrameRoleIdentity,
        range: PageRange,
        root: IndexRootLink,
        pages: u64,
    ) {
        let slot = self.slot(head).expect("a root just read is live");
        self.replace_record(
            slot,
            RoleRecord {
                range,
                role: FrameRole::IndexRoot(IndexRootLink {
                    pages,
                    state: IndexRootState::EagerFreeing,
                    ..root
                }),
            },
        );
    }

    /// Frees an owed backing's root once release steps have freed every
    /// run and node below it (DW2 §12.11 part 2 item 7), after checking the
    /// index empty. Nothing changes on a refusal.
    pub(crate) fn release_owed_backing(
        &mut self,
        owed: OwedBacking,
    ) -> Result<(), GrantTransitionError<OwedBacking>> {
        match self.index_root(owed.root, RootUse::Eager) {
            Ok((_, root))
                if root.state == IndexRootState::EagerFreeing && root.pages == owed.pages => {}
            Ok(_) => {
                return Err(GrantTransitionError::new(FrameRoleError::WrongRole, owed));
            }
            Err(error) => return Err(GrantTransitionError::new(error, owed)),
        }
        match self.index_count(owed.root, RootUse::Eager) {
            Ok(0) => {}
            Ok(_) => {
                return Err(GrantTransitionError::new(FrameRoleError::WrongRole, owed));
            }
            Err(error) => return Err(GrantTransitionError::new(error, owed)),
        }
        if let Err(error) = self.release_index(owed.root, RootUse::Eager) {
            return Err(GrantTransitionError::new(error, owed));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "build_tests.rs"]
mod tests;
