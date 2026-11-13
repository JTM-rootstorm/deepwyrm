//! Allocator-owned object backing as a chain of runs (DW2 M3 §6.2).
//!
//! Each run is one role slot whose record names the chain's head run, the
//! object page the run starts at, and the next run. A walk checks every
//! link against the head and the page count so far, so a stale, foreign or
//! cyclic link fails: a run seen twice would need two different starting
//! pages, and every run holds at least one page.

use super::*;

/// Which role a chain's runs hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ChainState {
    /// Allocated by [`FrameRoleManager::allocate_backing`], not yet zeroed.
    Allocated,
    /// An object backing.
    Backing,
}

/// One validated run of a chain.
#[derive(Clone, Copy)]
struct ChainRun {
    slot: usize,
    range: PageRange,
    link: ChainLink,
}

/// The physical pieces of one object range, in object order. The shared
/// borrow keeps the chain from changing, so the walk validated at creation
/// stays valid.
pub(crate) struct ObjectSegments<'a, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> {
    manager: &'a FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    head: FrameRoleIdentity,
    state: ChainState,
    next: Option<FrameRoleIdentity>,
    /// The object page the next run starts at.
    run_page: u64,
    /// The next object page to yield.
    position: u64,
    end: u64,
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> Iterator
    for ObjectSegments<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    type Item = ObjectSegment;

    fn next(&mut self) -> Option<ObjectSegment> {
        while self.position < self.end {
            let identity = self.next?;
            let run = self
                .manager
                .chain_run(self.head, identity, self.run_page, self.state)
                .expect("a validated chain cannot change while it is borrowed");
            let start = self.run_page;
            let run_end = start + run.range.page_count();
            self.run_page = run_end;
            self.next = self.manager.link_identity(run.link.next);
            if run_end <= self.position {
                continue;
            }
            let from = self.position;
            let to = run_end.min(self.end);
            self.position = to;
            return Some(ObjectSegment {
                run: identity,
                object_offset: from * BASE_PAGE_SIZE,
                physical_start: run.range.start + (from - start) * BASE_PAGE_SIZE,
                byte_len: (to - from) * BASE_PAGE_SIZE,
            });
        }
        None
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>
{
    /// Allocates `page_count` pages as a chain of runs, largest free run
    /// first, so unfragmented memory gives one run (DW2 M3 §6.3). Fails only
    /// when memory or role slots run out, and then frees what it took.
    pub(crate) fn allocate_backing(
        &mut self,
        page_count: u64,
    ) -> Result<BackingAllocation, FrameRoleError> {
        if page_count == 0 {
            return Err(FrameRoleError::Physical(
                PhysicalMemoryError::InvalidPageRange,
            ));
        }
        let mut head: Option<FrameRoleIdentity> = None;
        let mut last: Option<usize> = None;
        let mut pages = 0_u64;
        let mut runs = 0_u64;
        while pages < page_count {
            let (slot, generation, identity, range) = match self.take_run(page_count - pages) {
                Ok(taken) => taken,
                Err(error) => {
                    if let Some(head) = head {
                        self.free_chain(head, ChainState::Allocated);
                    }
                    return Err(error);
                }
            };
            let head = *head.get_or_insert(identity);
            self.occupy(
                slot,
                generation,
                RoleRecord {
                    range,
                    role: FrameRole::BackingAllocated(ChainLink {
                        head: head.raw,
                        object_page: pages,
                        next: 0,
                    }),
                },
            );
            if let Some(previous) = last {
                self.link_next(previous, identity.raw);
            }
            last = Some(slot);
            pages += range.page_count();
            runs += 1;
        }
        Ok(BackingAllocation {
            head: head.expect("a nonempty request took a run"),
            pages,
            runs,
        })
    }

    /// Allocates `page_count` pages as a chain, has `zero` clear every page,
    /// and makes the chain one object backing: the one path for the boot
    /// and user allocators (DW2 M3 §6.3). If any page fails, every run is
    /// freed.
    ///
    /// # Safety
    ///
    /// `zero(page)` must exclusively zero the whole base page at physical
    /// `page`, with any cache maintenance it needs, or return `false`.
    #[allow(
        unsafe_code,
        reason = "the caller's zeroing is an architecture access fact attested by a typed state transition"
    )]
    pub(crate) unsafe fn allocate_zeroed_backing(
        &mut self,
        page_count: u64,
        zero: &mut dyn FnMut(u64) -> bool,
    ) -> Result<ObjectBackingGrant, FrameRoleError> {
        let allocation = self.allocate_backing(page_count)?;
        let zeroed = self
            .backing_allocation_segments(&allocation)
            .expect("a fresh allocation is a whole chain")
            .all(|segment| {
                (0..segment.byte_len / BASE_PAGE_SIZE)
                    .all(|page| zero(segment.physical_start + page * BASE_PAGE_SIZE))
            });
        if !zeroed {
            self.cancel_backing_allocation(allocation)
                .unwrap_or_else(|_| panic!("a fresh backing allocation frees"));
            return Err(FrameRoleError::InitializationFailed);
        }
        // SAFETY: `zero` cleared every page of every run, per this
        // function's contract.
        Ok(unsafe { self.assume_backing_zeroed(allocation) }
            .unwrap_or_else(|_| panic!("a zeroed backing allocation becomes a backing")))
    }

    /// Has `zero` clear pages `[first, first + count)` of `allocation`: part
    /// of the zeroing `allocate_zeroed_backing` does whole, so a caller can
    /// release its locks between parts (DW2 M4b). `false` if a page fails,
    /// or the pages are not all in the allocation.
    pub(crate) fn zero_backing_pages(
        &self,
        allocation: &BackingAllocation,
        first: u64,
        count: u64,
        zero: &mut dyn FnMut(u64) -> bool,
    ) -> bool {
        let Some(end) = first
            .checked_add(count)
            .filter(|end| *end <= allocation.pages)
        else {
            return false;
        };
        if self.chain_totals(allocation.head, ChainState::Allocated)
            != Ok((allocation.pages, allocation.runs))
        {
            return false;
        }
        self.segments(allocation.head, ChainState::Allocated, first, end)
            .all(|segment| {
                (0..segment.byte_len / BASE_PAGE_SIZE)
                    .all(|page| zero(segment.physical_start + page * BASE_PAGE_SIZE))
            })
    }

    /// The physical pieces of an allocation, for zeroing.
    pub(crate) fn backing_allocation_segments(
        &self,
        allocation: &BackingAllocation,
    ) -> Result<ObjectSegments<'_, RANGE_CAPACITY, ROLE_CAPACITY>, FrameRoleError> {
        if self.chain_totals(allocation.head, ChainState::Allocated)?
            != (allocation.pages, allocation.runs)
        {
            return Err(FrameRoleError::WrongRole);
        }
        Ok(self.segments(allocation.head, ChainState::Allocated, 0, allocation.pages))
    }

    /// Consumes an allocation whose every run was zeroed and makes it one
    /// object backing.
    ///
    /// # Safety
    ///
    /// The caller must have exclusively zeroed every run of `allocation`
    /// and completed any cache maintenance it needs.
    #[allow(
        unsafe_code,
        reason = "physical zeroing is an architecture access fact represented by a typed state transition"
    )]
    pub(crate) unsafe fn assume_backing_zeroed(
        &mut self,
        allocation: BackingAllocation,
    ) -> Result<ObjectBackingGrant, GrantTransitionError<BackingAllocation>> {
        match self.chain_totals(allocation.head, ChainState::Allocated) {
            Ok(totals) if totals == (allocation.pages, allocation.runs) => {}
            Ok(_) => {
                return Err(GrantTransitionError::new(
                    FrameRoleError::WrongRole,
                    allocation,
                ));
            }
            Err(error) => return Err(GrantTransitionError::new(error, allocation)),
        }
        let head = allocation.head;
        let mut head_range = None;
        let mut object_page = 0;
        let mut next = Some(head);
        while let Some(identity) = next {
            let run = self
                .chain_run(head, identity, object_page, ChainState::Allocated)
                .expect("a validated chain stays whole while it changes role");
            self.replace_record(
                run.slot,
                RoleRecord {
                    range: run.range,
                    role: FrameRole::ObjectBacking(run.link),
                },
            );
            head_range.get_or_insert(run.range);
            object_page += run.range.page_count();
            next = self.link_identity(run.link.next);
        }
        Ok(ObjectBackingGrant {
            identity: BackingIdentity(head),
            range: head_range.expect("a chain has a head run"),
            kind: ObjectBackingKind::AllocatorOwned,
            pages: allocation.pages,
            runs: allocation.runs,
        })
    }

    pub(crate) fn cancel_backing_allocation(
        &mut self,
        allocation: BackingAllocation,
    ) -> Result<(), GrantTransitionError<BackingAllocation>> {
        if let Err(error) = self.release_chain(
            allocation.head,
            ChainState::Allocated,
            allocation.pages,
            allocation.runs,
        ) {
            return Err(GrantTransitionError::new(error, allocation));
        }
        Ok(())
    }

    /// The physical pieces of `[offset, offset + byte_len)` of a backing, in
    /// object order, after checking the whole range lies in the backing and
    /// that a writable use is allowed.
    pub(crate) fn object_segments(
        &self,
        backing: BackingIdentity,
        offset: u64,
        byte_len: u64,
        writable: bool,
    ) -> Result<ObjectSegments<'_, RANGE_CAPACITY, ROLE_CAPACITY>, FrameRoleError> {
        let pages = |bytes: u64| {
            bytes
                .is_multiple_of(BASE_PAGE_SIZE)
                .then_some(bytes / BASE_PAGE_SIZE)
        };
        let first = pages(offset).ok_or(FrameRoleError::WrongRole)?;
        let count = pages(byte_len)
            .filter(|count| *count != 0)
            .ok_or(FrameRoleError::WrongRole)?;
        let end = first.checked_add(count).ok_or(FrameRoleError::WrongRole)?;
        match self.record(backing.0)?.role {
            FrameRole::ObjectBacking(_) | FrameRole::ExternalDeviceMmio => {}
            FrameRole::ExternalImmutableModule { .. } if writable => {
                return Err(FrameRoleError::ReadOnlyBacking);
            }
            FrameRole::ExternalImmutableModule { .. } => {}
            _ => return Err(FrameRoleError::WrongRole),
        }
        let (total, _) = self.chain_totals(backing.0, ChainState::Backing)?;
        if end > total {
            return Err(FrameRoleError::WrongRole);
        }
        Ok(self.segments(backing.0, ChainState::Backing, first, end))
    }

    /// The run and physical address of the backing page at `offset`,
    /// walking from the head.
    pub(crate) fn resolve_object_page(
        &self,
        backing: BackingIdentity,
        offset: u64,
        writable: bool,
    ) -> Result<ObjectSegment, FrameRoleError> {
        self.resolve_at(&mut BackingCursor::new(backing), offset, writable)
    }

    /// The run and physical address of the page at `offset` of the backing
    /// `cursor` walks, moving `cursor` to that page's run. Resolving pages
    /// in increasing order costs one step per run crossed; an earlier page
    /// or a stale cursor restarts from the head. Every step checks its run
    /// against the head and the object page it starts at, so the cursor
    /// grants nothing by itself.
    pub(crate) fn resolve_at(
        &self,
        cursor: &mut BackingCursor,
        offset: u64,
        writable: bool,
    ) -> Result<ObjectSegment, FrameRoleError> {
        if !offset.is_multiple_of(BASE_PAGE_SIZE) {
            return Err(FrameRoleError::WrongRole);
        }
        let page = offset / BASE_PAGE_SIZE;
        let head = cursor.head;
        match self.record(head)?.role {
            FrameRole::IndexRoot(_) => {
                let (run, physical_start) = self.index_resolve(head, page)?;
                return Ok(ObjectSegment {
                    run,
                    object_offset: offset,
                    physical_start,
                    byte_len: BASE_PAGE_SIZE,
                });
            }
            FrameRole::ObjectBacking(_) | FrameRole::ExternalDeviceMmio => {}
            FrameRole::ExternalImmutableModule { .. } if writable => {
                return Err(FrameRoleError::ReadOnlyBacking);
            }
            FrameRole::ExternalImmutableModule { .. } => {}
            _ => return Err(FrameRoleError::WrongRole),
        }
        if page < cursor.run_page {
            *cursor = BackingCursor::new(BackingIdentity(head));
        }
        let mut restarted = cursor.run == head;
        loop {
            let run = match self.chain_run(head, cursor.run, cursor.run_page, ChainState::Backing) {
                Ok(run) => run,
                Err(_) if !restarted => {
                    *cursor = BackingCursor::new(BackingIdentity(head));
                    restarted = true;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let end = cursor.run_page + run.range.page_count();
            if page < end {
                return Ok(ObjectSegment {
                    run: cursor.run,
                    object_offset: offset,
                    physical_start: run.range.start + (page - cursor.run_page) * BASE_PAGE_SIZE,
                    byte_len: BASE_PAGE_SIZE,
                });
            }
            cursor.run = self
                .link_identity(run.link.next)
                .ok_or(FrameRoleError::WrongRole)?;
            cursor.run_page = end;
        }
    }

    /// Frees a whole chain after checking it is `pages` pages in `runs`
    /// allocator-owned runs.
    pub(super) fn release_chain(
        &mut self,
        head: FrameRoleIdentity,
        state: ChainState,
        pages: u64,
        runs: u64,
    ) -> Result<(), FrameRoleError> {
        if !matches!(
            self.record(head)?.role,
            FrameRole::BackingAllocated(_) | FrameRole::ObjectBacking(_)
        ) || self.chain_totals(head, state)? != (pages, runs)
        {
            return Err(FrameRoleError::WrongRole);
        }
        self.free_chain(head, state);
        Ok(())
    }

    /// Every chain is whole: each chain run is reached from exactly one
    /// head's walk.
    pub(super) fn check_chains(&self) -> Result<(), FrameRoleError> {
        let mut linked = 0_u64;
        let mut reached = 0_u64;
        for (slot, entry) in self.roles.as_slice().iter().enumerate() {
            let Some(record) = entry.record else {
                continue;
            };
            let (state, link) = match record.role {
                FrameRole::BackingAllocated(link) => (ChainState::Allocated, link),
                FrameRole::ObjectBacking(link) => (ChainState::Backing, link),
                _ => continue,
            };
            linked += 1;
            let identity = self.identity(slot, entry.generation)?;
            if link.head == identity.raw {
                let (_, runs) = self
                    .chain_totals(identity, state)
                    .map_err(|_| FrameRoleError::InvariantViolation)?;
                reached += runs;
            }
        }
        if linked != reached {
            return Err(FrameRoleError::InvariantViolation);
        }
        Ok(())
    }

    pub(super) fn take_run(
        &mut self,
        wanted: u64,
    ) -> Result<(usize, u32, FrameRoleIdentity, PageRange), FrameRoleError> {
        let largest = self.allocator.largest_free_pages();
        if largest == 0 {
            return Err(FrameRoleError::Physical(
                PhysicalMemoryError::NoFramesAvailable,
            ));
        }
        let (slot, generation) = self.next_slot()?;
        let identity = self.identity(slot, generation)?;
        let range = self.allocator.allocate_run(wanted.min(largest))?;
        Ok((slot, generation, identity, range))
    }

    fn link_next(&mut self, slot: usize, next: u64) {
        let mut record = self.roles.as_slice()[slot]
            .record
            .expect("a linked run is live");
        let FrameRole::BackingAllocated(link) = &mut record.role else {
            panic!("only a run being allocated is linked");
        };
        link.next = next;
        self.replace_record(slot, record);
    }

    /// Frees every run of a chain already checked whole.
    fn free_chain(&mut self, head: FrameRoleIdentity, state: ChainState) {
        let mut object_page = 0;
        let mut next = Some(head);
        while let Some(identity) = next {
            let run = self
                .chain_run(head, identity, object_page, state)
                .expect("a validated chain stays whole while it is freed");
            self.allocator
                .free_run(run.range)
                .expect("a live run frees: the free list is sized by the role slots (M1)");
            self.vacate(run.slot);
            object_page += run.range.page_count();
            next = self.link_identity(run.link.next);
        }
    }

    fn segments(
        &self,
        head: FrameRoleIdentity,
        state: ChainState,
        first: u64,
        end: u64,
    ) -> ObjectSegments<'_, RANGE_CAPACITY, ROLE_CAPACITY> {
        ObjectSegments {
            manager: self,
            head,
            state,
            next: Some(head),
            run_page: 0,
            position: first,
            end,
        }
    }

    /// The pages and runs of `head`'s whole chain.
    fn chain_totals(
        &self,
        head: FrameRoleIdentity,
        state: ChainState,
    ) -> Result<(u64, u64), FrameRoleError> {
        let mut pages = 0_u64;
        let mut runs = 0_u64;
        let mut next = Some(head);
        while let Some(identity) = next {
            let run = self.chain_run(head, identity, pages, state)?;
            pages = pages
                .checked_add(run.range.page_count())
                .ok_or(FrameRoleError::InvariantViolation)?;
            runs += 1;
            next = self.link_identity(run.link.next);
        }
        Ok((pages, runs))
    }

    /// The run `identity` names, checked to be the run of `head`'s chain
    /// that starts at `object_page` and holds `state`'s role. An external
    /// backing (boot module, device BAR) is a chain of its one run.
    fn chain_run(
        &self,
        head: FrameRoleIdentity,
        identity: FrameRoleIdentity,
        object_page: u64,
        state: ChainState,
    ) -> Result<ChainRun, FrameRoleError> {
        let slot = self.slot(identity)?;
        let record = self.roles.as_slice()[slot]
            .record
            .ok_or(FrameRoleError::InvalidGrant)?;
        let link = match (state, record.role) {
            (ChainState::Allocated, FrameRole::BackingAllocated(link))
            | (ChainState::Backing, FrameRole::ObjectBacking(link)) => link,
            (
                ChainState::Backing,
                FrameRole::ExternalImmutableModule { .. } | FrameRole::ExternalDeviceMmio,
            ) if identity == head => ChainLink {
                head: head.raw,
                object_page: 0,
                next: 0,
            },
            _ => return Err(FrameRoleError::WrongRole),
        };
        if head.domain != self.domain || link.head != head.raw || link.object_page != object_page {
            return Err(FrameRoleError::WrongRole);
        }
        Ok(ChainRun {
            slot,
            range: record.range,
            link,
        })
    }

    fn link_identity(&self, raw: u64) -> Option<FrameRoleIdentity> {
        (raw != 0).then_some(FrameRoleIdentity {
            domain: self.domain,
            raw,
        })
    }
}

#[cfg(test)]
#[path = "chain_tests.rs"]
mod tests;
