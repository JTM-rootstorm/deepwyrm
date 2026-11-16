//! Where the grown role table lives (DW2 large-memory plan, M7 §12.9): its
//! layout, the runs of RAM it is staged in, adoption from the one virtual
//! range those runs are mapped at, the start index over the grown table,
//! and the manager's invariant check.
//!
//! The table's RAM is taken as several runs ("pieces"), each an ordinary
//! allocation staged here in order while the deep root is built. The
//! architecture maps them back to back at one virtual range, and
//! [`FrameRoleManager::adopt_storage`] carves the table from that range's
//! base exactly as it did from one run, so the arrays stay plain slices.

use super::*;

/// The most runs the table is staged in: as many as the allocator has
/// initial ranges at most, which is what the table map holds.
pub(crate) const MAX_GROWTH_PARTS: usize = super::super::boot_map::MAX_SANITIZED_USABLE_RANGES
    + super::super::boot_map::MAX_BOOTSTRAP_RESERVATIONS;

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>
{
    /// The run the grown role table needs: one slot per page of allocator
    /// RAM beyond the boot slots, a start index entry
    /// per allocator page (DW2 M2 §5.3), and the buddy allocator's metadata:
    /// a link pair and a tag per allocator page, a base per initial range and
    /// a range-lookup hint per granule (DW2 M7 §12.2).
    pub(crate) fn grown_layout(&self) -> Result<RoleTableLayout, FrameRoleError> {
        let frames = self.allocator.initial_frames();
        let slots = usize::try_from(frames.div_ceil(GROWN_SLOT_PAGES))
            .ok()
            .and_then(|extra| ROLE_CAPACITY.checked_add(extra))
            .filter(|slots| u32::try_from(*slots).is_ok_and(|slots| slots < u32::MAX))
            .ok_or(FrameRoleError::Capacity)?;
        let starts = usize::try_from(frames).map_err(|_| FrameRoleError::Capacity)?;
        let bases = self.allocator.initial_range_count();
        let align = |offset: usize| offset.checked_next_multiple_of(8);
        let after = |offset: usize, count: usize, size: usize| {
            count
                .checked_mul(size)
                .and_then(|bytes| offset.checked_add(bytes))
                .and_then(align)
        };
        let starts_offset =
            after(0, slots, core::mem::size_of::<RoleSlot>()).ok_or(FrameRoleError::Capacity)?;
        let links_offset = after(starts_offset, starts, core::mem::size_of::<u32>())
            .ok_or(FrameRoleError::Capacity)?;
        let bases_offset = after(links_offset, starts, core::mem::size_of::<FreeLink>())
            .ok_or(FrameRoleError::Capacity)?;
        let hints = self.allocator.range_hint_count();
        let hints_offset = after(bases_offset, bases, core::mem::size_of::<u64>())
            .ok_or(FrameRoleError::Capacity)?;
        let tags_offset = after(hints_offset, hints, core::mem::size_of::<u32>())
            .ok_or(FrameRoleError::Capacity)?;
        let bytes = after(tags_offset, starts, core::mem::size_of::<u8>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(FrameRoleError::Capacity)?;
        Ok(RoleTableLayout {
            slots,
            starts_offset,
            starts,
            links_offset,
            bases_offset,
            bases,
            hints_offset,
            hints,
            tags_offset,
            bytes,
        })
    }

    /// Allocates an uninitialized run for the grown table while the boot
    /// allocator is in use (DW2 M7 §12.9): from the free range whose interior
    /// aligned to `align_pages` is longest, at most `max_pages` pages
    /// starting at its first aligned page (see
    /// `PhysicalFrameAllocator::allocate_largest_aligned`). Refused once the
    /// buddy allocator has taken over.
    pub(crate) fn allocate_largest_aligned(
        &mut self,
        max_pages: u64,
        align_pages: u64,
    ) -> Result<AllocationGrant, FrameRoleError> {
        let (slot, generation) = self.next_slot()?;
        let identity = self.identity(slot, generation)?;
        let range = self
            .allocator
            .allocate_largest_aligned(max_pages, align_pages)?;
        self.occupy(
            slot,
            generation,
            RoleRecord {
                range,
                role: FrameRole::AllocatedUninitialized,
            },
        );
        Ok(AllocationGrant { identity, range })
    }

    /// The runs staged so far, from the first on.
    fn staged_count(&self) -> usize {
        self.staged.iter().take_while(|part| part.is_some()).count()
    }

    /// Records the run `grant` names as the next piece of the grown table.
    /// Nothing uses it before [`Self::adopt_storage`]; the run keeps the
    /// role it was allocated with until then. Refuses, returning the grant
    /// and changing nothing, a full staging array (`Capacity`), and a grant
    /// that is not a live uninitialized allocation of this manager or any
    /// run once the table is grown (`WrongRole`).
    pub(crate) fn stage_growth_part(
        &mut self,
        grant: AllocationGrant,
    ) -> Result<(), GrantTransitionError<AllocationGrant>> {
        let index = self.staged_count();
        if self.roles.is_adopted() || self.starts.is_some() {
            return Err(GrantTransitionError::new(FrameRoleError::WrongRole, grant));
        }
        if index == MAX_GROWTH_PARTS {
            return Err(GrantTransitionError::new(FrameRoleError::Capacity, grant));
        }
        if let Err(error) = self.validate_allocation(&grant) {
            return Err(GrantTransitionError::new(error, grant));
        }
        self.staged[index] = Some(grant);
        Ok(())
    }

    /// Each staged run's physical start and pages, in staging order.
    pub(crate) fn staged_growth_parts(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.staged
            .iter()
            .map_while(Option::as_ref)
            .map(|grant| (grant.range.start, grant.range.page_count()))
    }

    /// Moves the role table into the staged runs, which `base` maps back to
    /// back in staging order, builds the start index there (DW2 M2 §5.3),
    /// and hands the allocator its buddy metadata there, which switches it to
    /// the buddy allocator (DW2 M7 §12.2). Slot numbers and generations are
    /// kept, so every issued identity stays valid. Every staged run takes the
    /// permanent `RoleTableStorage` role. Every check, the allocator's
    /// acceptance of the buddy storage included, happens before anything
    /// changes: the table is not grown, the staged runs hold exactly the
    /// layout's pages and are each still their uninitialized allocation, and
    /// `base` is 8-aligned. On an error the manager is as it was.
    ///
    /// # Safety
    ///
    /// `base` must be the start of a writable, 8-byte-aligned mapping of the
    /// staged runs back to back in staging order, used by nothing else for
    /// the rest of the kernel's life.
    #[allow(
        unsafe_code,
        reason = "the grown role table lives in RAM the caller maps; the manager carves typed slices from it"
    )]
    pub(crate) unsafe fn adopt_storage(&mut self, base: *mut u8) -> Result<(), FrameRoleError> {
        let layout = self.grown_layout()?;
        let staged = self.staged_count();
        let staged_pages = self.staged[..staged]
            .iter()
            .flatten()
            .try_fold(0_u64, |total, grant| {
                total.checked_add(grant.range.page_count())
            });
        let valid = !self.roles.is_adopted()
            && self.starts.is_none()
            && layout.slots > ROLE_CAPACITY
            && staged_pages == Some(layout.page_count())
            && self.staged[..staged]
                .iter()
                .flatten()
                .all(|grant| self.validate_allocation(grant).is_ok())
            && self.allocator.accepts_buddy_storage(
                layout.starts,
                layout.starts,
                layout.bases,
                layout.hints,
            )
            && (base as usize).is_multiple_of(8);
        if !valid {
            return Err(FrameRoleError::WrongRole);
        }
        // SAFETY: the caller maps the staged runs back to back at `base`,
        // writable and unused; they hold exactly the layout's pages, so every
        // part lies inside `layout.bytes`, at most their length, and starts
        // 8-aligned. Each part is fully written before a slice of it is made.
        let (slots, starts, buddy) = unsafe {
            (
                Self::carve(base, 0, layout.slots, EMPTY_ROLE_SLOT),
                Self::carve(base, layout.starts_offset, layout.starts, 0_u32),
                BuddyStorage {
                    links: Self::carve(base, layout.links_offset, layout.starts, FreeLink::EMPTY),
                    bases: Self::carve(base, layout.bases_offset, layout.bases, 0_u64),
                    hints: Self::carve(base, layout.hints_offset, layout.hints, 0_u32),
                    tags: Self::carve(base, layout.tags_offset, layout.starts, 0_u8),
                },
            )
        };
        for index in 0..staged {
            let (identity, range) = self.staged[index]
                .as_ref()
                .map(|grant| (grant.identity, grant.range))
                .expect("the staged runs are a prefix");
            let slot = self
                .slot(identity)
                .expect("a validated allocation has a live slot");
            self.replace_record(
                slot,
                RoleRecord {
                    range,
                    role: FrameRole::RoleTableStorage,
                },
            );
        }
        self.roles
            .adopt(slots, EMPTY_ROLE_SLOT)
            .unwrap_or_else(|_| panic!("the checked role table adoption failed"));
        // The new slots go on top of the free ones, lowest on top. The root
        // list needs nothing: it lives in the slots, which were copied.
        self.link_free_slots(ROLE_CAPACITY, layout.slots);
        self.allocator
            .adopt_buddy(buddy)
            .unwrap_or_else(|_| panic!("the checked buddy adoption failed"));
        self.starts = Some(starts);
        for slot in 0..self.roles.len() {
            if let Some(record) = self.record_at(slot) {
                self.set_start(record, slot);
            }
        }
        Ok(())
    }

    /// Writes `count` copies of `fill` at `base + offset` and returns them
    /// as a slice.
    ///
    /// # Safety
    ///
    /// `[base + offset, + count * size_of::<T>())` must be writable,
    /// aligned for `T`, unused by anything else, and live for ever.
    #[allow(
        unsafe_code,
        reason = "carves one typed part of the grown role table's run"
    )]
    unsafe fn carve<T: Copy>(
        base: *mut u8,
        offset: usize,
        count: usize,
        fill: T,
    ) -> &'static mut [T] {
        // SAFETY: the caller guarantees the range is writable, aligned for `T`,
        // unused and live for ever, so `count` writes and the slice stay in it.
        unsafe {
            let start = base.add(offset).cast::<T>();
            for index in 0..count {
                start.add(index).write(fill);
            }
            core::slice::from_raw_parts_mut(start, count)
        }
    }

    /// The start index position of `physical_start`, a page of allocator RAM.
    fn start_position(&self, physical_start: u64) -> Option<usize> {
        self.allocator.page_position(physical_start)
    }

    pub(super) fn set_start(&mut self, record: RoleRecord, slot: usize) {
        if !record.role.is_dynamic() {
            return;
        }
        let Some(position) = self.start_position(record.range.start) else {
            return;
        };
        if let Some(starts) = self.starts.as_deref_mut() {
            starts[position] = slot as u32 + 1;
        }
    }

    /// Clears the start index entry of a role that started at `start`;
    /// nothing for a role that is not `dynamic`.
    pub(super) fn clear_start(&mut self, start: u64, dynamic: bool) {
        if !dynamic {
            return;
        }
        let Some(position) = self.start_position(start) else {
            return;
        };
        if let Some(starts) = self.starts.as_deref_mut() {
            starts[position] = 0;
        }
    }

    /// The slot of the dynamic role starting at `physical_start`: through
    /// the start index once grown, by scanning the boot table before.
    pub(super) fn dynamic_slot_at(&self, physical_start: u64) -> Option<usize> {
        match self.starts.as_deref() {
            Some(starts) => {
                let position = self.start_position(physical_start)?;
                (starts[position] as usize).checked_sub(1)
            }
            None => self.slot_views().find_map(|(slot, view)| {
                view.record
                    .is_some_and(|record| {
                        record.role.is_dynamic() && record.range.start == physical_start
                    })
                    .then_some(slot)
            }),
        }
    }

    pub(crate) fn check_invariants(&self) -> Result<(), FrameRoleError> {
        let mut dynamic_pages = 0_u64;
        for (left_index, left) in self.slot_views() {
            let Some(left) = left.record else {
                continue;
            };
            for right in self
                .slot_views()
                .skip(left_index + 1)
                .filter_map(|(_, view)| view.record)
            {
                if left.range.overlaps(right.range) {
                    return Err(FrameRoleError::InvariantViolation);
                }
            }
            if left.role.is_dynamic() {
                if !self.allocator.contains_initial(left.range)
                    || self.allocator.overlaps_free(left.range)
                {
                    return Err(FrameRoleError::InvariantViolation);
                }
                dynamic_pages = dynamic_pages
                    .checked_add(left.range.page_count())
                    .ok_or(FrameRoleError::InvariantViolation)?;
            } else if self.allocator.overlaps_initial(left.range) {
                return Err(FrameRoleError::InvariantViolation);
            }
        }
        if self.allocator.available_frames().checked_add(dynamic_pages)
            != Some(self.allocator.initial_frames())
        {
            return Err(FrameRoleError::InvariantViolation);
        }
        self.allocator
            .check_buddy()
            .map_err(|_| FrameRoleError::InvariantViolation)?;
        self.check_storage()?;
        self.check_slot_lists()?;
        self.check_chains()?;
        self.check_indexes()
    }

    /// The staged runs are a prefix of the staging array. Before growth each
    /// is still its uninitialized allocation and no run holds the table's
    /// role. After it the runs holding the table's role are exactly the
    /// staged runs, which hold exactly the layout's pages.
    fn check_storage(&self) -> Result<(), FrameRoleError> {
        const VIOLATION: Result<(), FrameRoleError> = Err(FrameRoleError::InvariantViolation);
        let staged = self.staged_count();
        if self.staged[staged..].iter().any(Option::is_some) {
            return VIOLATION;
        }
        let storage_runs = self
            .slot_views()
            .filter(|(_, view)| {
                view.record
                    .is_some_and(|record| record.role == FrameRole::RoleTableStorage)
            })
            .count();
        let expected = match (self.roles.is_adopted(), self.starts.is_some()) {
            (false, false) if storage_runs == 0 => FrameRole::AllocatedUninitialized,
            (true, true) => {
                let pages = self
                    .staged_growth_parts()
                    .try_fold(0_u64, |total, (_, pages)| total.checked_add(pages));
                if storage_runs != staged
                    || self.grown_layout().map(|layout| layout.page_count()).ok() != pages
                {
                    return VIOLATION;
                }
                FrameRole::RoleTableStorage
            }
            (false, false) | (false, true) | (true, false) => return VIOLATION,
        };
        for grant in self.staged.iter().flatten() {
            let record = self
                .record(grant.identity)
                .map_err(|_| FrameRoleError::InvariantViolation)?;
            if record.range != grant.range || record.role != expected {
                return VIOLATION;
            }
        }
        Ok(())
    }
}
