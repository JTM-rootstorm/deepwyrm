//! The stored role slot (DW2 §12.3): packing a [`RoleRecord`] into a
//! [`RoleSlot`] and back, and the free list and root list threaded through
//! the slots. This module is the only code that reads or writes a slot's
//! fields or names [`StoredRole`].

use super::*;

impl StoredRole {
    /// The root-list link of a slot of PML4 level, or `None` on any other.
    const fn next_root(self) -> Option<u32> {
        match self {
            Self::RootCandidate { next_root, .. } | Self::Root { next_root, .. } => Some(next_root),
            Self::Free
            | Self::AllocatedUninitialized
            | Self::Zeroed
            | Self::BackingAllocated(_)
            | Self::ObjectBacking(_)
            | Self::ArchitectureBootstrap(_)
            | Self::TableCandidate { .. }
            | Self::PageTable { .. }
            | Self::External(_)
            | Self::ExternalImmutableModule { .. }
            | Self::ExternalDeviceMmio
            | Self::RoleTableStorage
            | Self::IndexRoot(_)
            | Self::IndexNode(_)
            | Self::ObjectPage(_) => None,
        }
    }

    /// The raw owner of a slot of PML4 level.
    const fn root_owner(self) -> Option<u64> {
        match self {
            Self::RootCandidate { owner, .. } | Self::Root { owner, .. } => Some(owner),
            Self::Free
            | Self::AllocatedUninitialized
            | Self::Zeroed
            | Self::BackingAllocated(_)
            | Self::ObjectBacking(_)
            | Self::ArchitectureBootstrap(_)
            | Self::TableCandidate { .. }
            | Self::PageTable { .. }
            | Self::External(_)
            | Self::ExternalImmutableModule { .. }
            | Self::ExternalDeviceMmio
            | Self::RoleTableStorage
            | Self::IndexRoot(_)
            | Self::IndexNode(_)
            | Self::ObjectPage(_) => None,
        }
    }

    /// The mark and the table count of a committed table.
    const fn committed_table(self) -> Option<(u64, u32)> {
        match self {
            Self::Root { mark, tables, .. } | Self::PageTable { mark, tables, .. } => {
                Some((mark, tables))
            }
            Self::Free
            | Self::AllocatedUninitialized
            | Self::Zeroed
            | Self::BackingAllocated(_)
            | Self::ObjectBacking(_)
            | Self::ArchitectureBootstrap(_)
            | Self::RootCandidate { .. }
            | Self::TableCandidate { .. }
            | Self::External(_)
            | Self::ExternalImmutableModule { .. }
            | Self::ExternalDeviceMmio
            | Self::RoleTableStorage
            | Self::IndexRoot(_)
            | Self::IndexNode(_)
            | Self::ObjectPage(_) => None,
        }
    }

    /// The mark and the table count of a committed table, to write.
    fn committed_table_mut(&mut self) -> Option<(&mut u64, &mut u32)> {
        match self {
            Self::Root { mark, tables, .. } | Self::PageTable { mark, tables, .. } => {
                Some((mark, tables))
            }
            Self::Free
            | Self::AllocatedUninitialized
            | Self::Zeroed
            | Self::BackingAllocated(_)
            | Self::ObjectBacking(_)
            | Self::ArchitectureBootstrap(_)
            | Self::RootCandidate { .. }
            | Self::TableCandidate { .. }
            | Self::External(_)
            | Self::ExternalImmutableModule { .. }
            | Self::ExternalDeviceMmio
            | Self::RoleTableStorage
            | Self::IndexRoot(_)
            | Self::IndexNode(_)
            | Self::ObjectPage(_) => None,
        }
    }

    /// Whether a slot holding this role is indexed by its start: the same
    /// truth table as [`FrameRole::is_dynamic`], false exactly for the
    /// three external roles.
    #[inline]
    const fn is_dynamic(self) -> bool {
        match self {
            Self::External(_) | Self::ExternalImmutableModule { .. } | Self::ExternalDeviceMmio => {
                false
            }
            Self::Free
            | Self::AllocatedUninitialized
            | Self::Zeroed
            | Self::BackingAllocated(_)
            | Self::ObjectBacking(_)
            | Self::ArchitectureBootstrap(_)
            | Self::RootCandidate { .. }
            | Self::TableCandidate { .. }
            | Self::Root { .. }
            | Self::PageTable { .. }
            | Self::RoleTableStorage
            | Self::IndexRoot(_)
            | Self::IndexNode(_)
            | Self::ObjectPage(_) => true,
        }
    }

    /// Rewrites the root-list link of a slot of PML4 level.
    fn set_next_root(&mut self, next: u32) {
        match self {
            Self::RootCandidate { next_root, .. } | Self::Root { next_root, .. } => {
                *next_root = next;
            }
            Self::Free
            | Self::AllocatedUninitialized
            | Self::Zeroed
            | Self::BackingAllocated(_)
            | Self::ObjectBacking(_)
            | Self::ArchitectureBootstrap(_)
            | Self::TableCandidate { .. }
            | Self::PageTable { .. }
            | Self::External(_)
            | Self::ExternalImmutableModule { .. }
            | Self::ExternalDeviceMmio
            | Self::RoleTableStorage
            | Self::IndexRoot(_)
            | Self::IndexNode(_)
            | Self::ObjectPage(_) => panic!("only a slot of PML4 level is on the root list"),
        }
    }

    /// Packs a role of this manager's `domain`. `counts` are the mark and
    /// table count a committed table keeps; `next_root` is the root-list
    /// link a slot of PML4 level takes. Each refusal is a kernel bug.
    fn pack(role: FrameRole, domain: u64, counts: (u64, u32), next_root: u32) -> Self {
        let owner_raw = |owner: TableOwnerKey| {
            assert!(
                owner.domain == domain,
                "a stored table owner belongs to another manager"
            );
            owner.raw
        };
        let (mark, tables) = counts;
        match role {
            FrameRole::AllocatedUninitialized => Self::AllocatedUninitialized,
            FrameRole::Zeroed => Self::Zeroed,
            FrameRole::BackingAllocated(link) => Self::BackingAllocated(link),
            FrameRole::ObjectBacking(link) => Self::ObjectBacking(link),
            FrameRole::ArchitectureBootstrap(kind) => Self::ArchitectureBootstrap(kind),
            FrameRole::TableCandidate {
                owner,
                level: TableLevel::Pml4,
            } => Self::RootCandidate {
                owner: owner_raw(owner),
                next_root,
            },
            FrameRole::TableCandidate { owner, level } => Self::TableCandidate {
                owner: owner_raw(owner),
                level,
            },
            FrameRole::PageTable {
                owner,
                level: TableLevel::Pml4,
                parent: None,
            } => Self::Root {
                owner: owner_raw(owner),
                mark,
                tables,
                next_root,
            },
            FrameRole::PageTable {
                level: TableLevel::Pml4,
                parent: Some(_),
                ..
            } => panic!("a stored PML4 has a parent table"),
            FrameRole::PageTable {
                owner,
                level,
                parent: Some(parent),
            } => {
                assert!(
                    parent.domain == domain,
                    "a stored parent table belongs to another manager"
                );
                Self::PageTable {
                    owner: owner_raw(owner),
                    parent: parent.raw,
                    mark,
                    tables,
                    level,
                }
            }
            FrameRole::PageTable { parent: None, .. } => {
                panic!("a stored table below a PML4 has no parent table")
            }
            FrameRole::External(role) => Self::External(role),
            FrameRole::ExternalImmutableModule { module_index } => {
                Self::ExternalImmutableModule { module_index }
            }
            FrameRole::ExternalDeviceMmio => Self::ExternalDeviceMmio,
            FrameRole::RoleTableStorage => Self::RoleTableStorage,
            FrameRole::IndexRoot(link) => Self::IndexRoot(link),
            FrameRole::IndexNode(link) => Self::IndexNode(link),
            FrameRole::ObjectPage(link) => Self::ObjectPage(link),
        }
    }

    /// The role this stores, with this manager's `domain` given back to
    /// owners and parents; `None` for a free slot.
    fn unpack(self, domain: u64) -> Option<FrameRole> {
        let key = |raw: u64| TableOwnerKey { domain, raw };
        Some(match self {
            Self::Free => return None,
            Self::AllocatedUninitialized => FrameRole::AllocatedUninitialized,
            Self::Zeroed => FrameRole::Zeroed,
            Self::BackingAllocated(link) => FrameRole::BackingAllocated(link),
            Self::ObjectBacking(link) => FrameRole::ObjectBacking(link),
            Self::ArchitectureBootstrap(kind) => FrameRole::ArchitectureBootstrap(kind),
            Self::RootCandidate { owner, .. } => FrameRole::TableCandidate {
                owner: key(owner),
                level: TableLevel::Pml4,
            },
            Self::TableCandidate { owner, level } => FrameRole::TableCandidate {
                owner: key(owner),
                level,
            },
            Self::Root { owner, .. } => FrameRole::PageTable {
                owner: key(owner),
                level: TableLevel::Pml4,
                parent: None,
            },
            Self::PageTable {
                owner,
                parent,
                level,
                ..
            } => FrameRole::PageTable {
                owner: key(owner),
                level,
                parent: Some(FrameRoleIdentity {
                    domain,
                    raw: parent,
                }),
            },
            Self::External(role) => FrameRole::External(role),
            Self::ExternalImmutableModule { module_index } => {
                FrameRole::ExternalImmutableModule { module_index }
            }
            Self::ExternalDeviceMmio => FrameRole::ExternalDeviceMmio,
            Self::RoleTableStorage => FrameRole::RoleTableStorage,
            Self::IndexRoot(link) => FrameRole::IndexRoot(link),
            Self::IndexNode(link) => FrameRole::IndexNode(link),
            Self::ObjectPage(link) => FrameRole::ObjectPage(link),
        })
    }
}

impl RoleSlot {
    /// The run a live slot holds: its start and page count.
    #[inline]
    fn run(&self) -> PageRange {
        PageRange {
            start: self.start,
            end: self.start + u64::from(self.pages) * BASE_PAGE_SIZE,
        }
    }
}

/// Whether `role` is of PML4 level: a PML4 candidate or a committed PML4.
const fn is_pml4_level(role: FrameRole) -> bool {
    matches!(
        role,
        FrameRole::TableCandidate {
            level: TableLevel::Pml4,
            ..
        } | FrameRole::PageTable {
            level: TableLevel::Pml4,
            ..
        }
    )
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>
{
    /// The generation of slot `slot` if it is live, from two fields: a live
    /// slot has at least one page. `None` for a free or retired slot and for
    /// a slot past the table.
    #[inline]
    pub(super) fn live_generation(&self, slot: usize) -> Option<u32> {
        self.roles
            .as_slice()
            .get(slot)
            .filter(|entry| entry.pages != 0)
            .map(|entry| entry.generation)
    }

    /// The record slot `slot` holds: one unpack of its role and range.
    #[inline]
    pub(super) fn record_at(&self, slot: usize) -> Option<RoleRecord> {
        let entry = self.roles.as_slice()[slot];
        entry.role.unpack(self.domain).map(|role| RoleRecord {
            range: PageRange {
                start: entry.start,
                end: entry.start + u64::from(entry.pages) * BASE_PAGE_SIZE,
            },
            role,
        })
    }

    /// The facts of a committed table of exactly one page in slot `slot`;
    /// `None` for any other slot. No [`FrameRole`] is built.
    #[inline]
    pub(super) fn table_at(&self, slot: usize) -> Option<TableFacts> {
        let entry = self.roles.as_slice()[slot];
        if entry.pages != 1 {
            return None;
        }
        match entry.role {
            StoredRole::Root {
                owner,
                mark,
                tables,
                ..
            } => Some(TableFacts {
                start: entry.start,
                owner,
                level: TableLevel::Pml4,
                parent: 0,
                mark,
                tables,
            }),
            StoredRole::PageTable {
                owner,
                parent,
                mark,
                tables,
                level,
            } => Some(TableFacts {
                start: entry.start,
                owner,
                level,
                parent,
                mark,
                tables,
            }),
            StoredRole::Free
            | StoredRole::AllocatedUninitialized
            | StoredRole::Zeroed
            | StoredRole::BackingAllocated(_)
            | StoredRole::ObjectBacking(_)
            | StoredRole::ArchitectureBootstrap(_)
            | StoredRole::RootCandidate { .. }
            | StoredRole::TableCandidate { .. }
            | StoredRole::External(_)
            | StoredRole::ExternalImmutableModule { .. }
            | StoredRole::ExternalDeviceMmio
            | StoredRole::RoleTableStorage
            | StoredRole::IndexRoot(_)
            | StoredRole::IndexNode(_)
            | StoredRole::ObjectPage(_) => None,
        }
    }

    /// The run of slot `slot` if it is live; `None` for a free or retired
    /// slot. No [`FrameRole`] is built.
    #[inline]
    pub(super) fn run_at(&self, slot: usize) -> Option<PageRange> {
        let entry = &self.roles.as_slice()[slot];
        match entry.role {
            StoredRole::Free => None,
            StoredRole::AllocatedUninitialized
            | StoredRole::Zeroed
            | StoredRole::BackingAllocated(_)
            | StoredRole::ObjectBacking(_)
            | StoredRole::ArchitectureBootstrap(_)
            | StoredRole::RootCandidate { .. }
            | StoredRole::TableCandidate { .. }
            | StoredRole::Root { .. }
            | StoredRole::PageTable { .. }
            | StoredRole::External(_)
            | StoredRole::ExternalImmutableModule { .. }
            | StoredRole::ExternalDeviceMmio
            | StoredRole::RoleTableStorage
            | StoredRole::IndexRoot(_)
            | StoredRole::IndexNode(_)
            | StoredRole::ObjectPage(_) => Some(entry.run()),
        }
    }

    /// Which kind of backing head slot `slot` holds; [`HeadKind::Other`]
    /// for any other role and for a free slot. No [`FrameRole`] is built.
    #[inline]
    pub(super) fn head_kind_at(&self, slot: usize) -> HeadKind {
        match self.roles.as_slice()[slot].role {
            StoredRole::ObjectBacking(_) => HeadKind::ObjectBacking,
            StoredRole::BackingAllocated(_) => HeadKind::BackingAllocated,
            StoredRole::ExternalDeviceMmio => HeadKind::DeviceMmio,
            StoredRole::ExternalImmutableModule { .. } => HeadKind::ImmutableModule,
            StoredRole::IndexRoot(_) => HeadKind::IndexRoot,
            StoredRole::Free
            | StoredRole::AllocatedUninitialized
            | StoredRole::Zeroed
            | StoredRole::ArchitectureBootstrap(_)
            | StoredRole::RootCandidate { .. }
            | StoredRole::TableCandidate { .. }
            | StoredRole::Root { .. }
            | StoredRole::PageTable { .. }
            | StoredRole::External(_)
            | StoredRole::RoleTableStorage
            | StoredRole::IndexNode(_)
            | StoredRole::ObjectPage(_) => HeadKind::Other,
        }
    }

    /// The facts of slot `slot` as a run of a chain: an allocator-owned
    /// run with its link, or an external backing. `None` for any other role
    /// and for a free slot. No [`FrameRole`] is built.
    #[inline]
    pub(super) fn chain_at(&self, slot: usize) -> Option<ChainFacts> {
        let entry = &self.roles.as_slice()[slot];
        let source = match entry.role {
            StoredRole::BackingAllocated(link) => ChainSource::Allocated(link),
            StoredRole::ObjectBacking(link) => ChainSource::Backing(link),
            StoredRole::ExternalImmutableModule { .. } => ChainSource::Module,
            StoredRole::ExternalDeviceMmio => ChainSource::Device,
            StoredRole::Free
            | StoredRole::AllocatedUninitialized
            | StoredRole::Zeroed
            | StoredRole::ArchitectureBootstrap(_)
            | StoredRole::RootCandidate { .. }
            | StoredRole::TableCandidate { .. }
            | StoredRole::Root { .. }
            | StoredRole::PageTable { .. }
            | StoredRole::External(_)
            | StoredRole::RoleTableStorage
            | StoredRole::IndexRoot(_)
            | StoredRole::IndexNode(_)
            | StoredRole::ObjectPage(_) => return None,
        };
        Some(ChainFacts {
            range: entry.run(),
            source,
        })
    }

    /// The run and link of slot `slot` if it holds the root of an
    /// on-demand backing; `None` otherwise. No [`FrameRole`] is built.
    #[inline]
    pub(super) fn index_root_at(&self, slot: usize) -> Option<(PageRange, IndexRootLink)> {
        let entry = &self.roles.as_slice()[slot];
        match entry.role {
            StoredRole::IndexRoot(link) => Some((entry.run(), link)),
            StoredRole::Free
            | StoredRole::AllocatedUninitialized
            | StoredRole::Zeroed
            | StoredRole::BackingAllocated(_)
            | StoredRole::ObjectBacking(_)
            | StoredRole::ArchitectureBootstrap(_)
            | StoredRole::RootCandidate { .. }
            | StoredRole::TableCandidate { .. }
            | StoredRole::Root { .. }
            | StoredRole::PageTable { .. }
            | StoredRole::External(_)
            | StoredRole::ExternalImmutableModule { .. }
            | StoredRole::ExternalDeviceMmio
            | StoredRole::RoleTableStorage
            | StoredRole::IndexNode(_)
            | StoredRole::ObjectPage(_) => None,
        }
    }

    /// The facts of slot `slot` if it holds an index node or a committed
    /// on-demand page; `None` otherwise. No [`FrameRole`] is built.
    #[inline]
    pub(super) fn index_entry_at(&self, slot: usize) -> Option<IndexEntryFacts> {
        let entry = &self.roles.as_slice()[slot];
        let (node, link) = match entry.role {
            StoredRole::IndexNode(link) => (true, link),
            StoredRole::ObjectPage(link) => (false, link),
            StoredRole::Free
            | StoredRole::AllocatedUninitialized
            | StoredRole::Zeroed
            | StoredRole::BackingAllocated(_)
            | StoredRole::ObjectBacking(_)
            | StoredRole::ArchitectureBootstrap(_)
            | StoredRole::RootCandidate { .. }
            | StoredRole::TableCandidate { .. }
            | StoredRole::Root { .. }
            | StoredRole::PageTable { .. }
            | StoredRole::External(_)
            | StoredRole::ExternalImmutableModule { .. }
            | StoredRole::ExternalDeviceMmio
            | StoredRole::RoleTableStorage
            | StoredRole::IndexRoot(_) => return None,
        };
        Some(IndexEntryFacts {
            range: entry.run(),
            node,
            link,
        })
    }

    /// Slot `slot`, unpacked.
    #[inline]
    pub(super) fn slot_view(&self, slot: usize) -> SlotView {
        Self::unpack_slot(self.roles.as_slice()[slot], self.domain)
    }

    /// Every slot, unpacked, for the scans that remain.
    pub(super) fn slot_views(&self) -> impl Iterator<Item = (usize, SlotView)> + '_ {
        self.roles
            .as_slice()
            .iter()
            .enumerate()
            .map(|(slot, entry)| (slot, Self::unpack_slot(*entry, self.domain)))
    }

    #[inline]
    fn unpack_slot(entry: RoleSlot, domain: u64) -> SlotView {
        let (mark, tables) = entry.role.committed_table().unwrap_or((0, 0));
        SlotView {
            generation: entry.generation,
            record: entry.role.unpack(domain).map(|role| RoleRecord {
                range: PageRange {
                    start: entry.start,
                    end: entry.start + u64::from(entry.pages) * BASE_PAGE_SIZE,
                },
                role,
            }),
            mark,
            tables,
        }
    }

    /// The one writer of a record (`occupy`, `replace_record` and `vacate`
    /// call it). It keeps three things right by comparing what the slot
    /// held with what it will hold: the mark and table count (kept while a
    /// committed table stays one, zero otherwise), the root list, and the
    /// free list (an occupied slot is popped from its head; a vacated one
    /// is pushed there unless its generation is spent).
    pub(super) fn store(&mut self, slot: usize, generation: u32, record: Option<RoleRecord>) {
        let old = self.roles.as_slice()[slot];
        let was_free = matches!(old.role, StoredRole::Free);
        let old_root = old.role.next_root();
        let becomes_root = record.is_some_and(|record| is_pml4_level(record.role));
        let slot_link = u32::try_from(slot)
            .ok()
            .and_then(|slot| slot.checked_add(1))
            .expect("a slot number fits the lists' links");
        let next_root = match (old_root, becomes_root) {
            (Some(next), true) => next,
            (None, true) => self.first_root,
            (Some(_) | None, false) => 0,
        };
        let stays_committed =
            record.is_some_and(|record| matches!(record.role, FrameRole::PageTable { .. }));
        let counts = if stays_committed {
            old.role.committed_table().unwrap_or((0, 0))
        } else {
            (0, 0)
        };
        let (pages, start, role) = match record {
            Some(record) => {
                let pages = u32::try_from(record.range.page_count())
                    .expect("a stored run has at most u32::MAX pages");
                assert!(pages != 0, "a stored run has at least one page");
                let role = StoredRole::pack(record.role, self.domain, counts, next_root);
                (pages, record.range.start, role)
            }
            None => (0, 0, StoredRole::Free),
        };

        // The root list.
        match (old_root.is_some(), becomes_root) {
            (false, true) => self.first_root = slot_link,
            (true, false) => self.unlink_root(slot_link),
            (true, true) | (false, false) => {}
        }
        // The free list.
        let start = match (was_free, record.is_some()) {
            (true, true) => {
                assert_eq!(
                    self.first_free, slot_link,
                    "slots are occupied from the head of the free list"
                );
                self.first_free =
                    u32::try_from(old.start).expect("a free slot links to a slot number");
                self.free_slot_count = self
                    .free_slot_count
                    .checked_sub(1)
                    .expect("an occupied slot came from the free list");
                start
            }
            (false, false) if generation == u32::MAX => 0,
            (false, false) => {
                let next = self.first_free;
                self.first_free = slot_link;
                self.free_slot_count += 1;
                u64::from(next)
            }
            (false, true) => start,
            (true, false) => panic!("a vacated slot was live"),
        };
        self.roles.as_mut_slice()[slot] = RoleSlot {
            generation,
            pages,
            start,
            role,
        };
    }

    /// Publishes `record` in the free slot `slot`, which must be the head of
    /// the free list (DW2 §12.6 item 3). A role of PML4 level goes through
    /// [`Self::store`], which keeps the root list; any other is written in
    /// place: the slot is popped from the free list and its four fields
    /// written, leaving exactly what `store` would.
    #[inline]
    pub(super) fn occupy_slot(&mut self, slot: usize, generation: u32, record: RoleRecord) {
        if is_pml4_level(record.role) {
            self.store(slot, generation, Some(record));
            return;
        }
        let slot_link = u32::try_from(slot)
            .ok()
            .and_then(|slot| slot.checked_add(1))
            .expect("a slot number fits the lists' links");
        let pages = u32::try_from(record.range.page_count())
            .expect("a stored run has at most u32::MAX pages");
        assert!(pages != 0, "a stored run has at least one page");
        // Not of PML4 level, and the slot was free: no root-list link, and
        // no mark or table count to keep.
        let role = StoredRole::pack(record.role, self.domain, (0, 0), 0);
        let entry = &mut self.roles.as_mut_slice()[slot];
        assert!(
            matches!(entry.role, StoredRole::Free),
            "an occupied slot was free"
        );
        assert_eq!(
            self.first_free, slot_link,
            "slots are occupied from the head of the free list"
        );
        self.first_free = u32::try_from(entry.start).expect("a free slot links to a slot number");
        self.free_slot_count = self
            .free_slot_count
            .checked_sub(1)
            .expect("an occupied slot came from the free list");
        entry.generation = generation;
        entry.pages = pages;
        entry.start = record.range.start;
        entry.role = role;
    }

    /// Empties the live slot `slot` (DW2 §12.6 item 3) and returns the start
    /// of the run it held and whether its role was dynamic, for the start
    /// index. A slot of PML4 level goes through [`Self::store`], which keeps
    /// the root list; any other is written in place: emptied, and pushed on
    /// the free list unless its generation is spent, leaving exactly what
    /// `store` would.
    #[inline]
    pub(super) fn vacate_slot(&mut self, slot: usize) -> (u64, bool) {
        let entry = self.roles.as_slice()[slot];
        assert!(entry.pages != 0, "a vacated slot was live");
        if entry.role.next_root().is_some() {
            let record = self.record_at(slot).expect("a vacated slot was live");
            self.store(slot, entry.generation, None);
            return (record.range.start, record.role.is_dynamic());
        }
        let slot_link = u32::try_from(slot)
            .ok()
            .and_then(|slot| slot.checked_add(1))
            .expect("a slot number fits the lists' links");
        let next = if entry.generation == u32::MAX {
            // Spent: retired, on no list.
            0
        } else {
            let next = self.first_free;
            self.first_free = slot_link;
            self.free_slot_count += 1;
            u64::from(next)
        };
        let stored = &mut self.roles.as_mut_slice()[slot];
        stored.pages = 0;
        stored.start = next;
        stored.role = StoredRole::Free;
        (entry.start, entry.role.is_dynamic())
    }

    /// Removes the slot whose link is `target` from the root list.
    fn unlink_root(&mut self, target: u32) {
        let slots = self.roles.as_mut_slice();
        let next = slots[target as usize - 1]
            .role
            .next_root()
            .expect("a slot of PML4 level is on the root list");
        if self.first_root == target {
            self.first_root = next;
            return;
        }
        let mut current = self.first_root;
        for _ in 0..slots.len() {
            let index = (current as usize)
                .checked_sub(1)
                .expect("a slot of PML4 level is on the root list");
            let after = slots[index]
                .role
                .next_root()
                .expect("the root list holds only slots of PML4 level");
            if after == target {
                slots[index].role.set_next_root(next);
                return;
            }
            current = after;
        }
        panic!("the root list is longer than the role table");
    }

    /// The slots on the root list, from its head; the walk stops after as
    /// many steps as there are slots.
    fn root_slots(&self) -> impl Iterator<Item = usize> + '_ {
        let slots = self.roles.as_slice();
        let mut current = self.first_root;
        let mut steps = 0;
        core::iter::from_fn(move || {
            if current == 0 || steps >= slots.len() {
                return None;
            }
            steps += 1;
            let slot = current as usize - 1;
            current = slots.get(slot)?.role.next_root().unwrap_or(0);
            Some(slot)
        })
    }

    /// Whether a slot of PML4 level other than `except` belongs to `owner`.
    pub(super) fn has_other_root(&self, owner: TableOwnerKey, except: usize) -> bool {
        owner.domain == self.domain
            && self.root_slots().any(|slot| {
                slot != except && self.roles.as_slice()[slot].role.root_owner() == Some(owner.raw)
            })
    }

    /// Writes the proof mark of a committed table.
    pub(super) fn set_mark(&mut self, slot: usize, epoch: u64) {
        let (mark, _) = self.roles.as_mut_slice()[slot]
            .role
            .committed_table_mut()
            .expect("only a committed table carries a proof mark");
        *mark = epoch;
    }

    /// Writes the table count of a committed table.
    pub(super) fn set_tables(&mut self, slot: usize, count: u32) {
        let (_, tables) = self.roles.as_mut_slice()[slot]
            .role
            .committed_table_mut()
            .expect("only a committed table carries a table count");
        *tables = count;
    }

    /// The free slot `depth` links after the head of the free list, with
    /// the generation it would take. Changes nothing.
    pub(super) fn free_slot(&self, depth: usize) -> Result<(usize, u32), FrameRoleError> {
        if depth >= self.free_slot_count {
            return Err(FrameRoleError::Capacity);
        }
        let slots = self.roles.as_slice();
        let free_entry = |link: u32| {
            let slot = (link as usize)
                .checked_sub(1)
                .ok_or(FrameRoleError::InvariantViolation)?;
            let entry = slots.get(slot).ok_or(FrameRoleError::InvariantViolation)?;
            if !matches!(entry.role, StoredRole::Free) {
                return Err(FrameRoleError::InvariantViolation);
            }
            Ok((slot, entry))
        };
        let mut link = self.first_free;
        for _ in 0..depth {
            let (_, entry) = free_entry(link)?;
            link = u32::try_from(entry.start).map_err(|_| FrameRoleError::InvariantViolation)?;
        }
        let (slot, entry) = free_entry(link)?;
        let generation = entry
            .generation
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(FrameRoleError::GenerationExhausted)?;
        Ok((slot, generation))
    }

    /// Links every boot slot onto the free list, slot 0 at its head.
    pub(super) fn fill_boot_free_slots(&mut self) -> Result<(), FrameRoleError> {
        u32::try_from(ROLE_CAPACITY)
            .ok()
            .filter(|capacity| *capacity < u32::MAX)
            .ok_or(FrameRoleError::Capacity)?;
        self.first_free = 0;
        self.free_slot_count = 0;
        self.link_free_slots(0, ROLE_CAPACITY);
        Ok(())
    }

    /// Links the free slots `first..end` on top of the free list, lowest at
    /// its head. Every slot number below `end` fits a link.
    pub(super) fn link_free_slots(&mut self, first: usize, end: usize) {
        for slot in (first..end).rev() {
            let entry = &mut self.roles.as_mut_slice()[slot];
            entry.start = u64::from(self.first_free);
            self.first_free = slot as u32 + 1;
        }
        self.free_slot_count += end - first;
    }

    /// The free list reaches exactly the free slots whose generation is not
    /// spent, each once, and `free_slot_count` is its length. The root list
    /// reaches exactly the slots of PML4 level, each once. No owner has two
    /// slots on the root list.
    pub(super) fn check_slot_lists(&self) -> Result<(), FrameRoleError> {
        let slots = self.roles.as_slice();
        // A walk longer than the table has a cycle; a walk that visits only
        // eligible slots, with no cycle, as many as there are, visits each
        // once.
        let mut reached = 0_usize;
        let mut link = self.first_free;
        while link != 0 {
            let entry = slots
                .get(link as usize - 1)
                .filter(|entry| {
                    matches!(entry.role, StoredRole::Free)
                        && entry.pages == 0
                        && entry.generation != u32::MAX
                })
                .ok_or(FrameRoleError::InvariantViolation)?;
            reached += 1;
            if reached > slots.len() {
                return Err(FrameRoleError::InvariantViolation);
            }
            link = u32::try_from(entry.start).map_err(|_| FrameRoleError::InvariantViolation)?;
        }
        let free = slots
            .iter()
            .filter(|entry| matches!(entry.role, StoredRole::Free) && entry.generation != u32::MAX)
            .count();
        if reached != free || reached != self.free_slot_count {
            return Err(FrameRoleError::InvariantViolation);
        }

        let mut reached = 0_usize;
        let mut link = self.first_root;
        while link != 0 {
            let entry = slots
                .get(link as usize - 1)
                .ok_or(FrameRoleError::InvariantViolation)?;
            reached += 1;
            if reached > slots.len() {
                return Err(FrameRoleError::InvariantViolation);
            }
            link = entry
                .role
                .next_root()
                .ok_or(FrameRoleError::InvariantViolation)?;
        }
        let roots = slots
            .iter()
            .filter(|entry| entry.role.next_root().is_some())
            .count();
        if reached != roots {
            return Err(FrameRoleError::InvariantViolation);
        }
        for (position, slot) in self.root_slots().enumerate() {
            let owner = slots[slot].role.root_owner();
            if self
                .root_slots()
                .skip(position + 1)
                .any(|other| slots[other].role.root_owner() == owner)
            {
                return Err(FrameRoleError::InvariantViolation);
            }
        }
        Ok(())
    }
}

/// Writes that only a test makes: a generation driven to its end, and the
/// faults the invariant checks must catch.
#[cfg(test)]
impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>
{
    pub(super) fn test_set_generation(&mut self, slot: usize, generation: u32) {
        self.roles.as_mut_slice()[slot].generation = generation;
    }

    /// Rewrites a free slot's link (the next free slot plus one).
    pub(super) fn test_set_free_link(&mut self, slot: usize, link: u64) {
        let entry = &mut self.roles.as_mut_slice()[slot];
        assert!(matches!(entry.role, StoredRole::Free));
        entry.start = link;
    }

    /// Rewrites a root-list link (the next slot of PML4 level plus one).
    pub(super) fn test_set_root_link(&mut self, slot: usize, link: u32) {
        self.roles.as_mut_slice()[slot].role.set_next_root(link);
    }

    /// Rewrites the raw owner of a slot of PML4 level.
    pub(super) fn test_set_root_owner(&mut self, slot: usize, raw: u64) {
        match &mut self.roles.as_mut_slice()[slot].role {
            StoredRole::RootCandidate { owner, .. } | StoredRole::Root { owner, .. } => {
                *owner = raw;
            }
            StoredRole::Free
            | StoredRole::AllocatedUninitialized
            | StoredRole::Zeroed
            | StoredRole::BackingAllocated(_)
            | StoredRole::ObjectBacking(_)
            | StoredRole::ArchitectureBootstrap(_)
            | StoredRole::TableCandidate { .. }
            | StoredRole::PageTable { .. }
            | StoredRole::External(_)
            | StoredRole::ExternalImmutableModule { .. }
            | StoredRole::ExternalDeviceMmio
            | StoredRole::RoleTableStorage
            | StoredRole::IndexRoot(_)
            | StoredRole::IndexNode(_)
            | StoredRole::ObjectPage(_) => panic!("not a slot of PML4 level"),
        }
    }
}
