use super::super::{MapError, MappingPermissions, PageTableRoot};
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum X86AddressSpacePublishError<E> {
    Identity,
    InvalidMapping,
    Capacity,
    FrameRole(FrameRoleError),
    Map(MapError<OwnedPageTableJournalError<E>>),
    Journal(OwnedPageTableJournalError<E>),
}

impl<E> X86AddressSpacePublishError<E> {
    /// Distinguishes bounded publisher-resource exhaustion from invalid
    /// authority, identity, or page-table state for the syscall boundary.
    pub(crate) const fn is_capacity_error(&self) -> bool {
        matches!(
            self,
            Self::Capacity
                | Self::Journal(OwnedPageTableJournalError::JournalCapacity)
                | Self::Map(MapError::InsufficientTableFrames)
                | Self::Map(MapError::Access(
                    OwnedPageTableJournalError::JournalCapacity
                ))
        )
    }

    /// Names which bounded publisher resource was exhausted.
    ///
    /// F3A.6w. `is_capacity_error` answers the *status* question with a bool,
    /// which is correct for choosing `NO_RESOURCES` and useless to a reader:
    /// it erases which of four distinct walls was hit before the status is even
    /// chosen. The production Wyrmroot bootstrap fails on that status while
    /// mapping bootfs, and the transcript could not say which. The bool still
    /// decides the status; this names the instance for the diagnostic channel,
    /// per `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` §3.2.
    ///
    /// Exhaustive over `Self` so a new variant must decide whether it is a
    /// capacity failure rather than inheriting `None`.
    pub(crate) const fn capacity_resource(&self) -> Option<&'static str> {
        match self {
            Self::Capacity => Some("publisher-slots"),
            Self::Journal(OwnedPageTableJournalError::JournalCapacity) => {
                Some("page-table-journal")
            }
            Self::Map(MapError::InsufficientTableFrames) => Some("page-table-frames"),
            Self::Map(MapError::Access(OwnedPageTableJournalError::JournalCapacity)) => {
                Some("page-table-journal-access")
            }
            Self::Identity
            | Self::InvalidMapping
            | Self::FrameRole(_)
            | Self::Map(_)
            | Self::Journal(_) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PageDescriptor {
    backing: BackingIdentity,
    /// Two descriptors with the same backing and object offset name the
    /// same page, however many runs the backing has (DW2 M3 §6.4).
    object_offset: u64,
    /// `None` when the backing is on demand and the page has no frame yet.
    physical_start: Option<u64>,
    /// The backing is on demand: a committed page may still have no leaf
    /// in this address space (DW2 M6 §8.6).
    on_demand: bool,
    permissions: MappingPermissions,
}

/// One page as it stands in this address space's tables.
#[derive(Clone, Copy)]
struct Leaf {
    backing: BackingIdentity,
    object_offset: u64,
    physical_start: u64,
    permissions: MappingPermissions,
}

impl Leaf {
    const fn of(descriptor: PageDescriptor, physical_start: u64) -> Self {
        Self {
            backing: descriptor.backing,
            object_offset: descriptor.object_offset,
            physical_start,
            permissions: descriptor.permissions,
        }
    }
}

/// Sealed `AddressRegion` bridge for one typed x86 page-table root and region.
pub(crate) struct X86AddressSpacePublisher<
    'a,
    T,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
    const CANDIDATE_CAPACITY: usize,
    const ENTRY_CAPACITY: usize,
    const INVALIDATION_CAPACITY: usize,
> {
    address_space: AddressSpaceKey,
    region: RegionKey,
    root: &'a PageTableRoot,
    root_identity: TableIdentity,
    roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    pub(super) target: &'a mut T,
    candidates: &'a mut [Option<TableCandidateGrant>; CANDIDATE_CAPACITY],
    storage: &'a mut JournalStorage<ENTRY_CAPACITY, INVALIDATION_CAPACITY>,
    /// The target holds the call's changed span against user pins.
    span_held: bool,
    /// The last publish failed after publishing and undoing batches.
    reverted: bool,
}

impl<
    'a,
    T,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
    const CANDIDATE_CAPACITY: usize,
    const ENTRY_CAPACITY: usize,
    const INVALIDATION_CAPACITY: usize,
>
    X86AddressSpacePublisher<
        'a,
        T,
        RANGE_CAPACITY,
        ROLE_CAPACITY,
        CANDIDATE_CAPACITY,
        ENTRY_CAPACITY,
        INVALIDATION_CAPACITY,
    >
where
    T: AtomicPageTableTarget,
{
    #[allow(
        dead_code,
        reason = "the live AddressRegion owner constructs this bridge after the temporary mapper lands"
    )]
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor binds every independent authority identity and fixed-capacity resource"
    )]
    /// Binds portable address-space identities to one architecture root.
    ///
    /// # Safety
    ///
    /// `address_space` and `region` must be authority-issued identities for
    /// the exact address space represented by `root` and `root_identity`.
    /// `target` must serialize and publish the hierarchy rooted at that exact
    /// `root` in the same authority domain; a target locked to any other root
    /// or serialization domain is invalid. That root must have
    /// `root_identity.owner()` as its exclusive table owner, and no other
    /// publisher may mutate it for this publisher's lifetime. The authority
    /// and role manager must outlive every issued identity.
    ///
    /// Candidate grants selected from `candidates` are dynamically validated
    /// against `root_identity.owner()` and their required levels before target
    /// publication. Unrelated grants may remain in the pool, but are ignored
    /// and must not be treated as belonging to this root. These root/target
    /// relationships are not yet represented by one mechanically checked
    /// binding token.
    #[allow(
        unsafe_code,
        reason = "address-space keys cannot yet mechanically prove their exact architecture-root binding"
    )]
    pub(crate) unsafe fn new(
        address_space: AddressSpaceKey,
        region: RegionKey,
        root: &'a PageTableRoot,
        root_identity: TableIdentity,
        roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
        target: &'a mut T,
        candidates: &'a mut [Option<TableCandidateGrant>; CANDIDATE_CAPACITY],
        storage: &'a mut JournalStorage<ENTRY_CAPACITY, INVALIDATION_CAPACITY>,
    ) -> Result<Self, X86AddressSpacePublishError<T::Error>> {
        if !address_space.same_domain(region)
            || root.frame().address() != root_identity.physical_start()
            || root_identity.level() != TableLevel::Pml4
        {
            return Err(X86AddressSpacePublishError::Identity);
        }
        roles
            .validate_table_identity(root_identity)
            .map_err(X86AddressSpacePublishError::FrameRole)?;
        Ok(Self {
            address_space,
            region,
            root,
            root_identity,
            roles,
            target,
            candidates,
            storage,
            span_held: false,
            reverted: false,
        })
    }

    /// Publishes the change from `before` to `after`. A change too large
    /// for one journal is published in batches, each a complete journal, in
    /// address order (DW2 M4). Between batches the table-candidate pool is
    /// refilled to what it held at the start, and the whole changed span is
    /// held against new user pins. If a later batch or a refill fails, the
    /// batches already published are undone, newest state first, so the call
    /// changes nothing it returns an error for; `failed_after_publishing`
    /// then tells the coherency layer that other CPUs may still cache the
    /// undone entries.
    /// Publishes the one leaf a touch at `address` needs (DW2 M6 §8.5):
    /// the committed frame of the on-demand page `mapping` maps there, with
    /// the mapping's protection. It is valid only while the leaf is empty:
    /// empty to present needs no shootdown and changes no pinned
    /// translation. `Ok(false)` when the leaf already maps that frame, as
    /// after another CPU's touch.
    /// How many page tables publishing a leaf at `address` would build
    /// (DW2 M6 §8.4), so a caller can admit them before taking candidates.
    #[cfg_attr(
        not(all(target_os = "none", target_arch = "x86_64")),
        allow(
            dead_code,
            reason = "the live fault gate is its only caller outside tests"
        )
    )]
    pub(crate) fn touch_table_cost(
        &mut self,
        address: u64,
    ) -> Result<usize, X86AddressSpacePublishError<T::Error>> {
        let page =
            VirtualPage::new(address).map_err(|_| X86AddressSpacePublishError::InvalidMapping)?;
        let mut journal = OwnedPageTableJournal::<
            _,
            RANGE_CAPACITY,
            ROLE_CAPACITY,
            CANDIDATE_CAPACITY,
            ENTRY_CAPACITY,
            INVALIDATION_CAPACITY,
        >::new(
            self.target,
            self.storage,
            self.roles,
            self.root_identity,
            self.root.physical_limit(),
            self.candidates,
        )
        .map_err(X86AddressSpacePublishError::FrameRole)?;
        self.root
            .missing_tables(&mut journal, page)
            .map_err(X86AddressSpacePublishError::Map)
    }

    #[cfg_attr(
        not(all(target_os = "none", target_arch = "x86_64")),
        allow(
            dead_code,
            reason = "the live fault gate is its only caller outside tests"
        )
    )]
    pub(crate) fn publish_touched_leaf(
        &mut self,
        mapping: &Mapping,
        address: u64,
    ) -> Result<bool, X86AddressSpacePublishError<T::Error>> {
        validate_mapping_batch(
            self.roles,
            self.address_space,
            self.region,
            core::slice::from_ref(mapping),
        )?;
        if !address.is_multiple_of(BASE_PAGE_SIZE)
            || address < mapping.virtual_start()
            || address - mapping.virtual_start() >= mapping.byte_len()
        {
            return Err(X86AddressSpacePublishError::InvalidMapping);
        }
        let page =
            VirtualPage::new(address).map_err(|_| X86AddressSpacePublishError::InvalidMapping)?;
        let mut journal = OwnedPageTableJournal::<
            _,
            RANGE_CAPACITY,
            ROLE_CAPACITY,
            CANDIDATE_CAPACITY,
            ENTRY_CAPACITY,
            INVALIDATION_CAPACITY,
        >::new(
            self.target,
            self.storage,
            self.roles,
            self.root_identity,
            self.root.physical_limit(),
            self.candidates,
        )
        .map_err(X86AddressSpacePublishError::FrameRole)?;
        let descriptor = page_descriptor(journal.roles(), mapping, address, &mut None)?;
        if !descriptor.on_demand {
            return Err(X86AddressSpacePublishError::InvalidMapping);
        }
        let physical_start =
            descriptor
                .physical_start
                .ok_or(X86AddressSpacePublishError::FrameRole(
                    FrameRoleError::Absent,
                ))?;
        match self
            .root
            .present_leaf(&mut journal, page)
            .map_err(X86AddressSpacePublishError::Map)?
        {
            Some(frame) if frame.address() == physical_start => return Ok(false),
            Some(_) => return Err(X86AddressSpacePublishError::Map(MapError::FrameMismatch)),
            None => {}
        }
        journal
            .authorize_leaf(descriptor.backing, descriptor.object_offset, physical_start)
            .map_err(X86AddressSpacePublishError::Journal)?;
        let (candidates, count) = journal
            .candidate_addresses_for_page(self.root, page)
            .map_err(X86AddressSpacePublishError::Journal)?;
        if let Err(error) = self.root.map_page(
            &mut journal,
            page,
            physical_start,
            descriptor.permissions,
            &candidates[..count],
        ) {
            journal.clear_leaf_authorization();
            return Err(X86AddressSpacePublishError::Map(error));
        }
        journal
            .publish()
            .map_err(X86AddressSpacePublishError::Journal)?;
        Ok(true)
    }

    fn publish_pages(
        &mut self,
        before: &[Mapping],
        after: &[Mapping],
    ) -> Result<(), X86AddressSpacePublishError<T::Error>> {
        self.reverted = false;
        validate_mapping_batch(self.roles, self.address_space, self.region, before)?;
        validate_mapping_batch(self.roles, self.address_space, self.region, after)?;
        let span = changed_span(self.roles, before, after)?;
        let pool = self.candidate_counts();
        let first = first_mapping_start(before, after);
        let result = self.publish_batches(before, after, first, span, pool);
        if self.span_held {
            self.target.end_mutation_span();
            self.span_held = false;
        }
        result
    }

    fn publish_batches(
        &mut self,
        before: &[Mapping],
        after: &[Mapping],
        first: Option<u64>,
        span: Option<(u64, u64)>,
        pool: [(TableLevel, usize); 3],
    ) -> Result<(), X86AddressSpacePublishError<T::Error>> {
        let mut from = first;
        let mut published_to = None;
        loop {
            let next = match self.publish_batch(before, after, from, u64::MAX, span) {
                Ok(None) => return Ok(()),
                Ok(Some(next)) => next,
                Err(error) => {
                    if let Some(published_to) = published_to {
                        self.undo(before, after, first, published_to);
                    }
                    return Err(error);
                }
            };
            published_to = Some(next);
            if let Err(error) = self.refill_candidates(pool) {
                self.undo(before, after, first, next);
                return Err(error);
            }
            from = Some(next);
        }
    }

    /// Restores `before` below `published_to` after a later batch failed.
    /// The reverse change only rewrites leaves under tables the forward
    /// batches left in place, inside the span still held against pins, so
    /// it needs no candidates and nothing userspace does can refuse it.
    fn undo(
        &mut self,
        before: &[Mapping],
        after: &[Mapping],
        first: Option<u64>,
        published_to: u64,
    ) {
        self.reverted = true;
        let mut from = first;
        loop {
            match self.publish_batch(after, before, from, published_to, None) {
                Ok(None) => return,
                Ok(Some(next)) => from = Some(next),
                Err(_) => panic!("a mapping published in batches could not be undone"),
            }
        }
    }

    /// Publishes, in one journal, the changed pages from `from` up to `end`
    /// that fit. `Some(address)`: the batch stopped before `address`, the
    /// first page it did not publish; every changed page below it is
    /// published. Before publishing a batch that stops early, the whole
    /// `span` is closed to user pins.
    fn publish_batch(
        &mut self,
        before: &[Mapping],
        after: &[Mapping],
        from: Option<u64>,
        end: u64,
        span: Option<(u64, u64)>,
    ) -> Result<Option<u64>, X86AddressSpacePublishError<T::Error>> {
        let mut journal = OwnedPageTableJournal::<
            _,
            RANGE_CAPACITY,
            ROLE_CAPACITY,
            CANDIDATE_CAPACITY,
            ENTRY_CAPACITY,
            INVALIDATION_CAPACITY,
        >::new(
            self.target,
            self.storage,
            self.roles,
            self.root_identity,
            self.root.physical_limit(),
            self.candidates,
        )
        .map_err(X86AddressSpacePublishError::FrameRole)?;

        let mut cursor = from;
        let mut staged = 0_usize;
        let mut stopped = None;
        // Places in the old and new backings' chains: addresses only grow,
        // so each mapping costs one chain walk (DW2 M3 review D1).
        let mut old_run = None;
        let mut new_run = None;
        'pages: while let Some(address) = cursor {
            if address >= end {
                break;
            }
            let old = mapping_at(before, address)?;
            let new = mapping_at(after, address)?;
            if old.is_none() && new.is_none() {
                cursor = next_mapping_start(before, after, address);
                continue;
            }
            let boundary = next_boundary(before, after, address, old, new)?.min(end);
            // Two linear mappings that agree at one page agree on the whole
            // stretch, so a batch may start mid-stretch.
            let old_page = match old {
                Some(mapping) => Some(page_descriptor(
                    journal.roles(),
                    mapping,
                    address,
                    &mut old_run,
                )?),
                None => None,
            };
            let new_page = match new {
                Some(mapping) => Some(page_descriptor(
                    journal.roles(),
                    mapping,
                    address,
                    &mut new_run,
                )?),
                None => None,
            };
            if old_page == new_page {
                cursor = (boundary != u64::MAX).then_some(boundary);
                continue;
            }

            let mut page_address = address;
            while page_address < boundary {
                if !journal.has_room_for_page() {
                    stopped = Some(page_address);
                    break 'pages;
                }
                let old_page = match old {
                    Some(mapping) => Some(page_descriptor(
                        journal.roles(),
                        mapping,
                        page_address,
                        &mut old_run,
                    )?),
                    None => None,
                };
                let new_page = match new {
                    Some(mapping) => Some(page_descriptor(
                        journal.roles(),
                        mapping,
                        page_address,
                        &mut new_run,
                    )?),
                    None => None,
                };
                match publish_page(self.root, &mut journal, page_address, old_page, new_page) {
                    // The table pool ran out. A page stages all or nothing,
                    // so publish what is staged and continue from this page
                    // with the pool refilled. A page that an empty journal
                    // and a full pool cannot take is a real failure.
                    Err(X86AddressSpacePublishError::Map(MapError::InsufficientTableFrames))
                        if staged != 0 =>
                    {
                        stopped = Some(page_address);
                        break 'pages;
                    }
                    result => result?,
                }
                staged += 1;
                page_address = page_address
                    .checked_add(BASE_PAGE_SIZE)
                    .ok_or(X86AddressSpacePublishError::InvalidMapping)?;
            }
            cursor = (boundary != u64::MAX).then_some(boundary);
        }
        if stopped.is_some()
            && !self.span_held
            && let Some((start, byte_len)) = span
        {
            journal
                .target_mut()
                .begin_mutation_span(start, byte_len)
                .map_err(|error| {
                    X86AddressSpacePublishError::Journal(OwnedPageTableJournalError::Target(error))
                })?;
            self.span_held = true;
        }
        journal
            .publish()
            .map_err(X86AddressSpacePublishError::Journal)?;
        Ok(stopped)
    }

    /// How many of this root's candidates the pool holds at each level.
    fn candidate_counts(&self) -> [(TableLevel, usize); 3] {
        let owner = self.root_identity.owner();
        [TableLevel::Pdpt, TableLevel::Pd, TableLevel::Pt].map(|level| {
            let count = self
                .candidates
                .iter()
                .flatten()
                .filter(|candidate| candidate.owner() == owner && candidate.level() == level)
                .count();
            (level, count)
        })
    }

    /// Tops the pool back up to `wanted` at each level.
    fn refill_candidates(
        &mut self,
        wanted: [(TableLevel, usize); 3],
    ) -> Result<(), X86AddressSpacePublishError<T::Error>> {
        let have = self.candidate_counts();
        for ((level, want), (_, mut count)) in wanted.into_iter().zip(have) {
            while count < want {
                let slot = self
                    .candidates
                    .iter()
                    .position(Option::is_none)
                    .ok_or(X86AddressSpacePublishError::Capacity)?;
                self.candidates[slot] = Some(self.prepare_candidate(level)?);
                count += 1;
            }
        }
        Ok(())
    }

    /// One zeroed table candidate for this root, as the live session
    /// prepares them. No frame left is `InsufficientTableFrames`, as when
    /// the caller's pool is too small.
    #[allow(
        unsafe_code,
        reason = "the target's zero_table_frame contract makes the frame zero before the role manager is told so"
    )]
    fn prepare_candidate(
        &mut self,
        level: TableLevel,
    ) -> Result<TableCandidateGrant, X86AddressSpacePublishError<T::Error>> {
        let allocation = self
            .roles
            .allocate(1)
            .map_err(|_| X86AddressSpacePublishError::Map(MapError::InsufficientTableFrames))?;
        let zeroed = FrameAddress::new(allocation.physical_start(), self.root.physical_limit())
            .map_err(|_| X86AddressSpacePublishError::InvalidMapping)
            .and_then(|frame| {
                self.target.zero_table_frame(frame).map_err(|error| {
                    X86AddressSpacePublishError::Journal(OwnedPageTableJournalError::Target(error))
                })
            });
        if let Err(error) = zeroed {
            self.roles
                .cancel_allocation(allocation)
                .unwrap_or_else(|_| panic!("table-candidate rollback lost allocation authority"));
            return Err(error);
        }
        // SAFETY: `zero_table_frame` succeeded, so every entry of the frame
        // is zero (`AtomicPageTableTarget`'s contract).
        let zeroed = unsafe { self.roles.assume_zeroed(allocation) }
            .unwrap_or_else(|_| panic!("zeroed table-candidate transition drifted"));
        self.roles
            .prepare_table(zeroed, self.root_identity.owner(), level)
            .map_err(|failure| {
                let error = failure.error();
                self.roles
                    .cancel_zeroed(failure.into_grant())
                    .unwrap_or_else(|_| panic!("zeroed table-candidate rollback drifted"));
                X86AddressSpacePublishError::FrameRole(error)
            })
    }
}

impl<
    T,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
    const CANDIDATE_CAPACITY: usize,
    const ENTRY_CAPACITY: usize,
    const INVALIDATION_CAPACITY: usize,
> publisher_seal::Sealed
    for X86AddressSpacePublisher<
        '_,
        T,
        RANGE_CAPACITY,
        ROLE_CAPACITY,
        CANDIDATE_CAPACITY,
        ENTRY_CAPACITY,
        INVALIDATION_CAPACITY,
    >
{
}

#[allow(
    unsafe_code,
    reason = "the constructor binds opaque model identities to one authenticated x86 root and atomic target"
)]
unsafe impl<
    T,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
    const CANDIDATE_CAPACITY: usize,
    const ENTRY_CAPACITY: usize,
    const INVALIDATION_CAPACITY: usize,
> AddressSpacePublisher
    for X86AddressSpacePublisher<
        '_,
        T,
        RANGE_CAPACITY,
        ROLE_CAPACITY,
        CANDIDATE_CAPACITY,
        ENTRY_CAPACITY,
        INVALIDATION_CAPACITY,
    >
where
    T: AtomicPageTableTarget,
{
    type Error = X86AddressSpacePublishError<T::Error>;

    fn address_space_key(&self) -> AddressSpaceKey {
        self.address_space
    }

    fn publish_replace(
        &mut self,
        address_space: AddressSpaceKey,
        region: RegionKey,
        before: &[Mapping],
        after: &[Mapping],
    ) -> Result<(), Self::Error> {
        self.reverted = false;
        if address_space != self.address_space || region != self.region {
            return Err(X86AddressSpacePublishError::Identity);
        }
        self.publish_pages(before, after)
    }

    fn failed_after_publishing(&mut self) -> bool {
        core::mem::take(&mut self.reverted)
    }
}

fn validate_mapping_batch<E, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    roles: &FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    address_space: AddressSpaceKey,
    region: RegionKey,
    mappings: &[Mapping],
) -> Result<(), X86AddressSpacePublishError<E>> {
    for (index, mapping) in mappings.iter().copied().enumerate() {
        let backing = mapping.backing();
        if mapping.address_space() != address_space
            || mapping.region() != region
            || mapping.virtual_start() == 0
            || !mapping.virtual_start().is_multiple_of(BASE_PAGE_SIZE)
            || mapping.byte_len() == 0
            || !mapping.byte_len().is_multiple_of(BASE_PAGE_SIZE)
            || backing.byte_len() != mapping.byte_len()
            || mapping
                .virtual_start()
                .checked_add(mapping.byte_len())
                .is_none()
        {
            return Err(X86AddressSpacePublishError::InvalidMapping);
        }
        roles
            .validate_object_range(
                backing.backing_identity(),
                backing.object_offset(),
                backing.byte_len(),
                mapping.protection().writable(),
            )
            .map_err(X86AddressSpacePublishError::FrameRole)?;
        let end = mapping.virtual_start() + mapping.byte_len();
        for other in &mappings[index + 1..] {
            let other_end = other
                .virtual_start()
                .checked_add(other.byte_len())
                .ok_or(X86AddressSpacePublishError::InvalidMapping)?;
            if mapping.virtual_start() < other_end && other.virtual_start() < end {
                return Err(X86AddressSpacePublishError::InvalidMapping);
            }
        }
    }
    Ok(())
}

fn publish_page<
    T,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
    const CANDIDATE_CAPACITY: usize,
    const ENTRY_CAPACITY: usize,
    const INVALIDATION_CAPACITY: usize,
>(
    root: &PageTableRoot,
    journal: &mut OwnedPageTableJournal<
        '_,
        '_,
        T,
        RANGE_CAPACITY,
        ROLE_CAPACITY,
        CANDIDATE_CAPACITY,
        ENTRY_CAPACITY,
        INVALIDATION_CAPACITY,
    >,
    address: u64,
    before: Option<PageDescriptor>,
    after: Option<PageDescriptor>,
) -> Result<(), X86AddressSpacePublishError<T::Error>>
where
    T: AtomicPageTableTarget,
{
    let page =
        VirtualPage::new(address).map_err(|_| X86AddressSpacePublishError::InvalidMapping)?;
    // What this address space's tables hold now. An on-demand page may be
    // committed in its object yet have no leaf here; an eager page always
    // has its leaf (DW2 M6 §8.6).
    let before = match before {
        Some(descriptor) => match descriptor.physical_start {
            Some(physical_start) if descriptor.on_demand => {
                match root
                    .present_leaf(journal, page)
                    .map_err(X86AddressSpacePublishError::Map)?
                {
                    Some(frame) if frame.address() == physical_start => {
                        Some(Leaf::of(descriptor, physical_start))
                    }
                    Some(_) => {
                        return Err(X86AddressSpacePublishError::Map(MapError::FrameMismatch));
                    }
                    None => None,
                }
            }
            Some(physical_start) => Some(Leaf::of(descriptor, physical_start)),
            None => None,
        },
        None => None,
    };
    // What they should hold after. An on-demand page gets a leaf here only
    // where it already had one; elsewhere a touch publishes it. So this
    // never builds a table for an on-demand page, and an undo never needs
    // one.
    let after = match after {
        Some(descriptor) if descriptor.on_demand && before.is_none() => None,
        Some(descriptor) => descriptor
            .physical_start
            .map(|physical_start| Leaf::of(descriptor, physical_start)),
        None => None,
    };
    let result = match (before, after) {
        (None, Some(after)) => {
            journal
                .authorize_leaf(after.backing, after.object_offset, after.physical_start)
                .map_err(X86AddressSpacePublishError::Journal)?;
            let (candidates, count) = journal
                .candidate_addresses_for_page(root, page)
                .map_err(X86AddressSpacePublishError::Journal)?;
            root.map_page(
                journal,
                page,
                after.physical_start,
                after.permissions,
                &candidates[..count],
            )
        }
        (Some(before), None) => {
            journal
                .authorize_leaf(before.backing, before.object_offset, before.physical_start)
                .map_err(X86AddressSpacePublishError::Journal)?;
            root.unmap_page(journal, page).and_then(|removed| {
                if removed.address() == before.physical_start {
                    Ok(())
                } else {
                    Err(MapError::FrameMismatch)
                }
            })
        }
        (Some(before), Some(after))
            if before.backing == after.backing && before.object_offset == after.object_offset =>
        {
            journal
                .authorize_leaf(after.backing, after.object_offset, after.physical_start)
                .map_err(X86AddressSpacePublishError::Journal)?;
            root.protect_page(journal, page, after.permissions)
        }
        (Some(before), Some(after)) => {
            journal
                .authorize_leaf(after.backing, after.object_offset, after.physical_start)
                .map_err(X86AddressSpacePublishError::Journal)?;
            root.replace_page(
                journal,
                page,
                before.physical_start,
                after.physical_start,
                after.permissions,
            )
        }
        (None, None) => return Ok(()),
    };
    if result.is_err() {
        journal.clear_leaf_authorization();
    }
    result.map_err(X86AddressSpacePublishError::Map)
}

pub(super) fn first_mapping_start(before: &[Mapping], after: &[Mapping]) -> Option<u64> {
    let mut first = None;
    let mut index = 0;
    while index < before.len() {
        let mapping = &before[index];
        let start = mapping.virtual_start();
        first = Some(first.map_or(start, |current: u64| current.min(start)));
        index += 1;
    }
    index = 0;
    while index < after.len() {
        let mapping = &after[index];
        let start = mapping.virtual_start();
        first = Some(first.map_or(start, |current: u64| current.min(start)));
        index += 1;
    }
    first
}

pub(super) fn next_mapping_start(
    before: &[Mapping],
    after: &[Mapping],
    address: u64,
) -> Option<u64> {
    let mut next = next_mapping_start_in(before, address);
    if let Some(after_start) = next_mapping_start_in(after, address) {
        next = Some(next.map_or(after_start, |current| current.min(after_start)));
    }
    next
}

fn next_mapping_start_in(mappings: &[Mapping], address: u64) -> Option<u64> {
    let mut next = None;
    let mut index = 0;
    while index < mappings.len() {
        let mapping = &mappings[index];
        let start = mapping.virtual_start();
        if start > address {
            next = Some(next.map_or(start, |current: u64| current.min(start)));
        }
        index += 1;
    }
    next
}

pub(super) fn mapping_at<E>(
    mappings: &[Mapping],
    address: u64,
) -> Result<Option<&Mapping>, X86AddressSpacePublishError<E>> {
    let mut found = None;
    let mut index = 0;
    while index < mappings.len() {
        let mapping = &mappings[index];
        let end = mapping
            .virtual_start()
            .checked_add(mapping.byte_len())
            .ok_or(X86AddressSpacePublishError::InvalidMapping)?;
        if mapping.virtual_start() <= address && address < end {
            if found.is_some() {
                return Err(X86AddressSpacePublishError::InvalidMapping);
            }
            found = Some(mapping);
        }
        index += 1;
    }
    Ok(found)
}

pub(super) fn next_boundary<E>(
    before: &[Mapping],
    after: &[Mapping],
    address: u64,
    old: Option<&Mapping>,
    new: Option<&Mapping>,
) -> Result<u64, X86AddressSpacePublishError<E>> {
    let mut boundary = u64::MAX;
    if let Some(mapping) = old {
        boundary = boundary.min(
            mapping
                .virtual_start()
                .checked_add(mapping.byte_len())
                .ok_or(X86AddressSpacePublishError::InvalidMapping)?,
        );
    }
    if let Some(mapping) = new {
        boundary = boundary.min(
            mapping
                .virtual_start()
                .checked_add(mapping.byte_len())
                .ok_or(X86AddressSpacePublishError::InvalidMapping)?,
        );
    }
    if old.is_none()
        && let Some(start) = next_mapping_start_in(before, address)
    {
        boundary = boundary.min(start);
    }
    if new.is_none()
        && let Some(start) = next_mapping_start_in(after, address)
    {
        boundary = boundary.min(start);
    }
    if boundary <= address {
        return Err(X86AddressSpacePublishError::InvalidMapping);
    }
    Ok(boundary)
}

/// The span from the first changed page to the end of the last changed
/// stretch, as `(start, byte_len)`; `None` when nothing changes.
fn changed_span<E, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    roles: &FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    before: &[Mapping],
    after: &[Mapping],
) -> Result<Option<(u64, u64)>, X86AddressSpacePublishError<E>> {
    let mut span: Option<(u64, u64)> = None;
    let mut cursor = first_mapping_start(before, after);
    let mut old_run = None;
    let mut new_run = None;
    while let Some(address) = cursor {
        let old = mapping_at(before, address)?;
        let new = mapping_at(after, address)?;
        if old.is_none() && new.is_none() {
            cursor = next_mapping_start(before, after, address);
            continue;
        }
        let boundary = next_boundary(before, after, address, old, new)?;
        let old_page = match old {
            Some(mapping) => Some(page_descriptor(roles, mapping, address, &mut old_run)?),
            None => None,
        };
        let new_page = match new {
            Some(mapping) => Some(page_descriptor(roles, mapping, address, &mut new_run)?),
            None => None,
        };
        if old_page != new_page {
            let start = span.map_or(address, |(start, _)| start);
            span = Some((start, boundary));
        }
        cursor = (boundary != u64::MAX).then_some(boundary);
    }
    span.map(|(start, end)| {
        end.checked_sub(start)
            .map(|byte_len| (start, byte_len))
            .ok_or(X86AddressSpacePublishError::InvalidMapping)
    })
    .transpose()
}

fn page_descriptor<E, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    roles: &FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    mapping: &Mapping,
    address: u64,
    run: &mut Option<BackingCursor>,
) -> Result<PageDescriptor, X86AddressSpacePublishError<E>> {
    let backing = mapping.backing();
    let object_offset = address
        .checked_sub(mapping.virtual_start())
        .and_then(|offset| offset.checked_add(backing.object_offset()))
        .ok_or(X86AddressSpacePublishError::InvalidMapping)?;
    let mut cursor = BackingCursor::for_backing(*run, backing.backing_identity());
    let physical_start =
        match roles.resolve_at(&mut cursor, object_offset, mapping.protection().writable()) {
            Ok(segment) => Some(segment.physical_start),
            Err(FrameRoleError::Absent) => None,
            Err(error) => return Err(X86AddressSpacePublishError::FrameRole(error)),
        };
    *run = Some(cursor);
    Ok(PageDescriptor {
        backing: backing.backing_identity(),
        object_offset,
        physical_start,
        on_demand: roles.is_on_demand(backing.backing_identity()),
        permissions: MappingPermissions {
            user: true,
            readable: true,
            writable: mapping.protection().writable(),
            executable: mapping.protection().executable(),
            uncached: backing.uncached(),
        },
    })
}
