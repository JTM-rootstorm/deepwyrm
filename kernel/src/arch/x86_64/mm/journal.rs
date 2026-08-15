//! Fixed-capacity atomic journal for x86 page-table publication.
//!
//! Planning reads observe an in-memory overlay. No target entry changes until
//! [`PageTableJournal::publish`] revalidates every original observation and
//! submits one atomic child-before-parent write batch.

use super::{
    CommitError, EntryAssertion, EntryMutation, FrameAddress, MutationPlan, PageTableTransaction,
    PhysicalAddressLimit, VirtualPage, decode_intermediate,
};
use crate::memory::address_region::{
    AddressSpaceKey, AddressSpacePublisher, Mapping, RegionKey, publisher_seal,
};
use crate::memory::frame_roles::{
    BackingIdentity, FrameRoleError, FrameRoleManager, StagedTableCommit, TableCandidateGrant,
    TableCommitParent, TableIdentity, TableLevel,
};
use crate::memory::physical::BASE_PAGE_SIZE;

const ENTRY_COUNT: usize = 512;

mod target_seal {
    pub trait Sealed {}
}

/// The architecture-owned final publication boundary beneath the journal.
///
/// # Safety
///
/// An implementation must serialize one page-table root for the complete
/// borrow, and `apply` must either publish every supplied write followed by
/// every invalidation or return an error with all entries unchanged and no
/// invalidation or other TLB-visible effect. Writes are supplied
/// child-before-parent and never contain duplicate locations.
///
/// The unsafe boundary which pairs a target with a publisher must additionally
/// attest that this serialization domain is the exact supplied root and
/// address-space authority domain. This trait cannot introspect that identity.
#[allow(
    unsafe_code,
    reason = "atomic page-table writes and TLB invalidation are architecture facts"
)]
pub(crate) unsafe trait AtomicPageTableTarget: target_seal::Sealed {
    type Error;

    fn read_entry(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error>;

    fn apply(
        &mut self,
        writes: &[JournalWrite],
        invalidations: &[VirtualPage],
    ) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JournalWrite {
    table: FrameAddress,
    index: usize,
    value: u64,
}

#[allow(
    dead_code,
    reason = "the live atomic mapper consumes these accessors after the host journal gate"
)]
impl JournalWrite {
    pub(crate) const fn table(self) -> FrameAddress {
        self.table
    }

    pub(crate) const fn index(self) -> usize {
        self.index
    }

    pub(crate) const fn value(self) -> u64 {
        self.value
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PageTableJournalError<E> {
    Access(E),
    Capacity,
    Conflict,
    InvalidIndex,
}

#[derive(Clone, Copy)]
struct EntryState {
    table: FrameAddress,
    index: usize,
    expected: u64,
    compare_mask: u64,
    replacement: u64,
    preserve_mask: u64,
    logical: u64,
    written: bool,
}

const EMPTY_ENTRY: EntryState = EntryState {
    table: FrameAddress(0),
    index: 0,
    expected: 0,
    compare_mask: 0,
    replacement: 0,
    preserve_mask: 0,
    logical: 0,
    written: false,
};

const EMPTY_PAGE: VirtualPage = VirtualPage(0);
const EMPTY_WRITE: JournalWrite = JournalWrite {
    table: FrameAddress(0),
    index: 0,
    value: 0,
};

/// One unpublished journal over an exclusively borrowed atomic target.
pub(crate) struct PageTableJournal<
    'a,
    T,
    const ENTRY_CAPACITY: usize,
    const INVALIDATION_CAPACITY: usize,
> {
    target: &'a mut T,
    entries: [EntryState; ENTRY_CAPACITY],
    entry_count: usize,
    invalidations: [VirtualPage; INVALIDATION_CAPACITY],
    invalidation_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnedPageTableJournalError<E> {
    Target(E),
    JournalCapacity,
    JournalConflict,
    FrameRole(FrameRoleError),
    InvalidPlan,
    UnauthorizedLeaf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TableReference {
    Committed(TableIdentity),
    Candidate(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CandidateUse {
    candidate_slot: usize,
    level: TableLevel,
    parent: TableReference,
}

const EMPTY_CANDIDATE_USE: CandidateUse = CandidateUse {
    candidate_slot: usize::MAX,
    level: TableLevel::Pml4,
    parent: TableReference::Candidate(usize::MAX),
};

#[derive(Clone, Copy)]
struct LeafAuthorization {
    backing: BackingIdentity,
    physical_start: u64,
}

/// A role-authenticated journal for exactly one committed four-level root.
///
/// Candidate grants remain in the caller-owned pool on every pre-publication
/// error. Successful target publication is immediately followed by infallible
/// frame-role publication while the manager remains exclusively borrowed.
pub(crate) struct OwnedPageTableJournal<
    'a,
    'target,
    T,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
    const CANDIDATE_CAPACITY: usize,
    const ENTRY_CAPACITY: usize,
    const INVALIDATION_CAPACITY: usize,
> {
    journal: PageTableJournal<'target, T, ENTRY_CAPACITY, INVALIDATION_CAPACITY>,
    roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    root: TableIdentity,
    physical_limit: PhysicalAddressLimit,
    candidates: &'a mut [Option<TableCandidateGrant>; CANDIDATE_CAPACITY],
    uses: [CandidateUse; CANDIDATE_CAPACITY],
    use_count: usize,
    leaf_authorization: Option<LeafAuthorization>,
}

impl<
    'a,
    'target,
    T,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
    const CANDIDATE_CAPACITY: usize,
    const ENTRY_CAPACITY: usize,
    const INVALIDATION_CAPACITY: usize,
>
    OwnedPageTableJournal<
        'a,
        'target,
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
    pub(crate) fn new(
        target: &'target mut T,
        roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
        root: TableIdentity,
        physical_limit: PhysicalAddressLimit,
        candidates: &'a mut [Option<TableCandidateGrant>; CANDIDATE_CAPACITY],
    ) -> Result<Self, FrameRoleError> {
        roles.validate_table_identity(root)?;
        if root.level() != TableLevel::Pml4 {
            return Err(FrameRoleError::WrongRole);
        }
        Ok(Self {
            journal: PageTableJournal::new(target),
            roles,
            root,
            physical_limit,
            candidates,
            uses: [EMPTY_CANDIDATE_USE; CANDIDATE_CAPACITY],
            use_count: 0,
            leaf_authorization: None,
        })
    }

    pub(crate) fn authorize_leaf(
        &mut self,
        backing: BackingIdentity,
        physical_start: u64,
    ) -> Result<(), OwnedPageTableJournalError<T::Error>> {
        self.roles
            .validate_object_backing(backing, physical_start, BASE_PAGE_SIZE, false)
            .map_err(OwnedPageTableJournalError::FrameRole)?;
        self.leaf_authorization = Some(LeafAuthorization {
            backing,
            physical_start,
        });
        Ok(())
    }

    pub(crate) fn clear_leaf_authorization(&mut self) {
        self.leaf_authorization = None;
    }

    pub(crate) fn candidate_addresses_for_page(
        &mut self,
        root: &super::PageTableRoot,
        page: VirtualPage,
    ) -> Result<([u64; 3], usize), OwnedPageTableJournalError<T::Error>> {
        let mut addresses = [0_u64; 3];
        let mut count = 0;
        let mut current = root.frame();
        for level_index in (1..=3).rev() {
            let entry = self
                .journal
                .read_entry(current, page.index(level_index))
                .map_err(journal_error)?;
            if entry == 0 {
                for missing_parent_level in (1..=level_index).rev() {
                    let needed = level_for_index(missing_parent_level - 1);
                    let candidate = self
                        .candidates
                        .iter()
                        .enumerate()
                        .find(|(slot, candidate)| {
                            !self.uses[..self.use_count]
                                .iter()
                                .any(|used| used.candidate_slot == *slot)
                                && !addresses[..count].iter().any(|address| {
                                    candidate.as_ref().is_some_and(|candidate| {
                                        candidate.physical_start() == *address
                                    })
                                })
                                && candidate.as_ref().is_some_and(|candidate| {
                                    candidate.owner() == self.root.owner()
                                        && candidate.level() == needed
                                })
                        });
                    let Some((_, candidate)) = candidate else {
                        return Ok((addresses, count));
                    };
                    addresses[count] = candidate
                        .as_ref()
                        .expect("selected candidate slot is populated")
                        .physical_start();
                    count += 1;
                }
                return Ok((addresses, count));
            }
            current = decode_intermediate(entry, page.is_user_half(), self.physical_limit)
                .map_err(|_| OwnedPageTableJournalError::InvalidPlan)?;
        }
        Ok((addresses, count))
    }

    pub(crate) fn publish(mut self) -> Result<(), OwnedPageTableJournalError<T::Error>> {
        self.roles
            .validate_table_identity(self.root)
            .map_err(OwnedPageTableJournalError::FrameRole)?;

        let mut staged: [Option<StagedTableCommit>; CANDIDATE_CAPACITY] =
            [const { None }; CANDIDATE_CAPACITY];
        for use_index in (0..self.use_count).rev() {
            let candidate_use = self.uses[use_index];
            let grant = self.candidates[candidate_use.candidate_slot]
                .take()
                .expect("validated candidate remains in its exclusive pool slot");
            let parent = match candidate_use.parent {
                TableReference::Committed(parent) => TableCommitParent::Committed(parent),
                TableReference::Candidate(parent_slot) => {
                    let parent = self.candidates[parent_slot]
                        .as_ref()
                        .expect("reverse staging retains every candidate parent");
                    TableCommitParent::Candidate(parent)
                }
            };
            match self.roles.stage_table_commit(grant, Some(parent)) {
                Ok(commit) => staged[use_index] = Some(commit),
                Err(error) => {
                    let role_error = error.error();
                    self.candidates[candidate_use.candidate_slot] = Some(error.into_grant());
                    self.restore_staged(&mut staged);
                    return Err(OwnedPageTableJournalError::FrameRole(role_error));
                }
            }
        }

        if let Err(error) = self.journal.publish() {
            self.restore_staged(&mut staged);
            return Err(journal_error(error));
        }

        for commit in staged[..self.use_count].iter_mut() {
            let commit = commit
                .take()
                .expect("every used candidate has one staged role commit");
            let _ = self.roles.publish_staged_table(commit);
        }
        Ok(())
    }

    fn restore_staged(&mut self, staged: &mut [Option<StagedTableCommit>; CANDIDATE_CAPACITY]) {
        for (use_index, commit) in staged[..self.use_count].iter_mut().enumerate() {
            let Some(commit) = commit.take() else {
                continue;
            };
            let slot = self.uses[use_index].candidate_slot;
            assert!(
                self.candidates[slot].is_none(),
                "staged candidate pool slot changed before rollback"
            );
            self.candidates[slot] = Some(commit.into_candidate());
        }
    }

    fn validate_plan(
        &mut self,
        plan: &MutationPlan,
    ) -> Result<(), OwnedPageTableJournalError<T::Error>> {
        if plan.root().address() != self.root.physical_start()
            || plan.assertions().len() + plan.new_tables().len() != 3
            || plan.mutations().len() != plan.new_tables().len() + 1
        {
            return Err(OwnedPageTableJournalError::InvalidPlan);
        }
        self.roles
            .validate_table_identity(self.root)
            .map_err(OwnedPageTableJournalError::FrameRole)?;

        let authorization = self
            .leaf_authorization
            .ok_or(OwnedPageTableJournalError::UnauthorizedLeaf)?;
        let leaf = plan
            .leaf_data()
            .ok_or(OwnedPageTableJournalError::UnauthorizedLeaf)?;
        if leaf.address() != authorization.physical_start {
            return Err(OwnedPageTableJournalError::UnauthorizedLeaf);
        }
        let leaf_mutation = *plan
            .mutations()
            .last()
            .ok_or(OwnedPageTableJournalError::InvalidPlan)?;
        let required_writable = leaf_mutation.replacement() & super::WRITABLE != 0;
        self.roles
            .validate_object_backing(
                authorization.backing,
                authorization.physical_start,
                BASE_PAGE_SIZE,
                required_writable,
            )
            .map_err(OwnedPageTableJournalError::FrameRole)?;

        let mut current = TableReference::Committed(self.root);
        let mut current_address = self.root.physical_start();
        for (depth, assertion) in plan.assertions().iter().copied().enumerate() {
            let level_index = 3 - depth;
            if assertion.table().address() != current_address
                || assertion.index() != plan.page().index(level_index)
            {
                return Err(OwnedPageTableJournalError::InvalidPlan);
            }
            let child_address = decode_intermediate(
                assertion.expected(),
                plan.page().is_user_half(),
                self.physical_limit,
            )
            .map_err(|_| OwnedPageTableJournalError::InvalidPlan)?
            .address();
            let child_level = level_for_index(level_index - 1);
            let child = self.table_reference(child_address, child_level)?;
            self.validate_parent(current, child)?;
            current = child;
            current_address = child_address;
        }

        for (offset, frame) in plan.new_tables().iter().copied().enumerate() {
            let mutation = plan.mutations()[offset];
            let level_index = 3 - plan.assertions().len() - offset;
            if mutation.table().address() != current_address
                || mutation.index() != plan.page().index(level_index)
                || mutation.expected() != 0
                || mutation.preserve_mask() != 0
            {
                return Err(OwnedPageTableJournalError::InvalidPlan);
            }
            let decoded = decode_intermediate(
                mutation.replacement(),
                plan.page().is_user_half(),
                self.physical_limit,
            )
            .map_err(|_| OwnedPageTableJournalError::InvalidPlan)?;
            if decoded != frame {
                return Err(OwnedPageTableJournalError::InvalidPlan);
            }
            let child_level = level_for_index(level_index - 1);
            let slot = self.candidate_slot(frame.address(), child_level)?;
            self.record_candidate_use(slot, child_level, current)?;
            current = TableReference::Candidate(slot);
            current_address = frame.address();
        }

        if leaf_mutation.table().address() != current_address
            || leaf_mutation.index() != plan.page().index(0)
            || (leaf_mutation.expected() | leaf_mutation.replacement()) & super::GLOBAL != 0
            || self.table_level(current)? != TableLevel::Pt
        {
            return Err(OwnedPageTableJournalError::InvalidPlan);
        }
        Ok(())
    }

    fn candidate_slot(
        &self,
        physical_start: u64,
        level: TableLevel,
    ) -> Result<usize, OwnedPageTableJournalError<T::Error>> {
        self.candidates
            .iter()
            .position(|candidate| {
                candidate.as_ref().is_some_and(|candidate| {
                    candidate.physical_start() == physical_start
                        && candidate.owner() == self.root.owner()
                        && candidate.level() == level
                })
            })
            .ok_or(OwnedPageTableJournalError::InvalidPlan)
    }

    fn record_candidate_use(
        &mut self,
        candidate_slot: usize,
        level: TableLevel,
        parent: TableReference,
    ) -> Result<(), OwnedPageTableJournalError<T::Error>> {
        if let Some(existing) = self.uses[..self.use_count]
            .iter()
            .find(|candidate| candidate.candidate_slot == candidate_slot)
        {
            return if existing.level == level && existing.parent == parent {
                Ok(())
            } else {
                Err(OwnedPageTableJournalError::InvalidPlan)
            };
        }
        if self.use_count == CANDIDATE_CAPACITY {
            return Err(OwnedPageTableJournalError::JournalCapacity);
        }
        self.uses[self.use_count] = CandidateUse {
            candidate_slot,
            level,
            parent,
        };
        self.use_count += 1;
        Ok(())
    }

    fn table_reference(
        &self,
        physical_start: u64,
        level: TableLevel,
    ) -> Result<TableReference, OwnedPageTableJournalError<T::Error>> {
        if let Some(candidate) = self.uses[..self.use_count].iter().find(|candidate| {
            candidate.level == level
                && self.candidates[candidate.candidate_slot]
                    .as_ref()
                    .is_some_and(|grant| grant.physical_start() == physical_start)
        }) {
            return Ok(TableReference::Candidate(candidate.candidate_slot));
        }
        self.roles
            .table_identity(self.root.owner(), level, physical_start)
            .map(TableReference::Committed)
            .map_err(OwnedPageTableJournalError::FrameRole)
    }

    fn validate_parent(
        &self,
        parent: TableReference,
        child: TableReference,
    ) -> Result<(), OwnedPageTableJournalError<T::Error>> {
        match (parent, child) {
            (TableReference::Committed(parent), TableReference::Committed(child)) => self
                .roles
                .validate_table_child(parent, child)
                .map_err(OwnedPageTableJournalError::FrameRole),
            (_, TableReference::Candidate(slot)) => {
                let candidate = self.uses[..self.use_count]
                    .iter()
                    .find(|candidate| candidate.candidate_slot == slot)
                    .ok_or(OwnedPageTableJournalError::InvalidPlan)?;
                if candidate.parent == parent {
                    Ok(())
                } else {
                    Err(OwnedPageTableJournalError::InvalidPlan)
                }
            }
            (TableReference::Candidate(_), TableReference::Committed(_)) => {
                Err(OwnedPageTableJournalError::InvalidPlan)
            }
        }
    }

    fn table_level(
        &self,
        table: TableReference,
    ) -> Result<TableLevel, OwnedPageTableJournalError<T::Error>> {
        match table {
            TableReference::Committed(table) => Ok(table.level()),
            TableReference::Candidate(slot) => self.uses[..self.use_count]
                .iter()
                .find(|candidate| candidate.candidate_slot == slot)
                .map(|candidate| candidate.level)
                .ok_or(OwnedPageTableJournalError::InvalidPlan),
        }
    }
}

impl<
    T,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
    const CANDIDATE_CAPACITY: usize,
    const ENTRY_CAPACITY: usize,
    const INVALIDATION_CAPACITY: usize,
> PageTableTransaction
    for OwnedPageTableJournal<
        '_,
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
    type Error = OwnedPageTableJournalError<T::Error>;

    fn read_entry(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error> {
        self.journal.read_entry(table, index).map_err(journal_error)
    }

    fn commit(&mut self, plan: &MutationPlan) -> Result<(), CommitError<Self::Error>> {
        let saved_uses = self.uses;
        let saved_use_count = self.use_count;
        if self.validate_plan(plan).is_err() {
            self.uses = saved_uses;
            self.use_count = saved_use_count;
            self.leaf_authorization = None;
            return Err(CommitError::TableClaimRejected);
        }
        let result = self.journal.commit(plan).map_err(|error| match error {
            CommitError::Access(error) => CommitError::Access(journal_error(error)),
            CommitError::JournalConflict => CommitError::JournalConflict,
            CommitError::TableClaimRejected => CommitError::TableClaimRejected,
        });
        self.leaf_authorization = None;
        if result.is_err() {
            self.uses = saved_uses;
            self.use_count = saved_use_count;
        }
        result
    }
}

fn journal_error<E>(error: PageTableJournalError<E>) -> OwnedPageTableJournalError<E> {
    match error {
        PageTableJournalError::Access(error) => OwnedPageTableJournalError::Target(error),
        PageTableJournalError::Capacity | PageTableJournalError::InvalidIndex => {
            OwnedPageTableJournalError::JournalCapacity
        }
        PageTableJournalError::Conflict => OwnedPageTableJournalError::JournalConflict,
    }
}

const fn level_for_index(index: usize) -> TableLevel {
    match index {
        3 => TableLevel::Pml4,
        2 => TableLevel::Pdpt,
        1 => TableLevel::Pd,
        0 => TableLevel::Pt,
        _ => panic!("invalid four-level page-table index"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum X86AddressSpacePublishError<E> {
    Identity,
    InvalidMapping,
    Capacity,
    FrameRole(FrameRoleError),
    Map(super::MapError<OwnedPageTableJournalError<E>>),
    Journal(OwnedPageTableJournalError<E>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PageDescriptor {
    backing: BackingIdentity,
    physical_start: u64,
    permissions: super::MappingPermissions,
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
    root: &'a super::PageTableRoot,
    root_identity: TableIdentity,
    roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    target: &'a mut T,
    candidates: &'a mut [Option<TableCandidateGrant>; CANDIDATE_CAPACITY],
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
        root: &'a super::PageTableRoot,
        root_identity: TableIdentity,
        roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
        target: &'a mut T,
        candidates: &'a mut [Option<TableCandidateGrant>; CANDIDATE_CAPACITY],
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
        })
    }

    fn publish_pages(
        &mut self,
        before: &[Mapping],
        after: &[Mapping],
    ) -> Result<(), X86AddressSpacePublishError<T::Error>> {
        validate_mapping_batch(self.roles, self.address_space, self.region, before)?;
        validate_mapping_batch(self.roles, self.address_space, self.region, after)?;

        let mut journal = OwnedPageTableJournal::<
            _,
            RANGE_CAPACITY,
            ROLE_CAPACITY,
            CANDIDATE_CAPACITY,
            ENTRY_CAPACITY,
            INVALIDATION_CAPACITY,
        >::new(
            self.target,
            self.roles,
            self.root_identity,
            self.root.physical_limit(),
            self.candidates,
        )
        .map_err(X86AddressSpacePublishError::FrameRole)?;

        let mut cursor = first_mapping_start(before, after);
        let mut changed_pages = 0;
        while let Some(address) = cursor {
            let old = mapping_at(before, address)?;
            let new = mapping_at(after, address)?;
            if old.is_none() && new.is_none() {
                cursor = next_mapping_start(before, after, address);
                continue;
            }
            let boundary = next_boundary(before, after, address, old, new)?;
            let old_page = old
                .map(|mapping| page_descriptor(mapping, address))
                .transpose()?;
            let new_page = new
                .map(|mapping| page_descriptor(mapping, address))
                .transpose()?;
            if old_page == new_page {
                cursor = (boundary != u64::MAX).then_some(boundary);
                continue;
            }

            let mut page_address = address;
            while page_address < boundary {
                if changed_pages == INVALIDATION_CAPACITY {
                    return Err(X86AddressSpacePublishError::Capacity);
                }
                let old_page = old
                    .map(|mapping| page_descriptor(mapping, page_address))
                    .transpose()?;
                let new_page = new
                    .map(|mapping| page_descriptor(mapping, page_address))
                    .transpose()?;
                publish_page(self.root, &mut journal, page_address, old_page, new_page)?;
                changed_pages += 1;
                page_address = page_address
                    .checked_add(BASE_PAGE_SIZE)
                    .ok_or(X86AddressSpacePublishError::InvalidMapping)?;
            }
            cursor = (boundary != u64::MAX).then_some(boundary);
        }
        journal
            .publish()
            .map_err(X86AddressSpacePublishError::Journal)
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
        if address_space != self.address_space || region != self.region {
            return Err(X86AddressSpacePublishError::Identity);
        }
        self.publish_pages(before, after)
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
            .validate_object_backing(
                backing.backing_identity(),
                backing.physical_start(),
                backing.byte_len(),
                mapping.protection().writable(),
            )
            .map_err(X86AddressSpacePublishError::FrameRole)?;
        let end = mapping.virtual_start() + mapping.byte_len();
        for other in mappings[index + 1..].iter().copied() {
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
    root: &super::PageTableRoot,
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
    let result = match (before, after) {
        (None, Some(after)) => {
            journal
                .authorize_leaf(after.backing, after.physical_start)
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
                .authorize_leaf(before.backing, before.physical_start)
                .map_err(X86AddressSpacePublishError::Journal)?;
            root.unmap_page(journal, page).and_then(|removed| {
                if removed.address() == before.physical_start {
                    Ok(())
                } else {
                    Err(super::MapError::FrameMismatch)
                }
            })
        }
        (Some(before), Some(after)) if before.physical_start == after.physical_start => {
            journal
                .authorize_leaf(after.backing, after.physical_start)
                .map_err(X86AddressSpacePublishError::Journal)?;
            root.protect_page(journal, page, after.permissions)
        }
        (Some(before), Some(after)) => {
            journal
                .authorize_leaf(after.backing, after.physical_start)
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

fn first_mapping_start(before: &[Mapping], after: &[Mapping]) -> Option<u64> {
    before
        .iter()
        .chain(after)
        .map(|mapping| mapping.virtual_start())
        .min()
}

fn next_mapping_start(before: &[Mapping], after: &[Mapping], address: u64) -> Option<u64> {
    before
        .iter()
        .chain(after)
        .map(|mapping| mapping.virtual_start())
        .filter(|start| *start > address)
        .min()
}

fn mapping_at<E>(
    mappings: &[Mapping],
    address: u64,
) -> Result<Option<Mapping>, X86AddressSpacePublishError<E>> {
    let mut found = None;
    for mapping in mappings.iter().copied() {
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
    }
    Ok(found)
}

fn next_boundary<E>(
    before: &[Mapping],
    after: &[Mapping],
    address: u64,
    old: Option<Mapping>,
    new: Option<Mapping>,
) -> Result<u64, X86AddressSpacePublishError<E>> {
    let mut boundary = u64::MAX;
    for mapping in [old, new].into_iter().flatten() {
        boundary = boundary.min(
            mapping
                .virtual_start()
                .checked_add(mapping.byte_len())
                .ok_or(X86AddressSpacePublishError::InvalidMapping)?,
        );
    }
    if old.is_none()
        && let Some(start) = before
            .iter()
            .map(|mapping| mapping.virtual_start())
            .filter(|start| *start > address)
            .min()
    {
        boundary = boundary.min(start);
    }
    if new.is_none()
        && let Some(start) = after
            .iter()
            .map(|mapping| mapping.virtual_start())
            .filter(|start| *start > address)
            .min()
    {
        boundary = boundary.min(start);
    }
    if boundary <= address {
        return Err(X86AddressSpacePublishError::InvalidMapping);
    }
    Ok(boundary)
}

fn page_descriptor<E>(
    mapping: Mapping,
    address: u64,
) -> Result<PageDescriptor, X86AddressSpacePublishError<E>> {
    let offset = address
        .checked_sub(mapping.virtual_start())
        .ok_or(X86AddressSpacePublishError::InvalidMapping)?;
    let backing = mapping.backing();
    let physical_start = backing
        .physical_start()
        .checked_add(offset)
        .ok_or(X86AddressSpacePublishError::InvalidMapping)?;
    Ok(PageDescriptor {
        backing: backing.backing_identity(),
        physical_start,
        permissions: super::MappingPermissions {
            user: true,
            readable: true,
            writable: mapping.protection().writable(),
            executable: mapping.protection().executable(),
        },
    })
}

impl<'a, T, const ENTRY_CAPACITY: usize, const INVALIDATION_CAPACITY: usize>
    PageTableJournal<'a, T, ENTRY_CAPACITY, INVALIDATION_CAPACITY>
where
    T: AtomicPageTableTarget,
{
    pub(crate) fn new(target: &'a mut T) -> Self {
        Self {
            target,
            entries: [EMPTY_ENTRY; ENTRY_CAPACITY],
            entry_count: 0,
            invalidations: [EMPTY_PAGE; INVALIDATION_CAPACITY],
            invalidation_count: 0,
        }
    }

    /// Revalidates all original observations and atomically publishes the
    /// complete journal. The target remains unchanged on every returned error.
    pub(crate) fn publish(&mut self) -> Result<(), PageTableJournalError<T::Error>> {
        let mut actual = [0_u64; ENTRY_CAPACITY];
        for (index, entry) in self.entries[..self.entry_count].iter().copied().enumerate() {
            let value = self
                .target
                .read_entry(entry.table, entry.index)
                .map_err(PageTableJournalError::Access)?;
            if value & entry.compare_mask != entry.expected & entry.compare_mask {
                return Err(PageTableJournalError::Conflict);
            }
            actual[index] = value;
        }

        let mut writes = [EMPTY_WRITE; ENTRY_CAPACITY];
        let mut write_count = 0;
        for index in (0..self.entry_count).rev() {
            let entry = self.entries[index];
            if !entry.written {
                continue;
            }
            writes[write_count] = JournalWrite {
                table: entry.table,
                index: entry.index,
                value: entry.replacement | (actual[index] & entry.preserve_mask),
            };
            write_count += 1;
        }
        self.target
            .apply(
                &writes[..write_count],
                &self.invalidations[..self.invalidation_count],
            )
            .map_err(PageTableJournalError::Access)
    }

    fn logical_entry(
        &mut self,
        table: FrameAddress,
        index: usize,
    ) -> Result<u64, PageTableJournalError<T::Error>> {
        if index >= ENTRY_COUNT {
            return Err(PageTableJournalError::InvalidIndex);
        }
        if let Some(entry) = self.entries[..self.entry_count]
            .iter()
            .find(|entry| entry.table == table && entry.index == index)
        {
            return Ok(entry.logical);
        }
        self.target
            .read_entry(table, index)
            .map_err(PageTableJournalError::Access)
    }

    fn stage_plan(&mut self, plan: &MutationPlan) -> Result<(), PageTableJournalError<T::Error>> {
        let original_entries = self.entries;
        let original_entry_count = self.entry_count;
        let original_invalidations = self.invalidations;
        let original_invalidation_count = self.invalidation_count;

        let result = self.stage_plan_inner(plan);
        if result.is_err() {
            self.entries = original_entries;
            self.entry_count = original_entry_count;
            self.invalidations = original_invalidations;
            self.invalidation_count = original_invalidation_count;
        }
        result
    }

    fn stage_plan_inner(
        &mut self,
        plan: &MutationPlan,
    ) -> Result<(), PageTableJournalError<T::Error>> {
        for assertion in plan.assertions().iter().copied() {
            self.stage_assertion(assertion)?;
        }
        for mutation in plan.mutations().iter().copied() {
            self.stage_mutation(mutation)?;
        }
        if !self.invalidations[..self.invalidation_count].contains(&plan.page()) {
            if self.invalidation_count == INVALIDATION_CAPACITY {
                return Err(PageTableJournalError::Capacity);
            }
            self.invalidations[self.invalidation_count] = plan.page();
            self.invalidation_count += 1;
        }
        Ok(())
    }

    fn stage_assertion(
        &mut self,
        assertion: EntryAssertion,
    ) -> Result<(), PageTableJournalError<T::Error>> {
        let logical = self.logical_entry(assertion.table(), assertion.index())?;
        if logical & assertion.compare_mask() != assertion.expected() & assertion.compare_mask() {
            return Err(PageTableJournalError::Conflict);
        }
        self.record_observation(
            assertion.table(),
            assertion.index(),
            assertion.expected(),
            assertion.compare_mask(),
            logical,
        )?;
        Ok(())
    }

    fn stage_mutation(
        &mut self,
        mutation: EntryMutation,
    ) -> Result<(), PageTableJournalError<T::Error>> {
        let logical = self.logical_entry(mutation.table(), mutation.index())?;
        if logical & mutation.compare_mask() != mutation.expected() & mutation.compare_mask() {
            return Err(PageTableJournalError::Conflict);
        }
        let slot = self.record_observation(
            mutation.table(),
            mutation.index(),
            mutation.expected(),
            mutation.compare_mask(),
            logical,
        )?;
        let entry = &mut self.entries[slot];
        if entry.written {
            entry.replacement =
                mutation.replacement() | (entry.replacement & mutation.preserve_mask());
            entry.preserve_mask &= mutation.preserve_mask();
        } else {
            entry.replacement = mutation.replacement();
            entry.preserve_mask = mutation.preserve_mask();
            entry.written = true;
        }
        entry.logical = mutation.replacement() | (logical & mutation.preserve_mask());
        Ok(())
    }

    fn record_observation(
        &mut self,
        table: FrameAddress,
        index: usize,
        expected: u64,
        compare_mask: u64,
        logical: u64,
    ) -> Result<usize, PageTableJournalError<T::Error>> {
        if let Some(slot) = self.entries[..self.entry_count]
            .iter()
            .position(|entry| entry.table == table && entry.index == index)
        {
            let entry = &mut self.entries[slot];
            if !entry.written {
                let overlap = entry.compare_mask & compare_mask;
                if (entry.expected ^ expected) & overlap != 0 {
                    return Err(PageTableJournalError::Conflict);
                }
                entry.expected = (entry.expected & entry.compare_mask) | (expected & compare_mask);
                entry.compare_mask |= compare_mask;
            }
            return Ok(slot);
        }
        if self.entry_count == ENTRY_CAPACITY {
            return Err(PageTableJournalError::Capacity);
        }
        let slot = self.entry_count;
        self.entries[slot] = EntryState {
            table,
            index,
            expected,
            compare_mask,
            replacement: 0,
            preserve_mask: 0,
            logical,
            written: false,
        };
        self.entry_count += 1;
        Ok(slot)
    }
}

impl<T, const ENTRY_CAPACITY: usize, const INVALIDATION_CAPACITY: usize> PageTableTransaction
    for PageTableJournal<'_, T, ENTRY_CAPACITY, INVALIDATION_CAPACITY>
where
    T: AtomicPageTableTarget,
{
    type Error = PageTableJournalError<T::Error>;

    fn read_entry(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error> {
        self.logical_entry(table, index)
    }

    fn commit(&mut self, plan: &MutationPlan) -> Result<(), CommitError<Self::Error>> {
        self.stage_plan(plan).map_err(|error| match error {
            PageTableJournalError::Conflict => CommitError::JournalConflict,
            PageTableJournalError::Capacity | PageTableJournalError::InvalidIndex => {
                CommitError::TableClaimRejected
            }
            PageTableJournalError::Access(error) => {
                CommitError::Access(PageTableJournalError::Access(error))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::super::{MappingPermissions, PageTableRoot, PagingCapabilities};
    use super::*;
    use crate::memory::address_region::{AddressSpaceAuthority, Protection};
    use crate::memory::frame_roles::synthetic_frame_role_manager;
    use crate::memory::object::{MemoryObjectAuthority, MemoryObjectKind};
    use crate::memory::physical::{PhysicalAddressLimit, PhysicalRange};
    use std::collections::BTreeMap;
    use std::vec::Vec;

    #[derive(Default)]
    struct FakeTarget {
        entries: BTreeMap<(u64, usize), u64>,
        applied: Vec<(u64, usize)>,
        invalidated: Vec<u64>,
        fail_apply: bool,
        read_count: usize,
        mutate_on_read: Option<(usize, (u64, usize), u64)>,
    }

    impl target_seal::Sealed for FakeTarget {}

    #[allow(
        unsafe_code,
        reason = "the host fake clones state before publishing its atomic batch"
    )]
    unsafe impl AtomicPageTableTarget for FakeTarget {
        type Error = ();

        fn read_entry(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error> {
            self.read_count += 1;
            if let Some((read, location, value)) = self.mutate_on_read
                && self.read_count == read
            {
                self.entries.insert(location, value);
            }
            Ok(*self.entries.get(&(table.address(), index)).unwrap_or(&0))
        }

        fn apply(
            &mut self,
            writes: &[JournalWrite],
            invalidations: &[VirtualPage],
        ) -> Result<(), Self::Error> {
            if self.fail_apply {
                return Err(());
            }
            let mut entries = self.entries.clone();
            for write in writes.iter().copied() {
                entries.insert((write.table().address(), write.index()), write.value());
            }
            self.entries = entries;
            self.applied.extend(
                writes
                    .iter()
                    .map(|write| (write.table().address(), write.index())),
            );
            self.invalidated
                .extend(invalidations.iter().map(|page| page.address()));
            Ok(())
        }
    }

    fn mutation(table: u64, index: usize, expected: u64, replacement: u64) -> EntryMutation {
        EntryMutation {
            table: FrameAddress(table),
            index,
            expected,
            compare_mask: u64::MAX,
            replacement,
            preserve_mask: 0,
        }
    }

    #[test]
    fn journal_is_invisible_until_atomic_child_first_publication() {
        let mut target = FakeTarget::default();
        let page = VirtualPage::new(0x4000).unwrap();
        let mut journal = PageTableJournal::<_, 4, 1>::new(&mut target);
        let mut plan = MutationPlan::empty(FrameAddress(0x1000), page);
        plan.push_mutation(mutation(0x1000, 0, 0, 0x2003));
        plan.push_mutation(mutation(0x2000, 0, 0, 0x3003));
        journal.commit(&plan).unwrap();
        assert_eq!(journal.read_entry(FrameAddress(0x1000), 0), Ok(0x2003));
        journal.publish().unwrap();

        assert_eq!(target.entries.get(&(0x1000, 0)), Some(&0x2003));
        assert_eq!(target.entries.get(&(0x2000, 0)), Some(&0x3003));
        assert_eq!(target.applied, [(0x2000, 0), (0x1000, 0)]);
        assert_eq!(target.invalidated, [0x4000]);
    }

    #[test]
    fn apply_failure_and_late_conflict_leave_the_target_unchanged() {
        let page = VirtualPage::new(0x4000).unwrap();
        let mut target = FakeTarget {
            fail_apply: true,
            ..FakeTarget::default()
        };
        let mut journal = PageTableJournal::<_, 2, 1>::new(&mut target);
        let mut plan = MutationPlan::empty(FrameAddress(0x1000), page);
        plan.push_mutation(mutation(0x1000, 0, 0, 0x2003));
        journal.commit(&plan).unwrap();
        assert_eq!(journal.publish(), Err(PageTableJournalError::Access(())));
        assert!(target.entries.is_empty());
        assert!(target.invalidated.is_empty());

        target.fail_apply = false;
        target.read_count = 0;
        target.mutate_on_read = Some((2, (0x1000, 0), 7));
        let mut journal = PageTableJournal::<_, 2, 1>::new(&mut target);
        journal.commit(&plan).unwrap();
        assert_eq!(journal.publish(), Err(PageTableJournalError::Conflict));
        assert_eq!(target.entries.get(&(0x1000, 0)), Some(&7));
        assert!(target.applied.is_empty());
        assert!(target.invalidated.is_empty());
    }

    #[test]
    fn capacity_failure_rolls_back_the_entire_plan_overlay() {
        let mut target = FakeTarget::default();
        let page = VirtualPage::new(0x4000).unwrap();
        let mut journal = PageTableJournal::<_, 1, 1>::new(&mut target);
        let mut plan = MutationPlan::empty(FrameAddress(0x1000), page);
        plan.push_mutation(mutation(0x1000, 0, 0, 0x2003));
        plan.push_mutation(mutation(0x2000, 0, 0, 0x3003));
        assert_eq!(journal.commit(&plan), Err(CommitError::TableClaimRejected));
        assert_eq!(journal.read_entry(FrameAddress(0x1000), 0), Ok(0));
        journal.publish().unwrap();
        assert!(target.entries.is_empty());
        assert!(target.invalidated.is_empty());
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "the host model attests synthetic frame zeroing and root ownership"
    )]
    fn owned_journal_claims_candidate_chain_only_after_target_publication() {
        let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
        let capabilities = PagingCapabilities {
            physical_limit: limit,
        };
        let mut roles = synthetic_frame_role_manager::<1, 16>(0x1000, 8);
        let owner = roles.create_table_owner().unwrap();

        let root_allocation = roles.allocate(1).unwrap();
        let root = unsafe { roles.assume_zeroed(root_allocation) }.unwrap();
        let root = roles.prepare_table(root, owner, TableLevel::Pml4).unwrap();
        let root = roles.commit_table(root, None).unwrap();
        let page_tables =
            unsafe { PageTableRoot::from_owned_root(root.physical_start(), capabilities) }.unwrap();

        let mut candidates: [Option<TableCandidateGrant>; 3] = [const { None }; 3];
        for (slot, level) in [TableLevel::Pdpt, TableLevel::Pd, TableLevel::Pt]
            .into_iter()
            .enumerate()
        {
            let allocation = roles.allocate(1).unwrap();
            let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
            candidates[slot] = Some(roles.prepare_table(zeroed, owner, level).unwrap());
        }
        let candidate_addresses: [u64; 3] = core::array::from_fn(|slot| {
            candidates[slot]
                .as_ref()
                .expect("candidate slot is populated")
                .physical_start()
        });

        let backing_allocation = roles.allocate(1).unwrap();
        let backing = unsafe { roles.assume_zeroed(backing_allocation) }.unwrap();
        let backing = roles.assign_object_backing(backing).unwrap();
        let mut target = FakeTarget::default();
        let page = VirtualPage::new(0x4000).unwrap();

        let mut journal = OwnedPageTableJournal::<_, 1, 16, 3, 8, 1>::new(
            &mut target,
            &mut roles,
            root,
            limit,
            &mut candidates,
        )
        .unwrap();
        journal
            .authorize_leaf(backing.identity(), backing.physical_start())
            .unwrap();
        page_tables
            .map_page(
                &mut journal,
                page,
                backing.physical_start(),
                MappingPermissions::USER_READ_WRITE,
                &candidate_addresses,
            )
            .unwrap();
        journal.publish().unwrap();

        assert!(candidates.iter().all(Option::is_none));
        assert_eq!(target.applied.len(), 4);
        assert_eq!(target.applied[0].0, candidate_addresses[2]);
        assert_eq!(target.applied[3].0, root.physical_start());
        for (address, level) in
            candidate_addresses
                .into_iter()
                .zip([TableLevel::Pdpt, TableLevel::Pd, TableLevel::Pt])
        {
            assert!(roles.table_identity(owner, level, address).is_ok());
        }
        assert_eq!(roles.check_invariants(), Ok(()));
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "the host model attests synthetic frame zeroing and root ownership"
    )]
    fn owned_journal_restores_candidate_grants_when_atomic_target_rejects() {
        let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
        let capabilities = PagingCapabilities {
            physical_limit: limit,
        };
        let mut roles = synthetic_frame_role_manager::<1, 16>(0x1000, 8);
        let owner = roles.create_table_owner().unwrap();
        let allocation = roles.allocate(1).unwrap();
        let root = unsafe { roles.assume_zeroed(allocation) }.unwrap();
        let root = roles.prepare_table(root, owner, TableLevel::Pml4).unwrap();
        let root = roles.commit_table(root, None).unwrap();
        let page_tables =
            unsafe { PageTableRoot::from_owned_root(root.physical_start(), capabilities) }.unwrap();

        let mut candidates: [Option<TableCandidateGrant>; 3] = [const { None }; 3];
        for (slot, level) in [TableLevel::Pdpt, TableLevel::Pd, TableLevel::Pt]
            .into_iter()
            .enumerate()
        {
            let allocation = roles.allocate(1).unwrap();
            let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
            candidates[slot] = Some(roles.prepare_table(zeroed, owner, level).unwrap());
        }
        let addresses: [u64; 3] =
            core::array::from_fn(|slot| candidates[slot].as_ref().unwrap().physical_start());
        let allocation = roles.allocate(1).unwrap();
        let backing = unsafe { roles.assume_zeroed(allocation) }.unwrap();
        let backing = roles.assign_object_backing(backing).unwrap();
        let mut target = FakeTarget {
            fail_apply: true,
            ..FakeTarget::default()
        };
        let page = VirtualPage::new(0x4000).unwrap();

        let mut journal = OwnedPageTableJournal::<_, 1, 16, 3, 8, 1>::new(
            &mut target,
            &mut roles,
            root,
            limit,
            &mut candidates,
        )
        .unwrap();
        journal
            .authorize_leaf(backing.identity(), backing.physical_start())
            .unwrap();
        page_tables
            .map_page(
                &mut journal,
                page,
                backing.physical_start(),
                MappingPermissions::USER_READ_ONLY,
                &addresses,
            )
            .unwrap();
        assert_eq!(
            journal.publish(),
            Err(OwnedPageTableJournalError::Target(()))
        );

        assert!(candidates.iter().all(Option::is_some));
        assert!(target.entries.is_empty());
        assert!(target.invalidated.is_empty());
        for (candidate, level) in
            candidates
                .iter()
                .zip([TableLevel::Pdpt, TableLevel::Pd, TableLevel::Pt])
        {
            assert_eq!(candidate.as_ref().unwrap().level(), level);
        }
        assert_eq!(roles.check_invariants(), Ok(()));
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "the host model attests synthetic frame zeroing, root ownership, and immutable module provenance"
    )]
    fn owned_journal_derives_writability_from_the_leaf_replacement() {
        let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
        let capabilities = PagingCapabilities {
            physical_limit: limit,
        };
        let mut roles = synthetic_frame_role_manager::<1, 16>(0x1000, 8);
        let owner = roles.create_table_owner().unwrap();
        let allocation = roles.allocate(1).unwrap();
        let root = unsafe { roles.assume_zeroed(allocation) }.unwrap();
        let root = roles.prepare_table(root, owner, TableLevel::Pml4).unwrap();
        let root = roles.commit_table(root, None).unwrap();
        let page_tables =
            unsafe { PageTableRoot::from_owned_root(root.physical_start(), capabilities) }.unwrap();

        let mut candidates: [Option<TableCandidateGrant>; 3] = [const { None }; 3];
        for (slot, level) in [TableLevel::Pdpt, TableLevel::Pd, TableLevel::Pt]
            .into_iter()
            .enumerate()
        {
            let allocation = roles.allocate(1).unwrap();
            let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
            candidates[slot] = Some(roles.prepare_table(zeroed, owner, level).unwrap());
        }
        let candidate_addresses: [u64; 3] = core::array::from_fn(|slot| {
            candidates[slot]
                .as_ref()
                .expect("candidate slot is populated")
                .physical_start()
        });

        let immutable_range = PhysicalRange::new(0x20_000, BASE_PAGE_SIZE).unwrap();
        let backing = unsafe { roles.import_immutable_module(immutable_range, 0) }.unwrap();
        let page = VirtualPage::new(0x4000).unwrap();
        let mut target = FakeTarget::default();

        {
            let mut journal = OwnedPageTableJournal::<_, 1, 16, 3, 8, 1>::new(
                &mut target,
                &mut roles,
                root,
                limit,
                &mut candidates,
            )
            .unwrap();
            journal
                .authorize_leaf(backing.identity(), backing.physical_start())
                .unwrap();
            assert_eq!(
                page_tables.map_page(
                    &mut journal,
                    page,
                    backing.physical_start(),
                    MappingPermissions::USER_READ_WRITE,
                    &candidate_addresses,
                ),
                Err(super::super::MapError::TableClaimRejected)
            );
        }
        assert!(candidates.iter().all(Option::is_some));
        assert!(target.entries.is_empty());

        {
            let mut journal = OwnedPageTableJournal::<_, 1, 16, 3, 8, 1>::new(
                &mut target,
                &mut roles,
                root,
                limit,
                &mut candidates,
            )
            .unwrap();
            journal
                .authorize_leaf(backing.identity(), backing.physical_start())
                .unwrap();
            page_tables
                .map_page(
                    &mut journal,
                    page,
                    backing.physical_start(),
                    MappingPermissions::USER_READ_ONLY,
                    &candidate_addresses,
                )
                .unwrap();
            journal.publish().unwrap();
        }
        assert!(candidates.iter().all(Option::is_none));
        let published = target.entries.clone();

        {
            let mut journal = OwnedPageTableJournal::<_, 1, 16, 3, 8, 1>::new(
                &mut target,
                &mut roles,
                root,
                limit,
                &mut candidates,
            )
            .unwrap();
            journal
                .authorize_leaf(backing.identity(), backing.physical_start())
                .unwrap();
            assert_eq!(
                page_tables.protect_page(&mut journal, page, MappingPermissions::USER_READ_WRITE,),
                Err(super::super::MapError::TableClaimRejected)
            );
        }
        assert_eq!(target.entries, published);
        assert_eq!(target.invalidated, [page.address()]);
        assert_eq!(roles.check_invariants(), Ok(()));
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "the negative host model deliberately presents mismatched authority and root identities"
    )]
    fn publisher_construction_rejects_mechanically_detectable_binding_mismatches() {
        let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
        let capabilities = PagingCapabilities {
            physical_limit: limit,
        };
        let mut roles = synthetic_frame_role_manager::<1, 16>(0x1000, 8);
        let owner = roles.create_table_owner().unwrap();
        let allocation = roles.allocate(1).unwrap();
        let root = unsafe { roles.assume_zeroed(allocation) }.unwrap();
        let root = roles.prepare_table(root, owner, TableLevel::Pml4).unwrap();
        let root = roles.commit_table(root, None).unwrap();
        let page_tables =
            unsafe { PageTableRoot::from_owned_root(root.physical_start(), capabilities) }.unwrap();

        let child = roles.allocate(1).unwrap();
        let child = unsafe { roles.assume_zeroed(child) }.unwrap();
        let child = roles.prepare_table(child, owner, TableLevel::Pdpt).unwrap();
        let child = roles.commit_table(child, Some(root)).unwrap();
        let child_as_root =
            unsafe { PageTableRoot::from_owned_root(child.physical_start(), capabilities) }
                .unwrap();
        let wrong_frame =
            unsafe { PageTableRoot::from_owned_root(0x20_000, capabilities) }.unwrap();

        let mut authority = unsafe { AddressSpaceAuthority::<1, 1>::new() };
        let address_space = authority.create_address_space().unwrap();
        let region = authority
            .create_region::<1>(address_space, 0x4000, BASE_PAGE_SIZE)
            .unwrap();
        let mut foreign_authority = unsafe { AddressSpaceAuthority::<1, 1>::new() };
        let foreign_address_space = foreign_authority.create_address_space().unwrap();
        let mut target = FakeTarget::default();
        let mut candidates: [Option<TableCandidateGrant>; 0] = [];

        assert!(matches!(
            unsafe {
                X86AddressSpacePublisher::<_, 1, 16, 0, 1, 1>::new(
                    foreign_address_space,
                    region.region_key(),
                    &page_tables,
                    root,
                    &mut roles,
                    &mut target,
                    &mut candidates,
                )
            },
            Err(X86AddressSpacePublishError::Identity)
        ));
        assert!(matches!(
            unsafe {
                X86AddressSpacePublisher::<_, 1, 16, 0, 1, 1>::new(
                    address_space,
                    region.region_key(),
                    &wrong_frame,
                    root,
                    &mut roles,
                    &mut target,
                    &mut candidates,
                )
            },
            Err(X86AddressSpacePublishError::Identity)
        ));
        assert!(matches!(
            unsafe {
                X86AddressSpacePublisher::<_, 1, 16, 0, 1, 1>::new(
                    address_space,
                    region.region_key(),
                    &child_as_root,
                    child,
                    &mut roles,
                    &mut target,
                    &mut candidates,
                )
            },
            Err(X86AddressSpacePublishError::Identity)
        ));

        let mut foreign_roles = synthetic_frame_role_manager::<1, 4>(0x1000, 2);
        let foreign_owner = foreign_roles.create_table_owner().unwrap();
        let foreign_root = foreign_roles.allocate(1).unwrap();
        let foreign_root = unsafe { foreign_roles.assume_zeroed(foreign_root) }.unwrap();
        let foreign_root = foreign_roles
            .prepare_table(foreign_root, foreign_owner, TableLevel::Pml4)
            .unwrap();
        let foreign_root = foreign_roles.commit_table(foreign_root, None).unwrap();
        let foreign_page_tables =
            unsafe { PageTableRoot::from_owned_root(foreign_root.physical_start(), capabilities) }
                .unwrap();
        assert!(matches!(
            unsafe {
                X86AddressSpacePublisher::<_, 1, 16, 0, 1, 1>::new(
                    address_space,
                    region.region_key(),
                    &foreign_page_tables,
                    foreign_root,
                    &mut roles,
                    &mut target,
                    &mut candidates,
                )
            },
            Err(X86AddressSpacePublishError::FrameRole(_))
        ));
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "the host integration model attests synthetic frame zeroing, root ownership, and handle authority"
    )]
    fn address_region_bridge_commits_replacements_and_rolls_back_target_failure() {
        let limit = PhysicalAddressLimit::new(1_u64 << 40).unwrap();
        let capabilities = PagingCapabilities {
            physical_limit: limit,
        };
        let mut roles = synthetic_frame_role_manager::<1, 32>(0x1000, 16);
        let owner = roles.create_table_owner().unwrap();
        let allocation = roles.allocate(1).unwrap();
        let root = unsafe { roles.assume_zeroed(allocation) }.unwrap();
        let root = roles.prepare_table(root, owner, TableLevel::Pml4).unwrap();
        let root = roles.commit_table(root, None).unwrap();
        let page_tables =
            unsafe { PageTableRoot::from_owned_root(root.physical_start(), capabilities) }.unwrap();

        let mut candidates: [Option<TableCandidateGrant>; 3] = [const { None }; 3];
        for (slot, level) in [TableLevel::Pt, TableLevel::Pdpt, TableLevel::Pd]
            .into_iter()
            .enumerate()
        {
            let allocation = roles.allocate(1).unwrap();
            let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
            candidates[slot] = Some(roles.prepare_table(zeroed, owner, level).unwrap());
        }
        let pt_address = candidates
            .iter()
            .flatten()
            .find(|candidate| candidate.level() == TableLevel::Pt)
            .unwrap()
            .physical_start();

        let allocation = roles.allocate(2).unwrap();
        let backing = unsafe { roles.assume_zeroed(allocation) }.unwrap();
        let backing = roles.assign_object_backing(backing).unwrap();
        let backing_start = backing.physical_start();
        let mut objects = MemoryObjectAuthority::<1, 8>::new();
        let object = objects
            .grant_backing(
                backing,
                BASE_PAGE_SIZE * 2,
                MemoryObjectKind::PageBacked,
                Protection::READ_WRITE_EXECUTE,
            )
            .unwrap();

        let mut spaces = unsafe { AddressSpaceAuthority::<1, 1>::new() };
        let address_space = spaces.create_address_space().unwrap();
        let mut region = spaces
            .create_region::<4>(address_space, 0x4000, BASE_PAGE_SIZE * 4)
            .unwrap();
        let mut target = FakeTarget::default();
        {
            let mut limited = unsafe {
                X86AddressSpacePublisher::<_, 1, 32, 3, 32, 1>::new(
                    region.address_space_key(),
                    region.region_key(),
                    &page_tables,
                    root,
                    &mut roles,
                    &mut target,
                    &mut candidates,
                )
            }
            .unwrap();
            let authorization = unsafe {
                region
                    .authorize_map(&objects, object, Protection::READ_WRITE_EXECUTE)
                    .unwrap()
            };
            assert!(matches!(
                region.map(
                    &mut objects,
                    &mut limited,
                    0x4000,
                    authorization,
                    0,
                    BASE_PAGE_SIZE * 2,
                    Protection::READ_WRITE,
                ),
                Err(
                    crate::memory::address_region::AddressSpaceTransactionError::Publish(
                        X86AddressSpacePublishError::Capacity
                    )
                )
            ));
        }
        assert!(region.mappings().iter().all(Option::is_none));
        assert_eq!(objects.active_lease_count(), 0);
        assert!(target.entries.is_empty());
        assert!(candidates.iter().all(Option::is_some));

        {
            let mut publisher = unsafe {
                X86AddressSpacePublisher::<_, 1, 32, 3, 32, 8>::new(
                    region.address_space_key(),
                    region.region_key(),
                    &page_tables,
                    root,
                    &mut roles,
                    &mut target,
                    &mut candidates,
                )
            }
            .unwrap();

            let authorization = unsafe {
                region
                    .authorize_map(&objects, object, Protection::READ_WRITE_EXECUTE)
                    .unwrap()
            };
            region
                .map(
                    &mut objects,
                    &mut publisher,
                    0x4000,
                    authorization,
                    0,
                    BASE_PAGE_SIZE * 2,
                    Protection::READ_WRITE,
                )
                .unwrap();
            region
                .unmap(&mut objects, &mut publisher, 0x4000, BASE_PAGE_SIZE)
                .unwrap();
            region
                .protect(
                    &mut objects,
                    &mut publisher,
                    0x5000,
                    BASE_PAGE_SIZE,
                    Protection::READ_EXECUTE,
                )
                .unwrap();
            assert_eq!(region.mappings().iter().flatten().count(), 1);
            assert_eq!(objects.active_lease_count(), 1);

            publisher.target.fail_apply = true;
            let authorization = unsafe {
                region
                    .authorize_map(&objects, object, Protection::READ_EXECUTE)
                    .unwrap()
            };
            assert!(matches!(
                region.map(
                    &mut objects,
                    &mut publisher,
                    0x4000,
                    authorization,
                    0,
                    BASE_PAGE_SIZE,
                    Protection::READ_EXECUTE,
                ),
                Err(
                    crate::memory::address_region::AddressSpaceTransactionError::Publish(
                        X86AddressSpacePublishError::Journal(
                            OwnedPageTableJournalError::Target(())
                        )
                    )
                )
            ));
            assert_eq!(region.mappings().iter().flatten().count(), 1);
            assert_eq!(objects.active_lease_count(), 1);

            publisher.target.fail_apply = false;
            let authorization = unsafe {
                region
                    .authorize_map(&objects, object, Protection::READ_EXECUTE)
                    .unwrap()
            };
            region
                .map(
                    &mut objects,
                    &mut publisher,
                    0x4000,
                    authorization,
                    0,
                    BASE_PAGE_SIZE,
                    Protection::READ_EXECUTE,
                )
                .unwrap();
        }

        assert!(candidates.iter().all(Option::is_none));
        assert_eq!(target.invalidated, [0x4000, 0x5000, 0x4000, 0x5000, 0x4000]);
        assert_eq!(
            target.entries.get(&(pt_address, 4)).copied(),
            Some(backing_start | super::super::PRESENT | super::super::USER)
        );
        assert_eq!(objects.active_lease_count(), 2);
        assert_eq!(roles.check_invariants(), Ok(()));
    }
}
