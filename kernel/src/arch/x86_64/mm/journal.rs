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

#[path = "journal/publisher.rs"]
mod publisher;

use crate::memory::physical::BASE_PAGE_SIZE;
pub(crate) use publisher::{X86AddressSpacePublishError, X86AddressSpacePublisher};
#[cfg(test)]
use publisher::{first_mapping_start, mapping_at, next_boundary, next_mapping_start};

const ENTRY_COUNT: usize = 512;

pub(super) mod target_seal {
    pub trait Sealed {}
}

/// The architecture-owned final publication boundary beneath the journal.
///
/// # Safety
///
/// An implementation must serialize one page-table root for the complete
/// borrow, and `apply` must either publish every supplied write followed by
/// every invalidation or return an error with every owned-root entry unchanged
/// and no requested mapping invalidation or other mapping-visible TLB effect.
/// An error may follow private scratch-leaf CAS and private-window `invlpg`
/// maintenance only when that scratch state is fully restored before return.
/// Writes are supplied child-before-parent and never contain duplicate
/// locations.
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
    #[cfg(test)]
    pub(crate) const fn test_new(table: FrameAddress, index: usize, value: u64) -> Self {
        Self {
            table,
            index,
            value,
        }
    }

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
mod tests;
