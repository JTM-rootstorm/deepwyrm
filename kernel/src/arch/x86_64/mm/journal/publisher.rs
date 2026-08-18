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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PageDescriptor {
    backing: BackingIdentity,
    physical_start: u64,
    permissions: MappingPermissions,
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
            let old_page = match old {
                Some(mapping) => Some(page_descriptor(mapping, address)?),
                None => None,
            };
            let new_page = match new {
                Some(mapping) => Some(page_descriptor(mapping, address)?),
                None => None,
            };
            if old_page == new_page {
                cursor = (boundary != u64::MAX).then_some(boundary);
                continue;
            }

            let mut page_address = address;
            while page_address < boundary {
                if changed_pages == INVALIDATION_CAPACITY {
                    return Err(X86AddressSpacePublishError::Capacity);
                }
                let old_page = match old {
                    Some(mapping) => Some(page_descriptor(mapping, page_address)?),
                    None => None,
                };
                let new_page = match new {
                    Some(mapping) => Some(page_descriptor(mapping, page_address)?),
                    None => None,
                };
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
                    Err(MapError::FrameMismatch)
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

fn page_descriptor<E>(
    mapping: &Mapping,
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
        permissions: MappingPermissions {
            user: true,
            readable: true,
            writable: mapping.protection().writable(),
            executable: mapping.protection().executable(),
        },
    })
}
