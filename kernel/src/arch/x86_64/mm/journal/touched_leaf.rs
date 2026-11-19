//! One touched leaf, found by one walk and written by one store (DW2
//! §13.16 part e1), over shared access to the role manager (DW2 §15.2).
//!
//! [`TouchedLeafWriter`] holds `&FrameRoleManager`, the target, the root
//! and its identity, and the address space and region the walk and the
//! write check. Nothing it does needs the role manager mutably: it reads
//! table identities and resolves the backing's page. The publisher builds
//! one from its own borrows for each call and delegates
//! ([`X86AddressSpacePublisher::find_touched_leaf`] and
//! [`X86AddressSpacePublisher::write_touched_leaf`]); the commit between
//! them stays on the publisher, which alone holds the role manager mutably.

use super::super::{MapError, PageTableRoot};
use super::publisher::{mapping_permissions, page_descriptor, validate_mapping_batch};
use super::*;

/// What [`TouchedLeafWriter::find_touched_leaf`] found (DW2 §13.16 part
/// e1).
#[cfg_attr(
    not(all(target_os = "none", target_arch = "x86_64")),
    allow(
        dead_code,
        reason = "the live fault gate is its only reader outside tests"
    )
)]
#[allow(
    clippy::large_enum_variant,
    reason = "made once a fault and consumed in the same hold, on the stack: the mapping it carries is what the write checks"
)]
pub(crate) enum TouchedLeaf<'a> {
    /// All three tables above the leaf exist: where the leaf is, for
    /// [`TouchedLeafWriter::write_touched_leaf`].
    Found(TouchedLeafPlace<'a>),
    /// This many page tables are missing, counted as `touch_table_cost`
    /// counts them: the journal publishes this leaf.
    MissingTables(usize),
}

/// Where a touched leaf is, found by one walk and not yet written (DW2
/// §13.16 part e1). It is consumed by the one write it allows. Its lifetime
/// brands it with the writer that found it: a publisher's writers carry the
/// publisher's borrow of its root, target and role manager, so a place
/// cannot be written by a publisher made from a later borrow, and the
/// root's tables cannot be changed by anything else while it exists.
#[must_use = "a found leaf is written or dropped in the hold that found it"]
pub(crate) struct TouchedLeafPlace<'a> {
    pub(super) mapping: Mapping,
    pub(super) page: VirtualPage,
    /// The root, PDPT, PD and PT, as the walk decoded them.
    pub(super) path: [FrameAddress; 4],
    /// A table appeared twice on the path.
    pub(super) revisits: bool,
    /// The first table on the path that is not this root's own, at its level
    /// and under its parent: the error the role manager gave.
    pub(super) unauthenticated: Option<FrameRoleError>,
    /// The page's frame, set only by
    /// [`X86AddressSpacePublisher::commit_touched_page`] from the commit's
    /// one walk of the backing's index (DW2 §13.18 part f1); `None` from
    /// `find_touched_leaf`, and the write then resolves the page itself.
    pub(super) frame: Option<u64>,
    pub(super) _writer: core::marker::PhantomData<fn(&'a ()) -> &'a ()>,
}

/// The walk and the store of one touched leaf, over `&FrameRoleManager`
/// (DW2 §15.2). `'w` is the borrow of the root, role manager and target;
/// `'p` brands the places it finds and accepts.
///
/// Its walk and its store are inlined into each caller (the publisher's
/// two methods and the shared serve's leaf), so a publisher's find and
/// write compile as they did when they were the publisher's own bodies:
/// no writer is built in memory and no place is copied between them.
pub(crate) struct TouchedLeafWriter<
    'w,
    'p,
    T,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
> {
    address_space: AddressSpaceKey,
    region: RegionKey,
    root: &'w PageTableRoot,
    root_identity: TableIdentity,
    roles: &'w FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    target: &'w mut T,
    _places: core::marker::PhantomData<fn(&'p ()) -> &'p ()>,
}

/// The checks [`X86AddressSpacePublisher::new`] makes of its root, before
/// it binds the root to a target: the address space and region are of one
/// domain, the root identity names the root's frame at the PML4 level, and
/// the role manager knows that identity.
pub(super) fn check_root<E, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    address_space: AddressSpaceKey,
    region: RegionKey,
    root: &PageTableRoot,
    root_identity: TableIdentity,
    roles: &FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
) -> Result<(), X86AddressSpacePublishError<E>> {
    if !address_space.same_domain(region)
        || root.frame().address() != root_identity.physical_start()
        || root_identity.level() != TableLevel::Pml4
    {
        return Err(X86AddressSpacePublishError::Identity);
    }
    roles
        .validate_table_identity(root_identity)
        .map_err(X86AddressSpacePublishError::FrameRole)
}

impl<'w, T, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    TouchedLeafWriter<'w, 'w, T, RANGE_CAPACITY, ROLE_CAPACITY>
where
    T: AtomicPageTableTarget,
{
    /// A writer over `roles` and `target` for `root`, after the checks
    /// [`X86AddressSpacePublisher::new`] makes of its root
    /// ([`check_root`]): the shared fault session's (DW2 §15.2).
    ///
    /// # Safety
    ///
    /// - `address_space` and `region` are authority-issued identities for
    ///   the exact address space `root` and `root_identity` represent, and
    ///   `target` reads and writes the hierarchy rooted at that exact root.
    /// - For the writer's lifetime no table of that root is added, removed
    ///   or re-parented and no present leaf is changed or cleared: the
    ///   caller holds P, shared or exclusive, and every such change needs P
    ///   exclusive.
    /// - Other writers over the same root may exist at once on other CPUs.
    ///   Each stores only an empty leaf, inside a mutation span over that
    ///   page which its target holds in the pin tracker, and reads the leaf
    ///   again inside the span before it stores
    ///   ([`Self::write_touched_leaf`]), so two never store one leaf.
    ///
    /// This is not the publisher's contract: a publisher is the only
    /// mutator of its root for its lifetime; a writer is not.
    #[cfg_attr(
        not(all(target_os = "none", target_arch = "x86_64")),
        allow(dead_code, reason = "only the live shared fault session builds one")
    )]
    #[allow(
        unsafe_code,
        reason = "the caller attests the root, address-space and target binding and holds P"
    )]
    pub(crate) unsafe fn new(
        address_space: AddressSpaceKey,
        region: RegionKey,
        root: &'w PageTableRoot,
        root_identity: TableIdentity,
        roles: &'w FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
        target: &'w mut T,
    ) -> Result<Self, X86AddressSpacePublishError<T::Error>> {
        check_root(address_space, region, root, root_identity, roles)?;
        Ok(Self::from_parts(
            address_space,
            region,
            root,
            root_identity,
            roles,
            target,
        ))
    }
}

impl<'w, 'p, T, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    TouchedLeafWriter<'w, 'p, T, RANGE_CAPACITY, ROLE_CAPACITY>
where
    T: AtomicPageTableTarget,
{
    /// A writer from parts whose root has passed [`check_root`] and whose
    /// binding is attested: a publisher's own borrows (its constructor made
    /// both), with the publisher's brand for places.
    #[inline(always)]
    pub(super) fn from_parts(
        address_space: AddressSpaceKey,
        region: RegionKey,
        root: &'w PageTableRoot,
        root_identity: TableIdentity,
        roles: &'w FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
        target: &'w mut T,
    ) -> Self {
        Self {
            address_space,
            region,
            root,
            root_identity,
            roles,
            target,
            _places: core::marker::PhantomData,
        }
    }

    /// One walk from the root to the leaf a touch at `address` of `mapping`
    /// needs, writing nothing (DW2 §13.16 part e1). It reads and decodes
    /// the three table entries as `touch_table_cost` does and fails as it
    /// does, so `MissingTables(n)` is its count. When every table exists it
    /// also authenticates each as the journal does (this root's own, at its
    /// level, under its parent) and returns the leaf's place; what that
    /// authentication and the walk found wrong is reported by
    /// [`Self::write_touched_leaf`] where `publish_touched_leaf` reports
    /// it, after the commit, so a serve's outcomes are the journal path's.
    #[cfg_attr(
        not(all(target_os = "none", target_arch = "x86_64")),
        allow(
            dead_code,
            reason = "the live fault gate is its only caller outside tests"
        )
    )]
    #[inline(always)]
    pub(crate) fn find_touched_leaf(
        &mut self,
        mapping: &Mapping,
        address: u64,
    ) -> Result<TouchedLeaf<'p>, X86AddressSpacePublishError<T::Error>> {
        let page =
            VirtualPage::new(address).map_err(|_| X86AddressSpacePublishError::InvalidMapping)?;
        // As `touch_table_cost`'s journal checks its root.
        self.roles
            .validate_table_identity(self.root_identity)
            .map_err(X86AddressSpacePublishError::FrameRole)?;
        // As `missing_tables`.
        if page.address() == 0 {
            return Err(X86AddressSpacePublishError::Map(MapError::PageZero));
        }
        let user = page.is_user_half();
        let limit = self.root.physical_limit();
        let mut path = [self.root.frame(); 4];
        let mut parent = self.root_identity;
        let mut revisits = false;
        let mut unauthenticated = None;
        for (depth, level) in (1..=3).rev().enumerate() {
            let entry = self
                .target
                .read_entry(path[depth], page.index(level))
                .map_err(|error| {
                    X86AddressSpacePublishError::Map(MapError::Access(
                        OwnedPageTableJournalError::Target(error),
                    ))
                })?;
            if entry == 0 {
                return Ok(TouchedLeaf::MissingTables(3 - depth));
            }
            // Strict: an ancestor of a user leaf without the user bit, or
            // one with it above a supervisor leaf, fails here as it does in
            // `missing_tables`.
            let child = super::super::decode_intermediate(entry, user, limit)
                .map_err(|_| X86AddressSpacePublishError::Map(MapError::InvalidPath))?;
            revisits |= path[..=depth].contains(&child);
            path[depth + 1] = child;
            if unauthenticated.is_none() {
                // As `validate_present_path` and `validate_plan`: the table
                // is this root owner's, at the child level, and its parent
                // is the table above it.
                match self
                    .roles
                    .table_identity(
                        self.root_identity.owner(),
                        level_for_index(level - 1),
                        child.address(),
                    )
                    .and_then(|table| {
                        self.roles
                            .validate_table_child(parent, table)
                            .map(|()| table)
                    }) {
                    Ok(table) => parent = table,
                    Err(error) => unauthenticated = Some(error),
                }
            }
        }
        Ok(TouchedLeaf::Found(TouchedLeafPlace {
            mapping: *mapping,
            page,
            path,
            revisits,
            unauthenticated,
            frame: None,
            _writer: core::marker::PhantomData,
        }))
    }

    /// Resolves the page `place` was found for as [`Self::write_touched_leaf`]'s
    /// resolve does (DW2 §15.2), for a serve that takes no frame:
    /// `page_descriptor` with the mapping's writability, refusing a backing
    /// that is not on demand. `Ok(true)`: the page has a frame, recorded in
    /// `place` as a commit through the place records it, so the write
    /// takes it from there and does not resolve the page again (its
    /// permissions are the mapping's, as the resolve's are). `Ok(false)`:
    /// the page is absent, and `place` is unchanged. Any other error is the
    /// resolve's.
    #[cfg_attr(
        not(all(target_os = "none", target_arch = "x86_64")),
        allow(dead_code, reason = "only the live shared fast serve resolves")
    )]
    pub(crate) fn resolve_touched_page(
        &mut self,
        place: &mut TouchedLeafPlace<'p>,
    ) -> Result<bool, X86AddressSpacePublishError<T::Error>> {
        let address = place.page.address();
        let descriptor = page_descriptor(self.roles, &place.mapping, address, &mut None)?;
        if !descriptor.on_demand {
            return Err(X86AddressSpacePublishError::InvalidMapping);
        }
        Ok(descriptor.physical_start.is_some_and(|physical_start| {
            place.frame = Some(physical_start);
            true
        }))
    }

    /// Writes the leaf `place` was found for, as `publish_touched_leaf`
    /// would with every table present, and with one store (DW2 §13.16 part
    /// e1). It makes `publish_touched_leaf`'s checks in its order and
    /// returns its results: the mapping and the page's committed frame;
    /// then the leaf, read once, `Ok(false)` when it is exactly this page's
    /// leaf apart from the accessed and dirty bits and `FrameMismatch` when
    /// it is another; then, for an empty leaf, `map_page`'s checks and the
    /// journal's authentication of the path; and then writes the entry
    /// `map_page` would, through `apply`, with no invalidation (empty to
    /// present needs none), inside a mutation span over exactly this page,
    /// which the target reserves against user pins, another mutation and a
    /// teardown reservation as the journal's `apply` reserves the page it
    /// invalidates; a refusal is returned as the journal returns it, and
    /// the span is ended on every path after it was begun. An
    /// already-present leaf reserves nothing, as in the journal path. One
    /// new leaf under existing tables changes no frame role. When the page
    /// was committed through `place`
    /// ([`X86AddressSpacePublisher::commit_touched_page`]), its frame is
    /// the commit's and is not resolved again (DW2 §13.18 part f1); every
    /// other check is made as above, in its order.
    #[cfg_attr(
        not(all(target_os = "none", target_arch = "x86_64")),
        allow(
            dead_code,
            reason = "the live fault gate is its only caller outside tests"
        )
    )]
    #[inline(always)]
    pub(crate) fn write_touched_leaf(
        &mut self,
        place: TouchedLeafPlace<'p>,
    ) -> Result<bool, X86AddressSpacePublishError<T::Error>> {
        let TouchedLeafPlace {
            mapping,
            page,
            path,
            revisits,
            unauthenticated,
            frame: committed,
            _writer,
        } = place;
        // A place found under another root is no place of this one.
        if path[0] != self.root.frame() {
            return Err(X86AddressSpacePublishError::Identity);
        }
        let address = page.address();
        validate_mapping_batch(
            self.roles,
            self.address_space,
            self.region,
            core::slice::from_ref(&mapping),
        )?;
        if address < mapping.virtual_start()
            || address - mapping.virtual_start() >= mapping.byte_len()
        {
            return Err(X86AddressSpacePublishError::InvalidMapping);
        }
        // As the journal checks its root when it is made, before staging
        // and before publishing; nothing in this hold changes it between.
        self.roles
            .validate_table_identity(self.root_identity)
            .map_err(X86AddressSpacePublishError::FrameRole)?;
        // The frame is the backing's page at this offset, resolved with
        // the writability the leaf will carry: `authorize_leaf` and the
        // journal's plan check resolve the same page again and compare.
        // A commit through this place already resolved it in its one walk
        // of the on-demand backing's index, under this publisher's borrow of
        // the role manager, which nothing else changes before this write
        // (DW2 §13.18 part f1).
        let (physical_start, permissions) = match committed {
            Some(physical_start) => (physical_start, mapping_permissions(&mapping)),
            None => {
                let descriptor = page_descriptor(self.roles, &mapping, address, &mut None)?;
                if !descriptor.on_demand {
                    return Err(X86AddressSpacePublishError::InvalidMapping);
                }
                let physical_start =
                    descriptor
                        .physical_start
                        .ok_or(X86AddressSpacePublishError::FrameRole(
                            FrameRoleError::Absent,
                        ))?;
                (physical_start, descriptor.permissions)
            }
        };
        let limit = self.root.physical_limit();
        let frame = super::super::FrameAddress::new(physical_start, limit)
            .map_err(|_| X86AddressSpacePublishError::Map(MapError::FrameMismatch))?;
        // As `present_leaf_matches`, on the walk `find_touched_leaf` made.
        if revisits {
            return Err(X86AddressSpacePublishError::Map(MapError::InvalidPath));
        }
        let index = page.index(0);
        let leaf = self.target.read_entry(path[3], index).map_err(|error| {
            X86AddressSpacePublishError::Map(MapError::Access(OwnedPageTableJournalError::Target(
                error,
            )))
        })?;
        let entry = super::super::leaf_entry(frame, permissions);
        if leaf != 0 {
            return present_leaf(leaf, entry, page, limit, unauthenticated);
        }
        // As `map_page`: the policy, and a frame that is no table of the
        // path. (`decode_intermediate` above already required each table
        // entry present, not huge and with the user bit a user leaf needs.)
        super::super::validate_mapping(page, permissions)
            .map_err(|error| X86AddressSpacePublishError::Map(super::super::policy_error(error)))?;
        if path.contains(&frame) {
            return Err(X86AddressSpacePublishError::Map(MapError::InvalidPath));
        }
        // As the journal's plan check, which refuses a plan through a table
        // that is not this root's own.
        if unauthenticated.is_some() {
            return Err(X86AddressSpacePublishError::Map(
                MapError::TableClaimRejected,
            ));
        }
        // The journal's `apply` reserves the page it invalidates against
        // user pins, another mutation and a teardown reservation before it
        // stores; this store reserves exactly that page, in its place, and
        // a refusal is the journal's error for it. This span is the store's
        // own: it is begun and ended here, apart from the batch path's
        // `span_held`, and is ended only if it was begun.
        self.target
            .begin_mutation_span(address, BASE_PAGE_SIZE)
            .map_err(|error| {
                X86AddressSpacePublishError::Journal(OwnedPageTableJournalError::Target(error))
            })?;
        // The leaf is read again inside the span, and stored only while it
        // is still empty (DW2 §15.2). Under a shared hold of P another
        // CPU's serve of this page may have stored it since the read above;
        // two spans over one page are never held at once, so this read sees
        // that store, and storing again would clear the accessed and dirty
        // bits the other CPU's TLB already holds. A leaf found present is
        // answered as the read above would have answered it. Under an
        // exclusive hold nothing else stores a leaf, so this read is 0.
        let stored = match self.target.read_entry(path[3], index) {
            Err(error) => Err(X86AddressSpacePublishError::Map(MapError::Access(
                OwnedPageTableJournalError::Target(error),
            ))),
            Ok(0) => self
                .target
                .apply(&[JournalWrite::new(path[3], index, entry)], &[])
                .map(|()| true)
                .map_err(|error| {
                    X86AddressSpacePublishError::Journal(OwnedPageTableJournalError::Target(error))
                }),
            Ok(leaf) => present_leaf(leaf, entry, page, limit, unauthenticated),
        };
        self.target.end_mutation_span();
        stored
    }
}

/// What a touch answers for a present `leaf` where this page's leaf would
/// be `entry` (DW2 §13.16 part e1): the decode's error for a leaf that is
/// no valid leaf, `FrameMismatch` for one that is not `entry` apart from
/// the accessed and dirty bits, the path's authentication error if a table
/// on it is not this root's own (`validate_present_path`, §5.3a), and
/// otherwise `Ok(false)`: already this page's.
fn present_leaf<E>(
    leaf: u64,
    entry: u64,
    page: VirtualPage,
    limit: PhysicalAddressLimit,
    unauthenticated: Option<FrameRoleError>,
) -> Result<bool, X86AddressSpacePublishError<E>> {
    super::super::decode_leaf::<OwnedPageTableJournalError<E>>(leaf, page.is_user_half(), limit)
        .map_err(X86AddressSpacePublishError::Map)?;
    if leaf & !(super::super::ACCESSED | super::super::DIRTY) != entry {
        return Err(X86AddressSpacePublishError::Map(MapError::FrameMismatch));
    }
    if let Some(error) = unauthenticated {
        return Err(X86AddressSpacePublishError::Journal(
            OwnedPageTableJournalError::FrameRole(error),
        ));
    }
    Ok(false)
}
