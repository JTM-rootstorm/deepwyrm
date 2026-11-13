use super::*;

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>
{
    pub(super) fn new(
        allocator: PhysicalFrameAllocator<RANGE_CAPACITY>,
    ) -> Result<Self, FrameRoleError> {
        let domain = NEXT_MANAGER_DOMAIN
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1).filter(|next| *next != 0)
            })
            .map_err(|_| FrameRoleError::ManagerDomainExhausted)?;
        let mut manager = Self {
            domain,
            allocator,
            roles: GrowableStore::new(EMPTY_ROLE_SLOT),
            free_slots: GrowableStore::new(0),
            free_slot_count: 0,
            starts: None,
            next_table_owner: 1,
            next_epoch: 1,
            version: 0,
            index_memory: None,
        };
        manager.fill_boot_free_slots()?;
        Ok(manager)
    }

    /// Every boot slot is free; slot 0 is used first.
    fn fill_boot_free_slots(&mut self) -> Result<(), FrameRoleError> {
        u32::try_from(ROLE_CAPACITY).map_err(|_| FrameRoleError::Capacity)?;
        for (position, entry) in self.free_slots.as_mut_slice().iter_mut().enumerate() {
            *entry = (ROLE_CAPACITY - 1 - position) as u32;
        }
        self.free_slot_count = ROLE_CAPACITY;
        Ok(())
    }

    /// Creates the kernel's sole dynamic frame owner from a consumed map.
    ///
    /// Validation and allocator construction complete before the global
    /// one-shot claim. Once claimed, initialization is terminal even if the
    /// subsequent manager-domain allocation fails.
    ///
    /// # Safety
    ///
    /// The caller must be the sole boot-memory owner, must not have created or
    /// retained any other allocator over the handoff's usable ranges, and must
    /// retain the returned manager for the lifetime of all issued grants.
    #[allow(
        unsafe_code,
        reason = "boot ownership uniqueness cannot be derived from a repeatable sanitized-map value alone"
    )]
    pub(crate) unsafe fn from_boot_map(
        map: SanitizedBootMap,
        reservations: &[BootstrapReservation],
    ) -> Result<Self, FrameRoleInitializationError> {
        let allocator = super::super::boot_map::initialize_frame_allocator(&map, reservations)
            .map_err(FrameRoleInitializationError::BootMap)?;
        claim_manager(&FRAME_ROLE_MANAGER_CLAIMED)?;
        Self::new(allocator).map_err(FrameRoleInitializationError::Role)
    }

    /// Initializes the sole manager directly in caller-owned static storage,
    /// avoiding a large bootstrap-stack temporary.
    ///
    /// # Safety
    ///
    /// In addition to [`Self::from_boot_map`]'s ownership contract, `slot`
    /// must be unique, uninitialized storage which remains alive for every
    /// grant and active paging session issued by the returned manager.
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    #[allow(
        unsafe_code,
        reason = "one-shot bootstrap constructs the large role registry directly in static storage"
    )]
    pub(crate) unsafe fn from_boot_map_in<'a>(
        slot: &'a mut MaybeUninit<Self>,
        map: &'a SanitizedBootMap,
        reservations: &'a [BootstrapReservation],
    ) -> Result<(&'a mut Self, BootstrapMemoryWitness<'a>), FrameRoleInitializationError> {
        let destination = slot.as_mut_ptr();
        let allocator_slot = unsafe {
            &mut *core::ptr::addr_of_mut!((*destination).allocator)
                .cast::<MaybeUninit<PhysicalFrameAllocator<RANGE_CAPACITY>>>()
        };
        unsafe {
            super::super::boot_map::initialize_frame_allocator_in(allocator_slot, map, reservations)
        }
        .map_err(FrameRoleInitializationError::BootMap)?;
        claim_manager(&FRAME_ROLE_MANAGER_CLAIMED)?;
        let domain = NEXT_MANAGER_DOMAIN
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1).filter(|next| *next != 0)
            })
            .map_err(|_| {
                FrameRoleInitializationError::Role(FrameRoleError::ManagerDomainExhausted)
            })?;
        unsafe {
            core::ptr::addr_of_mut!((*destination).domain).write(domain);
            GrowableStore::init_in_place(
                core::ptr::addr_of_mut!((*destination).roles),
                EMPTY_ROLE_SLOT,
            );
            GrowableStore::init_in_place(core::ptr::addr_of_mut!((*destination).free_slots), 0);
            core::ptr::addr_of_mut!((*destination).free_slot_count).write(0);
            core::ptr::addr_of_mut!((*destination).starts).write(None);
            core::ptr::addr_of_mut!((*destination).next_table_owner).write(1);
            core::ptr::addr_of_mut!((*destination).next_epoch).write(1);
            core::ptr::addr_of_mut!((*destination).version).write(0);
            let manager = &mut *destination;
            manager
                .fill_boot_free_slots()
                .map_err(FrameRoleInitializationError::Role)?;
            Ok((manager, BootstrapMemoryWitness::new(map, reservations)))
        }
    }

    pub(crate) fn allocate(&mut self, page_count: u64) -> Result<AllocationGrant, FrameRoleError> {
        let (slot, generation) = self.next_slot()?;
        let identity = self.identity(slot, generation)?;
        let range = self.allocator.allocate_run(page_count)?;
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

    /// Allocates an uninitialized contiguous grant strictly below an exclusive
    /// physical ceiling.
    ///
    /// This is the only role-manager entry point for consumers which need a
    /// low physical run, such as an x86 AP startup trampoline. Slot and
    /// generation validation occurs before the allocator changes, and the
    /// role record is published only after a run is owned, preserving exact
    /// grant ownership across every failure path.
    pub(crate) fn allocate_below(
        &mut self,
        page_count: u64,
        exclusive_ceiling: u64,
    ) -> Result<AllocationGrant, FrameRoleError> {
        let (slot, generation) = self.next_slot()?;
        let identity = self.identity(slot, generation)?;
        let range = self
            .allocator
            .allocate_run_below(page_count, exclusive_ceiling)?;
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

    /// Revalidates a live allocation grant before architecture code mutates
    /// its physical contents.
    pub(crate) fn validate_allocation(
        &self,
        grant: &AllocationGrant,
    ) -> Result<(), FrameRoleError> {
        let record = self.record(grant.identity)?;
        if record.range != grant.range || record.role != FrameRole::AllocatedUninitialized {
            return Err(FrameRoleError::WrongRole);
        }
        Ok(())
    }

    /// Attests that architecture-owned access initialized every byte in the
    /// allocation to zero.
    ///
    /// # Safety
    ///
    /// The caller must have exclusively zeroed the complete physical run and
    /// completed any cache maintenance required before returning the grant.
    #[allow(
        unsafe_code,
        reason = "physical zeroing is an architecture access fact represented by a typed state transition"
    )]
    pub(crate) unsafe fn assume_zeroed(
        &mut self,
        grant: AllocationGrant,
    ) -> Result<ZeroedGrant, GrantTransitionError<AllocationGrant>> {
        if let Err(error) = self.transition(
            grant.identity,
            grant.range,
            FrameRole::AllocatedUninitialized,
            FrameRole::Zeroed,
        ) {
            return Err(GrantTransitionError::new(error, grant));
        }
        Ok(ZeroedGrant {
            identity: grant.identity,
            range: grant.range,
        })
    }

    /// Consumes an allocation after architecture code initialized its complete
    /// byte range for one retained bootstrap purpose.
    ///
    /// # Safety
    ///
    /// The caller must have exclusively initialized every byte of `grant`,
    /// completed any required cache maintenance, and ensured the contents
    /// satisfy the selected architecture contract.
    #[allow(
        unsafe_code,
        reason = "architecture initialization is an external physical-access fact represented by a typed role transition"
    )]
    pub(crate) unsafe fn assume_architecture_bootstrap_initialized(
        &mut self,
        grant: AllocationGrant,
        kind: ArchitectureBootstrapKind,
    ) -> Result<ArchitectureBootstrapGrant, GrantTransitionError<AllocationGrant>> {
        if let Err(error) = self.transition(
            grant.identity,
            grant.range,
            FrameRole::AllocatedUninitialized,
            FrameRole::ArchitectureBootstrap(kind),
        ) {
            return Err(GrantTransitionError::new(error, grant));
        }
        Ok(ArchitectureBootstrapGrant {
            identity: grant.identity,
            range: grant.range,
            kind,
        })
    }

    /// Revalidates retained ownership of an architecture bootstrap range.
    pub(crate) fn validate_architecture_bootstrap(
        &self,
        grant: &ArchitectureBootstrapGrant,
    ) -> Result<(), FrameRoleError> {
        let record = self.record(grant.identity)?;
        if record.range != grant.range
            || record.role != FrameRole::ArchitectureBootstrap(grant.kind)
        {
            return Err(FrameRoleError::WrongRole);
        }
        Ok(())
    }

    pub(crate) fn assign_object_backing(
        &mut self,
        grant: ZeroedGrant,
    ) -> Result<ObjectBackingGrant, GrantTransitionError<ZeroedGrant>> {
        let link = ChainLink {
            head: grant.identity.raw,
            object_page: 0,
            next: 0,
        };
        if let Err(error) = self.transition(
            grant.identity,
            grant.range,
            FrameRole::Zeroed,
            FrameRole::ObjectBacking(link),
        ) {
            return Err(GrantTransitionError::new(error, grant));
        }
        Ok(ObjectBackingGrant {
            identity: BackingIdentity(grant.identity),
            range: grant.range,
            kind: ObjectBackingKind::AllocatorOwned,
            pages: grant.range.page_count(),
            runs: 1,
        })
    }

    pub(crate) fn create_table_owner(&mut self) -> Result<TableOwnerKey, FrameRoleError> {
        let raw = self.next_table_owner;
        self.next_table_owner = raw
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(FrameRoleError::InvalidTableOwner)?;
        Ok(TableOwnerKey {
            domain: self.domain,
            raw,
        })
    }

    pub(crate) fn prepare_table(
        &mut self,
        grant: ZeroedGrant,
        owner: TableOwnerKey,
        level: TableLevel,
    ) -> Result<TableCandidateGrant, GrantTransitionError<ZeroedGrant>> {
        if let Err(error) = self.validate_owner(owner) {
            return Err(GrantTransitionError::new(error, grant));
        }
        if grant.range.page_count() != 1 {
            return Err(GrantTransitionError::new(FrameRoleError::WrongRole, grant));
        }
        if let Err(error) = self.transition(
            grant.identity,
            grant.range,
            FrameRole::Zeroed,
            FrameRole::TableCandidate { owner, level },
        ) {
            return Err(GrantTransitionError::new(error, grant));
        }
        Ok(TableCandidateGrant {
            identity: grant.identity,
            range: grant.range,
            owner,
            level,
        })
    }

    pub(crate) fn commit_table(
        &mut self,
        grant: TableCandidateGrant,
        parent: Option<TableIdentity>,
    ) -> Result<TableIdentity, GrantTransitionError<TableCandidateGrant>> {
        let parent = parent.map(TableCommitParent::Committed);
        let staged = self.stage_table_commit(grant, parent)?;
        Ok(self.publish_staged_table(staged))
    }

    pub(crate) fn stage_table_commit(
        &self,
        grant: TableCandidateGrant,
        parent: Option<TableCommitParent<'_>>,
    ) -> Result<StagedTableCommit, GrantTransitionError<TableCandidateGrant>> {
        if let Err(error) = self.validate_owner(grant.owner) {
            return Err(GrantTransitionError::new(error, grant));
        }
        let slot = match self.slot(grant.identity) {
            Ok(slot) => slot,
            Err(error) => return Err(GrantTransitionError::new(error, grant)),
        };
        if self.roles.as_slice()[slot].record
            != Some(RoleRecord {
                range: grant.range,
                role: FrameRole::TableCandidate {
                    owner: grant.owner,
                    level: grant.level,
                },
            })
        {
            return Err(GrantTransitionError::new(FrameRoleError::WrongRole, grant));
        }
        if grant.level == TableLevel::Pml4
            && self
                .roles
                .as_slice()
                .iter()
                .enumerate()
                .filter(|(other_slot, _)| *other_slot != slot)
                .filter_map(|(_, slot)| slot.record)
                .any(|record| {
                    matches!(
                        record.role,
                        FrameRole::PageTable {
                            owner,
                            level: TableLevel::Pml4,
                            ..
                        } | FrameRole::TableCandidate {
                            owner,
                            level: TableLevel::Pml4,
                        } if owner == grant.owner
                    )
                })
        {
            return Err(GrantTransitionError::new(
                FrameRoleError::DuplicateTableRoot,
                grant,
            ));
        }
        let parent_role = match (grant.level, parent) {
            (TableLevel::Pml4, None) => None,
            (TableLevel::Pml4, Some(_)) | (_, None) => {
                return Err(GrantTransitionError::new(
                    FrameRoleError::InvalidTableParent,
                    grant,
                ));
            }
            (level, Some(TableCommitParent::Committed(parent))) => {
                if self.validate_table_identity(parent).is_err()
                    || parent.owner != grant.owner
                    || parent.level.child() != Some(level)
                {
                    return Err(GrantTransitionError::new(
                        FrameRoleError::InvalidTableParent,
                        grant,
                    ));
                }
                Some(parent.role)
            }
            (level, Some(TableCommitParent::Candidate(parent))) => {
                let record = match self.record(parent.identity) {
                    Ok(record) => record,
                    Err(_) => {
                        return Err(GrantTransitionError::new(
                            FrameRoleError::InvalidTableParent,
                            grant,
                        ));
                    }
                };
                if record.range != parent.range
                    || record.role
                        != (FrameRole::TableCandidate {
                            owner: parent.owner,
                            level: parent.level,
                        })
                    || parent.owner != grant.owner
                    || parent.level.child() != Some(level)
                {
                    return Err(GrantTransitionError::new(
                        FrameRoleError::InvalidTableParent,
                        grant,
                    ));
                }
                Some(parent.identity)
            }
        };
        Ok(StagedTableCommit {
            grant,
            slot,
            parent: parent_role,
        })
    }

    pub(crate) fn publish_staged_table(&mut self, staged: StagedTableCommit) -> TableIdentity {
        assert_eq!(
            self.validate_staged_table(&staged),
            Ok(()),
            "staged table commit became invalid before publication"
        );
        let grant = staged.grant;
        // Every committed table below a root counts toward that root, which
        // is how an empty-hierarchy proof knows it saw them all.
        if let Some(parent) = staged.parent {
            let root = self
                .root_slot_of(parent)
                .expect("a validated parent table leads to its root");
            let root = &mut self.roles.as_mut_slice()[root];
            root.tables = root
                .tables
                .checked_add(1)
                .expect("a root's table count stays below the slot count");
        }
        self.replace_record(
            staged.slot,
            RoleRecord {
                range: grant.range,
                role: FrameRole::PageTable {
                    owner: grant.owner,
                    level: grant.level,
                    parent: staged.parent,
                },
            },
        );
        TableIdentity {
            role: grant.identity,
            owner: grant.owner,
            level: grant.level,
            physical_start: grant.range.start,
        }
    }

    pub(crate) fn cancel_staged_table(
        &mut self,
        staged: StagedTableCommit,
    ) -> Result<(), GrantTransitionError<TableCandidateGrant>> {
        self.cancel_table_candidate(staged.grant)
    }

    pub(crate) fn validate_table_identity(
        &self,
        table: TableIdentity,
    ) -> Result<(), FrameRoleError> {
        let record = self.record(table.role)?;
        if record.range.start != table.physical_start
            || record.range.page_count() != 1
            || record.role
                != (FrameRole::PageTable {
                    owner: table.owner,
                    level: table.level,
                    parent: match record.role {
                        FrameRole::PageTable { parent, .. } => parent,
                        _ => None,
                    },
                })
        {
            return Err(FrameRoleError::WrongRole);
        }
        Ok(())
    }

    pub(crate) fn table_identity(
        &self,
        owner: TableOwnerKey,
        level: TableLevel,
        physical_start: u64,
    ) -> Result<TableIdentity, FrameRoleError> {
        self.validate_owner(owner)?;
        // Page tables are dynamic roles, so the start index finds them.
        let slot = self
            .dynamic_slot_at(physical_start)
            .ok_or(FrameRoleError::WrongRole)?;
        let entry = self.roles.as_slice()[slot];
        let record = entry.record.ok_or(FrameRoleError::WrongRole)?;
        if !(record.range.start == physical_start
            && record.range.page_count() == 1
            && matches!(
                record.role,
                FrameRole::PageTable {
                    owner: record_owner,
                    level: record_level,
                    ..
                } if record_owner == owner && record_level == level
            ))
        {
            return Err(FrameRoleError::WrongRole);
        }
        Ok(TableIdentity {
            role: self.identity(slot, entry.generation)?,
            owner,
            level,
            physical_start,
        })
    }

    pub(crate) fn validate_table_child(
        &self,
        parent: TableIdentity,
        child: TableIdentity,
    ) -> Result<(), FrameRoleError> {
        self.validate_table_identity(parent)?;
        self.validate_table_identity(child)?;
        if parent.owner != child.owner || parent.level.child() != Some(child.level) {
            return Err(FrameRoleError::InvalidTableParent);
        }
        let child_record = self.record(child.role)?;
        if !matches!(
            child_record.role,
            FrameRole::PageTable {
                parent: Some(parent_role),
                ..
            } if parent_role == parent.role
        ) {
            return Err(FrameRoleError::InvalidTableParent);
        }
        Ok(())
    }

    /// Starts an architecture-attested empty-hierarchy preflight for one exact
    /// committed PML4. Descendants must subsequently be observed top-down.
    pub(crate) fn begin_empty_table_hierarchy(
        &mut self,
        root: TableIdentity,
    ) -> Result<EmptyTableHierarchyCandidate, FrameRoleError> {
        self.validate_table_identity(root)?;
        if root.level != TableLevel::Pml4 {
            return Err(FrameRoleError::WrongRole);
        }
        let epoch = self.next_epoch;
        self.next_epoch = epoch
            .checked_add(1)
            .ok_or(FrameRoleError::InvariantViolation)?;
        let slot = self.slot(root.role)?;
        self.roles.as_mut_slice()[slot].mark = epoch;
        Ok(EmptyTableHierarchyCandidate {
            root,
            epoch,
            version: self.version,
            observed: 0,
        })
    }

    /// Records one exact child discovered by the architecture walk. Requiring
    /// the parent to have already been observed makes the proof structurally
    /// top-down; rejecting a slot observed twice catches same-frame aliases.
    pub(crate) fn observe_empty_table_child(
        &mut self,
        candidate: &mut EmptyTableHierarchyCandidate,
        parent: TableIdentity,
        child: TableIdentity,
    ) -> Result<(), FrameRoleError> {
        if candidate.version != self.version {
            return Err(FrameRoleError::InvalidTableParent);
        }
        self.validate_table_identity(candidate.root)?;
        if candidate.root.owner != parent.owner || candidate.root.owner != child.owner {
            return Err(FrameRoleError::InvalidTableParent);
        }
        let parent_slot = self.slot(parent.role)?;
        if self.roles.as_slice()[parent_slot].mark != candidate.epoch {
            return Err(FrameRoleError::InvalidTableParent);
        }
        self.validate_table_child(parent, child)?;
        let child_slot = self.slot(child.role)?;
        if self.roles.as_slice()[child_slot].mark == candidate.epoch {
            return Err(FrameRoleError::InvalidTableParent);
        }
        self.roles.as_mut_slice()[child_slot].mark = candidate.epoch;
        candidate.observed = candidate
            .observed
            .checked_add(1)
            .ok_or(FrameRoleError::InvalidTableParent)?;
        Ok(())
    }

    /// Seals the hierarchy proof only when the architecture walk accounted for
    /// every committed table below the root. Each observed table was a
    /// distinct committed table of the root's owner below it, and none changed
    /// since (the role version), so when their number equals the root's count
    /// they are exactly that set: no disconnected table record is left over.
    pub(crate) fn finish_empty_table_hierarchy(
        &self,
        candidate: EmptyTableHierarchyCandidate,
    ) -> Result<EmptyTableHierarchyGrant, FrameRoleError> {
        if candidate.version != self.version {
            return Err(FrameRoleError::InvalidTableParent);
        }
        self.validate_table_identity(candidate.root)?;
        let root = self.roles.as_slice()[self.slot(candidate.root.role)?];
        if root.mark != candidate.epoch || root.tables != candidate.observed {
            return Err(FrameRoleError::InvalidTableParent);
        }
        Ok(EmptyTableHierarchyGrant {
            root: candidate.root,
            epoch: candidate.epoch,
            version: candidate.version,
            remaining: candidate.observed,
        })
    }

    /// Reclaims one table the proof observed, after the architecture root has
    /// atomically disconnected its low half. Architecture teardown walks the
    /// disconnected hierarchy again and reclaims each table after its
    /// children; any order would do, since nothing can reach them.
    ///
    /// # Safety
    ///
    /// The caller must own the architecture binding for `grant`, must have
    /// closed its residency gate with zero resident CPUs, must have atomically
    /// cleared every observed low-half PML4 entry, and must retain exclusive
    /// access to this manager through root reclaim.
    #[allow(
        unsafe_code,
        reason = "architecture residency and atomic root disconnection are outside the target-independent role manager"
    )]
    pub(crate) unsafe fn reclaim_preflighted_table(
        &mut self,
        grant: &mut EmptyTableHierarchyGrant,
        table: TableIdentity,
    ) {
        assert_eq!(
            grant.version, self.version,
            "a role changed during preflighted hierarchy reclaim"
        );
        let slot = self
            .slot(table.role)
            .unwrap_or_else(|error| panic!("preflighted table disappeared: {error:?}"));
        let entry = self.roles.as_slice()[slot];
        let Some(RoleRecord {
            range,
            role:
                FrameRole::PageTable {
                    owner,
                    level,
                    parent: Some(parent),
                },
        }) = entry.record
        else {
            panic!("preflighted table is not a committed child table");
        };
        if entry.mark != grant.epoch
            || owner != grant.root.owner
            || level != table.level
            || range.start != table.physical_start
        {
            panic!("table was not observed by this hierarchy proof");
        }
        grant.remaining = grant
            .remaining
            .checked_sub(1)
            .expect("a proof reclaims no more tables than it observed");
        let root = self
            .slot(grant.root.role)
            .expect("the hierarchy root outlives its tables");
        let root = &mut self.roles.as_mut_slice()[root];
        root.tables = root
            .tables
            .checked_sub(1)
            .expect("a root counts every table below it");
        self.cancel(
            table.role,
            range,
            FrameRole::PageTable {
                owner,
                level,
                parent: Some(parent),
            },
        )
        .unwrap_or_else(|error| panic!("preflighted table reclaim drifted: {error:?}"));
        grant.version = self.version;
    }

    /// Ends hierarchy reclaim once every observed table is reclaimed. The
    /// returned root grant remains gated by the retired/nonresident root
    /// reclaim API.
    pub(crate) fn finish_preflighted_hierarchy(
        &self,
        grant: EmptyTableHierarchyGrant,
    ) -> EmptyTableRootGrant {
        assert_eq!(
            (grant.remaining, grant.version),
            (0, self.version),
            "preflighted hierarchy reclaim left tables or saw a role change"
        );
        self.prepare_empty_table_root(grant.root)
            .unwrap_or_else(|error| {
                panic!("retired hierarchy root did not become empty: {error:?}")
            })
    }

    /// The slot of the PML4 above committed table `identity` (or its own).
    fn root_slot_of(&self, mut identity: FrameRoleIdentity) -> Result<usize, FrameRoleError> {
        for _ in 0..4 {
            let slot = self.slot(identity)?;
            match self.roles.as_slice()[slot].record.map(|record| record.role) {
                Some(FrameRole::PageTable {
                    level: TableLevel::Pml4,
                    ..
                }) => return Ok(slot),
                Some(FrameRole::PageTable {
                    parent: Some(parent),
                    ..
                }) => identity = parent,
                _ => return Err(FrameRoleError::InvalidTableParent),
            }
        }
        Err(FrameRoleError::InvalidTableParent)
    }

    /// Reclaims one dynamically allocated, committed PML4 only after its
    /// address-space owner has proved teardown complete and no committed child
    /// table remains attached. Shared kernel-half descendants are deliberately
    /// not represented as children of this owner; their lifetime remains with
    /// the primordial kernel-half binding.
    pub(crate) fn prepare_empty_table_root(
        &self,
        root: TableIdentity,
    ) -> Result<EmptyTableRootGrant, FrameRoleError> {
        self.validate_empty_table_root(root)?;
        Ok(EmptyTableRootGrant { root })
    }

    fn validate_empty_table_root(&self, root: TableIdentity) -> Result<(), FrameRoleError> {
        self.validate_table_identity(root)?;
        if root.level != TableLevel::Pml4 {
            return Err(FrameRoleError::WrongRole);
        }
        if self.roles.as_slice()[self.slot(root.role)?].tables != 0 {
            return Err(FrameRoleError::InvalidTableParent);
        }
        Ok(())
    }

    /// Consumes one preflighted empty-root proof after the architecture binding
    /// has retired the exact root and proved it nonresident.
    ///
    /// # Safety
    ///
    /// The caller must own the architecture binding for `grant`, must have
    /// completed its H0 teardown barrier, and must retain exclusive access to
    /// this manager from `prepare_empty_table_root` through this commit.
    #[allow(
        unsafe_code,
        reason = "architecture residency retirement cannot be represented inside the target-independent role manager"
    )]
    pub(crate) unsafe fn reclaim_preflighted_empty_table_root(
        &mut self,
        grant: EmptyTableRootGrant,
    ) {
        let root = grant.root;
        self.cancel(
            root.role,
            PageRange::from_page_count(root.physical_start, 1, self.allocator.physical_limit())
                .expect("preflighted PML4 range remains representable"),
            FrameRole::PageTable {
                owner: root.owner,
                level: TableLevel::Pml4,
                parent: None,
            },
        )
        .unwrap_or_else(|error| panic!("preflighted retired PML4 reclaim drifted: {error:?}"));
    }

    /// Imports one transition-table or kernel-image range which has already
    /// been excluded from the allocator.
    ///
    /// # Safety
    ///
    /// The caller must have validated the range's boot provenance, role, and
    /// lifetime against the copied handoff and live architecture state.
    #[allow(
        unsafe_code,
        reason = "external boot provenance cannot be derived from allocator state alone"
    )]
    pub(crate) unsafe fn import_external(
        &mut self,
        range: PhysicalRange,
        role: ExternalFrameRole,
    ) -> Result<FrameRoleIdentity, FrameRoleError> {
        let pages = self.validate_external_page_range(range)?;
        let identity = self.insert_role(pages, FrameRole::External(role))?;
        Ok(identity)
    }

    /// Validates the exact three kernel image ranges and reserves registry
    /// slots without changing role state. The caller retains an unchanged
    /// manager on every error.
    ///
    /// # Safety
    ///
    /// The supplied ranges and segment labels must come from the live-attested
    /// loader root and exact linker bounds, with firmware already exited and
    /// the physical storage retained through the pending CR3 switch.
    #[allow(
        unsafe_code,
        reason = "kernel image provenance is established by the live transition graph"
    )]
    pub(crate) unsafe fn stage_kernel_image_roles(
        &self,
        declarations: [(PhysicalRange, KernelImageSegment); 3],
    ) -> Result<StagedKernelImageRoles, FrameRoleError> {
        let mut ranges = [PageRange::empty(); 3];
        let mut segments = [KernelImageSegment::Text; 3];
        for (index, (range, segment)) in declarations.into_iter().enumerate() {
            if segments[..index].contains(&segment) {
                return Err(FrameRoleError::WrongRole);
            }
            ranges[index] = self.validate_external_page_range(range)?;
            segments[index] = segment;
            if ranges[..index]
                .iter()
                .any(|existing| existing.overlaps(ranges[index]))
            {
                return Err(FrameRoleError::Overlap);
            }
        }
        if !segments.contains(&KernelImageSegment::Text)
            || !segments.contains(&KernelImageSegment::ReadOnlyData)
            || !segments.contains(&KernelImageSegment::WritableData)
        {
            return Err(FrameRoleError::WrongRole);
        }

        let mut slots = [usize::MAX; 3];
        let mut generations = [0_u32; 3];
        let mut identities = [FrameRoleIdentity::EMPTY; 3];
        // The three slots on top of the free-slot stack, in the order
        // publication occupies them.
        for depth in 0..3 {
            let (slot, generation) = self.free_slot(depth)?;
            slots[depth] = slot;
            generations[depth] = generation;
            identities[depth] = self.identity(slot, generation)?;
        }
        Ok(StagedKernelImageRoles {
            domain: self.domain,
            ranges,
            segments,
            slots,
            generations,
            identities,
        })
    }

    /// Publishes a previously staged image-role set. The exclusive manager
    /// borrow prevents intervening mutation, so this phase is infallible.
    pub(crate) fn publish_staged_kernel_image(
        &mut self,
        staged: StagedKernelImageRoles,
    ) -> KernelImageRoleSet {
        assert_eq!(
            staged.domain, self.domain,
            "staged kernel image roles belong to another manager"
        );
        assert!(
            staged.segments.contains(&KernelImageSegment::Text)
                && staged.segments.contains(&KernelImageSegment::ReadOnlyData)
                && staged.segments.contains(&KernelImageSegment::WritableData),
            "staged kernel image segment set changed before publication"
        );
        for index in 0..3 {
            assert!(
                self.free_slot(index) == Ok((staged.slots[index], staged.generations[index]))
                    && !staged.slots[..index].contains(&staged.slots[index])
                    && !staged.ranges[..index]
                        .iter()
                        .any(|range| range.overlaps(staged.ranges[index]))
                    && self.validate_external_pages(staged.ranges[index]).is_ok()
                    && self.identity(staged.slots[index], staged.generations[index])
                        == Ok(staged.identities[index])
                    && staged.identities[index].domain == self.domain,
                "staged kernel image role changed before publication"
            );
        }
        for index in 0..3 {
            self.occupy(
                staged.slots[index],
                staged.generations[index],
                RoleRecord {
                    range: staged.ranges[index],
                    role: FrameRole::External(ExternalFrameRole::KernelImage {
                        segment: staged.segments[index],
                    }),
                },
            );
        }
        KernelImageRoleSet {
            _identities: staged.identities,
            ranges: staged.ranges,
            segments: staged.segments,
        }
    }

    /// Atomically imports the complete live-attested transition-table set.
    ///
    /// Every range, overlap, capacity, generation, and identity check finishes
    /// before the first registry slot changes. Failure therefore imports none
    /// of the supplied frames.
    ///
    /// # Safety
    ///
    /// The caller must have consumed a one-shot live transition attestation
    /// proving that `frames` is the exact, strictly ascending set of retained
    /// loader table frames for the current root. The accepted loader contract
    /// supplies their boot provenance and allocator exclusion.
    #[allow(
        unsafe_code,
        reason = "external transition-table provenance is established by the one-shot architecture attestation"
    )]
    pub(crate) unsafe fn import_transition_tables<const CAPACITY: usize>(
        &mut self,
        frames: &[u64],
    ) -> Result<TransitionTableRoleSet<CAPACITY>, FrameRoleError> {
        if frames.is_empty() || frames.len() > CAPACITY {
            return Err(FrameRoleError::Capacity);
        }

        let mut ranges = [PageRange::empty(); CAPACITY];
        let mut slots = [usize::MAX; CAPACITY];
        let mut generations = [0_u32; CAPACITY];
        let mut table_indices = [0_u32; CAPACITY];

        for (index, &frame) in frames.iter().enumerate() {
            if index != 0 && frames[index - 1] >= frame {
                return Err(FrameRoleError::Overlap);
            }
            let range = PageRange::from_page_count(frame, 1, self.allocator.physical_limit())?;
            ranges[index] = self.validate_external_pages(range)?;
            table_indices[index] = u32::try_from(index).map_err(|_| FrameRoleError::Capacity)?;
        }

        for depth in 0..frames.len() {
            let (slot, generation) = self.free_slot(depth)?;
            slots[depth] = slot;
            generations[depth] = generation;
        }

        for index in 0..frames.len() {
            self.occupy(
                slots[index],
                generations[index],
                RoleRecord {
                    range: ranges[index],
                    role: FrameRole::External(ExternalFrameRole::TransitionTable {
                        table_index: table_indices[index],
                    }),
                },
            );
        }
        Ok(TransitionTableRoleSet {
            _domain: self.domain,
            count: frames.len(),
            _capacity: core::marker::PhantomData,
        })
    }

    /// Imports immutable module pages as typed read-only object backing.
    ///
    /// # Safety
    ///
    /// The caller must have validated the module reservation, immutable
    /// lifetime, initialized tail bytes, and exclusion from allocator ranges.
    #[allow(
        unsafe_code,
        reason = "immutable boot-module provenance is established by the boot handoff boundary"
    )]
    pub(crate) unsafe fn import_immutable_module(
        &mut self,
        range: PhysicalRange,
        module_index: u32,
    ) -> Result<ObjectBackingGrant, FrameRoleError> {
        let pages = self.validate_immutable_module_range(range)?;
        let identity =
            self.insert_role(pages, FrameRole::ExternalImmutableModule { module_index })?;
        Ok(ObjectBackingGrant {
            identity: BackingIdentity(identity),
            range: pages,
            kind: ObjectBackingKind::ImmutableModule { module_index },
            pages: pages.page_count(),
            runs: 1,
        })
    }

    /// Imports one admitted PCI memory BAR as typed device-register backing.
    /// The role is permanent: BARs never move once the kernel has probed them.
    ///
    /// # Safety
    ///
    /// The caller must have sized the BAR from the device with decoding off,
    /// checked it lies below the physical limit, and checked it overlaps no
    /// memory-map range other than MMIO.
    #[allow(
        unsafe_code,
        reason = "BAR provenance is established by the boot-time PCI probe"
    )]
    pub(crate) unsafe fn import_device_mmio(
        &mut self,
        range: PhysicalRange,
    ) -> Result<ObjectBackingGrant, FrameRoleError> {
        if !range.physical_start().is_multiple_of(BASE_PAGE_SIZE)
            || !range.byte_len().is_multiple_of(BASE_PAGE_SIZE)
        {
            return Err(FrameRoleError::Physical(
                PhysicalMemoryError::InvalidPageRange,
            ));
        }
        let pages = PageRange::cover(range, self.allocator.physical_limit())?;
        let pages = self.validate_external_pages(pages)?;
        let identity = self.insert_role(pages, FrameRole::ExternalDeviceMmio)?;
        Ok(ObjectBackingGrant {
            identity: BackingIdentity(identity),
            range: pages,
            kind: ObjectBackingKind::DeviceMmio,
            pages: pages.page_count(),
            runs: 1,
        })
    }

    pub(crate) fn cancel_allocation(
        &mut self,
        grant: AllocationGrant,
    ) -> Result<(), GrantTransitionError<AllocationGrant>> {
        if let Err(error) = self.cancel(
            grant.identity,
            grant.range,
            FrameRole::AllocatedUninitialized,
        ) {
            return Err(GrantTransitionError::new(error, grant));
        }
        Ok(())
    }

    pub(crate) fn cancel_zeroed(
        &mut self,
        grant: ZeroedGrant,
    ) -> Result<(), GrantTransitionError<ZeroedGrant>> {
        if let Err(error) = self.cancel(grant.identity, grant.range, FrameRole::Zeroed) {
            return Err(GrantTransitionError::new(error, grant));
        }
        Ok(())
    }

    pub(crate) fn cancel_object_backing(
        &mut self,
        grant: ObjectBackingGrant,
    ) -> Result<(), GrantTransitionError<ObjectBackingGrant>> {
        let result = match grant.kind {
            ObjectBackingKind::AllocatorOwned => self.release_chain(
                grant.identity.0,
                ChainState::Backing,
                grant.pages,
                grant.runs,
            ),
            ObjectBackingKind::OnDemand => self.release_index(grant.identity.0),
            ObjectBackingKind::ImmutableModule { .. } | ObjectBackingKind::DeviceMmio => {
                Err(FrameRoleError::WrongRole)
            }
        };
        if let Err(error) = result {
            return Err(GrantTransitionError::new(error, grant));
        }
        Ok(())
    }

    pub(crate) fn cancel_table_candidate(
        &mut self,
        grant: TableCandidateGrant,
    ) -> Result<(), GrantTransitionError<TableCandidateGrant>> {
        if let Err(error) = self.cancel(
            grant.identity,
            grant.range,
            FrameRole::TableCandidate {
                owner: grant.owner,
                level: grant.level,
            },
        ) {
            return Err(GrantTransitionError::new(error, grant));
        }
        Ok(())
    }

    /// Confirms that one exact base page belongs to the boot-authenticated
    /// kernel image segment whose permissions C2 is about to retain.
    pub(crate) fn validate_kernel_image_page(
        &self,
        physical_start: u64,
        segment: KernelImageSegment,
    ) -> Result<(), FrameRoleError> {
        let page = PageRange::from_page_count(physical_start, 1, self.allocator.physical_limit())?;
        self.roles
            .as_slice()
            .iter()
            .filter_map(|slot| slot.record)
            .find(|record| record.range.contains(page))
            .filter(|record| {
                record.role == FrameRole::External(ExternalFrameRole::KernelImage { segment })
            })
            .map(|_| ())
            .ok_or(FrameRoleError::WrongRole)
    }

    pub(crate) fn role(
        &self,
        identity: FrameRoleIdentity,
    ) -> Result<FrameRoleKind, FrameRoleError> {
        Ok(self.record(identity)?.role.kind())
    }

    /// Whether any page of `range` is RAM this manager accounts for: an
    /// allocator candidate or any role record (kernel image, modules,
    /// transition and page tables, object backing). A range it cannot cover
    /// counts as owned.
    pub(crate) fn owns_any(&self, range: PhysicalRange) -> bool {
        PageRange::cover(range, self.allocator.physical_limit())
            .map_or(true, |pages| self.validate_external_pages(pages).is_err())
    }

    /// Every range the allocator may ever hand out, in address order: the
    /// memory the direct map covers (DW2 M2).
    pub(crate) fn allocator_ranges(&self) -> impl Iterator<Item = PhysicalRange> + '_ {
        self.allocator.initial_ranges()
    }

    /// The run the grown role table needs: one slot per 2 MiB of allocator
    /// RAM beyond the boot slots, its free-slot stack, a start index entry
    /// per allocator page, and the free list sized by `free_range_bound`
    /// (DW2 M2 §5.3).
    pub(crate) fn grown_layout(&self) -> Result<RoleTableLayout, FrameRoleError> {
        let frames = self.allocator.initial_frames();
        let slots = usize::try_from(frames.div_ceil(GROWN_SLOT_PAGES))
            .ok()
            .and_then(|extra| ROLE_CAPACITY.checked_add(extra))
            .filter(|slots| u32::try_from(*slots).is_ok_and(|slots| slots < u32::MAX))
            .ok_or(FrameRoleError::Capacity)?;
        let starts = usize::try_from(frames).map_err(|_| FrameRoleError::Capacity)?;
        // The bound can be below the boot list on small machines, but the
        // move needs a longer list: keep at least one more than the boot list.
        let ranges = self
            .allocator
            .free_list_capacity_for(slots)
            .max(RANGE_CAPACITY + 1);
        let align = |offset: usize| offset.checked_next_multiple_of(8);
        let after = |offset: usize, count: usize, size: usize| {
            count
                .checked_mul(size)
                .and_then(|bytes| offset.checked_add(bytes))
                .and_then(align)
        };
        let free_slots_offset =
            after(0, slots, core::mem::size_of::<RoleSlot>()).ok_or(FrameRoleError::Capacity)?;
        let starts_offset = after(free_slots_offset, slots, core::mem::size_of::<u32>())
            .ok_or(FrameRoleError::Capacity)?;
        let ranges_offset = after(starts_offset, starts, core::mem::size_of::<u32>())
            .ok_or(FrameRoleError::Capacity)?;
        let bytes = after(ranges_offset, ranges, core::mem::size_of::<PageRange>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(FrameRoleError::Capacity)?;
        Ok(RoleTableLayout {
            slots,
            free_slots_offset,
            starts_offset,
            starts,
            ranges_offset,
            ranges,
            bytes,
        })
    }

    /// Moves the role table, the free-slot stack and the free list into the
    /// run `grant` names, which `base` maps, and builds the start index there
    /// (DW2 M2 §5.3). Slot numbers and generations are kept, so every issued
    /// identity stays valid. The run itself takes a permanent role. Every
    /// check happens before anything changes; on an error the grant comes
    /// back and the manager is as it was.
    ///
    /// # Safety
    ///
    /// `base` must be the start of a writable, 8-byte-aligned mapping of
    /// exactly the run `grant` names, used by nothing else for the rest of
    /// the kernel's life.
    #[allow(
        unsafe_code,
        reason = "the grown role table lives in RAM the caller maps; the manager carves typed slices from it"
    )]
    pub(crate) unsafe fn adopt_storage(
        &mut self,
        grant: AllocationGrant,
        base: *mut u8,
    ) -> Result<(), GrantTransitionError<AllocationGrant>> {
        let layout = match self.grown_layout() {
            Ok(layout) => layout,
            Err(error) => return Err(GrantTransitionError::new(error, grant)),
        };
        let valid = self.validate_allocation(&grant).is_ok()
            && grant.byte_len() >= layout.bytes
            && !self.roles.is_adopted()
            && self.starts.is_none()
            && layout.slots > ROLE_CAPACITY
            && layout.ranges > RANGE_CAPACITY
            && (base as usize).is_multiple_of(8);
        if !valid {
            return Err(GrantTransitionError::new(FrameRoleError::WrongRole, grant));
        }
        let slot = self
            .slot(grant.identity)
            .expect("a validated allocation has a live slot");
        // SAFETY: the caller maps `grant`'s whole run at `base`, writable and
        // unused; every part lies inside `layout.bytes`, at most its length,
        // and starts 8-aligned. Each part is fully written before a slice of
        // it is made.
        let (slots, free_slots, starts, ranges) = unsafe {
            (
                Self::carve(base, 0, layout.slots, EMPTY_ROLE_SLOT),
                Self::carve(base, layout.free_slots_offset, layout.slots, 0_u32),
                Self::carve(base, layout.starts_offset, layout.starts, 0_u32),
                Self::carve(
                    base,
                    layout.ranges_offset,
                    layout.ranges,
                    PageRange::empty(),
                ),
            )
        };
        self.replace_record(
            slot,
            RoleRecord {
                range: grant.range,
                role: FrameRole::RoleTableStorage,
            },
        );
        self.roles
            .adopt(slots, EMPTY_ROLE_SLOT)
            .unwrap_or_else(|_| panic!("the checked role table adoption failed"));
        self.free_slots
            .adopt(free_slots, 0)
            .unwrap_or_else(|_| panic!("the checked free-slot adoption failed"));
        // The new slots go on top of the free ones, lowest on top.
        let old_free = self.free_slot_count;
        let new_free = layout.slots - ROLE_CAPACITY;
        for (position, entry) in self.free_slots.as_mut_slice()[old_free..old_free + new_free]
            .iter_mut()
            .enumerate()
        {
            *entry = (layout.slots - 1 - position) as u32;
        }
        self.free_slot_count = old_free + new_free;
        self.allocator
            .adopt_free_list(ranges)
            .unwrap_or_else(|_| panic!("the checked free-list adoption failed"));
        self.starts = Some(starts);
        for slot in 0..self.roles.len() {
            if let Some(record) = self.roles.as_slice()[slot].record {
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
        unsafe {
            let start = base.add(offset).cast::<T>();
            for index in 0..count {
                start.add(index).write(fill);
            }
            core::slice::from_raw_parts_mut(start, count)
        }
    }

    pub(crate) fn available_frames(&self) -> u64 {
        self.allocator.available_frames()
    }

    pub(crate) fn check_invariants(&self) -> Result<(), FrameRoleError> {
        let mut dynamic_pages = 0_u64;
        for (left_index, left) in self.roles.as_slice().iter().enumerate() {
            let Some(left) = left.record else {
                continue;
            };
            for right in self.roles.as_slice()[left_index + 1..]
                .iter()
                .filter_map(|slot| slot.record)
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
        self.check_chains()?;
        self.check_indexes()
    }

    fn transition(
        &mut self,
        identity: FrameRoleIdentity,
        range: PageRange,
        expected: FrameRole,
        replacement: FrameRole,
    ) -> Result<(), FrameRoleError> {
        let slot = self.slot(identity)?;
        let record = self.roles.as_slice()[slot]
            .record
            .ok_or(FrameRoleError::InvalidGrant)?;
        if record.range != range || record.role != expected {
            return Err(FrameRoleError::WrongRole);
        }
        self.replace_record(
            slot,
            RoleRecord {
                range,
                role: replacement,
            },
        );
        Ok(())
    }

    fn cancel(
        &mut self,
        identity: FrameRoleIdentity,
        range: PageRange,
        expected: FrameRole,
    ) -> Result<(), FrameRoleError> {
        let slot = self.slot(identity)?;
        let record = self.roles.as_slice()[slot]
            .record
            .ok_or(FrameRoleError::InvalidGrant)?;
        if record.range != range || record.role != expected || !record.role.is_dynamic() {
            return Err(FrameRoleError::WrongRole);
        }
        self.allocator.free_run(range)?;
        self.vacate(slot);
        Ok(())
    }

    fn validate_external_page_range(
        &self,
        range: PhysicalRange,
    ) -> Result<PageRange, FrameRoleError> {
        if !range.physical_start().is_multiple_of(BASE_PAGE_SIZE)
            || !range.byte_len().is_multiple_of(BASE_PAGE_SIZE)
        {
            return Err(FrameRoleError::Physical(
                PhysicalMemoryError::InvalidPageRange,
            ));
        }
        let pages = PageRange::from_page_count(
            range.physical_start(),
            range.byte_len() / BASE_PAGE_SIZE,
            self.allocator.physical_limit(),
        )?;
        self.validate_external_pages(pages)
    }

    fn validate_immutable_module_range(
        &self,
        range: PhysicalRange,
    ) -> Result<PageRange, FrameRoleError> {
        if !range.physical_start().is_multiple_of(BASE_PAGE_SIZE) {
            return Err(FrameRoleError::Physical(
                PhysicalMemoryError::InvalidPageRange,
            ));
        }
        let pages = PageRange::cover(range, self.allocator.physical_limit())?;
        self.validate_external_pages(pages)
    }

    fn validate_external_pages(&self, pages: PageRange) -> Result<PageRange, FrameRoleError> {
        if self.allocator.overlaps_initial(pages) {
            return Err(FrameRoleError::ExternalAllocatorOverlap);
        }
        if self
            .roles
            .as_slice()
            .iter()
            .filter_map(|slot| slot.record)
            .any(|record| record.range.overlaps(pages))
        {
            return Err(FrameRoleError::Overlap);
        }
        Ok(pages)
    }

    fn insert_role(
        &mut self,
        range: PageRange,
        role: FrameRole,
    ) -> Result<FrameRoleIdentity, FrameRoleError> {
        if self
            .roles
            .as_slice()
            .iter()
            .filter_map(|slot| slot.record)
            .any(|record| record.range.overlaps(range))
        {
            return Err(FrameRoleError::Overlap);
        }
        let (slot, generation) = self.next_slot()?;
        let identity = self.identity(slot, generation)?;
        self.occupy(slot, generation, RoleRecord { range, role });
        Ok(identity)
    }

    pub(super) fn next_slot(&self) -> Result<(usize, u32), FrameRoleError> {
        self.free_slot(0)
    }

    /// The free slot `depth` places below the top of the free-slot stack,
    /// with the generation it would take. Changes nothing.
    fn free_slot(&self, depth: usize) -> Result<(usize, u32), FrameRoleError> {
        let position = self
            .free_slot_count
            .checked_sub(depth + 1)
            .ok_or(FrameRoleError::Capacity)?;
        let slot = self.free_slots.as_slice()[position] as usize;
        let entry = self.roles.as_slice()[slot];
        if entry.record.is_some() {
            return Err(FrameRoleError::InvariantViolation);
        }
        let generation = entry
            .generation
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(FrameRoleError::GenerationExhausted)?;
        Ok((slot, generation))
    }

    /// Publishes `record` in the slot on top of the free-slot stack, which
    /// must be `slot`.
    pub(super) fn occupy(&mut self, slot: usize, generation: u32, record: RoleRecord) {
        let top = self
            .free_slot_count
            .checked_sub(1)
            .expect("an occupied slot came from the free-slot stack");
        assert_eq!(
            self.free_slots.as_slice()[top] as usize,
            slot,
            "slots are occupied from the top of the free-slot stack"
        );
        self.free_slot_count = top;
        self.roles.as_mut_slice()[slot] = RoleSlot {
            generation,
            record: Some(record),
            mark: 0,
            tables: 0,
        };
        self.set_start(record, slot);
        self.version = self.version.wrapping_add(1);
    }

    /// Replaces the record of a live slot with the same range.
    pub(super) fn replace_record(&mut self, slot: usize, record: RoleRecord) {
        self.roles.as_mut_slice()[slot].record = Some(record);
        self.version = self.version.wrapping_add(1);
    }

    /// Empties a live slot and returns it to the free-slot stack unless its
    /// generation is spent.
    pub(super) fn vacate(&mut self, slot: usize) {
        let entry = &mut self.roles.as_mut_slice()[slot];
        let record = entry.record.take().expect("a vacated slot was live");
        entry.mark = 0;
        entry.tables = 0;
        let retired = entry.generation == u32::MAX;
        self.clear_start(record);
        if !retired {
            let position = self.free_slot_count;
            self.free_slots.as_mut_slice()[position] = slot as u32;
            self.free_slot_count = position + 1;
        }
        self.version = self.version.wrapping_add(1);
    }

    /// The start index position of `physical_start`, a page of allocator RAM.
    fn start_position(&self, physical_start: u64) -> Option<usize> {
        let mut base = 0_u64;
        for range in self.allocator.initial_page_ranges() {
            if range.start <= physical_start && physical_start < range.end {
                return usize::try_from(base + (physical_start - range.start) / BASE_PAGE_SIZE)
                    .ok();
            }
            base += range.page_count();
        }
        None
    }

    fn set_start(&mut self, record: RoleRecord, slot: usize) {
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

    fn clear_start(&mut self, record: RoleRecord) {
        if !record.role.is_dynamic() {
            return;
        }
        let Some(position) = self.start_position(record.range.start) else {
            return;
        };
        if let Some(starts) = self.starts.as_deref_mut() {
            starts[position] = 0;
        }
    }

    /// The slot of the dynamic role starting at `physical_start`: through
    /// the start index once grown, by scanning the boot table before.
    fn dynamic_slot_at(&self, physical_start: u64) -> Option<usize> {
        match self.starts.as_deref() {
            Some(starts) => {
                let position = self.start_position(physical_start)?;
                (starts[position] as usize).checked_sub(1)
            }
            None => self.roles.as_slice().iter().position(|entry| {
                entry.record.is_some_and(|record| {
                    record.role.is_dynamic() && record.range.start == physical_start
                })
            }),
        }
    }

    pub(super) fn identity(
        &self,
        slot: usize,
        generation: u32,
    ) -> Result<FrameRoleIdentity, FrameRoleError> {
        let slot = u32::try_from(slot)
            .ok()
            .and_then(|slot| slot.checked_add(1))
            .ok_or(FrameRoleError::Capacity)?;
        Ok(FrameRoleIdentity {
            domain: self.domain,
            raw: (u64::from(generation) << 32) | u64::from(slot),
        })
    }

    pub(super) fn slot(&self, identity: FrameRoleIdentity) -> Result<usize, FrameRoleError> {
        if identity.domain != self.domain {
            return Err(FrameRoleError::ForeignManager);
        }
        let generation = (identity.raw >> 32) as u32;
        let slot = usize::try_from(
            (identity.raw as u32)
                .checked_sub(1)
                .ok_or(FrameRoleError::InvalidGrant)?,
        )
        .map_err(|_| FrameRoleError::InvalidGrant)?;
        let entry = self
            .roles
            .as_slice()
            .get(slot)
            .ok_or(FrameRoleError::InvalidGrant)?;
        if generation == 0 || entry.generation != generation || entry.record.is_none() {
            return Err(FrameRoleError::InvalidGrant);
        }
        Ok(slot)
    }

    pub(super) fn record(&self, identity: FrameRoleIdentity) -> Result<RoleRecord, FrameRoleError> {
        let slot = self.slot(identity)?;
        self.roles.as_slice()[slot]
            .record
            .ok_or(FrameRoleError::InvalidGrant)
    }

    fn validate_owner(&self, owner: TableOwnerKey) -> Result<(), FrameRoleError> {
        if owner.domain != self.domain || owner.raw == 0 || owner.raw >= self.next_table_owner {
            return Err(FrameRoleError::InvalidTableOwner);
        }
        Ok(())
    }

    fn validate_staged_table(&self, staged: &StagedTableCommit) -> Result<(), FrameRoleError> {
        let grant = &staged.grant;
        self.validate_owner(grant.owner)?;
        if self.slot(grant.identity)? != staged.slot
            || self.roles.as_slice()[staged.slot].record
                != Some(RoleRecord {
                    range: grant.range,
                    role: FrameRole::TableCandidate {
                        owner: grant.owner,
                        level: grant.level,
                    },
                })
        {
            return Err(FrameRoleError::InvalidGrant);
        }

        match (grant.level, staged.parent) {
            (TableLevel::Pml4, None) => {
                if self
                    .roles
                    .as_slice()
                    .iter()
                    .enumerate()
                    .filter(|(slot, _)| *slot != staged.slot)
                    .filter_map(|(_, slot)| slot.record)
                    .any(|record| {
                        matches!(
                            record.role,
                            FrameRole::PageTable {
                                owner,
                                level: TableLevel::Pml4,
                                ..
                            } | FrameRole::TableCandidate {
                                owner,
                                level: TableLevel::Pml4,
                            } if owner == grant.owner
                        )
                    })
                {
                    return Err(FrameRoleError::DuplicateTableRoot);
                }
            }
            (TableLevel::Pml4, Some(_)) | (_, None) => {
                return Err(FrameRoleError::InvalidTableParent);
            }
            (level, Some(parent)) => {
                if parent == grant.identity {
                    return Err(FrameRoleError::InvalidTableParent);
                }
                let parent = self.record(parent)?;
                let valid_parent = match parent.role {
                    FrameRole::PageTable {
                        owner,
                        level: parent_level,
                        ..
                    } => owner == grant.owner && parent_level.child() == Some(level),
                    _ => false,
                };
                if !valid_parent {
                    return Err(FrameRoleError::InvalidTableParent);
                }
            }
        }
        Ok(())
    }
}
