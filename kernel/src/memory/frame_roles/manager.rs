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
            first_free: 0,
            free_slot_count: 0,
            first_root: 0,
            starts: None,
            staged: [const { None }; MAX_GROWTH_PARTS],
            next_table_owner: 1,
            next_epoch: 1,
            version: 0,
            index_memory: None,
        };
        manager.fill_boot_free_slots()?;
        Ok(manager)
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
        // SAFETY: `destination` is the caller's unique, live storage (this
        // function's contract). Each field is written once through a raw
        // field pointer, never read first; the allocator was initialized in
        // place above. Only after every field is written is the storage
        // borrowed as a manager. The destructuring below names every field
        // without `..`, so a field added later without a write here does not
        // compile.
        unsafe {
            core::ptr::addr_of_mut!((*destination).domain).write(domain);
            GrowableStore::init_in_place(
                core::ptr::addr_of_mut!((*destination).roles),
                EMPTY_ROLE_SLOT,
            );
            core::ptr::addr_of_mut!((*destination).first_free).write(0);
            core::ptr::addr_of_mut!((*destination).free_slot_count).write(0);
            core::ptr::addr_of_mut!((*destination).first_root).write(0);
            core::ptr::addr_of_mut!((*destination).starts).write(None);
            let staged =
                core::ptr::addr_of_mut!((*destination).staged).cast::<Option<AllocationGrant>>();
            for index in 0..MAX_GROWTH_PARTS {
                staged.add(index).write(None);
            }
            core::ptr::addr_of_mut!((*destination).next_table_owner).write(1);
            core::ptr::addr_of_mut!((*destination).next_epoch).write(1);
            core::ptr::addr_of_mut!((*destination).version).write(0);
            core::ptr::addr_of_mut!((*destination).index_memory).write(None);
            let manager = &mut *destination;
            let Self {
                domain: _,
                allocator: _,
                roles: _,
                first_free: _,
                free_slot_count: _,
                first_root: _,
                starts: _,
                staged: _,
                next_table_owner: _,
                next_epoch: _,
                version: _,
                index_memory: _,
            } = manager;
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
            Self::validate_external_page_count(ranges[index])?;
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
        // The three slots at the head of the free list, in the order
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
            ObjectBackingKind::OnDemand => self.release_index(grant.identity.0, RootUse::OnDemand),
            ObjectBackingKind::AllocatorIndexed => {
                self.release_eager_index(grant.identity.0, RootUse::Eager, grant.pages)
            }
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
        self.slot_views()
            .filter_map(|(_, view)| view.record)
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

    pub(crate) fn available_frames(&self) -> u64 {
        self.allocator.available_frames()
    }

    /// Pages in the largest run one allocation can take now.
    pub(crate) fn largest_free_pages(&self) -> u64 {
        self.allocator.largest_free_pages()
    }

    pub(super) fn transition(
        &mut self,
        identity: FrameRoleIdentity,
        range: PageRange,
        expected: FrameRole,
        replacement: FrameRole,
    ) -> Result<(), FrameRoleError> {
        let slot = self.slot(identity)?;
        let record = self.record_at(slot).ok_or(FrameRoleError::InvalidGrant)?;
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

    pub(super) fn cancel(
        &mut self,
        identity: FrameRoleIdentity,
        range: PageRange,
        expected: FrameRole,
    ) -> Result<(), FrameRoleError> {
        let slot = self.slot(identity)?;
        let record = self.record_at(slot).ok_or(FrameRoleError::InvalidGrant)?;
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

    /// An external role is stored with a 32-bit page count (DW2 §12.3), so a
    /// longer one is refused before anything is stored.
    fn validate_external_page_count(pages: PageRange) -> Result<(), FrameRoleError> {
        u32::try_from(pages.page_count())
            .map(|_| ())
            .map_err(|_| FrameRoleError::Capacity)
    }

    fn validate_external_pages(&self, pages: PageRange) -> Result<PageRange, FrameRoleError> {
        if self.allocator.overlaps_initial(pages) {
            return Err(FrameRoleError::ExternalAllocatorOverlap);
        }
        if self
            .slot_views()
            .filter_map(|(_, view)| view.record)
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
        Self::validate_external_page_count(range)?;
        if self
            .slot_views()
            .filter_map(|(_, view)| view.record)
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

    /// Publishes `record` in the slot at the head of the free list, which
    /// must be `slot`.
    pub(super) fn occupy(&mut self, slot: usize, generation: u32, record: RoleRecord) {
        self.occupy_slot(slot, generation, record);
        self.set_start(record, slot);
        self.version = self.version.wrapping_add(1);
    }

    /// Replaces the record of a live slot with the same range.
    pub(super) fn replace_record(&mut self, slot: usize, record: RoleRecord) {
        let generation = self
            .live_generation(slot)
            .expect("a replaced record was live");
        self.store(slot, generation, Some(record));
        self.version = self.version.wrapping_add(1);
    }

    /// Empties a live slot and returns it to the free list unless its
    /// generation is spent.
    pub(super) fn vacate(&mut self, slot: usize) {
        let (start, dynamic) = self.vacate_slot(slot);
        self.clear_start(start, dynamic);
        self.version = self.version.wrapping_add(1);
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
        if generation == 0 || self.live_generation(slot) != Some(generation) {
            return Err(FrameRoleError::InvalidGrant);
        }
        Ok(slot)
    }

    pub(super) fn record(&self, identity: FrameRoleIdentity) -> Result<RoleRecord, FrameRoleError> {
        let slot = self.slot(identity)?;
        self.record_at(slot).ok_or(FrameRoleError::InvalidGrant)
    }
}
