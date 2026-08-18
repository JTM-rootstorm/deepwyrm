use super::*;

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
struct ActiveRootTestAuthority<'a, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> {
    root: &'a PageTableRoot,
    identity: TableIdentity,
    roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    scratch: &'a mut ActiveScratchTarget<LiveActiveScratchIo>,
    _not_send_sync: core::marker::PhantomData<*mut ()>,
}

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
#[derive(Clone, Copy)]
struct ActiveWalk {
    entry: u64,
    physical_start: u64,
    user: bool,
    writable: bool,
    executable: bool,
}

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActiveUserAccessError {
    MissingOrInvalid,
    Permission,
}

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
struct ActiveUserPageAccess<'a, 'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> {
    authority: &'a mut ActiveRootTestAuthority<'root, RANGE_CAPACITY, ROLE_CAPACITY>,
}

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
struct PinnedActiveUserPages<'a, 'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> {
    authority: &'a mut ActiveRootTestAuthority<'root, RANGE_CAPACITY, ROLE_CAPACITY>,
}

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
impl<'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    crate::memory::usercopy::UserPageAccess
    for ActiveUserPageAccess<'_, 'root, RANGE_CAPACITY, ROLE_CAPACITY>
{
    type Error = ActiveUserAccessError;
    type Pinned<'a>
        = PinnedActiveUserPages<'a, 'root, RANGE_CAPACITY, ROLE_CAPACITY>
    where
        Self: 'a;

    fn pin(
        &mut self,
        _range: crate::memory::user_range::UserRange,
    ) -> Result<Self::Pinned<'_>, Self::Error> {
        Ok(PinnedActiveUserPages {
            authority: self.authority,
        })
    }
}

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    crate::memory::usercopy::PinnedUserPages
    for PinnedActiveUserPages<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    type Error = ActiveUserAccessError;

    fn preflight(
        &mut self,
        chunk: crate::memory::user_range::UserPageChunk,
    ) -> Result<(), Self::Error> {
        let walk = self
            .authority
            .walk_leaf(chunk.page_start())
            .map_err(|_| ActiveUserAccessError::MissingOrInvalid)?;
        if !walk.user
            || (chunk
                .access()
                .includes(crate::memory::user_range::UserAccess::WRITE)
                && !walk.writable)
            || (chunk
                .access()
                .includes(crate::memory::user_range::UserAccess::EXECUTE)
                && !walk.executable)
        {
            return Err(ActiveUserAccessError::Permission);
        }
        Ok(())
    }

    #[allow(
        unsafe_code,
        reason = "the pinned live-root walk proved every source page present and user-readable before this exact copy"
    )]
    fn read_exact(&mut self, range: crate::memory::user_range::UserRange, destination: &mut [u8]) {
        unsafe {
            core::ptr::copy_nonoverlapping(
                range.start() as *const u8,
                destination.as_mut_ptr(),
                destination.len(),
            );
        }
    }

    #[allow(
        unsafe_code,
        reason = "the pinned live-root walk proved every destination page present and user-writable before this exact copy"
    )]
    fn write_exact(&mut self, range: crate::memory::user_range::UserRange, source: &[u8]) {
        unsafe {
            core::ptr::copy_nonoverlapping(source.as_ptr(), range.start() as *mut u8, source.len());
        }
    }
}

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    ActiveRootTestAuthority<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    const TEST_REGION_START: u64 = 0x0000_0000_4000_0000;
    const TEST_REGION_PAGES: u64 = 16;
    const ALIAS_VALUE: u64 = 0x4457_3043_334d_454d;

    fn guard_leaf_is_exact_zero(&mut self, virtual_address: u64) -> Result<bool, u32> {
        let page = VirtualPage::new(virtual_address).map_err(|_| 0x00d0_u32)?;
        let mut current = self.identity;
        for level in (1..=3).rev() {
            let entry = self
                .scratch
                .read_location(
                    FrameAddress::new(current.physical_start(), self.root.physical_limit())
                        .map_err(|_| 0x00d1_u32)?,
                    page.index(level),
                )
                .map_err(|_| 0x00d2_u32)?;
            if entry & !(physical_mask(self.root.capabilities) | HARDWARE_MUTABLE)
                != PRESENT | WRITABLE
            {
                return Ok(false);
            }
            let child_level = match level {
                3 => TableLevel::Pdpt,
                2 => TableLevel::Pd,
                1 => TableLevel::Pt,
                _ => unreachable!(),
            };
            let child = self
                .roles
                .table_identity(
                    self.identity.owner(),
                    child_level,
                    entry & physical_mask(self.root.capabilities),
                )
                .map_err(|_| 0x00d3_u32)?;
            self.roles
                .validate_table_child(current, child)
                .map_err(|_| 0x00d4_u32)?;
            current = child;
        }
        let entry = self
            .scratch
            .read_location(
                FrameAddress::new(current.physical_start(), self.root.physical_limit())
                    .map_err(|_| 0x00d5_u32)?,
                page.index(0),
            )
            .map_err(|_| 0x00d6_u32)?;
        Ok(entry == 0)
    }

    fn validate_live_kernel_guard_layout(&mut self) -> Result<(), u32> {
        let ist = crate::arch::x86_64::linked_ist_stack_layout().map_err(|_| 0x00e0_u32)?;
        let mut payload_pages = 0_usize;
        for stack in ist.stacks() {
            if !self.guard_leaf_is_exact_zero(stack.guard_page)? {
                return Err(0x00e1);
            }
            let first = self.walk_leaf(stack.bottom)?;
            let mut page = stack.bottom;
            while page < stack.top {
                let walk = self.walk_leaf(page)?;
                let offset = page.checked_sub(stack.bottom).ok_or(0x00e2_u32)?;
                if walk.physical_start
                    != first.physical_start.checked_add(offset).ok_or(0x00e3_u32)?
                    || walk.user
                    || !walk.writable
                    || walk.executable
                    || walk.entry & !physical_mask(self.root.capabilities) & !HARDWARE_MUTABLE
                        != PRESENT | WRITABLE | NO_EXECUTE
                    || self
                        .roles
                        .validate_kernel_image_page(
                            walk.physical_start,
                            KernelImageSegment::WritableData,
                        )
                        .is_err()
                {
                    return Err(0x00e4);
                }
                payload_pages = payload_pages.checked_add(1).ok_or(0x00e5_u32)?;
                page = page.checked_add(PAGE_SIZE).ok_or(0x00e6_u32)?;
            }
        }
        let thread_stacks =
            crate::arch::x86_64::linked_thread_kernel_stack_layout().map_err(|_| 0x00e7_u32)?;
        for stack in thread_stacks {
            if !self.guard_leaf_is_exact_zero(stack.guard_page)? {
                return Err(0x00e8);
            }
            let first = self.walk_leaf(stack.bottom)?;
            let mut page = stack.bottom;
            while page < stack.top {
                let walk = self.walk_leaf(page)?;
                let offset = page.checked_sub(stack.bottom).ok_or(0x00e9_u32)?;
                if walk.physical_start
                    != first.physical_start.checked_add(offset).ok_or(0x00ea_u32)?
                    || walk.user
                    || !walk.writable
                    || walk.executable
                    || walk.entry & !physical_mask(self.root.capabilities) & !HARDWARE_MUTABLE
                        != PRESENT | WRITABLE | NO_EXECUTE
                    || self
                        .roles
                        .validate_kernel_image_page(
                            walk.physical_start,
                            KernelImageSegment::WritableData,
                        )
                        .is_err()
                {
                    return Err(0x00eb);
                }
                payload_pages = payload_pages.checked_add(1).ok_or(0x00ec_u32)?;
                page = page.checked_add(PAGE_SIZE).ok_or(0x00ed_u32)?;
            }
        }
        let expected_pages = 12_usize
            .checked_add(
                crate::task::E3_THREAD_STACK_COUNT
                    * usize::try_from(crate::task::E3_THREAD_STACK_SIZE / PAGE_SIZE)
                        .map_err(|_| 0x00ee_u32)?,
            )
            .ok_or(0x00ef_u32)?;
        if payload_pages != expected_pages {
            return Err(0x00f0);
        }
        Ok(())
    }

    #[allow(
        unsafe_code,
        reason = "the active scratch mapper provides the physical zeroing fact consumed by the typed role transition"
    )]
    fn allocate_zeroed(&mut self) -> Result<(crate::memory::frame_roles::ZeroedGrant, u64), u32> {
        let allocation = self.roles.allocate(1).map_err(|_| 0x0101_u32)?;
        let physical_start = allocation.physical_start();
        self.roles
            .validate_allocation(&allocation)
            .map_err(|_| 0x0102_u32)?;
        let frame = FrameAddress::new(allocation.physical_start(), self.root.physical_limit())
            .map_err(|_| 0x0103_u32)?;
        self.scratch
            .zero_allocator_frame(frame)
            .map_err(|_| 0x0104_u32)?;
        // SAFETY: the exact live allocation was exclusively mapped through
        // the active Deep scratch window, every byte was zeroed, and the
        // window was removed and invalidated before this transition.
        unsafe { self.roles.assume_zeroed(allocation) }
            .map(|grant| (grant, physical_start))
            .map_err(|_| 0x0105_u32)
    }

    fn prepare_candidate(
        &mut self,
        level: TableLevel,
    ) -> Result<crate::memory::frame_roles::TableCandidateGrant, u32> {
        let (zeroed, _) = self.allocate_zeroed()?;
        self.roles
            .prepare_table(zeroed, self.identity.owner(), level)
            .map_err(|_| 0x0106_u32)
    }

    fn walk_leaf(&mut self, virtual_address: u64) -> Result<ActiveWalk, u32> {
        let page = VirtualPage::new(virtual_address).map_err(|_| 0x0201_u32)?;
        let user_half = page.is_user_half();
        let mut current = self.identity;
        let mut effective_user = true;
        let mut effective_writable = true;
        let mut effective_executable = true;
        for level in (1..=3).rev() {
            let entry = self
                .scratch
                .read_location(
                    FrameAddress::new(current.physical_start(), self.root.physical_limit())
                        .map_err(|_| 0x0202_u32)?,
                    page.index(level),
                )
                .map_err(|_| 0x0203_u32)?;
            if entry & PRESENT == 0 || entry & HUGE != 0 {
                return Err(0x0204);
            }
            effective_user &= entry & USER != 0;
            effective_writable &= entry & WRITABLE != 0;
            effective_executable &= entry & NO_EXECUTE == 0;
            let child_level = match level {
                3 => TableLevel::Pdpt,
                2 => TableLevel::Pd,
                1 => TableLevel::Pt,
                _ => unreachable!(),
            };
            let physical_start = entry & physical_mask(self.root.capabilities);
            let child = self
                .roles
                .table_identity(self.identity.owner(), child_level, physical_start)
                .map_err(|_| 0x0205_u32)?;
            self.roles
                .validate_table_child(current, child)
                .map_err(|_| 0x0206_u32)?;
            current = child;
        }
        let entry = self
            .scratch
            .read_location(
                FrameAddress::new(current.physical_start(), self.root.physical_limit())
                    .map_err(|_| 0x0207_u32)?,
                page.index(0),
            )
            .map_err(|_| 0x0208_u32)?;
        if entry & PRESENT == 0 || entry & HUGE != 0 {
            return Err(0x0209);
        }
        effective_user &= entry & USER != 0;
        effective_writable &= entry & WRITABLE != 0;
        effective_executable &= entry & NO_EXECUTE == 0;
        if effective_user != user_half {
            return Err(0x020a);
        }
        Ok(ActiveWalk {
            entry,
            physical_start: entry & physical_mask(self.root.capabilities),
            user: effective_user,
            writable: effective_writable,
            executable: effective_executable,
        })
    }

    #[allow(
        unsafe_code,
        reason = "the test-only authority created both model keys for this exact retained active root and uniquely borrowed scratch target"
    )]
    fn bind_test_publisher<'borrow>(
        &'borrow mut self,
        address_space: crate::memory::address_region::AddressSpaceKey,
        region: crate::memory::address_region::RegionKey,
        candidates: &'borrow mut [Option<crate::memory::frame_roles::TableCandidateGrant>; 3],
    ) -> Result<
        super::super::super::journal::X86AddressSpacePublisher<
            'borrow,
            ActiveScratchTarget<LiveActiveScratchIo>,
            RANGE_CAPACITY,
            ROLE_CAPACITY,
            3,
            4,
            1,
        >,
        u32,
    > {
        unsafe {
            super::super::super::journal::X86AddressSpacePublisher::new(
                address_space,
                region,
                self.root,
                self.identity,
                self.roles,
                self.scratch,
                candidates,
            )
        }
        .map_err(|_| 0x0405_u32)
    }

    fn model_has_exact_single_mapping(
        region: &crate::memory::address_region::AddressRegion<2>,
        objects: &crate::memory::object::MemoryObjectAuthority<1, 2>,
        virtual_start: u64,
        physical_start: u64,
        protection: crate::memory::object::MemoryProtection,
    ) -> bool {
        let mut mappings = region.mappings().iter().flatten();
        mappings.next().is_some_and(|mapping| {
            mapping.virtual_start() == virtual_start
                && mapping.byte_len() == PAGE_SIZE
                && mapping.backing().physical_start() == physical_start
                && mapping.protection() == protection
        }) && mappings.next().is_none()
            && objects.active_lease_count() == 1
    }

    fn model_has_exact_two_mappings(
        region: &crate::memory::address_region::AddressRegion<2>,
        objects: &crate::memory::object::MemoryObjectAuthority<1, 2>,
        first: (u64, crate::memory::object::MemoryProtection),
        second: (u64, crate::memory::object::MemoryProtection),
        physical_start: u64,
    ) -> bool {
        let mappings = region.mappings();
        let Some(first_mapping) = mappings[0] else {
            return false;
        };
        let Some(second_mapping) = mappings[1] else {
            return false;
        };
        first_mapping.virtual_start() == first.0
            && second_mapping.virtual_start() == second.0
            && first_mapping.byte_len() == PAGE_SIZE
            && second_mapping.byte_len() == PAGE_SIZE
            && first_mapping.backing().physical_start() == physical_start
            && second_mapping.backing().physical_start() == physical_start
            && first_mapping.protection() == first.1
            && second_mapping.protection() == second.1
            && mappings[2..].iter().all(Option::is_none)
            && objects.active_lease_count() == 2
    }

    #[allow(
        unsafe_code,
        reason = "the target-only guest fixture uniquely owns its synthetic AddressSpaceAuthority root"
    )]
    fn run_mapped_case(&mut self, test: crate::test_support::BuildGuestTest) -> ! {
        use crate::memory::address_region::{
            AddressSpaceAuthority, AddressSpaceTransactionFailure,
        };
        use crate::memory::object::{
            MappingFinalReleases, MemoryObjectAuthority, MemoryObjectKind, MemoryProtection,
        };
        use crate::object::ObjectRegistry;
        use deepwyrm_abi::DW_OBJECT_TYPE_MEMORY_OBJECT;

        fn require_clean_mapping<E, const FINALIZERS: usize>(
            result: Result<
                MappingFinalReleases<FINALIZERS>,
                AddressSpaceTransactionFailure<E, FINALIZERS>,
            >,
            detail: u32,
        ) -> Result<(), u32> {
            match result {
                Ok(releases) if releases.is_empty() => Ok(()),
                Ok(_) => Err(detail),
                Err(failure) => {
                    let _clean = failure.into_final_releases().is_empty();
                    Err(detail)
                }
            }
        }

        let first = Self::TEST_REGION_START;
        let (allocation, backing_physical) = self
            .allocate_zeroed()
            .unwrap_or_else(|detail| crate::test_support::complete_fail(detail));
        if backing_physical == first {
            crate::test_support::complete_fail(0x0400);
        }
        let backing = self
            .roles
            .assign_object_backing(allocation)
            .unwrap_or_else(|_| crate::test_support::complete_fail(0x0401));
        let mut registry = ObjectRegistry::<1>::new();
        let creation = registry
            .create(DW_OBJECT_TYPE_MEMORY_OBJECT)
            .unwrap_or_else(|_| crate::test_support::complete_fail(0x0402));
        let mut objects = MemoryObjectAuthority::<1, 2>::new();
        let object = objects
            .grant_backing(
                &creation,
                backing,
                PAGE_SIZE,
                MemoryObjectKind::PageBacked,
                MemoryProtection::READ_WRITE_EXECUTE,
            )
            .unwrap_or_else(|_| crate::test_support::complete_fail(0x0402));
        let object_owner = registry
            .creation_into_internal(creation)
            .unwrap_or_else(|_| crate::test_support::complete_fail(0x0402));
        if object.object_id() != Some(object_owner.id()) {
            crate::test_support::complete_fail(0x0402);
        }

        let mut candidates = [
            Some(
                self.prepare_candidate(TableLevel::Pdpt)
                    .unwrap_or_else(|detail| crate::test_support::complete_fail(detail)),
            ),
            Some(
                self.prepare_candidate(TableLevel::Pd)
                    .unwrap_or_else(|detail| crate::test_support::complete_fail(detail)),
            ),
            Some(
                self.prepare_candidate(TableLevel::Pt)
                    .unwrap_or_else(|detail| crate::test_support::complete_fail(detail)),
            ),
        ];
        let mut spaces = unsafe { AddressSpaceAuthority::<1, 2>::new() };
        let address_space = spaces
            .create_address_space()
            .unwrap_or_else(|_| crate::test_support::complete_fail(0x0403));
        let mut region = spaces
            .create_region::<2>(
                address_space,
                Self::TEST_REGION_START,
                Self::TEST_REGION_PAGES * PAGE_SIZE,
            )
            .unwrap_or_else(|_| crate::test_support::complete_fail(0x0404));

        // Keep every portable model authority and role-backed object in this
        // terminal frame. The closure may report a scenario result, but the
        // owners cannot be dropped while any published test mapping survives:
        // both completion paths below diverge before this scope can unwind.
        let result = (|| -> Result<(), u32> {
            let resolved = crate::handle::resolve_test_internal_owner(
                &mut registry,
                &object_owner,
                deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
            );
            let authorization = region
                .authorize_map(&objects, resolved, MemoryProtection::READ_WRITE_EXECUTE)
                .map_err(|_| 0x0406_u32)?;
            {
                let mut publisher =
                    self.bind_test_publisher(address_space, region.region_key(), &mut candidates)?;
                require_clean_mapping(
                    region.map(
                        &mut objects,
                        &mut registry,
                        &mut publisher,
                        first,
                        authorization,
                        0,
                        PAGE_SIZE,
                        MemoryProtection::READ_WRITE,
                    ),
                    0x0407_u32,
                )?;
            }

            match test {
                crate::test_support::BuildGuestTest::MemoryMapping => (|| -> Result<(), u32> {
                    let walk = self.walk_leaf(first)?;
                    if walk.physical_start != backing_physical
                        || !walk.user
                        || !walk.writable
                        || walk.executable
                        || walk.entry & GLOBAL != 0
                        || !Self::model_has_exact_single_mapping(
                            &region,
                            &objects,
                            first,
                            backing_physical,
                            MemoryProtection::READ_WRITE,
                        )
                    {
                        return Err(0x0410);
                    }
                    self.write_then_read_alias(first, first)?;
                    Ok(())
                })(),
                crate::test_support::BuildGuestTest::MemoryUnmapping => (|| -> Result<(), u32> {
                    self.write_then_read_alias(first, first)?;
                    {
                        let mut publisher = self.bind_test_publisher(
                            address_space,
                            region.region_key(),
                            &mut candidates,
                        )?;
                        require_clean_mapping(
                            region.unmap(
                                &mut objects,
                                &mut registry,
                                &mut publisher,
                                first,
                                PAGE_SIZE,
                            ),
                            0x0420_u32,
                        )?;
                    }
                    if self.walk_leaf(first).is_ok()
                        || !region.mappings().iter().all(Option::is_none)
                        || objects.active_lease_count() != 0
                    {
                        return Err(0x0421);
                    }
                    crate::test_support::expect_terminal_page_fault(
                        first,
                        crate::test_support::ExpectedPageFaultKind::UnmappedSupervisorRead,
                    )
                })(),
                crate::test_support::BuildGuestTest::MemoryPermissions => {
                    (|| -> Result<(), u32> {
                        let initial = self.walk_leaf(first)?;
                        if initial.physical_start != backing_physical
                            || !Self::model_has_exact_single_mapping(
                                &region,
                                &objects,
                                first,
                                backing_physical,
                                MemoryProtection::READ_WRITE,
                            )
                        {
                            return Err(0x042f);
                        }
                        self.write_then_read_alias(first, first)?;
                        {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            require_clean_mapping(
                                region.protect(
                                    &mut objects,
                                    &mut registry,
                                    &mut publisher,
                                    first,
                                    PAGE_SIZE,
                                    MemoryProtection::READ,
                                ),
                                0x0430_u32,
                            )?;
                        }
                        let read_only = self.walk_leaf(first)?;
                        if !read_only.user
                            || read_only.writable
                            || read_only.executable
                            || read_only.physical_start != backing_physical
                            || !Self::model_has_exact_single_mapping(
                                &region,
                                &objects,
                                first,
                                backing_physical,
                                MemoryProtection::READ,
                            )
                        {
                            return Err(0x0431);
                        }
                        {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            require_clean_mapping(
                                region.protect(
                                    &mut objects,
                                    &mut registry,
                                    &mut publisher,
                                    first,
                                    PAGE_SIZE,
                                    MemoryProtection::READ_EXECUTE,
                                ),
                                0x0432_u32,
                            )?;
                        }
                        let executable = self.walk_leaf(first)?;
                        if !executable.user
                            || executable.writable
                            || !executable.executable
                            || executable.physical_start != backing_physical
                            || !Self::model_has_exact_single_mapping(
                                &region,
                                &objects,
                                first,
                                backing_physical,
                                MemoryProtection::READ_EXECUTE,
                            )
                        {
                            return Err(0x0433);
                        }
                        let before = executable.entry;
                        let rejected = {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            region.protect(
                                &mut objects,
                                &mut registry,
                                &mut publisher,
                                first,
                                PAGE_SIZE,
                                MemoryProtection::READ_WRITE_EXECUTE,
                            )
                        };
                        let rejected_clean = match rejected {
                            Err(failure) => failure.into_final_releases().is_empty(),
                            Ok(releases) => {
                                let _clean = releases.is_empty();
                                false
                            }
                        };
                        let after_rejected = self.walk_leaf(first)?;
                        if !rejected_clean
                            || after_rejected.entry != before
                            || after_rejected.physical_start != backing_physical
                            || !Self::model_has_exact_single_mapping(
                                &region,
                                &objects,
                                first,
                                backing_physical,
                                MemoryProtection::READ_EXECUTE,
                            )
                        {
                            return Err(0x0434);
                        }
                        {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            require_clean_mapping(
                                region.protect(
                                    &mut objects,
                                    &mut registry,
                                    &mut publisher,
                                    first,
                                    PAGE_SIZE,
                                    MemoryProtection::READ,
                                ),
                                0x0435_u32,
                            )?;
                        }
                        let read_only = self.walk_leaf(first)?;
                        if !read_only.user
                            || read_only.writable
                            || read_only.executable
                            || read_only.physical_start != backing_physical
                            || !Self::model_has_exact_single_mapping(
                                &region,
                                &objects,
                                first,
                                backing_physical,
                                MemoryProtection::READ,
                            )
                        {
                            return Err(0x0436);
                        }
                        crate::test_support::expect_terminal_page_fault(
                            first,
                            crate::test_support::ExpectedPageFaultKind::WriteProtectedSupervisorWrite,
                        )
                    })()
                }
                crate::test_support::BuildGuestTest::MemoryInvalidPointer => {
                    (|| -> Result<(), u32> {
                        use crate::memory::user_range::{
                            EmptyAddressRule, UserAccess, UserAddressSpace, UserRange,
                            UserRangeError, X86_64_USER_END_EXCLUSIVE,
                        };
                        use crate::memory::usercopy::UserCopyError;

                        let user_space = UserAddressSpace::x86_64_four_level(PAGE_SIZE)
                            .map_err(|_| 0x0437_u32)?;
                        let original_entry = self.walk_leaf(first)?.entry;
                        let original_mappings = *region.mappings();
                        let original_leases = objects.active_lease_count();
                        for access in [UserAccess::READ, UserAccess::WRITE] {
                            if UserRange::new(user_space, 0, 1, 1, access, EmptyAddressRule::Reject)
                                != Err(UserRangeError::NullAddress)
                                || UserRange::new(
                                    user_space,
                                    X86_64_USER_END_EXCLUSIVE,
                                    1,
                                    1,
                                    access,
                                    EmptyAddressRule::Reject,
                                ) != Err(UserRangeError::OutsideUserAddressSpace)
                                || UserRange::new(
                                    user_space,
                                    0xffff_8000_0000_0000,
                                    1,
                                    1,
                                    access,
                                    EmptyAddressRule::Reject,
                                ) != Err(UserRangeError::OutsideUserAddressSpace)
                                || UserRange::new(
                                    user_space,
                                    u64::MAX - 3,
                                    8,
                                    1,
                                    access,
                                    EmptyAddressRule::Reject,
                                ) != Err(UserRangeError::AddressOverflow)
                            {
                                return Err(0x0438);
                            }
                        }
                        if self.walk_leaf(first)?.entry != original_entry
                            || *region.mappings() != original_mappings
                            || objects.active_lease_count() != original_leases
                        {
                            return Err(0x0439);
                        }

                        let probe = first + PAGE_SIZE - 8;
                        let crossing = first + PAGE_SIZE - 4;
                        self.write_then_read_alias(probe, probe)?;
                        if self.walk_leaf(first + PAGE_SIZE).is_ok() {
                            return Err(0x043a);
                        }
                        let read_crossing = UserRange::new(
                            user_space,
                            crossing,
                            8,
                            1,
                            UserAccess::READ,
                            EmptyAddressRule::Reject,
                        )
                        .map_err(|_| 0x043b_u32)?;
                        let mut destination = [0xa5_u8; 8];
                        let destination_before = destination;
                        let mut scratch = [0x5a_u8; 8];
                        let read_result = {
                            let mut access = ActiveUserPageAccess { authority: self };
                            crate::memory::usercopy::copy_from_user(
                                &mut access,
                                read_crossing,
                                &mut destination,
                                &mut scratch,
                            )
                        };
                        if !matches!(
                            read_result,
                            Err(UserCopyError::Access(
                                ActiveUserAccessError::MissingOrInvalid
                            ))
                        ) || destination != destination_before
                            || self.read_alias_word(probe)? != Self::ALIAS_VALUE
                        {
                            return Err(0x043c);
                        }

                        let write_crossing = UserRange::new(
                            user_space,
                            crossing,
                            8,
                            1,
                            UserAccess::WRITE,
                            EmptyAddressRule::Reject,
                        )
                        .map_err(|_| 0x043d_u32)?;
                        let write_result = {
                            let mut access = ActiveUserPageAccess { authority: self };
                            crate::memory::usercopy::copy_to_user(
                                &mut access,
                                write_crossing,
                                b"BADWRITE",
                            )
                        };
                        if !matches!(
                            write_result,
                            Err(UserCopyError::Access(
                                ActiveUserAccessError::MissingOrInvalid
                            ))
                        ) || self.read_alias_word(probe)? != Self::ALIAS_VALUE
                        {
                            return Err(0x043e);
                        }

                        {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            require_clean_mapping(
                                region.protect(
                                    &mut objects,
                                    &mut registry,
                                    &mut publisher,
                                    first,
                                    PAGE_SIZE,
                                    MemoryProtection::READ,
                                ),
                                0x043f_u32,
                            )?;
                        }
                        let read_only = self.walk_leaf(first)?;
                        if !read_only.user || read_only.writable || read_only.executable {
                            return Err(0x0470);
                        }

                        destination.fill(0xa5);
                        scratch.fill(0x5a);
                        let read_result = {
                            let mut access = ActiveUserPageAccess { authority: self };
                            crate::memory::usercopy::copy_from_user(
                                &mut access,
                                read_crossing,
                                &mut destination,
                                &mut scratch,
                            )
                        };
                        if !matches!(
                            read_result,
                            Err(UserCopyError::Access(
                                ActiveUserAccessError::MissingOrInvalid
                            ))
                        ) || destination != [0xa5_u8; 8]
                            || self.read_alias_word(probe)? != Self::ALIAS_VALUE
                        {
                            return Err(0x0471);
                        }

                        let read_exact = UserRange::new(
                            user_space,
                            probe,
                            8,
                            8,
                            UserAccess::READ,
                            EmptyAddressRule::Reject,
                        )
                        .map_err(|_| 0x0472_u32)?;
                        destination.fill(0);
                        scratch.fill(0);
                        {
                            let mut access = ActiveUserPageAccess { authority: self };
                            crate::memory::usercopy::copy_from_user(
                                &mut access,
                                read_exact,
                                &mut destination,
                                &mut scratch,
                            )
                            .map_err(|_| 0x0473_u32)?;
                        }
                        if destination != Self::ALIAS_VALUE.to_ne_bytes() {
                            return Err(0x0474);
                        }

                        let write_exact = UserRange::new(
                            user_space,
                            probe,
                            8,
                            8,
                            UserAccess::WRITE,
                            EmptyAddressRule::Reject,
                        )
                        .map_err(|_| 0x0475_u32)?;
                        let write_result = {
                            let mut access = ActiveUserPageAccess { authority: self };
                            crate::memory::usercopy::copy_to_user(
                                &mut access,
                                write_exact,
                                b"BADWRITE",
                            )
                        };
                        if !matches!(
                            write_result,
                            Err(UserCopyError::Access(ActiveUserAccessError::Permission))
                        ) || self.read_alias_word(probe)? != Self::ALIAS_VALUE
                        {
                            return Err(0x0476);
                        }

                        {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            require_clean_mapping(
                                region.protect(
                                    &mut objects,
                                    &mut registry,
                                    &mut publisher,
                                    first,
                                    PAGE_SIZE,
                                    MemoryProtection::READ_WRITE,
                                ),
                                0x0477_u32,
                            )?;
                        }
                        let second = first + PAGE_SIZE;
                        if backing_physical == second {
                            return Err(0x0478);
                        }
                        let resolved = crate::handle::resolve_test_internal_owner(
                            &mut registry,
                            &object_owner,
                            deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
                        );
                        let authorization = region
                            .authorize_map(&objects, resolved, MemoryProtection::READ_WRITE_EXECUTE)
                            .map_err(|_| 0x0479_u32)?;
                        {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            require_clean_mapping(
                                region.map(
                                    &mut objects,
                                    &mut registry,
                                    &mut publisher,
                                    second,
                                    authorization,
                                    0,
                                    PAGE_SIZE,
                                    MemoryProtection::READ_WRITE,
                                ),
                                0x047a_u32,
                            )?;
                        }
                        self.write_then_read_alias(second, second)?;
                        {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            require_clean_mapping(
                                region.protect(
                                    &mut objects,
                                    &mut registry,
                                    &mut publisher,
                                    second,
                                    PAGE_SIZE,
                                    MemoryProtection::READ,
                                ),
                                0x047b_u32,
                            )?;
                        }
                        let first_walk = self.walk_leaf(first)?;
                        let second_walk = self.walk_leaf(second)?;
                        if !first_walk.user
                            || !first_walk.writable
                            || first_walk.executable
                            || !second_walk.user
                            || second_walk.writable
                            || second_walk.executable
                            || first_walk.physical_start != backing_physical
                            || second_walk.physical_start != backing_physical
                            || !Self::model_has_exact_two_mappings(
                                &region,
                                &objects,
                                (first, MemoryProtection::READ_WRITE),
                                (second, MemoryProtection::READ),
                                backing_physical,
                            )
                        {
                            return Err(0x047c);
                        }
                        let first_entry = first_walk.entry;
                        let second_entry = second_walk.entry;
                        let write_result = {
                            let mut access = ActiveUserPageAccess { authority: self };
                            crate::memory::usercopy::copy_to_user(
                                &mut access,
                                write_crossing,
                                b"BADWRITE",
                            )
                        };
                        if !matches!(
                            write_result,
                            Err(UserCopyError::Access(ActiveUserAccessError::Permission))
                        ) || self.read_alias_word(probe)? != Self::ALIAS_VALUE
                            || self.read_alias_word(second)? != Self::ALIAS_VALUE
                            || self.walk_leaf(first)?.entry != first_entry
                            || self.walk_leaf(second)?.entry != second_entry
                            || !Self::model_has_exact_two_mappings(
                                &region,
                                &objects,
                                (first, MemoryProtection::READ_WRITE),
                                (second, MemoryProtection::READ),
                                backing_physical,
                            )
                        {
                            return Err(0x047d);
                        }
                        Ok(())
                    })()
                }
                crate::test_support::BuildGuestTest::MemoryUserKernelIsolation => {
                    (|| -> Result<(), u32> {
                        use crate::memory::address_region::{
                            AddressRegionError, AddressSpaceTransactionError,
                        };

                        let user = self.walk_leaf(first)?;
                        let kernel_page = live_kernel_segments()
                            .map_err(|_| 0x0440_u32)?
                            .first()
                            .ok_or(0x0441_u32)?
                            .start;
                        let kernel = self.walk_leaf(kernel_page)?;
                        if !user.user || kernel.user {
                            return Err(0x0442);
                        }
                        if !matches!(
                            spaces.create_region::<1>(
                                address_space,
                                0xffff_8000_0000_0000,
                                PAGE_SIZE,
                            ),
                            Err(AddressRegionError::OutsideRegion)
                        ) {
                            return Err(0x0443);
                        }
                        if self.walk_leaf(0).is_ok() {
                            return Err(0x0444);
                        }
                        let mappings_before = *region.mappings();
                        let leases_before = objects.active_lease_count();
                        let first_before = self.walk_leaf(first)?.entry;
                        let resolved = crate::handle::resolve_test_internal_owner(
                            &mut registry,
                            &object_owner,
                            deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
                        );
                        let authorization = region
                            .authorize_map(&objects, resolved, MemoryProtection::READ_WRITE_EXECUTE)
                            .map_err(|_| 0x0445_u32)?;
                        let rejected = {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            region.map(
                                &mut objects,
                                &mut registry,
                                &mut publisher,
                                0,
                                authorization,
                                0,
                                PAGE_SIZE,
                                MemoryProtection::READ_WRITE,
                            )
                        };
                        let rejected = match rejected {
                            Err(failure) => {
                                let (error, final_releases) = failure.into_parts();
                                if !final_releases.is_empty() {
                                    return Err(0x0446);
                                }
                                error
                            }
                            Ok(releases) => {
                                let _clean = releases.is_empty();
                                return Err(0x0446);
                            }
                        };
                        if !matches!(
                            rejected,
                            AddressSpaceTransactionError::Model(AddressRegionError::PageZero)
                        ) || self.walk_leaf(0).is_ok()
                            || self.walk_leaf(first)?.entry != first_before
                            || *region.mappings() != mappings_before
                            || objects.active_lease_count() != leases_before
                        {
                            return Err(0x0446);
                        }
                        Ok(())
                    })()
                }
                crate::test_support::BuildGuestTest::MemorySharedMemoryObject => {
                    (|| -> Result<(), u32> {
                        let second = first + PAGE_SIZE;
                        if backing_physical == second {
                            return Err(0x044f);
                        }
                        let resolved = crate::handle::resolve_test_internal_owner(
                            &mut registry,
                            &object_owner,
                            deepwyrm_abi::dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT),
                        );
                        let authorization = region
                            .authorize_map(&objects, resolved, MemoryProtection::READ_WRITE_EXECUTE)
                            .map_err(|_| 0x0450_u32)?;
                        {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            require_clean_mapping(
                                region.map(
                                    &mut objects,
                                    &mut registry,
                                    &mut publisher,
                                    second,
                                    authorization,
                                    0,
                                    PAGE_SIZE,
                                    MemoryProtection::READ_WRITE,
                                ),
                                0x0451_u32,
                            )?;
                        }
                        let first_walk = self.walk_leaf(first)?;
                        let second_walk = self.walk_leaf(second)?;
                        if first_walk.physical_start != backing_physical
                            || second_walk.physical_start != backing_physical
                            || !Self::model_has_exact_two_mappings(
                                &region,
                                &objects,
                                (first, MemoryProtection::READ_WRITE),
                                (second, MemoryProtection::READ_WRITE),
                                backing_physical,
                            )
                        {
                            return Err(0x0452);
                        }
                        self.write_then_read_alias(first, second)?;
                        {
                            let mut publisher = self.bind_test_publisher(
                                address_space,
                                region.region_key(),
                                &mut candidates,
                            )?;
                            require_clean_mapping(
                                region.unmap(
                                    &mut objects,
                                    &mut registry,
                                    &mut publisher,
                                    first,
                                    PAGE_SIZE,
                                ),
                                0x0453_u32,
                            )?;
                        }
                        let retained = self.walk_leaf(second)?;
                        if self.walk_leaf(first).is_ok()
                            || retained.physical_start != backing_physical
                            || !retained.user
                            || !retained.writable
                            || retained.executable
                            || self.read_alias_word(second)? != Self::ALIAS_VALUE
                            || !Self::model_has_exact_single_mapping(
                                &region,
                                &objects,
                                second,
                                backing_physical,
                                MemoryProtection::READ_WRITE,
                            )
                        {
                            return Err(0x0454);
                        }
                        Ok(())
                    })()
                }
                _ => Err(0x04ff),
            }
        })();

        match result {
            Ok(()) => crate::test_support::complete_pass(0),
            Err(detail) => crate::test_support::complete_fail(detail),
        }
    }

    #[allow(
        unsafe_code,
        reason = "the bound live-root walks prove both exact user aliases writable while this authority excludes address-space mutation"
    )]
    fn write_then_read_alias(&mut self, writer: u64, reader: u64) -> Result<(), u32> {
        let writer_walk = self.walk_leaf(writer)?;
        let reader_walk = self.walk_leaf(reader)?;
        if !writer_walk.user
            || !writer_walk.writable
            || !reader_walk.user
            || !reader_walk.writable
            || !unsafe {
                crate::test_support::write_then_read_user_alias(writer, reader, Self::ALIAS_VALUE)
            }
        {
            return Err(0x0460);
        }
        Ok(())
    }

    #[allow(
        unsafe_code,
        reason = "the bound live-root walk proves this exact user word readable while the authority excludes address-space mutation"
    )]
    fn read_alias_word(&mut self, address: u64) -> Result<u64, u32> {
        let walk = self.walk_leaf(address)?;
        if !walk.user {
            return Err(0x0461);
        }
        Ok(unsafe { crate::test_support::read_user_alias_word(address) })
    }
}

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
impl<'roles, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    ActiveDeepPaging<LiveActivePagingTarget<'roles, RANGE_CAPACITY, ROLE_CAPACITY>>
{
    pub(crate) fn run_memory_foundation_test(
        mut self,
        test: crate::test_support::BuildGuestTest,
    ) -> ! {
        let authority = &mut ActiveRootTestAuthority {
            root: &self.root,
            identity: self.identity,
            roles: &mut *self.target.roles,
            scratch: &mut self.target.scratch,
            _not_send_sync: core::marker::PhantomData,
        };
        if let Err(detail) = authority.validate_live_kernel_guard_layout() {
            crate::test_support::complete_fail(detail)
        }
        match test {
            test if test.is_memory_foundation() => authority.run_mapped_case(test),
            _ => crate::test_support::complete_fail(0x00ff),
        }
    }
}

#[cfg(all(
    feature = "test-support",
    target_os = "none",
    target_arch = "x86_64",
    deepwyrm_c3_one_shot_ui
))]
fn active_deep_paging_cannot_be_duplicated<
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
>(
    active: ActiveDeepPaging<LiveActivePagingTarget<'_, RANGE_CAPACITY, ROLE_CAPACITY>>,
    test: crate::test_support::BuildGuestTest,
) -> ! {
    let claimed = active;
    core::hint::black_box(&active);
    claimed.run_memory_foundation_test(test)
}
