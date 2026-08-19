use super::*;

use crate::memory::frame_roles::{ObjectBackingGrant, TableCandidateGrant};
use crate::memory::user_range::{UserAccess, UserPageChunk, UserRange};
use crate::memory::usercopy::{
    PinnedUserPages, UserPageAccess, UserPinError, UserPinTracker, UserRangePin,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveUserAccessError {
    MissingOrInvalid,
    Permission,
    Pin(UserPinError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveTrackedTargetError {
    Target(LiveActiveTargetError),
    Pin(UserPinError),
}

#[derive(Clone, Copy)]
struct LiveUserWalk {
    user: bool,
    writable: bool,
    executable: bool,
}

/// Pin-aware atomic target over the live x86 scratch publisher.
///
/// Actual page-table writes reserve the exact invalidation span before the
/// underlying atomic batch begins. New user pins and mapping mutations thus
/// exclude one another without holding the tracker spin lock across publication.
pub(crate) struct TrackedActiveTarget<'a> {
    pub(super) scratch: &'a mut ActiveScratchTarget<LiveActiveScratchIo>,
    pub(super) pins: &'a UserPinTracker<E5_USER_PIN_CAPACITY>,
}

impl super::journal_target_seal::Sealed for TrackedActiveTarget<'_> {}

#[allow(
    unsafe_code,
    reason = "the wrapper preserves the sealed live target's atomicity while adding range reservation before every write batch"
)]
unsafe impl AtomicPageTableTarget for TrackedActiveTarget<'_> {
    type Error = LiveTrackedTargetError;

    fn read_entry(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error> {
        self.scratch
            .read_entry(table, index)
            .map_err(LiveTrackedTargetError::Target)
    }

    fn apply(
        &mut self,
        writes: &[JournalWrite],
        invalidations: &[VirtualPage],
    ) -> Result<(), Self::Error> {
        let permit = if invalidations.is_empty() {
            None
        } else {
            let mut start = u64::MAX;
            let mut end = 0_u64;
            for page in invalidations {
                start = start.min(page.address());
                end = end.max(page.address().checked_add(PAGE_SIZE).ok_or(
                    LiveTrackedTargetError::Pin(UserPinError::InvalidMutationRange),
                )?);
            }
            Some(
                self.pins
                    .begin_mutation(start, end - start)
                    .map_err(LiveTrackedTargetError::Pin)?,
            )
        };
        let result = self
            .scratch
            .apply(writes, invalidations)
            .map_err(LiveTrackedTargetError::Target);
        drop(permit);
        result
    }
}

/// E5 view of the sole active BSP address-space root.
///
/// Usercopy pins are range-scoped through `pins`; physical backing work and
/// non-overlapping page-table mutation may continue while a pin is live. The
/// active target itself remains !Send/!Sync and every actual write batch must
/// acquire a non-overlapping mutation permit above.
pub(crate) struct LiveProcessAddressSpace<
    'borrow,
    'root,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
> {
    pub(super) root: &'borrow PageTableRoot,
    pub(super) identity: TableIdentity,
    pub(super) roles: &'borrow mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    pub(super) target: TrackedActiveTarget<'borrow>,
    pub(super) _root: core::marker::PhantomData<&'root mut ()>,
}

pub(crate) struct PinnedLiveUserPages<'tracker> {
    _pin: UserRangePin<'tracker, E5_USER_PIN_CAPACITY>,
    range: UserRange,
}

impl<'borrow, 'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> UserPageAccess
    for LiveProcessAddressSpace<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>
{
    type Error = LiveUserAccessError;
    type Pinned<'a>
        = PinnedLiveUserPages<'borrow>
    where
        Self: 'a;

    fn pin(&mut self, range: UserRange) -> Result<Self::Pinned<'_>, Self::Error> {
        let pins = self.target.pins;
        let pin = pins.pin(range).map_err(LiveUserAccessError::Pin)?;
        for chunk in range.page_chunks() {
            if let Err(error) = self.preflight(chunk) {
                drop(pin);
                return Err(error);
            }
        }
        Ok(PinnedLiveUserPages { _pin: pin, range })
    }
}

impl PinnedUserPages for PinnedLiveUserPages<'_> {
    type Error = LiveUserAccessError;

    fn preflight(&mut self, chunk: UserPageChunk) -> Result<(), Self::Error> {
        let chunk_end = chunk
            .address()
            .checked_add(chunk.byte_len())
            .ok_or(LiveUserAccessError::MissingOrInvalid)?;
        if chunk.address() < self.range.start()
            || chunk_end > self.range.end_exclusive()
            || chunk.access() != self.range.access()
        {
            return Err(LiveUserAccessError::Permission);
        }
        Ok(())
    }

    #[allow(
        unsafe_code,
        reason = "the range pin remains active and live-root preflight proved every source page readable before exact copy"
    )]
    fn read_exact(&mut self, range: UserRange, destination: &mut [u8]) {
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
        reason = "the range pin remains active and live-root preflight proved every destination page writable before exact copy"
    )]
    fn write_exact(&mut self, range: UserRange, source: &[u8]) {
        unsafe {
            core::ptr::copy_nonoverlapping(source.as_ptr(), range.start() as *mut u8, source.len());
        }
    }
}

impl<'borrow, 'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    LiveProcessAddressSpace<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn walk_leaf(&mut self, virtual_address: u64) -> Result<LiveUserWalk, LiveUserAccessError> {
        let page =
            VirtualPage::new(virtual_address).map_err(|_| LiveUserAccessError::MissingOrInvalid)?;
        if !page.is_user_half() {
            return Err(LiveUserAccessError::Permission);
        }
        let mut current = self.identity;
        let mut user = true;
        let mut writable = true;
        let mut executable = true;
        for level in (1..=3).rev() {
            let entry = self.read_entry(current, page.index(level))?;
            if entry & PRESENT == 0 || entry & HUGE != 0 {
                return Err(LiveUserAccessError::MissingOrInvalid);
            }
            user &= entry & USER != 0;
            writable &= entry & WRITABLE != 0;
            executable &= entry & NO_EXECUTE == 0;
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
                .map_err(|_| LiveUserAccessError::MissingOrInvalid)?;
            self.roles
                .validate_table_child(current, child)
                .map_err(|_| LiveUserAccessError::MissingOrInvalid)?;
            current = child;
        }
        let entry = self.read_entry(current, page.index(0))?;
        if entry & PRESENT == 0 || entry & HUGE != 0 {
            return Err(LiveUserAccessError::MissingOrInvalid);
        }
        user &= entry & USER != 0;
        writable &= entry & WRITABLE != 0;
        executable &= entry & NO_EXECUTE == 0;
        if !user {
            return Err(LiveUserAccessError::Permission);
        }
        Ok(LiveUserWalk {
            user,
            writable,
            executable,
        })
    }

    fn read_entry(
        &mut self,
        table: TableIdentity,
        index: usize,
    ) -> Result<u64, LiveUserAccessError> {
        self.target
            .read_entry(
                FrameAddress::new(table.physical_start(), self.root.physical_limit())
                    .map_err(|_| LiveUserAccessError::MissingOrInvalid)?,
                index,
            )
            .map_err(|_| LiveUserAccessError::MissingOrInvalid)
    }

    fn preflight(&mut self, chunk: UserPageChunk) -> Result<(), LiveUserAccessError> {
        let walk = self.walk_leaf(chunk.page_start())?;
        if !walk.user
            || (chunk.access().includes(UserAccess::WRITE) && !walk.writable)
            || (chunk.access().includes(UserAccess::EXECUTE) && !walk.executable)
        {
            return Err(LiveUserAccessError::Permission);
        }
        Ok(())
    }

    #[allow(
        unsafe_code,
        reason = "the authenticated scratch session zeroes the exclusive physical allocation before the typed Zeroed transition"
    )]
    pub(crate) fn allocate_zeroed_backing(
        &mut self,
        page_count: u64,
    ) -> Result<ObjectBackingGrant, LiveUserAccessError> {
        let allocation = self
            .roles
            .allocate(page_count)
            .map_err(|_| LiveUserAccessError::MissingOrInvalid)?;
        let physical_start = allocation.physical_start();
        let byte_len = allocation.byte_len();
        let mut offset = 0;
        while offset < byte_len {
            let frame = FrameAddress::new(physical_start + offset, self.root.physical_limit())
                .map_err(|_| LiveUserAccessError::MissingOrInvalid)?;
            if self.target.scratch.zero_allocator_frame(frame).is_err() {
                self.roles
                    .cancel_allocation(allocation)
                    .unwrap_or_else(|_| panic!("E5 backing rollback lost allocation authority"));
                return Err(LiveUserAccessError::MissingOrInvalid);
            }
            offset += PAGE_SIZE;
        }
        // SAFETY: every page in the exact exclusive allocation was zeroed
        // through the authenticated scratch mapping immediately above.
        let zeroed = unsafe { self.roles.assume_zeroed(allocation) }
            .unwrap_or_else(|_| panic!("E5 zeroed allocation role transition drifted"));
        self.roles.assign_object_backing(zeroed).map_err(|failure| {
            self.roles
                .cancel_zeroed(failure.into_grant())
                .unwrap_or_else(|_| panic!("E5 zeroed backing rollback drifted"));
            LiveUserAccessError::MissingOrInvalid
        })
    }

    #[allow(
        unsafe_code,
        reason = "the live session binds authority-issued identities to its exact pin-aware serialized architecture root"
    )]
    pub(crate) fn publisher<
        'publisher,
        const CANDIDATE_CAPACITY: usize,
        const ENTRY_CAPACITY: usize,
        const INVALIDATION_CAPACITY: usize,
    >(
        &'publisher mut self,
        address_space: crate::memory::address_region::AddressSpaceKey,
        region: crate::memory::address_region::RegionKey,
        candidates: &'publisher mut [Option<TableCandidateGrant>; CANDIDATE_CAPACITY],
    ) -> Result<
        crate::arch::x86_64::mm::X86AddressSpacePublisher<
            'publisher,
            TrackedActiveTarget<'borrow>,
            RANGE_CAPACITY,
            ROLE_CAPACITY,
            CANDIDATE_CAPACITY,
            ENTRY_CAPACITY,
            INVALIDATION_CAPACITY,
        >,
        crate::arch::x86_64::mm::X86AddressSpacePublishError<LiveTrackedTargetError>,
    > {
        let root = self.root;
        let identity = self.identity;
        let roles = &mut *self.roles;
        let target = &mut self.target;
        // SAFETY: this session owns the exact active root, role manager and
        // pin-aware serialized target; E5 supplies authority-issued identities.
        unsafe {
            crate::arch::x86_64::mm::X86AddressSpacePublisher::new(
                address_space,
                region,
                root,
                identity,
                roles,
                target,
                candidates,
            )
        }
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    crate::arch::x86_64::syscall::UserReturnMappingValidation
    for LiveProcessAddressSpace<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn executable_at(&mut self, address: u64) -> bool {
        self.walk_leaf(address)
            .is_ok_and(|walk| walk.user && walk.executable)
    }

    fn writable_byte_below(&mut self, stack_pointer: u64) -> bool {
        stack_pointer.checked_sub(1).is_some_and(|address| {
            self.walk_leaf(address)
                .is_ok_and(|walk| walk.user && walk.writable)
        })
    }
}
