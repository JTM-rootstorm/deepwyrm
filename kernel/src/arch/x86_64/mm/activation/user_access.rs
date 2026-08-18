use super::*;

use crate::memory::frame_roles::{ObjectBackingGrant, TableCandidateGrant};
use crate::memory::user_range::{UserAccess, UserPageChunk, UserRange};
use crate::memory::usercopy::{PinnedUserPages, UserPageAccess};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveUserAccessError {
    MissingOrInvalid,
    Permission,
}

#[derive(Clone, Copy)]
struct LiveUserWalk {
    user: bool,
    writable: bool,
    executable: bool,
}

/// Exclusive E5 view of the sole active BSP address-space root.
///
/// Holding this value is the mapping pin: safe Rust cannot simultaneously
/// create a publisher or another mutable live-root session while usercopy is
/// preflighted or committed. `ActiveDeepPaging` and its live target remain
/// !Send/!Sync, so this one-CPU contract cannot be aliased onto another CPU.
pub(crate) struct LiveProcessAddressSpace<
    'borrow,
    'root,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
> {
    pub(super) root: &'borrow PageTableRoot,
    pub(super) identity: TableIdentity,
    pub(super) roles: &'borrow mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    pub(super) scratch: &'borrow mut ActiveScratchTarget<LiveActiveScratchIo>,
    pub(super) _root: core::marker::PhantomData<&'root mut ()>,
}

pub(crate) struct PinnedLiveUserPages<
    'pin,
    'borrow,
    'root,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
> {
    address_space: &'pin mut LiveProcessAddressSpace<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>,
}

impl<'borrow, 'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> UserPageAccess
    for LiveProcessAddressSpace<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>
{
    type Error = LiveUserAccessError;
    type Pinned<'a>
        = PinnedLiveUserPages<'a, 'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>
    where
        Self: 'a;

    fn pin(&mut self, _range: UserRange) -> Result<Self::Pinned<'_>, Self::Error> {
        Ok(PinnedLiveUserPages {
            address_space: self,
        })
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> PinnedUserPages
    for PinnedLiveUserPages<'_, '_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    type Error = LiveUserAccessError;

    fn preflight(&mut self, chunk: UserPageChunk) -> Result<(), Self::Error> {
        self.address_space.preflight(chunk)
    }

    #[allow(
        unsafe_code,
        reason = "exclusive live-root pin proved every source page present and user-readable before exact copy"
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
        reason = "exclusive live-root pin proved every destination page present and user-writable before exact copy"
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
        self.scratch
            .read_location(
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
            if self.scratch.zero_allocator_frame(frame).is_err() {
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
        reason = "the exclusive live-root session binds authority-issued identities to its exact serialized architecture root"
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
            ActiveScratchTarget<LiveActiveScratchIo>,
            RANGE_CAPACITY,
            ROLE_CAPACITY,
            CANDIDATE_CAPACITY,
            ENTRY_CAPACITY,
            INVALIDATION_CAPACITY,
        >,
        crate::arch::x86_64::mm::X86AddressSpacePublishError<LiveActiveTargetError>,
    > {
        // SAFETY: this exclusive session owns the exact active root, its role
        // manager, and its serialized scratch target; E5 supplies authority-
        // issued address-space/region identities for that current Process.
        unsafe {
            crate::arch::x86_64::mm::X86AddressSpacePublisher::new(
                address_space,
                region,
                self.root,
                self.identity,
                self.roles,
                self.scratch,
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
