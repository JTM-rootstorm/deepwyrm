//! Linear activation of one validated, inactive Deepwyrm page-table root.
//!
//! Preparation is the only fallible phase. It retains both the live-transition
//! handoff and the target backend on failure. A prepared activation owns all
//! authority needed for one infallible CR3 publication, after which the
//! transition handoff is consumed and cannot be recovered.

#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
use crate::memory::boot_map::{BootstrapMemoryWitness, KernelImageBoundaryError};
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use crate::memory::frame_roles::TableOwnerKey;
use crate::memory::frame_roles::{
    FrameRoleError, FrameRoleManager, KernelImageRoleSet, KernelImageSegment,
    StagedKernelImageRoles, TableIdentity, TableLevel,
};
#[cfg(any(test, all(target_os = "none", target_arch = "x86_64")))]
use crate::memory::physical::PhysicalRange;

use super::super::VirtualPage;
use super::super::journal::{
    AtomicPageTableTarget, JournalWrite, target_seal as journal_target_seal,
};
use super::super::{
    ACCESSED, AddressError, CACHE_DISABLE, DIRTY, FrameAddress, GLOBAL, HUGE, NO_EXECUTE,
    PAGE_SIZE, PERMITTED_ENTRY_FLAGS, PRESENT, PageTableRoot, PagingCapabilities, SOFTWARE_HIGH,
    SOFTWARE_LOW, USER, WRITABLE, WRITE_THROUGH,
};
#[path = "activation/graph.rs"]
mod graph;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[path = "activation/user_access.rs"]
mod user_access;
use graph::*;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) use user_access::LiveProcessAddressSpace;
#[path = "activation/build.rs"]
mod build;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use build::build_and_bind_deep_root;

use super::private::TransitionActivationHandoff;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use super::private::{
    LiveTransitionError, LiveTransitionMapper, TransitionActivationAccessError,
    TransitionZeroError, claim_live_transition_mapper,
};

const ENTRY_COUNT: usize = 512;
const E5_USER_PIN_CAPACITY: usize = 8;
const MAX_DEEP_TABLE_FRAMES: usize = 256;
const ADDRESS_OFFSET_MASK: u64 = PAGE_SIZE - 1;
const HARDWARE_MUTABLE: u64 = ACCESSED | DIRTY;
const MIN_ACTIVATION_STACK_HEADROOM: u64 = PAGE_SIZE;
const DISALLOWED_COMMON: u64 =
    USER | WRITE_THROUGH | CACHE_DISABLE | HUGE | GLOBAL | SOFTWARE_LOW | SOFTWARE_HIGH;

/// One exact linker-owned descending IST stack and its low guard page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IstStackBounds {
    pub(crate) guard_page: u64,
    pub(crate) bottom: u64,
    pub(crate) top: u64,
}

/// The only three IST ranges retained by the first Deep-owned root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IstStackLayout {
    pub(crate) double_fault: IstStackBounds,
    pub(crate) non_maskable_interrupt: IstStackBounds,
    pub(crate) machine_check: IstStackBounds,
}

impl IstStackLayout {
    pub(crate) const fn stacks(self) -> [IstStackBounds; 3] {
        [
            self.double_fault,
            self.non_maskable_interrupt,
            self.machine_check,
        ]
    }

    pub(crate) fn has_exact_shape(self) -> bool {
        let stacks = self.stacks();
        stacks.iter().all(|stack| {
            stack.guard_page >= 0xffff_8000_0000_0000
                && stack.guard_page.is_multiple_of(PAGE_SIZE)
                && stack.bottom == stack.guard_page.checked_add(PAGE_SIZE).unwrap_or(0)
                && stack.top == stack.bottom.checked_add(16 * 1024).unwrap_or(0)
        }) && stacks[0].top == stacks[1].guard_page
            && stacks[1].top == stacks[2].guard_page
    }
}

#[derive(Clone, Copy)]
pub(super) struct DeepScratchBinding {
    window_page: u64,
    control_page: u64,
    pt: TableIdentity,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[derive(Clone, Copy)]
struct BuildEdge {
    parent: TableIdentity,
    index: usize,
    child: TableIdentity,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
struct BuildWorkspace(core::cell::UnsafeCell<[Option<BuildEdge>; MAX_DEEP_TABLE_FRAMES]>);

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl BuildWorkspace {
    const fn new() -> Self {
        Self(core::cell::UnsafeCell::new([None; MAX_DEEP_TABLE_FRAMES]))
    }
}

// SAFETY: the sole unsafe bootstrap activation session owns this workspace;
// APs are offline and C1's atomic claim excludes a second initializer.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "one-shot BSP activation serializes the static graph-build workspace"
)]
unsafe impl Sync for BuildWorkspace {}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static BUILD_WORKSPACE: BuildWorkspace = BuildWorkspace::new();

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DeepRootBuildError {
    Capacity,
    InvalidKernelLayout,
    MappingMismatch,
    BootBoundary(KernelImageBoundaryError),
    FrameRole(FrameRoleError),
    Transition,
    Root(AddressError),
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) struct DeepRootBuildFailure {
    error: DeepRootBuildError,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl DeepRootBuildFailure {
    pub(crate) const fn error(&self) -> &DeepRootBuildError {
        &self.error
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ActivationCpuState {
    processor_id: u8,
    physical_address_width: u8,
    current_root: FrameAddress,
    cpl: u8,
    paging_enabled: bool,
    long_mode_active: bool,
    four_level_paging: bool,
    no_execute_enabled: bool,
    write_protect_enabled: bool,
    interrupts_enabled: bool,
    pcid_enabled: bool,
    global_pages_enabled: bool,
    smap_enabled: bool,
    access_flag_set: bool,
    pat_supported: bool,
    pat_entry_zero: u8,
    stack_pointer: u64,
    code_selector: u16,
    gdt_base: u64,
    gdt_limit: u16,
    idt_base: u64,
    idt_limit: u16,
    task_register: u16,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ActivationPrepareError<E> {
    FrameRole(FrameRoleError),
    Root(AddressError),
    WrongProcessorState,
    WrongControlState,
    ActiveRootReused,
    InterruptsEnabled,
    PcidEnabled,
    GlobalPagesEnabled,
    Target(E),
}

struct InactiveDeepRoot {
    root: PageTableRoot,
    identity: TableIdentity,
}

/// Serialized authority for the exact inactive root built through the live C1
/// target. It owns the terminal transition handoff and exclusively borrows the
/// role registry, so no sibling can mutate roles or the graph between C2
/// preflight and activation.
pub(crate) struct InactiveRootAuthority<'a, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
{
    handoff: TransitionActivationHandoff<'a>,
    root: PageTableRoot,
    identity: TableIdentity,
    scratch: DeepScratchBinding,
    kernel_roles: KernelImageRoleSet,
    roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    _not_send_sync: core::marker::PhantomData<*mut ()>,
}

impl<'a, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    InactiveRootAuthority<'a, RANGE_CAPACITY, ROLE_CAPACITY>
{
    #[allow(
        clippy::result_large_err,
        reason = "the allocation-free linear failure path must return the unique transition handoff and root authority"
    )]
    pub(super) fn bind(
        handoff: TransitionActivationHandoff<'a>,
        root: PageTableRoot,
        identity: TableIdentity,
        scratch: DeepScratchBinding,
        kernel_roles: KernelImageRoleSet,
        roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    ) -> Result<
        Self,
        (
            FrameRoleError,
            TransitionActivationHandoff<'a>,
            PageTableRoot,
        ),
    > {
        if root.frame().address() != identity.physical_start()
            || root.physical_limit().exclusive() == 0
            || identity.level() != TableLevel::Pml4
            || scratch.pt.level() != TableLevel::Pt
            || scratch.pt.owner() != identity.owner()
            || scratch.control_page != scratch.window_page + PAGE_SIZE
        {
            return Err((FrameRoleError::WrongRole, handoff, root));
        }
        if let Err(error) = roles.validate_table_identity(identity) {
            return Err((error, handoff, root));
        }
        if let Err(error) = roles.validate_table_identity(scratch.pt) {
            return Err((error, handoff, root));
        }
        Ok(Self {
            handoff,
            root,
            identity,
            scratch,
            kernel_roles,
            roles,
            _not_send_sync: core::marker::PhantomData,
        })
    }
}

impl InactiveDeepRoot {
    fn validate(
        root: &PageTableRoot,
        identity: TableIdentity,
        capabilities: PagingCapabilities,
        cpu: ActivationCpuState,
    ) -> Result<(), ActivationPrepareError<core::convert::Infallible>> {
        if identity.level() != TableLevel::Pml4
            || root.frame().address() != identity.physical_start()
            || root.physical_limit() != capabilities.physical_limit()
        {
            return Err(ActivationPrepareError::FrameRole(FrameRoleError::WrongRole));
        }
        if root.frame() == cpu.current_root {
            return Err(ActivationPrepareError::ActiveRootReused);
        }
        if cpu.cpl != 0 {
            return Err(ActivationPrepareError::WrongProcessorState);
        }
        if !cpu.paging_enabled
            || !cpu.long_mode_active
            || !cpu.four_level_paging
            || !cpu.no_execute_enabled
            || !cpu.write_protect_enabled
            || cpu.smap_enabled
            || cpu.access_flag_set
            || !cpu.pat_supported
            || cpu.pat_entry_zero != 6
            || Some(capabilities.physical_limit().exclusive())
                != 1_u64.checked_shl(u32::from(cpu.physical_address_width))
        {
            return Err(ActivationPrepareError::WrongControlState);
        }
        if cpu.interrupts_enabled {
            return Err(ActivationPrepareError::InterruptsEnabled);
        }
        if cpu.pcid_enabled {
            return Err(ActivationPrepareError::PcidEnabled);
        }
        if cpu.global_pages_enabled {
            return Err(ActivationPrepareError::GlobalPagesEnabled);
        }
        Ok(())
    }
}

mod target_seal {
    pub trait Sealed {}
}

/// Architecture backend for the single irreversible C2 publication step.
///
/// # Safety
///
/// Implementations must make `preflight` validate every condition needed to
/// continue executing through `activate`: the complete inactive graph, its
/// frame roles, the current instruction/control/stack mappings, and the
/// Deep-owned scratch path. Once `preflight` succeeds, `activate` must perform
/// exactly one CR3 write, perform no fallible operation, and return only after
/// the new root is usable. PCID and global pages remain disabled in DW0-C2.
#[allow(
    unsafe_code,
    reason = "exactly one architecture CR3 write is the audited C2 commit boundary"
)]
pub(crate) unsafe trait Cr3ActivationTarget<H>: target_seal::Sealed + Sized {
    type Error;
    type Active;

    fn observe(
        &mut self,
        handoff: &mut H,
    ) -> Result<(ActivationCpuState, PagingCapabilities), Self::Error>;

    fn preflight(
        &mut self,
        handoff: &mut H,
        root: &PageTableRoot,
        identity: TableIdentity,
    ) -> Result<(), Self::Error>;

    /// Performs the sole irreversible CR3 publication.
    ///
    /// # Safety
    ///
    /// The caller must have completed `preflight` on this exact backend and
    /// root without permitting intervening mutation or CPU-state drift.
    unsafe fn activate(self, handoff: H, root: FrameAddress) -> Self::Active;
}

pub(crate) struct PreparedActivation<H, T: Cr3ActivationTarget<H>> {
    handoff: H,
    target: T,
    inactive: InactiveDeepRoot,
}

pub(crate) struct ActivationPrepareFailure<H, T, E> {
    error: ActivationPrepareError<E>,
    handoff: H,
    target: T,
    root: PageTableRoot,
    identity: TableIdentity,
}

impl<H, T, E> ActivationPrepareFailure<H, T, E> {
    pub(crate) fn into_parts(
        self,
    ) -> (
        ActivationPrepareError<E>,
        H,
        T,
        PageTableRoot,
        TableIdentity,
    ) {
        (
            self.error,
            self.handoff,
            self.target,
            self.root,
            self.identity,
        )
    }
}

pub(crate) struct ActiveDeepPaging<A> {
    target: A,
    root: PageTableRoot,
    identity: TableIdentity,
    #[cfg(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64"))]
    user_pins: crate::memory::usercopy::UserPinTracker<E5_USER_PIN_CAPACITY>,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum LiveActivationError {
    WrongProcessorState,
    WrongControlState,
    Transition,
    Graph,
    InvalidKernelLayout,
    KernelRoles(FrameRoleError),
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) struct LiveCr3ActivationTarget<
    'a,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
> {
    roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    kernel_roles: Option<KernelImageRoleSet>,
    scratch: DeepScratchBinding,
    root_identity: Option<TableIdentity>,
    _not_send_sync: core::marker::PhantomData<*mut ()>,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) struct LiveActivePagingTarget<
    'a,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
> {
    roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    _kernel_roles: KernelImageRoleSet,
    scratch: ActiveScratchTarget<LiveActiveScratchIo>,
    _not_send_sync: core::marker::PhantomData<*mut ()>,
}

pub(crate) struct ActiveScratchTarget<I> {
    scratch: DeepScratchBinding,
    io: I,
    poisoned: bool,
    _not_send_sync: core::marker::PhantomData<*mut ()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveActiveTargetError {
    Busy,
    InvalidIndex,
    ReservedScratchEntry,
}

pub(crate) trait ActiveScratchIo {
    fn load(&mut self, address: u64) -> u64;
    fn store(&mut self, address: u64, value: u64);
    fn compare_exchange(&mut self, address: u64, current: u64, new: u64) -> Result<(), u64>;
    fn invalidate(&mut self, virtual_address: u64);
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) struct LiveActiveScratchIo;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> target_seal::Sealed
    for LiveCr3ActivationTarget<'_, RANGE_CAPACITY, ROLE_CAPACITY>
{
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "the authenticated control/window aliases provide aligned atomic PTE access and local invalidation"
)]
impl ActiveScratchIo for LiveActiveScratchIo {
    fn load(&mut self, address: u64) -> u64 {
        unsafe {
            (&*(address as *const core::sync::atomic::AtomicU64))
                .load(core::sync::atomic::Ordering::SeqCst)
        }
    }

    fn store(&mut self, address: u64, value: u64) {
        unsafe {
            (&*(address as *const core::sync::atomic::AtomicU64))
                .store(value, core::sync::atomic::Ordering::SeqCst);
        }
    }

    fn compare_exchange(&mut self, address: u64, current: u64, new: u64) -> Result<(), u64> {
        unsafe { &*(address as *const core::sync::atomic::AtomicU64) }
            .compare_exchange(
                current,
                new,
                core::sync::atomic::Ordering::SeqCst,
                core::sync::atomic::Ordering::SeqCst,
            )
            .map(|_| ())
    }

    fn invalidate(&mut self, virtual_address: u64) {
        unsafe {
            core::arch::asm!(
                "invlpg [{}]",
                in(reg) virtual_address,
                options(nostack, preserves_flags),
            );
        }
    }
}

impl<I: ActiveScratchIo> journal_target_seal::Sealed for ActiveScratchTarget<I> {}

impl<I: ActiveScratchIo> ActiveScratchTarget<I> {
    fn scratch_leaf_index(&self) -> usize {
        ((self.scratch.window_page >> 12) & 0x1ff) as usize
    }

    fn scratch_control_index(&self) -> usize {
        ((self.scratch.control_page >> 12) & 0x1ff) as usize
    }

    fn mmio_page(&self) -> u64 {
        self.scratch.control_page + PAGE_SIZE
    }

    fn mmio_leaf_index(&self) -> usize {
        ((self.mmio_page() >> 12) & 0x1ff) as usize
    }

    fn scratch_leaf_address(&self) -> u64 {
        self.scratch.control_page + (self.scratch_leaf_index() as u64) * 8
    }

    fn restore_scratch_mapping(&mut self, installed: u64) {
        let leaf = self.scratch_leaf_address();
        let mut expected = installed;
        for _ in 0..3 {
            match self.io.compare_exchange(leaf, expected, 0) {
                Ok(()) => {
                    self.io.invalidate(self.scratch.window_page);
                    return;
                }
                Err(observed) if observed & !(ACCESSED | DIRTY) == installed => {
                    expected = observed;
                }
                Err(observed) => {
                    self.poisoned = true;
                    panic!("hostile active scratch leaf drift: observed {observed:#018x}");
                }
            }
        }
        self.poisoned = true;
        panic!("active scratch leaf did not converge after A/D drift");
    }

    #[allow(
        unsafe_code,
        reason = "the active Deep-owned scratch window performs bounded volatile table access and local invlpg"
    )]
    fn access_frame_entry(
        &mut self,
        frame: FrameAddress,
        index: usize,
        replacement: Option<u64>,
    ) -> Result<u64, LiveActiveTargetError> {
        assert!(!self.poisoned, "active Deep scratch mapper is poisoned");
        let (base, installed) = if frame.address() == self.scratch.pt.physical_start() {
            (self.scratch.control_page, None)
        } else {
            let installed = frame.address() | PRESENT | WRITABLE | NO_EXECUTE;
            let leaf = self.scratch_leaf_address();
            if self.io.compare_exchange(leaf, 0, installed).is_err() {
                return Err(LiveActiveTargetError::Busy);
            }
            self.io.invalidate(self.scratch.window_page);
            (self.scratch.window_page, Some(installed))
        };
        let address = base + (index as u64) * 8;
        let result = self.io.load(address);
        if let Some(value) = replacement {
            self.io.store(address, value);
        }
        let Some(installed) = installed else {
            return Ok(result);
        };
        self.restore_scratch_mapping(installed);
        Ok(result)
    }

    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    fn zero_allocator_frame(&mut self, frame: FrameAddress) -> Result<(), LiveActiveTargetError> {
        assert!(!self.poisoned, "active Deep scratch mapper is poisoned");
        if frame.address() == self.scratch.pt.physical_start() {
            return Err(LiveActiveTargetError::ReservedScratchEntry);
        }
        let installed = frame.address() | PRESENT | WRITABLE | NO_EXECUTE;
        let leaf = self.scratch_leaf_address();
        if self.io.compare_exchange(leaf, 0, installed).is_err() {
            return Err(LiveActiveTargetError::Busy);
        }
        self.io.invalidate(self.scratch.window_page);
        for index in 0..ENTRY_COUNT {
            self.io
                .store(self.scratch.window_page + (index as u64) * 8, 0);
        }
        self.restore_scratch_mapping(installed);
        Ok(())
    }

    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    #[allow(
        unsafe_code,
        reason = "F3 reads bounded firmware table bytes through the authenticated transient Deep scratch leaf"
    )]
    fn read_physical_bytes(
        &mut self,
        frame: FrameAddress,
        offset: usize,
        destination: &mut [u8],
    ) -> Result<(), LiveActiveTargetError> {
        assert!(!self.poisoned, "active Deep scratch mapper is poisoned");
        if frame.address() == self.scratch.pt.physical_start()
            || offset
                .checked_add(destination.len())
                .is_none_or(|end| end > PAGE_SIZE as usize)
        {
            return Err(LiveActiveTargetError::ReservedScratchEntry);
        }
        if destination.is_empty() {
            return Ok(());
        }
        let installed = frame.address() | PRESENT | NO_EXECUTE;
        let leaf = self.scratch_leaf_address();
        if self.io.compare_exchange(leaf, 0, installed).is_err() {
            return Err(LiveActiveTargetError::Busy);
        }
        self.io.invalidate(self.scratch.window_page);
        unsafe {
            core::ptr::copy_nonoverlapping(
                (self.scratch.window_page as usize + offset) as *const u8,
                destination.as_mut_ptr(),
                destination.len(),
            );
        }
        self.restore_scratch_mapping(installed);
        Ok(())
    }

    fn install_mmio_frame(&mut self, frame: FrameAddress) -> Result<u64, LiveActiveTargetError> {
        assert!(!self.poisoned, "active Deep scratch mapper is poisoned");
        if frame.address() == self.scratch.pt.physical_start() {
            return Err(LiveActiveTargetError::ReservedScratchEntry);
        }
        let leaf = self.scratch.control_page + (self.mmio_leaf_index() as u64) * 8;
        let installed =
            frame.address() | PRESENT | WRITABLE | WRITE_THROUGH | CACHE_DISABLE | NO_EXECUTE;
        if self.io.compare_exchange(leaf, 0, installed).is_err() {
            return Err(LiveActiveTargetError::Busy);
        }
        self.io.invalidate(self.mmio_page());
        Ok(self.mmio_page())
    }

    fn validate_location(
        &self,
        table: FrameAddress,
        index: usize,
    ) -> Result<(), LiveActiveTargetError> {
        if index >= ENTRY_COUNT {
            return Err(LiveActiveTargetError::InvalidIndex);
        }
        if table.address() == self.scratch.pt.physical_start()
            && (index == self.scratch_leaf_index()
                || index == self.scratch_control_index()
                || index == self.mmio_leaf_index())
        {
            return Err(LiveActiveTargetError::ReservedScratchEntry);
        }
        Ok(())
    }

    #[allow(
        unsafe_code,
        reason = "aligned active page-table entries are accessed atomically through the authenticated scratch mapping"
    )]
    fn read_location(
        &mut self,
        table: FrameAddress,
        index: usize,
    ) -> Result<u64, LiveActiveTargetError> {
        self.validate_location(table, index)?;
        self.access_frame_entry(table, index, None)
    }

    #[allow(
        unsafe_code,
        reason = "serialized journal publication stores one aligned PTE through the authenticated scratch mapping"
    )]
    fn write_location(
        &mut self,
        table: FrameAddress,
        index: usize,
        value: u64,
    ) -> Result<(), LiveActiveTargetError> {
        self.validate_location(table, index)?;
        self.access_frame_entry(table, index, Some(value))
            .map(|_| ())
    }
}

// SAFETY: this target is linear, root/role bound, and uses the authenticated
// Deep-owned control alias to preflight every access. After its first target
// entry write, any impossible scratch conflict is fail-stop rather than Err.
#[allow(
    unsafe_code,
    reason = "sealed active root publication implements the journal's exact all-or-fail-stop contract"
)]
unsafe impl<I: ActiveScratchIo> AtomicPageTableTarget for ActiveScratchTarget<I> {
    type Error = LiveActiveTargetError;

    fn read_entry(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error> {
        self.read_location(table, index)
    }

    fn apply(
        &mut self,
        writes: &[JournalWrite],
        invalidations: &[VirtualPage],
    ) -> Result<(), Self::Error> {
        for write in writes {
            self.validate_location(write.table(), write.index())?;
            let _ = self.read_location(write.table(), write.index())?;
        }
        if self.io.load(self.scratch_leaf_address()) != 0 {
            return Err(LiveActiveTargetError::Busy);
        }

        let mut wrote = false;
        for write in writes {
            if let Err(error) = self.write_location(write.table(), write.index(), write.value()) {
                if wrote {
                    panic!("active scratch access failed after page-table publication began");
                }
                return Err(error);
            }
            wrote = true;
        }
        for page in invalidations {
            self.io.invalidate(page.address());
        }
        Ok(())
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
struct LiveGraphAccess<'borrow, 'handoff>(&'borrow mut TransitionActivationHandoff<'handoff>);

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl ActivationGraphAccess for LiveGraphAccess<'_, '_> {
    type Error = TransitionActivationAccessError;

    fn read_transition(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error> {
        self.0.read_transition_entry(table, index)
    }

    fn read_inactive(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error> {
        self.0
            .read_inactive_entry(table, index)
            .map_err(TransitionActivationAccessError::Scratch)
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn page_aligned_end(end: u64) -> Option<u64> {
    end.checked_add(ADDRESS_OFFSET_MASK)
        .map(|value| value & !ADDRESS_OFFSET_MASK)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "linker-defined kernel segment bounds are immutable activation facts"
)]
fn live_kernel_segments() -> Result<[KernelSegment; 3], LiveActivationError> {
    unsafe extern "C" {
        static __dw_text_start: u8;
        static __dw_text_end: u8;
        static __dw_rodata_start: u8;
        static __dw_rodata_end: u8;
        static __dw_data_start: u8;
        static __dw_data_end: u8;
    }
    let text_start = core::ptr::addr_of!(__dw_text_start) as u64;
    let text_end = page_aligned_end(core::ptr::addr_of!(__dw_text_end) as u64)
        .ok_or(LiveActivationError::InvalidKernelLayout)?;
    let rodata_start = core::ptr::addr_of!(__dw_rodata_start) as u64;
    let rodata_end = page_aligned_end(core::ptr::addr_of!(__dw_rodata_end) as u64)
        .ok_or(LiveActivationError::InvalidKernelLayout)?;
    let data_start = core::ptr::addr_of!(__dw_data_start) as u64;
    let data_end = page_aligned_end(core::ptr::addr_of!(__dw_data_end) as u64)
        .ok_or(LiveActivationError::InvalidKernelLayout)?;
    Ok([
        KernelSegment {
            start: text_start,
            end: text_end,
            kind: SegmentKind::Text,
        },
        KernelSegment {
            start: rodata_start,
            end: rodata_end,
            kind: SegmentKind::ReadOnly,
        },
        KernelSegment {
            start: data_start,
            end: data_end,
            kind: SegmentKind::Writable,
        },
    ])
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "C2 reobserves privileged CPU state at the sealed one-shot boundary"
)]
unsafe fn observe_activation_cpu(
    capabilities: PagingCapabilities,
) -> Result<ActivationCpuState, LiveActivationError> {
    use core::arch::asm;
    use core::arch::x86_64::__cpuid;

    let maximum_basic = __cpuid(0).eax;
    let maximum_extended = __cpuid(0x8000_0000).eax;
    if maximum_basic < 1 || maximum_extended < 0x8000_0008 {
        return Err(LiveActivationError::WrongControlState);
    }
    let leaf_one = __cpuid(1);
    let pat_supported = leaf_one.edx & (1 << 16) != 0;
    let physical_address_width = (__cpuid(0x8000_0008).eax & 0xff) as u8;
    let cr0: u64;
    let cr3: u64;
    let cr4: u64;
    let rflags: u64;
    let stack_pointer: u64;
    let cs: u16;
    let task_register: u16;
    let mut gdtr = [0_u8; 10];
    let mut idtr = [0_u8; 10];
    let efer_low: u32;
    let efer_high: u32;
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        asm!("pushfq", "pop {}", out(reg) rflags, options(nomem, preserves_flags));
        asm!("mov {}, rsp", out(reg) stack_pointer, options(nomem, nostack, preserves_flags));
        asm!("mov {:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
        asm!("str {:x}", out(reg) task_register, options(nomem, nostack, preserves_flags));
        asm!("sgdt [{}]", in(reg) gdtr.as_mut_ptr(), options(nostack, preserves_flags));
        asm!("sidt [{}]", in(reg) idtr.as_mut_ptr(), options(nostack, preserves_flags));
        asm!(
            "rdmsr",
            in("ecx") 0xc000_0080_u32,
            out("eax") efer_low,
            out("edx") efer_high,
            options(nomem, nostack, preserves_flags),
        );
    }
    let pat_entry_zero = if pat_supported {
        let pat_low: u32;
        let pat_high: u32;
        unsafe {
            asm!(
                "rdmsr",
                in("ecx") 0x277_u32,
                out("eax") pat_low,
                out("edx") pat_high,
                options(nomem, nostack, preserves_flags),
            );
        }
        let _ = pat_high;
        pat_low as u8
    } else {
        0
    };
    let current_root = FrameAddress::new(cr3, capabilities.physical_limit())
        .map_err(|_| LiveActivationError::WrongControlState)?;
    let efer = u64::from(efer_low) | (u64::from(efer_high) << 32);
    let gdt_limit = u16::from_le_bytes(gdtr[..2].try_into().expect("GDTR limit is two bytes"));
    let gdt_base = u64::from_le_bytes(gdtr[2..].try_into().expect("GDTR base is eight bytes"));
    let idt_limit = u16::from_le_bytes(idtr[..2].try_into().expect("IDTR limit is two bytes"));
    let idt_base = u64::from_le_bytes(idtr[2..].try_into().expect("IDTR base is eight bytes"));
    Ok(ActivationCpuState {
        processor_id: (leaf_one.ebx >> 24) as u8,
        physical_address_width,
        current_root,
        cpl: (cs & 3) as u8,
        paging_enabled: cr0 & (1 << 31) != 0,
        long_mode_active: efer & (1 << 10) != 0,
        four_level_paging: cr4 & (1 << 12) == 0,
        no_execute_enabled: efer & (1 << 11) != 0,
        write_protect_enabled: cr0 & (1 << 16) != 0,
        interrupts_enabled: rflags & (1 << 9) != 0,
        pcid_enabled: cr4 & (1 << 17) != 0,
        global_pages_enabled: cr4 & (1 << 7) != 0,
        smap_enabled: cr4 & (1 << 21) != 0,
        access_flag_set: rflags & (1 << 18) != 0,
        pat_supported,
        pat_entry_zero,
        stack_pointer,
        code_selector: cs,
        gdt_base,
        gdt_limit,
        idt_base,
        idt_limit,
        task_register,
    })
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn validate_execution_carriers(
    cpu: ActivationCpuState,
    segments: &[KernelSegment; 3],
) -> Result<(), LiveActivationError> {
    let descriptors = crate::arch::x86_64::early_descriptor_addresses()
        .ok_or(LiveActivationError::WrongControlState)?;
    let (stack_bottom, stack_top) = live_boot_stack_bounds()?;
    let facts = ExecutionCarrierFacts {
        stack_bottom,
        stack_top,
        gdt_base: descriptors.gdt,
        gdt_limit: descriptors.gdt_limit,
        idt_base: descriptors.idt,
        idt_limit: descriptors.idt_limit,
        tss_base: descriptors.tss,
        tss_limit: descriptors.tss_limit,
        code_selector: crate::arch::x86_64::gdt::KERNEL_CODE_SELECTOR.bits(),
        task_register: crate::arch::x86_64::gdt::KERNEL_TSS_SELECTOR.bits(),
        ist: descriptors.ist,
        installed_ist_tops: descriptors.installed_ist_tops,
        privilege_entry: crate::arch::x86_64::linked_privilege_entry_stack_layout()
            .map_err(|_| LiveActivationError::InvalidKernelLayout)?,
        installed_privilege_stack0: descriptors.privilege_stack0,
    };
    if !execution_carriers_match(cpu, segments, facts) {
        return Err(LiveActivationError::WrongControlState);
    }
    Ok(())
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "linker-owned boot-stack bounds are immutable activation facts"
)]
fn live_boot_stack_bounds() -> Result<(u64, u64), LiveActivationError> {
    unsafe extern "C" {
        static __dw_boot_stack_bottom: u8;
        static __dw_boot_stack_top: u8;
    }
    let bottom = core::ptr::addr_of!(__dw_boot_stack_bottom) as u64;
    let top = core::ptr::addr_of!(__dw_boot_stack_top) as u64;
    if bottom >= top || !bottom.is_multiple_of(PAGE_SIZE) {
        return Err(LiveActivationError::InvalidKernelLayout);
    }
    Ok((bottom, top))
}

fn range_avoids_ist_guards(ist: IstStackLayout, start: u64, end: u64) -> bool {
    start < end
        && ist.stacks().iter().all(|stack| {
            let guard_end = stack.guard_page + PAGE_SIZE;
            end <= stack.guard_page || start >= guard_end
        })
}

fn range_is_retained_writable(
    writable: KernelSegment,
    ist: IstStackLayout,
    start: u64,
    inclusive_limit: u16,
) -> bool {
    start
        .checked_add(u64::from(inclusive_limit) + 1)
        .is_some_and(|end| {
            start >= writable.start
                && end <= writable.end
                && range_avoids_ist_guards(ist, start, end)
        })
}

fn execution_carriers_match(
    cpu: ActivationCpuState,
    segments: &[KernelSegment; 3],
    facts: ExecutionCarrierFacts,
) -> bool {
    let Some(writable) = segments
        .iter()
        .find(|segment| segment.kind == SegmentKind::Writable)
    else {
        return false;
    };
    let stack_has_headroom = cpu
        .stack_pointer
        .checked_sub(MIN_ACTIVATION_STACK_HEADROOM)
        .is_some_and(|lowest_push| lowest_push >= facts.stack_bottom)
        && cpu.stack_pointer <= facts.stack_top
        && range_avoids_ist_guards(facts.ist, facts.stack_bottom, facts.stack_top);
    let ist_stacks = facts.ist.stacks();
    let ist_tops_match =
        facts.installed_ist_tops == [ist_stacks[0].top, ist_stacks[1].top, ist_stacks[2].top];
    let ist_stacks_retained = ist_stacks.iter().all(|stack| {
        stack.bottom >= writable.start
            && stack.top <= writable.end
            && stack.bottom < stack.top
            && range_avoids_ist_guards(facts.ist, stack.bottom, stack.top)
    });
    let privilege_entry_retained = facts.privilege_entry.bottom >= writable.start
        && facts.privilege_entry.top <= writable.end
        && facts.privilege_entry.bottom < facts.privilege_entry.top
        && facts.installed_privilege_stack0 == facts.privilege_entry.top
        && range_avoids_ist_guards(
            facts.ist,
            facts.privilege_entry.bottom,
            facts.privilege_entry.top,
        );
    stack_has_headroom
        && facts.ist.has_exact_shape()
        && ist_tops_match
        && ist_stacks_retained
        && privilege_entry_retained
        && cpu.code_selector == facts.code_selector
        && cpu.gdt_base == facts.gdt_base
        && cpu.gdt_limit == facts.gdt_limit
        && cpu.idt_base == facts.idt_base
        && cpu.idt_limit == facts.idt_limit
        && cpu.task_register == facts.task_register
        && range_is_retained_writable(*writable, facts.ist, facts.gdt_base, facts.gdt_limit)
        && range_is_retained_writable(*writable, facts.ist, facts.idt_base, facts.idt_limit)
        && range_is_retained_writable(*writable, facts.ist, facts.tss_base, facts.tss_limit)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn validate_live_observation(
    cpu: ActivationCpuState,
    handoff: &TransitionActivationHandoff,
) -> Result<(), LiveActivationError> {
    if cpu.processor_id != handoff.processor_id() || cpu.cpl != 0 {
        return Err(LiveActivationError::WrongProcessorState);
    }
    if cpu.current_root != handoff.transition_root()
        || cpu.physical_address_width
            != handoff.capabilities().physical_limit().exclusive().ilog2() as u8
        || !cpu.paging_enabled
        || !cpu.long_mode_active
        || !cpu.four_level_paging
        || !cpu.no_execute_enabled
        || !cpu.write_protect_enabled
        || cpu.interrupts_enabled
        || cpu.pcid_enabled
        || cpu.global_pages_enabled
        || cpu.smap_enabled
        || cpu.access_flag_set
        || !cpu.pat_supported
        || cpu.pat_entry_zero != 6
    {
        return Err(LiveActivationError::WrongControlState);
    }
    Ok(())
}

// SAFETY: the implementation is sealed in the C1 transition authority module.
// It revalidates every recoverable fact before exposing a prepared typestate;
// its commit retires that authority before one CR3 write and has no post-write
// failure or destructor path.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "privileged observation and the sole CR3 write form the audited C2 boundary"
)]
unsafe impl<'a, 'handoff, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    Cr3ActivationTarget<TransitionActivationHandoff<'handoff>>
    for LiveCr3ActivationTarget<'a, RANGE_CAPACITY, ROLE_CAPACITY>
{
    type Error = LiveActivationError;
    type Active = LiveActivePagingTarget<'a, RANGE_CAPACITY, ROLE_CAPACITY>;

    fn observe(
        &mut self,
        handoff: &mut TransitionActivationHandoff,
    ) -> Result<(ActivationCpuState, PagingCapabilities), Self::Error> {
        let capabilities = handoff.capabilities();
        let cpu = unsafe { observe_activation_cpu(capabilities) }?;
        validate_live_observation(cpu, handoff)?;
        handoff
            .revalidate_temporary_path(cpu.current_root)
            .map_err(|_| LiveActivationError::Transition)?;
        Ok((cpu, capabilities))
    }

    fn preflight(
        &mut self,
        handoff: &mut TransitionActivationHandoff,
        root: &PageTableRoot,
        identity: TableIdentity,
    ) -> Result<(), Self::Error> {
        let kernel_roles = self
            .kernel_roles
            .as_ref()
            .ok_or(LiveActivationError::WrongControlState)?;
        let segments = live_kernel_segments()?;
        let ist = crate::arch::x86_64::linked_ist_stack_layout()
            .map_err(|_| LiveActivationError::InvalidKernelLayout)?;
        let thread_stacks = crate::arch::x86_64::linked_thread_kernel_stack_layout()
            .map_err(|_| LiveActivationError::InvalidKernelLayout)?;
        let privilege_entry = crate::arch::x86_64::linked_privilege_entry_stack_layout()
            .map_err(|_| LiveActivationError::InvalidKernelLayout)?;
        let carrier_cpu = unsafe { observe_activation_cpu(handoff.capabilities()) }?;
        validate_live_observation(carrier_cpu, handoff)?;
        validate_execution_carriers(carrier_cpu, &segments)?;
        let capabilities = handoff.capabilities();
        let transition_root = handoff.transition_root();
        let graph_pending = unsafe { &mut *GRAPH_VALIDATION_WORKSPACE.pending.get() };
        let graph_visited = unsafe { &mut *GRAPH_VALIDATION_WORKSPACE.visited.get() };
        validate_inactive_graph_with_workspace(
            &mut LiveGraphAccess(handoff),
            &*self.roles,
            kernel_roles,
            identity,
            transition_root,
            self.scratch,
            &segments,
            ist,
            &thread_stacks,
            privilege_entry,
            capabilities,
            graph_pending,
            graph_visited,
        )
        .map_err(|_| LiveActivationError::Graph)?;
        if root.frame().address() != identity.physical_start() {
            return Err(LiveActivationError::WrongControlState);
        }

        // This is the last recoverable observation after all scratch-window
        // reads. It proves the old root/path/empty leaf were restored before a
        // prepared activation can escape.
        let cpu = unsafe { observe_activation_cpu(capabilities) }?;
        validate_live_observation(cpu, handoff)?;
        validate_execution_carriers(cpu, &segments)?;
        handoff
            .revalidate_temporary_path(cpu.current_root)
            .map_err(|_| LiveActivationError::Transition)?;
        self.root_identity = Some(identity);
        Ok(())
    }

    unsafe fn activate(
        self,
        mut handoff: TransitionActivationHandoff,
        root: FrameAddress,
    ) -> Self::Active {
        // Final drift checks are deliberately fail-stop and occur before the
        // retirement CAS or irreversible CR3 write.
        let capabilities = handoff.capabilities();
        let cpu = unsafe { observe_activation_cpu(capabilities) }
            .expect("C2 CPU state drifted after successful preflight");
        validate_live_observation(cpu, &handoff)
            .expect("C2 processor/control state drifted after successful preflight");
        let segments = live_kernel_segments()
            .expect("C2 linker segment layout drifted after successful preflight");
        validate_execution_carriers(cpu, &segments)
            .expect("C2 stack or descriptor carrier drifted after successful preflight");
        handoff
            .revalidate_temporary_path(cpu.current_root)
            .expect("C2 transition path drifted after successful preflight");
        let kernel_roles = self
            .kernel_roles
            .expect("C2 kernel image roles were not published during preflight");
        let _root_identity = self
            .root_identity
            .expect("C2 root identity was not retained during preflight");
        handoff.retire_before_activation();
        unsafe {
            core::arch::asm!(
                "mov cr3, {}",
                in(reg) root.address(),
                options(nostack, preserves_flags),
            );
        }
        LiveActivePagingTarget {
            roles: self.roles,
            _kernel_roles: kernel_roles,
            scratch: ActiveScratchTarget {
                scratch: self.scratch,
                io: LiveActiveScratchIo,
                poisoned: false,
                _not_send_sync: core::marker::PhantomData,
            },
            _not_send_sync: core::marker::PhantomData,
        }
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl<'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    ActiveDeepPaging<LiveActivePagingTarget<'root, RANGE_CAPACITY, ROLE_CAPACITY>>
{
    pub(crate) fn read_physical_bytes(
        &mut self,
        physical_start: u64,
        destination: &mut [u8],
    ) -> Result<(), LiveActiveTargetError> {
        let mut physical = physical_start;
        let mut copied = 0_usize;
        while copied < destination.len() {
            let page = physical & !(PAGE_SIZE - 1);
            let offset = usize::try_from(physical & (PAGE_SIZE - 1))
                .map_err(|_| LiveActiveTargetError::InvalidIndex)?;
            let take = (PAGE_SIZE as usize - offset).min(destination.len() - copied);
            let frame = FrameAddress::new(page, self.root.physical_limit())
                .map_err(|_| LiveActiveTargetError::InvalidIndex)?;
            self.target.scratch.read_physical_bytes(
                frame,
                offset,
                &mut destination[copied..copied + take],
            )?;
            physical = physical
                .checked_add(take as u64)
                .ok_or(LiveActiveTargetError::InvalidIndex)?;
            copied += take;
        }
        Ok(())
    }

    pub(crate) fn install_kernel_mmio_page(
        &mut self,
        frame: FrameAddress,
    ) -> Result<u64, LiveActiveTargetError> {
        self.target.scratch.install_mmio_frame(frame)
    }

    pub(crate) fn current_process_address_space(
        &mut self,
        process: crate::task::ProcessKey,
    ) -> LiveProcessAddressSpace<'_, 'root, RANGE_CAPACITY, ROLE_CAPACITY> {
        let target = &mut self.target;
        LiveProcessAddressSpace {
            root: &self.root,
            identity: self.identity,
            process,
            roles: target.roles,
            target: user_access::TrackedActiveTarget {
                scratch: &mut target.scratch,
                pins: &self.user_pins,
            },
            _root: core::marker::PhantomData,
        }
    }
}

impl<A> ActiveDeepPaging<A> {
    pub(crate) const fn root(&self) -> &PageTableRoot {
        &self.root
    }

    pub(crate) const fn identity(&self) -> TableIdentity {
        self.identity
    }
}

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
#[path = "activation/test_support.rs"]
mod test_support;

impl<H, T: Cr3ActivationTarget<H>> PreparedActivation<H, T> {
    /// Publishes the prepared root. There is deliberately no recoverable error
    /// path after the architecture backend begins the CR3 transition.
    #[allow(
        unsafe_code,
        reason = "the prepared typestate proves the backend preflight completed"
    )]
    pub(crate) fn activate(self) -> ActiveDeepPaging<T::Active> {
        let Self {
            handoff,
            target,
            inactive,
        } = self;
        let InactiveDeepRoot { root, identity } = inactive;
        // SAFETY: construction of `PreparedActivation` is private to the
        // successful preflight path and owns both backend and root linearly.
        let target = unsafe { target.activate(handoff, root.frame()) };
        ActiveDeepPaging {
            target,
            root,
            identity,
            #[cfg(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64"))]
            user_pins: crate::memory::usercopy::UserPinTracker::new(),
        }
    }
}

fn prepare_activation<H, T: Cr3ActivationTarget<H>>(
    mut handoff: H,
    mut target: T,
    root: PageTableRoot,
    identity: TableIdentity,
) -> Result<PreparedActivation<H, T>, ActivationPrepareFailure<H, T, T::Error>> {
    let (cpu, capabilities) = match target.observe(&mut handoff) {
        Ok(preflight) => preflight,
        Err(error) => {
            return Err(ActivationPrepareFailure {
                error: ActivationPrepareError::Target(error),
                handoff,
                target,
                root,
                identity,
            });
        }
    };
    if let Err(error) = InactiveDeepRoot::validate(&root, identity, capabilities, cpu) {
        let error = match error {
            ActivationPrepareError::FrameRole(error) => ActivationPrepareError::FrameRole(error),
            ActivationPrepareError::Root(error) => ActivationPrepareError::Root(error),
            ActivationPrepareError::WrongProcessorState => {
                ActivationPrepareError::WrongProcessorState
            }
            ActivationPrepareError::WrongControlState => ActivationPrepareError::WrongControlState,
            ActivationPrepareError::ActiveRootReused => ActivationPrepareError::ActiveRootReused,
            ActivationPrepareError::InterruptsEnabled => ActivationPrepareError::InterruptsEnabled,
            ActivationPrepareError::PcidEnabled => ActivationPrepareError::PcidEnabled,
            ActivationPrepareError::GlobalPagesEnabled => {
                ActivationPrepareError::GlobalPagesEnabled
            }
            ActivationPrepareError::Target(never) => match never {},
        };
        return Err(ActivationPrepareFailure {
            error,
            handoff,
            target,
            root,
            identity,
        });
    }
    let inactive = InactiveDeepRoot { root, identity };
    if let Err(error) = target.preflight(&mut handoff, &inactive.root, inactive.identity) {
        return Err(ActivationPrepareFailure {
            error: ActivationPrepareError::Target(error),
            handoff,
            target,
            root: inactive.root,
            identity: inactive.identity,
        });
    }
    Ok(PreparedActivation {
        handoff,
        target,
        inactive,
    })
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
struct DeepActivationPrepareFailure<'a, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> {
    error: ActivationPrepareError<LiveActivationError>,
    authority: InactiveRootAuthority<'a, RANGE_CAPACITY, ROLE_CAPACITY>,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn prepare_deep_activation<'a, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    authority: InactiveRootAuthority<'a, RANGE_CAPACITY, ROLE_CAPACITY>,
) -> Result<
    PreparedActivation<
        TransitionActivationHandoff<'a>,
        LiveCr3ActivationTarget<'a, RANGE_CAPACITY, ROLE_CAPACITY>,
    >,
    DeepActivationPrepareFailure<'a, RANGE_CAPACITY, ROLE_CAPACITY>,
> {
    let InactiveRootAuthority {
        handoff,
        root,
        identity,
        scratch,
        kernel_roles,
        roles,
        _not_send_sync: _,
    } = authority;
    let target = LiveCr3ActivationTarget {
        roles,
        kernel_roles: Some(kernel_roles),
        scratch,
        root_identity: None,
        _not_send_sync: core::marker::PhantomData,
    };
    prepare_activation(handoff, target, root, identity).map_err(|failure| {
        let (error, handoff, target, root, identity) = failure.into_parts();
        DeepActivationPrepareFailure {
            error,
            authority: InactiveRootAuthority {
                handoff,
                root,
                identity,
                scratch: target.scratch,
                kernel_roles: target
                    .kernel_roles
                    .expect("preflight failure retains imported kernel roles"),
                roles: target.roles,
                _not_send_sync: core::marker::PhantomData,
            },
        }
    })
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum BootstrapDeepPagingError {
    Transition(LiveTransitionError),
    Build(DeepRootBuildError),
    Prepare(ActivationPrepareError<LiveActivationError>),
}

/// Performs the complete one-shot early-bootstrap paging transition and
/// returns the only live Deep-owned paging session.
///
/// # Safety
///
/// The caller must own the sole boot-memory manager on the BSP with APs
/// offline, CPL0, and IF clear. From entry until return it must not move or
/// replace the current kernel stack, GDT, IDT, TSS, transition root, or any
/// referenced page-table storage. The accepted loader's C1 integrity contract
/// must remain valid until this function consumes it. Failure is terminal for
/// the boot attempt; no transition mapper or partially built root escapes.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "one unsafe bootstrap session encloses C1 claim, inactive construction, carrier preflight, and the sole CR3 write"
)]
pub(crate) unsafe fn activate_bootstrap_deep_paging<
    'a,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
>(
    handoff: &'a crate::boot::ValidatedPagingHandoff,
    roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    memory_witness: BootstrapMemoryWitness<'_>,
) -> Result<
    ActiveDeepPaging<LiveActivePagingTarget<'a, RANGE_CAPACITY, ROLE_CAPACITY>>,
    BootstrapDeepPagingError,
> {
    // SAFETY: this facade's contract is exactly the stronger C1 ownership and
    // CPU-state contract required by the one-shot claim.
    let mapper = unsafe { claim_live_transition_mapper(handoff, roles) }
        .map_err(BootstrapDeepPagingError::Transition)?;
    let authority = build_and_bind_deep_root(mapper, roles, memory_witness)
        .map_err(|failure| BootstrapDeepPagingError::Build(failure.error))?;
    let prepared = prepare_deep_activation(authority).map_err(|failure| {
        let DeepActivationPrepareFailure {
            error,
            authority: _terminal_authority,
        } = failure;
        BootstrapDeepPagingError::Prepare(error)
    })?;
    Ok(prepared.activate())
}

#[cfg(test)]
#[path = "activation/tests.rs"]
mod tests;
