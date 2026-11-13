use super::*;

use crate::memory::frame_roles::{ObjectBackingGrant, TableCandidateGrant};
use crate::memory::user_range::{
    EmptyAddressRule, UserAccess, UserAddressSpace, UserPageChunk, UserRange,
};
use crate::memory::usercopy::{
    OwnedUserOutputAccess, PinnedUserBatchPages, PinnedUserPages, UserPageAccess,
    UserPageBatchAccess, UserPinError, UserPinTracker, UserRangePin, UserRangePinToken,
};
use core::sync::atomic::{AtomicBool, Ordering};

use super::tlb_mailbox::LiveTlbMailbox;

/// Entries in the live publishers' journal (Deepwyrm D7).
pub(crate) const LIVE_JOURNAL_ENTRIES: usize = super::primordial::PRIMORDIAL_JOURNAL_ENTRIES;
/// Pages the live publishers' journal may invalidate.
pub(crate) const LIVE_JOURNAL_INVALIDATIONS: usize = super::primordial::PRIMORDIAL_INVALIDATIONS;
/// The live publishers' journal storage: sized for the largest mapping one
/// call may change, too large for a kernel stack, so it lives in static
/// storage that the paging state lends to each session beneath P.
pub(crate) type LiveJournalStorage =
    crate::arch::x86_64::mm::JournalStorage<LIVE_JOURNAL_ENTRIES, LIVE_JOURNAL_INVALIDATIONS>;

static LIVE_TLB_MAILBOXES: [LiveTlbMailbox; crate::cpu::CPU_CAPACITY] =
    [const { LiveTlbMailbox::new() }; crate::cpu::CPU_CAPACITY];
static LIVE_TLB_READY: AtomicBool = AtomicBool::new(false);

/// A page-table mutation session (D1 option B3, design §11.2.9): the
/// target-root selection, table candidates and coherent publisher of one
/// family-G transaction, and no usercopy. It is distinct from the usercopy
/// session so that commit 9 can retire the usercopy session's unguarded
/// constructor while T-held page-table work keeps this one. It is built from
/// a held P guard and borrows it, so it witnesses P for the
/// shootdown-initiator lock S.
pub(crate) struct PageTableMutationSession<
    'borrow,
    'root,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
> {
    session: LiveProcessAddressSpace<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>,
}

impl<'borrow, 'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    PageTableMutationSession<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>
{
    pub(super) const fn new(
        session: LiveProcessAddressSpace<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>,
    ) -> Self {
        Self { session }
    }

    pub(crate) fn select_process_for_return_validation(
        &mut self,
        process: crate::task::ProcessKey,
    ) -> Result<(), super::RootBindingError> {
        self.session.select_process_for_return_validation(process)
    }

    pub(crate) fn prepare_table_candidate(
        &mut self,
        level: TableLevel,
    ) -> Result<TableCandidateGrant, LiveUserAccessError> {
        self.session.prepare_table_candidate(level)
    }

    /// Whether any user pin or mutation holds part of `address_space`.
    pub(crate) fn pins_hold_any(
        &self,
        address_space: crate::memory::address_region::AddressSpaceKey,
    ) -> bool {
        self.session.target.pins.holds_any(address_space)
    }

    /// Frames committing object page `page` of the on-demand `backing`
    /// would take (DW2 M6 §8.4).
    pub(crate) fn on_demand_commit_cost(
        &self,
        backing: crate::memory::frame_roles::BackingIdentity,
        page: u64,
    ) -> Result<u64, crate::memory::frame_roles::FrameRoleError> {
        self.session.roles.on_demand_commit_cost(backing, page)
    }

    /// Frames committing `count` pages of the on-demand `backing` from
    /// `first` would take, nodes shared between them counted once.
    pub(crate) fn on_demand_commit_range_cost(
        &self,
        backing: crate::memory::frame_roles::BackingIdentity,
        first: u64,
        count: u64,
    ) -> Result<u64, crate::memory::frame_roles::FrameRoleError> {
        self.session
            .roles
            .on_demand_commit_range_cost(backing, first, count)
    }

    /// Gives object page `page` of the on-demand `backing` a zeroed frame.
    pub(crate) fn commit_on_demand_page(
        &mut self,
        backing: crate::memory::frame_roles::BackingIdentity,
        page: u64,
    ) -> Result<
        crate::memory::frame_roles::OnDemandCommit,
        crate::memory::frame_roles::FrameRoleError,
    > {
        self.session.roles.commit_on_demand_page(backing, page)
    }

    pub(crate) fn recycle_table_candidate(&mut self, candidate: TableCandidateGrant) {
        self.session.recycle_table_candidate(candidate);
    }

    /// Publishes a child architecture root (D1 commit 9: ProcessCreate's
    /// reservation, a page-table mutation).
    pub(crate) fn reserve_child_address_space(
        &mut self,
        process: crate::task::ProcessKey,
        address_space: crate::memory::address_region::AddressSpaceKey,
    ) -> Result<(), super::RootBindingError> {
        self.session
            .reserve_child_address_space(process, address_space)
    }

    pub(crate) fn rollback_empty_child_address_space(
        &mut self,
        process: crate::task::ProcessKey,
        address_space: crate::memory::address_region::AddressSpaceKey,
    ) -> Result<(), super::RootBindingError> {
        self.session
            .rollback_empty_child_address_space(process, address_space)
    }

    /// The plain (non-coherent) publisher, for the terminal unmaps of a
    /// quiesced Process, whose root no other CPU uses (D1 commit 9; the
    /// teardown's own shootdown story is D2's).
    pub(crate) fn publisher<'publisher, const CANDIDATE_CAPACITY: usize>(
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
            LIVE_JOURNAL_ENTRIES,
            LIVE_JOURNAL_INVALIDATIONS,
        >,
        crate::arch::x86_64::mm::X86AddressSpacePublishError<LiveTrackedTargetError>,
    > {
        self.session
            .publisher::<CANDIDATE_CAPACITY>(address_space, region, candidates)
    }

    #[allow(
        clippy::type_complexity,
        reason = "the publisher and its coherency domain share the session's one borrow"
    )]
    pub(crate) fn publisher_with_coherency<'publisher, const CANDIDATE_CAPACITY: usize>(
        &'publisher mut self,
        address_space: crate::memory::address_region::AddressSpaceKey,
        region: crate::memory::address_region::RegionKey,
        candidates: &'publisher mut [Option<TableCandidateGrant>; CANDIDATE_CAPACITY],
    ) -> Result<
        (
            crate::arch::x86_64::mm::X86AddressSpacePublisher<
                'publisher,
                TrackedActiveTarget<'borrow>,
                RANGE_CAPACITY,
                ROLE_CAPACITY,
                CANDIDATE_CAPACITY,
                LIVE_JOURNAL_ENTRIES,
                LIVE_JOURNAL_INVALIDATIONS,
            >,
            &'publisher crate::memory::address_region::AddressSpaceCoherency<
                { crate::cpu::CPU_CAPACITY },
            >,
        ),
        crate::arch::x86_64::mm::X86AddressSpacePublishError<LiveTrackedTargetError>,
    > {
        self.session.publisher_with_coherency::<CANDIDATE_CAPACITY>(
            address_space,
            region,
            candidates,
        )
    }
}

#[cfg(deepwyrm_integrated)]
impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> super::runtime_authority::PagingHeld
    for PageTableMutationSession<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
}

/// A pin-settlement session (D1 commit 9): releases a suspended operation's
/// owned output pin, or atomic-word pin, without writing it. A stop that
/// retires a suspended syscall discards its pins under the runtime authority;
/// that is pin-tracker bookkeeping, not a usercopy. Terminal cleanup's
/// broader shape is D2's.
pub(crate) struct PinSettlementSession<
    'borrow,
    'root,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
> {
    session: LiveProcessAddressSpace<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>,
}

impl<'borrow, 'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    PinSettlementSession<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>
{
    pub(super) const fn new(
        session: LiveProcessAddressSpace<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>,
    ) -> Self {
        Self { session }
    }

    pub(crate) fn discard_owned_output(
        &mut self,
        output: OwnedLiveUserOutput,
    ) -> Result<(), LiveUserAccessError> {
        self.session.discard_owned_output(output)
    }

    pub(crate) fn release_atomic_u32(
        &mut self,
        word: OwnedLiveAtomicU32,
    ) -> Result<(), LiveUserAccessError> {
        self.session.release_atomic_u32(word)
    }
}

/// A user-return validation session (D1 commit 9): read-only walks of a
/// resident process root, checking that a user RIP is mapped executable and
/// the byte below a user RSP is mapped writable, and the retargeting that
/// selects which process root is walked. It reads page-table entries
/// through the scratch window, which P serializes, and never user memory.
/// So it is no usercopy, and H0 §12.8 does not apply to it: a return
/// authorization keeps it in its runtime-authority hold, where it checks the
/// root's binding generation.
pub(crate) struct ReturnValidationSession<
    'borrow,
    'root,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
> {
    session: LiveProcessAddressSpace<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>,
}

impl<'borrow, 'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    ReturnValidationSession<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>
{
    pub(super) const fn new(
        session: LiveProcessAddressSpace<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>,
    ) -> Self {
        Self { session }
    }

    pub(crate) fn select_process_for_return_validation(
        &mut self,
        process: crate::task::ProcessKey,
    ) -> Result<(), super::RootBindingError> {
        self.session.select_process_for_return_validation(process)
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    crate::arch::x86_64::syscall::UserReturnMappingValidation
    for ReturnValidationSession<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn executable_at(&mut self, address: u64) -> bool {
        crate::arch::x86_64::syscall::UserReturnMappingValidation::executable_at(
            &mut self.session,
            address,
        )
    }

    fn writable_byte_below(&mut self, stack_pointer: u64) -> bool {
        crate::arch::x86_64::syscall::UserReturnMappingValidation::writable_byte_below(
            &mut self.session,
            stack_pointer,
        )
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    crate::arch::x86_64::syscall::ProcessUserReturnMappingValidation
    for ReturnValidationSession<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn process_key(&self) -> crate::task::ProcessKey {
        crate::arch::x86_64::syscall::ProcessUserReturnMappingValidation::process_key(&self.session)
    }
}

/// Waits, with neither T nor P held, for every acknowledgement of a family-G
/// shootdown published beneath them, and mints its reclaim permit (D1 option
/// B3, design §11.2.9). The `GuardFree` token makes "no runtime lock across
/// the acknowledgement wait" (H0 §12.8) a type fact. Each wait step services
/// this CPU's own mailbox.
pub(crate) fn await_shootdown(
    _guard_free: crate::arch::x86_64::syscall::GuardFree<'_>,
    pending: crate::memory::address_region::PendingShootdown<{ crate::cpu::CPU_CAPACITY }>,
    driver: &mut LiveTlbShootdownDriver,
) -> crate::memory::address_region::ReclaimPermit {
    pending.await_permit::<_, LIVE_SHOOTDOWN_WAIT_STEPS>(driver)
}

/// The acknowledgement wait's bound, in wait steps.
pub(crate) const LIVE_SHOOTDOWN_WAIT_STEPS: usize = 1_000_000;

/// Bounded e2 adapter for the live address-space publisher.
///
/// One runtime mapping transaction owns this value. The runtime's existing
/// serialization prevents concurrent publishers, while the mailbox state
/// rejects accidental target overlap rather than overwriting a request.
pub(crate) struct LiveTlbShootdownDriver {
    initiating_cpu: crate::cpu::CpuIndex,
    published_targets: [bool; crate::cpu::CPU_CAPACITY],
}

impl LiveTlbShootdownDriver {
    pub(crate) fn current() -> Self {
        let initiating_cpu = crate::arch::x86_64::syscall::current_cpu_index_for_diagnostics()
            .and_then(crate::cpu::CpuIndex::new)
            .unwrap_or_else(|| panic!("live TLB publication has no current CPU identity"));
        Self {
            initiating_cpu,
            published_targets: [false; crate::cpu::CPU_CAPACITY],
        }
    }

    fn mailbox(cpu: crate::cpu::CpuIndex) -> &'static LiveTlbMailbox {
        LIVE_TLB_MAILBOXES
            .get(cpu.index())
            .unwrap_or_else(|| panic!("TLB shootdown CPU is outside the live mailbox bound"))
    }
}

impl Drop for LiveTlbShootdownDriver {
    fn drop(&mut self) {
        // A successful acknowledgement clears its mailbox before publishing
        // the ack.  This only recovers a send failure/panic path and never
        // steals a handler that already owns CONSUMING.
        for (cpu, published) in self.published_targets.iter().enumerate() {
            if *published {
                LIVE_TLB_MAILBOXES[cpu].cancel_if_published();
            }
        }
    }
}

impl crate::memory::address_region::ShootdownDriver<{ crate::cpu::CPU_CAPACITY }>
    for LiveTlbShootdownDriver
{
    fn initiating_cpu(&self) -> crate::cpu::CpuIndex {
        self.initiating_cpu
    }

    fn notify_remote(
        &mut self,
        coherency: &crate::memory::address_region::AddressSpaceCoherency<
            { crate::cpu::CPU_CAPACITY },
        >,
        target: crate::cpu::CpuIndex,
        request: crate::memory::address_region::ShootdownRequest,
    ) {
        if self.published_targets[target.index()] {
            panic!("TLB shootdown publisher attempted a duplicate target notification");
        }
        let mailbox = Self::mailbox(target);
        mailbox.publish(coherency, request);
        self.published_targets[target.index()] = true;
        let snapshot = crate::arch::x86_64::smp::live_cpu_registry()
            .snapshot(target.index())
            .unwrap_or_else(|error| panic!("TLB target CPU identity unavailable: {error:?}"));
        crate::arch::x86_64::ipi::send_live_ipi(
            snapshot.local_apic_id,
            crate::arch::x86_64::ipi::LiveIpiVector::TlbShootdown,
        )
        .unwrap_or_else(|error| panic!("TLB shootdown IPI delivery failed: {error:?}"));
    }

    fn wait_step(
        &mut self,
        _coherency: &crate::memory::address_region::AddressSpaceCoherency<
            { crate::cpu::CPU_CAPACITY },
        >,
    ) {
        // The initiator holds no IRQ-safe mailbox or address-space lock while
        // it waits. The target's acknowledgement is the Release event that
        // lets the model mint its reclaim permit. It waits with IF clear, so it
        // services its own mailbox here (D1 commit 4).
        service_local_tlb_shootdown();
        core::hint::spin_loop();
    }
}

/// Installs the e2 receive path after the live APIC transport is available and
/// before AP runtime carriers can execute userspace mappings.
pub(crate) fn initialize_live_tlb_shootdown() {
    crate::arch::x86_64::ipi::bind_live_tlb_shootdown_handler(live_tlb_shootdown_handler)
        .unwrap_or_else(|error| panic!("could not bind live TLB shootdown handler: {error:?}"));
    LIVE_TLB_READY
        .compare_exchange(false, true, Ordering::Release, Ordering::Acquire)
        .unwrap_or_else(|_| panic!("live TLB shootdown initialized twice"));
}

pub(crate) fn live_tlb_shootdown_is_ready() -> bool {
    LIVE_TLB_READY.load(Ordering::Acquire)
}

/// e2 runs after EOI with IF clear. It takes no runtime lock and no scheduler,
/// usercopy, finalization, or page-table mutation authority.
fn live_tlb_shootdown_handler() {
    let cpu = crate::arch::x86_64::syscall::current_cpu_index_for_diagnostics()
        .and_then(crate::cpu::CpuIndex::new)
        .unwrap_or_else(|| panic!("TLB shootdown arrived without CPU identity"));
    service_tlb_mailbox_on(cpu);
}

/// Acknowledges this CPU's pending TLB shootdown, if one is published, from a
/// spin that runs with IF clear (D1 commit 4, design §11.2.2): the runtime
/// authority's ticket spin, the paging lock's spin, and the shootdown
/// acknowledgement wait. A CPU spinning with IF clear cannot take e2, so an
/// initiator waiting for its acknowledgement would otherwise wait forever.
///
/// Safe at each of those sites:
/// - It takes no lock but the address space's `AddressSpaceCoherency` state
///   lock, an `IrqSpinMutex` held only inside that type's own short methods.
///   None of them spins on the runtime authority or the paging lock, or
///   waits for an acknowledgement, so no spinner can already hold it.
/// - It touches no runtime-authority or paging state. It reloads the current
///   CR3, which is valid everywhere these spins run, and they never run
///   inside a root switch (that takes `GuardFree`).
/// - The handler does the same work wherever e2 can interrupt. The mailbox
///   state machine admits one consumer, so if e2 lands during a serviced
///   spin, it finds the mailbox consumed and returns.
///
/// Before the shootdown transport is ready, or on a CPU whose identity is not
/// yet installed, there is nothing to acknowledge.
pub(crate) fn service_local_tlb_shootdown() {
    if !live_tlb_shootdown_is_ready() {
        return;
    }
    let Some(cpu) = crate::arch::x86_64::syscall::current_cpu_index_for_diagnostics()
        .and_then(crate::cpu::CpuIndex::new)
    else {
        return;
    };
    if LiveTlbShootdownDriver::mailbox(cpu).is_published() {
        service_tlb_mailbox_on(cpu);
    }
}

fn service_tlb_mailbox_on(cpu: crate::cpu::CpuIndex) {
    let mailbox = LiveTlbShootdownDriver::mailbox(cpu);
    let Some((coherency, request)) = mailbox.consume() else {
        // A stale e2 after a failed sender cannot acknowledge any generation.
        return;
    };
    local_full_tlb_serialization();
    // Return the mailbox before acknowledgement so the initiator can only
    // observe completion after a later operation is permitted to reuse this
    // exact CPU slot. The immutable request/coherency copies above remain
    // local to this handler.
    mailbox.release_after_local_serialization();
    let _acknowledgement = coherency
        .acknowledge(cpu, request)
        .unwrap_or_else(|error| panic!("live TLB shootdown acknowledgement drifted: {error:?}"));
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "reloading the current no-PCID CR3 is the bounded local translation serialization required before an e2 acknowledgement"
)]
fn local_full_tlb_serialization() {
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
}

#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
fn local_full_tlb_serialization() {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveUserAccessError {
    MissingOrInvalid,
    MapModel(crate::memory::address_region::AddressRegionError),
    MapPublish(crate::arch::x86_64::mm::X86AddressSpacePublishError<LiveTrackedTargetError>),
    Permission,
    Pin(UserPinError),
}

/// The live target's errors: the scratch target's, or a pin conflict.
pub(crate) type LiveTrackedTargetError =
    crate::arch::x86_64::mm::PinTrackedError<LiveActiveTargetError>;

#[derive(Clone, Copy)]
struct LiveUserWalk {
    user: bool,
    writable: bool,
    executable: bool,
    /// The frame the leaf maps.
    physical: u64,
}

/// Pin-aware atomic target over the live x86 scratch publisher.
///
/// Actual page-table writes reserve the exact invalidation span before the
/// underlying atomic batch begins. New user pins and mapping mutations thus
/// exclude one another without holding the tracker spin lock across publication.
pub(crate) type TrackedActiveTarget<'a> = crate::arch::x86_64::mm::PinTrackedTarget<
    'a,
    ActiveScratchTarget<LiveActiveScratchIo>,
    E5_USER_PIN_CAPACITY,
>;

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
    // The selected root may be stored inside `root_bindings`. Keeping only its
    // stationary pointer lets this session mutate a different binding slot
    // during ProcessCreate without manufacturing overlapping Rust references.
    // Every dereference is serialized away from binding-table mutation below.
    pub(super) root: *const PageTableRoot,
    pub(super) primordial_root: &'borrow PageTableRoot,
    pub(super) identity: TableIdentity,
    pub(super) address_space: crate::memory::address_region::AddressSpaceKey,
    pub(super) process: crate::task::ProcessKey,
    pub(super) root_bindings: &'borrow mut super::AddressSpaceRootBindings<
        { super::LIVE_ADDRESS_SPACE_CAPACITY },
        { crate::cpu::CPU_CAPACITY },
    >,
    pub(super) roles: &'borrow mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    pub(super) target: TrackedActiveTarget<'borrow>,
    /// The journal every publisher of this session stages into (D7).
    pub(super) journal: &'borrow mut LiveJournalStorage,
    pub(super) _root: core::marker::PhantomData<&'root mut ()>,
}

#[must_use = "owned live user outputs must be committed or discarded through the originating process address space"]
pub(crate) struct OwnedLiveUserOutput {
    process: crate::task::ProcessKey,
    address_space: crate::memory::address_region::AddressSpaceKey,
    range: UserRange,
    token: UserRangePinToken,
}

/// Detached mapping-stability authority for one aligned readable userspace
/// atomic word. The originating live address-space session must load or release
/// it; it is suitable for storage in a blocked-operation resource bundle.
#[must_use = "owned live atomic-word pins must be released through their originating process address space"]
pub(crate) struct OwnedLiveAtomicU32 {
    process: crate::task::ProcessKey,
    address_space: crate::memory::address_region::AddressSpaceKey,
    range: UserRange,
    token: UserRangePinToken,
}

impl OwnedLiveAtomicU32 {
    pub(crate) const fn address(&self) -> u64 {
        self.range.start()
    }

    pub(crate) fn release_terminal(
        self,
        pins: &UserPinTracker<E5_USER_PIN_CAPACITY>,
    ) -> Result<(), LiveUserAccessError> {
        pins.release_owned(self.address_space, self.token)
            .map_err(LiveUserAccessError::Pin)
    }
}

impl OwnedLiveUserOutput {
    pub(crate) const fn process(&self) -> crate::task::ProcessKey {
        self.process
    }

    pub(crate) fn discard_terminal(
        self,
        pins: &UserPinTracker<E5_USER_PIN_CAPACITY>,
    ) -> Result<(), LiveUserAccessError> {
        pins.release_owned(self.address_space, self.token)
            .map_err(LiveUserAccessError::Pin)
    }
}

/// A pinned, preflighted range and the session that copies it through the
/// direct map.
pub(crate) struct PinnedLiveUserPages<
    'session,
    'borrow,
    'root,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
> {
    _pin: UserRangePin<'borrow, E5_USER_PIN_CAPACITY>,
    range: UserRange,
    space: &'session mut LiveProcessAddressSpace<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>,
}

pub(crate) struct PinnedLiveUserBatch<
    'session,
    'borrow,
    'root,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
> {
    _pins: [Option<UserRangePin<'borrow, E5_USER_PIN_CAPACITY>>; 3],
    ranges: [Option<UserRange>; 3],
    space: &'session mut LiveProcessAddressSpace<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>,
}

impl<'borrow, 'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> UserPageAccess
    for LiveProcessAddressSpace<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>
{
    type Error = LiveUserAccessError;
    type Pinned<'a>
        = PinnedLiveUserPages<'a, 'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>
    where
        Self: 'a;

    fn pin(&mut self, range: UserRange) -> Result<Self::Pinned<'_>, Self::Error> {
        let pins = self.target.pins;
        let pin = pins
            .pin(self.address_space, range)
            .map_err(LiveUserAccessError::Pin)?;
        for chunk in range.page_chunks() {
            if let Err(error) = self.preflight(chunk) {
                drop(pin);
                return Err(error);
            }
        }
        Ok(PinnedLiveUserPages {
            _pin: pin,
            range,
            space: self,
        })
    }
}

impl<'borrow, 'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> UserPageBatchAccess
    for LiveProcessAddressSpace<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>
{
    type PinnedBatch<'a>
        = PinnedLiveUserBatch<'a, 'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>
    where
        Self: 'a;

    fn pin_batch(
        &mut self,
        ranges: [Option<UserRange>; 3],
    ) -> Result<Self::PinnedBatch<'_>, Self::Error> {
        let tracker = self.target.pins;
        let mut pins = [None, None, None];
        for (index, range) in ranges.into_iter().enumerate() {
            let Some(range) = range else {
                continue;
            };
            if range.is_empty() {
                continue;
            }
            pins[index] = Some(
                tracker
                    .pin(self.address_space, range)
                    .map_err(LiveUserAccessError::Pin)?,
            );
        }
        for range in ranges.into_iter().flatten() {
            for chunk in range.page_chunks() {
                self.preflight(chunk)?;
            }
        }
        Ok(PinnedLiveUserBatch {
            _pins: pins,
            ranges,
            space: self,
        })
    }
}

impl<'borrow, 'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> OwnedUserOutputAccess
    for LiveProcessAddressSpace<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>
{
    type OwnedOutput = OwnedLiveUserOutput;

    fn preflight_owned_output(
        &mut self,
        range: UserRange,
    ) -> Result<Self::OwnedOutput, Self::Error> {
        LiveProcessAddressSpace::preflight_owned_output(self, range)
    }

    fn commit_owned_output(&mut self, output: Self::OwnedOutput, source: &[u8]) {
        LiveProcessAddressSpace::commit_owned_output(self, output, source)
            .unwrap_or_else(|error| panic!("owned wait output commit drifted: {error:?}"));
    }

    fn discard_owned_output(&mut self, output: Self::OwnedOutput) {
        LiveProcessAddressSpace::discard_owned_output(self, output)
            .unwrap_or_else(|error| panic!("owned wait output discard drifted: {error:?}"));
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    PinnedLiveUserPages<'_, '_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn assert_exact_copy_range(&self, range: UserRange, byte_len: usize) {
        assert_eq!(
            range, self.range,
            "pinned live usercopy range drifted after preflight"
        );
        assert_eq!(
            u64::try_from(byte_len).ok(),
            Some(range.byte_len()),
            "pinned live usercopy byte length drifted after preflight"
        );
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> PinnedUserPages
    for PinnedLiveUserPages<'_, '_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
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

    fn read_exact(&mut self, range: UserRange, destination: &mut [u8]) {
        self.assert_exact_copy_range(range, destination.len());
        self.space.read_user(range.start(), destination);
    }

    fn write_exact(&mut self, range: UserRange, source: &[u8]) {
        self.assert_exact_copy_range(range, source.len());
        self.space.write_user(range.start(), source);
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> PinnedUserBatchPages
    for PinnedLiveUserBatch<'_, '_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    type Error = LiveUserAccessError;

    fn preflight(&mut self, index: usize, chunk: UserPageChunk) -> Result<(), Self::Error> {
        let range = self
            .ranges
            .get(index)
            .copied()
            .flatten()
            .ok_or(LiveUserAccessError::Permission)?;
        let chunk_end = chunk
            .address()
            .checked_add(chunk.byte_len())
            .ok_or(LiveUserAccessError::MissingOrInvalid)?;
        if chunk.address() < range.start()
            || chunk_end > range.end_exclusive()
            || chunk.access() != range.access()
        {
            return Err(LiveUserAccessError::Permission);
        }
        Ok(())
    }

    fn write_exact(&mut self, index: usize, range: UserRange, source: &[u8]) {
        let allowed = self
            .ranges
            .get(index)
            .copied()
            .flatten()
            .expect("batch output index remains present");
        assert_eq!(range.start(), allowed.start());
        assert!(range.end_exclusive() <= allowed.end_exclusive());
        assert_eq!(range.access(), allowed.access());
        assert_eq!(u64::try_from(source.len()).ok(), Some(range.byte_len()));
        self.space.write_user(range.start(), source);
    }
}

impl<'borrow, 'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    LiveProcessAddressSpace<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>
{
    /// Publishes a child architecture root while this same session owns the
    /// originating user-output pin, role manager, scratch mapper, and binding
    /// table. Keeping those capabilities in one borrow prevents an aliased
    /// ProcessCreate transaction from observing only half of the reservation.
    pub(crate) fn reserve_child_address_space(
        &mut self,
        process: crate::task::ProcessKey,
        address_space: crate::memory::address_region::AddressSpaceKey,
    ) -> Result<(), super::RootBindingError> {
        super::reserve_child_address_space_parts(
            self.primordial_root,
            self.root_bindings,
            self.roles,
            &mut self.target.scratch,
            process,
            address_space,
        )
    }

    pub(crate) fn rollback_empty_child_address_space(
        &mut self,
        process: crate::task::ProcessKey,
        address_space: crate::memory::address_region::AddressSpaceKey,
    ) -> Result<(), super::RootBindingError> {
        let pins = self.target.pins;
        let reservation = pins
            .reserve_teardown(address_space)
            .map_err(|_| super::RootBindingError::MutationInFlight)?;
        self.root_bindings.teardown_empty_owned(
            self.roles,
            &mut self.target,
            process,
            address_space,
            pins,
            reservation,
        )
    }

    /// Retargets only the scratch-walk validation identity. Raw usercopy must
    /// already be complete before this is called; the hardware-active root and
    /// its residency token remain unchanged until the scheduler selects the
    /// child Thread.
    pub(crate) fn select_process_for_return_validation(
        &mut self,
        process: crate::task::ProcessKey,
    ) -> Result<(), super::RootBindingError> {
        let (root, identity, address_space) = self
            .root_bindings
            .root_for_process(self.primordial_root, process)?;
        self.root = root as *const PageTableRoot;
        self.identity = identity;
        self.address_space = address_space;
        self.process = process;
        self.target.address_space = address_space;
        Ok(())
    }

    #[allow(
        unsafe_code,
        reason = "the active-root table owns stationary entries and this session never dereferences its selected root while mutating that table"
    )]
    fn selected_root(&self) -> &PageTableRoot {
        unsafe { &*self.root }
    }

    /// Pins and preflights one aligned readable userspace `u32`, then detaches
    /// the range reservation so it can survive a blocking syscall.
    pub(crate) fn pin_atomic_u32(
        &mut self,
        address: u64,
    ) -> Result<OwnedLiveAtomicU32, LiveUserAccessError> {
        let user = UserAddressSpace::x86_64_four_level(PAGE_SIZE)
            .expect("live x86_64 user address-space constants remain valid");
        let range = UserRange::new(
            user,
            address,
            core::mem::size_of::<u32>() as u64,
            core::mem::align_of::<u32>() as u64,
            UserAccess::READ,
            EmptyAddressRule::Reject,
        )
        .map_err(|_| LiveUserAccessError::MissingOrInvalid)?;
        let token = self
            .target
            .pins
            .pin_owned(self.address_space, range)
            .map_err(LiveUserAccessError::Pin)?;
        for chunk in range.page_chunks() {
            if let Err(error) = self.preflight(chunk) {
                self.target
                    .pins
                    .release_owned(self.address_space, token)
                    .expect(
                        "fresh owned atomic-word pin remains releasable after failed preflight",
                    );
                return Err(error);
            }
        }
        Ok(OwnedLiveAtomicU32 {
            process: self.process,
            address_space: self.address_space,
            range,
            token,
        })
    }

    /// Atomically samples a still-pinned shared userspace `u32` with acquire
    /// ordering. The pin prevents a recoverable mapping change while this
    /// pointer-derived atomic reference exists.
    #[allow(
        unsafe_code,
        reason = "the owned pin validates the exact aligned readable word and excludes overlapping page-table publication"
    )]
    pub(crate) fn load_atomic_u32_acquire(
        &mut self,
        word: &OwnedLiveAtomicU32,
    ) -> Result<u32, LiveUserAccessError> {
        if word.process != self.process {
            return Err(LiveUserAccessError::Permission);
        }
        let (start, end_exclusive) = self
            .target
            .pins
            .validate_owned(word.address_space, &word.token)
            .map_err(LiveUserAccessError::Pin)?;
        if start != word.range.start()
            || end_exclusive != word.range.end_exclusive()
            || word.range.byte_len() != core::mem::size_of::<u32>() as u64
            || !start.is_multiple_of(core::mem::align_of::<u32>() as u64)
        {
            return Err(LiveUserAccessError::Permission);
        }
        let walk = self.walk_leaf(start)?;
        let page = self
            .direct_page(walk.physical)
            .ok_or(LiveUserAccessError::MissingOrInvalid)?;
        let address = page + (start & (PAGE_SIZE - 1));
        // SAFETY: an aligned word of a pinned user page, through the direct
        // map: the same memory the user maps, so the same atomic object.
        let atomic = unsafe { core::sync::atomic::AtomicU32::from_ptr(address as *mut u32) };
        Ok(atomic.load(core::sync::atomic::Ordering::Acquire))
    }

    /// Releases a detached atomic-word mapping pin after every wait, wake,
    /// timeout, cancellation, or terminal-teardown path has finished with it.
    pub(crate) fn release_atomic_u32(
        &mut self,
        word: OwnedLiveAtomicU32,
    ) -> Result<(), LiveUserAccessError> {
        if word.process != self.process {
            return Err(LiveUserAccessError::Permission);
        }
        self.target
            .pins
            .release_owned(word.address_space, word.token)
            .map_err(LiveUserAccessError::Pin)
    }

    /// Preflights a writable range and detaches its mapping-stability pin from
    /// this short address-space borrow so a blocked syscall may retain it.
    pub(crate) fn preflight_owned_output(
        &mut self,
        range: UserRange,
    ) -> Result<OwnedLiveUserOutput, LiveUserAccessError> {
        if !range.access().includes(UserAccess::WRITE) || range.is_empty() {
            return Err(LiveUserAccessError::Permission);
        }
        let token = self
            .target
            .pins
            .pin_owned(self.address_space, range)
            .map_err(LiveUserAccessError::Pin)?;
        for chunk in range.page_chunks() {
            if let Err(error) = self.preflight(chunk) {
                self.target
                    .pins
                    .release_owned(self.address_space, token)
                    .expect("fresh owned user pin remains releasable after failed preflight");
                return Err(error);
            }
        }
        Ok(OwnedLiveUserOutput {
            process: self.process,
            address_space: self.address_space,
            range,
            token,
        })
    }

    pub(crate) fn discard_owned_output(
        &mut self,
        output: OwnedLiveUserOutput,
    ) -> Result<(), LiveUserAccessError> {
        if output.process != self.process {
            return Err(LiveUserAccessError::Permission);
        }
        self.target
            .pins
            .release_owned(output.address_space, output.token)
            .map_err(LiveUserAccessError::Pin)
    }

    /// The detached tracker token keeps the fully preflighted destination
    /// mapping stable across syscall suspension.
    pub(crate) fn commit_owned_output(
        &mut self,
        output: OwnedLiveUserOutput,
        source: &[u8],
    ) -> Result<(), LiveUserAccessError> {
        if output.process != self.process {
            return Err(LiveUserAccessError::Permission);
        }
        assert_eq!(
            u64::try_from(source.len()).ok(),
            Some(output.range.byte_len()),
            "owned live output length drift"
        );
        let (start, end_exclusive) = self
            .target
            .pins
            .validate_owned(output.address_space, &output.token)
            .map_err(LiveUserAccessError::Pin)?;
        assert_eq!(start, output.range.start());
        assert_eq!(end_exclusive, output.range.end_exclusive());
        assert_eq!(start, output.token.start());
        assert_eq!(end_exclusive, output.token.end_exclusive());
        self.write_user(start, source);
        self.target
            .pins
            .release_owned(output.address_space, output.token)
            .map_err(LiveUserAccessError::Pin)
    }

    fn walk_leaf(&mut self, virtual_address: u64) -> Result<LiveUserWalk, LiveUserAccessError> {
        let page = VirtualPage::containing(virtual_address)
            .map_err(|_| LiveUserAccessError::MissingOrInvalid)?;
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
                    entry & physical_mask(self.selected_root().capabilities),
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
            physical: entry & physical_mask(self.selected_root().capabilities),
        })
    }

    fn read_entry(
        &mut self,
        table: TableIdentity,
        index: usize,
    ) -> Result<u64, LiveUserAccessError> {
        self.target
            .read_entry(
                FrameAddress::new(
                    table.physical_start(),
                    self.selected_root().physical_limit(),
                )
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
        // The kernel copies through the direct map, never through the user
        // address (DW2 M2, which turns SMAP on): a page that is not RAM the
        // allocator owns, such as a device's registers, cannot be copied to
        // or from.
        if self.direct_page(walk.physical).is_none() {
            return Err(LiveUserAccessError::MissingOrInvalid);
        }
        Ok(())
    }

    /// The direct-map address of the frame at `physical`.
    fn direct_page(&self, physical: u64) -> Option<u64> {
        self.target
            .scratch
            .direct?
            .virtual_address(physical, PAGE_SIZE)
    }

    /// Runs `copy` over each piece of `[start, start + length)` that lies in
    /// one user page, with the direct-map address of that piece and its
    /// offset into the range. Every page must have passed preflight under a
    /// pin that is still held, so its mapping cannot have changed and the
    /// walk cannot fail.
    fn for_each_user_piece(
        &mut self,
        start: u64,
        length: usize,
        mut copy: impl FnMut(u64, usize, usize),
    ) {
        let mut done = 0_usize;
        while done < length {
            let address = start + done as u64;
            let in_page = (address & (PAGE_SIZE - 1)) as usize;
            let take = (PAGE_SIZE as usize - in_page).min(length - done);
            let walk = self.walk_leaf(address).unwrap_or_else(|error| {
                panic!("pinned user page drifted after preflight: {error:?}")
            });
            let page = self
                .direct_page(walk.physical)
                .unwrap_or_else(|| panic!("pinned user page left the direct map"));
            copy(page + in_page as u64, done, take);
            done += take;
        }
    }

    /// Copies `destination.len()` bytes from preflighted, pinned user memory
    /// at `start`.
    #[allow(
        unsafe_code,
        reason = "each piece is a pinned, preflighted user page reached through the direct map"
    )]
    fn read_user(&mut self, start: u64, destination: &mut [u8]) {
        let pointer = destination.as_mut_ptr();
        self.for_each_user_piece(start, destination.len(), |from, offset, length| {
            // SAFETY: `from` is `length` bytes of one direct-mapped frame and
            // `offset + length` lies inside `destination`.
            unsafe {
                core::ptr::copy_nonoverlapping(from as *const u8, pointer.add(offset), length);
            }
        });
    }

    /// Copies `source` into preflighted, pinned, writable user memory at
    /// `start`.
    #[allow(
        unsafe_code,
        reason = "each piece is a pinned, preflighted writable user page reached through the direct map"
    )]
    fn write_user(&mut self, start: u64, source: &[u8]) {
        self.for_each_user_piece(start, source.len(), |to, offset, length| {
            // SAFETY: `to` is `length` bytes of one direct-mapped frame and
            // `offset + length` lies inside `source`.
            unsafe {
                core::ptr::copy_nonoverlapping(source.as_ptr().add(offset), to as *mut u8, length);
            }
        });
    }

    #[allow(
        unsafe_code,
        reason = "the authenticated scratch session zeroes the exclusive physical allocation before the typed Zeroed transition"
    )]
    pub(crate) fn allocate_zeroed_backing(
        &mut self,
        page_count: u64,
    ) -> Result<ObjectBackingGrant, LiveUserAccessError> {
        let limit = self.selected_root().physical_limit();
        let scratch = &mut self.target.scratch;
        let mut zero = |page: u64| {
            FrameAddress::new(page, limit)
                .is_ok_and(|frame| scratch.zero_allocator_frame(frame).is_ok())
        };
        // SAFETY: `zero` clears each exclusively owned page of the new
        // backing through the authenticated scratch mapping, or fails.
        unsafe { self.roles.allocate_zeroed_backing(page_count, &mut zero) }
            .map_err(|_| LiveUserAccessError::MissingOrInvalid)
    }

    /// A new MemoryObject's backing, allocated and not yet zeroed, for
    /// zeroing in steps (DW2 M4b).
    pub(crate) fn allocate_backing(
        &mut self,
        page_count: u64,
    ) -> Result<crate::memory::frame_roles::BackingAllocation, LiveUserAccessError> {
        self.roles
            .allocate_backing(page_count)
            .map_err(|_| LiveUserAccessError::MissingOrInvalid)
    }

    /// A new on-demand MemoryObject's backing: its index root, zeroed, and
    /// no pages (DW2 M6 §8.3).
    pub(crate) fn allocate_on_demand_backing(
        &mut self,
        page_count: u64,
    ) -> Result<crate::memory::frame_roles::ObjectBackingGrant, LiveUserAccessError> {
        self.roles
            .allocate_on_demand_backing(page_count)
            .map_err(|_| LiveUserAccessError::MissingOrInvalid)
    }

    /// Zeroes pages `[first, first + count)` of `allocation` through the
    /// authenticated scratch session; `false` if any fails.
    pub(crate) fn zero_backing_pages(
        &mut self,
        allocation: &crate::memory::frame_roles::BackingAllocation,
        first: u64,
        count: u64,
    ) -> bool {
        let limit = self.selected_root().physical_limit();
        let scratch = &mut self.target.scratch;
        let mut zero = |page: u64| {
            FrameAddress::new(page, limit)
                .is_ok_and(|frame| scratch.zero_allocator_frame(frame).is_ok())
        };
        self.roles
            .zero_backing_pages(allocation, first, count, &mut zero)
    }

    /// Makes a zeroed allocation one object backing.
    ///
    /// # Safety
    ///
    /// `zero_backing_pages` must have zeroed every page of `allocation`.
    #[allow(
        unsafe_code,
        reason = "the caller attests that every page was zeroed through the authenticated scratch session"
    )]
    pub(crate) unsafe fn finish_zeroed_backing(
        &mut self,
        allocation: crate::memory::frame_roles::BackingAllocation,
    ) -> ObjectBackingGrant {
        // SAFETY: the caller zeroed every page, per this function's contract.
        unsafe { self.roles.assume_backing_zeroed(allocation) }
            .unwrap_or_else(|_| panic!("a zeroed backing allocation becomes a backing"))
    }

    /// Frees an allocation that will not become a backing.
    pub(crate) fn cancel_backing(
        &mut self,
        allocation: crate::memory::frame_roles::BackingAllocation,
    ) {
        self.roles
            .cancel_backing_allocation(allocation)
            .unwrap_or_else(|_| panic!("a fresh backing allocation frees"));
    }

    #[allow(
        unsafe_code,
        reason = "the authenticated scratch session zeroes the exclusive table allocation before the typed Zeroed transition"
    )]
    pub(crate) fn prepare_table_candidate(
        &mut self,
        level: TableLevel,
    ) -> Result<TableCandidateGrant, LiveUserAccessError> {
        let allocation = self
            .roles
            .allocate(1)
            .map_err(|_| LiveUserAccessError::MissingOrInvalid)?;
        let frame = FrameAddress::new(
            allocation.physical_start(),
            self.selected_root().physical_limit(),
        )
        .map_err(|_| LiveUserAccessError::MissingOrInvalid)?;
        if self.target.scratch.zero_allocator_frame(frame).is_err() {
            self.roles
                .cancel_allocation(allocation)
                .unwrap_or_else(|_| {
                    panic!("G3 table-candidate rollback lost allocation authority")
                });
            return Err(LiveUserAccessError::MissingOrInvalid);
        }
        let zeroed = unsafe { self.roles.assume_zeroed(allocation) }
            .unwrap_or_else(|_| panic!("G3 zeroed table-candidate transition drifted"));
        match self
            .roles
            .prepare_table(zeroed, self.identity.owner(), level)
        {
            Ok(candidate) => Ok(candidate),
            Err(failure) => {
                self.roles
                    .cancel_zeroed(failure.into_grant())
                    .unwrap_or_else(|_| panic!("G3 zeroed table-candidate rollback drifted"));
                Err(LiveUserAccessError::MissingOrInvalid)
            }
        }
    }

    pub(crate) fn recycle_table_candidate(&mut self, candidate: TableCandidateGrant) {
        self.roles
            .cancel_table_candidate(candidate)
            .unwrap_or_else(|_| panic!("G3 unused table-candidate rollback drifted"));
    }

    #[allow(
        unsafe_code,
        reason = "the live session binds authority-issued identities to its exact pin-aware serialized architecture root"
    )]
    pub(crate) fn publisher<'publisher, const CANDIDATE_CAPACITY: usize>(
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
            LIVE_JOURNAL_ENTRIES,
            LIVE_JOURNAL_INVALIDATIONS,
        >,
        crate::arch::x86_64::mm::X86AddressSpacePublishError<LiveTrackedTargetError>,
    > {
        if address_space != self.address_space {
            return Err(crate::arch::x86_64::mm::X86AddressSpacePublishError::Identity);
        }
        let root_pointer = self.root;
        let identity = self.identity;
        let roles = &mut *self.roles;
        let target = &mut self.target;
        let journal = &mut *self.journal;
        // SAFETY: this session owns the exact active root, role manager and
        // pin-aware serialized target; E5 supplies authority-issued identities.
        unsafe {
            let root = &*root_pointer;
            crate::arch::x86_64::mm::X86AddressSpacePublisher::new(
                address_space,
                region,
                root,
                identity,
                roles,
                target,
                candidates,
                journal,
            )
        }
    }

    /// Splits the disjoint live root-binding and page-table publisher borrows
    /// for one synchronous coherent mutation. Keeping that split here makes
    /// the exact residency domain mechanically follow the selected root rather
    /// than allowing a caller to pair a raw publisher with a different root.
    #[allow(
        unsafe_code,
        reason = "the live session binds authority-issued identities to its exact pin-aware serialized architecture root"
    )]
    pub(crate) fn publisher_with_coherency<'publisher, const CANDIDATE_CAPACITY: usize>(
        &'publisher mut self,
        address_space: crate::memory::address_region::AddressSpaceKey,
        region: crate::memory::address_region::RegionKey,
        candidates: &'publisher mut [Option<TableCandidateGrant>; CANDIDATE_CAPACITY],
    ) -> Result<
        (
            crate::arch::x86_64::mm::X86AddressSpacePublisher<
                'publisher,
                TrackedActiveTarget<'borrow>,
                RANGE_CAPACITY,
                ROLE_CAPACITY,
                CANDIDATE_CAPACITY,
                LIVE_JOURNAL_ENTRIES,
                LIVE_JOURNAL_INVALIDATIONS,
            >,
            &'publisher crate::memory::address_region::AddressSpaceCoherency<
                { crate::cpu::CPU_CAPACITY },
            >,
        ),
        crate::arch::x86_64::mm::X86AddressSpacePublishError<LiveTrackedTargetError>,
    > {
        if address_space != self.address_space {
            return Err(crate::arch::x86_64::mm::X86AddressSpacePublishError::Identity);
        }
        let coherency = self
            .root_bindings
            .coherency_for(self.process, address_space)
            .map_err(|_| crate::arch::x86_64::mm::X86AddressSpacePublishError::Identity)?;
        let root_pointer = self.root;
        let identity = self.identity;
        let roles = &mut *self.roles;
        let target = &mut self.target;
        let journal = &mut *self.journal;
        // SAFETY: the immutable coherency borrow is disjoint from the mutable
        // role/target fields. This session still owns the exact root and its
        // pin-aware serialized publisher for the complete returned lifetime.
        let publisher = unsafe {
            crate::arch::x86_64::mm::X86AddressSpacePublisher::new(
                address_space,
                region,
                &*root_pointer,
                identity,
                roles,
                target,
                candidates,
                journal,
            )
        }?;
        Ok((publisher, coherency))
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

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    crate::arch::x86_64::syscall::ProcessUserReturnMappingValidation
    for LiveProcessAddressSpace<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn process_key(&self) -> crate::task::ProcessKey {
        self.process
    }
}

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> crate::syscall::FAtomicUserAccess
    for LiveProcessAddressSpace<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    type AtomicPin = OwnedLiveAtomicU32;

    fn pin_atomic_u32(
        &mut self,
        address: deepwyrm_abi::DwUserAddress,
    ) -> Result<Self::AtomicPin, deepwyrm_abi::DwStatus> {
        LiveProcessAddressSpace::pin_atomic_u32(self, address.0)
            .map_err(|_| deepwyrm_abi::DW_STATUS_BAD_ADDRESS)
    }

    fn load_atomic_u32_acquire(&mut self, pin: &Self::AtomicPin) -> u32 {
        LiveProcessAddressSpace::load_atomic_u32_acquire(self, pin)
            .unwrap_or_else(|_| panic!("live atomic pin lost its mapping authority"))
    }

    fn release_atomic_u32(&mut self, pin: Self::AtomicPin) {
        LiveProcessAddressSpace::release_atomic_u32(self, pin)
            .unwrap_or_else(|_| panic!("live atomic pin release lost its owner"));
    }
}
