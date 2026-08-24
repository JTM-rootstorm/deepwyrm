use super::*;

use crate::memory::frame_roles::{ObjectBackingGrant, TableCandidateGrant};
use crate::memory::user_range::{
    EmptyAddressRule, UserAccess, UserAddressSpace, UserPageChunk, UserRange,
};
use crate::memory::usercopy::{
    OwnedUserOutputAccess, PinnedUserBatchPages, PinnedUserPages, UserPageAccess,
    UserPageBatchAccess, UserPinError, UserPinTracker, UserRangePin, UserRangePinToken,
};
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

const TLB_MAILBOX_EMPTY: u8 = 0;
const TLB_MAILBOX_PUBLISHING: u8 = 1;
const TLB_MAILBOX_PUBLISHED: u8 = 2;
const TLB_MAILBOX_CONSUMING: u8 = 3;

/// One CPU-private, protocol-owned e2 mailbox.
///
/// The sender owns `PUBLISHING` and may only advance it to `PUBLISHED` after
/// fully writing the exact request and stationary coherency pointer.  The e2
/// handler owns `CONSUMING`; it copies those fields before local serialization
/// and never consults the mailbox after returning it to `EMPTY`.
struct LiveTlbMailbox {
    state: AtomicU8,
    coherency: AtomicPtr<
        crate::memory::address_region::AddressSpaceCoherency<{ crate::cpu::CPU_CAPACITY }>,
    >,
    request: UnsafeCell<MaybeUninit<crate::memory::address_region::ShootdownRequest>>,
}

impl LiveTlbMailbox {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(TLB_MAILBOX_EMPTY),
            coherency: AtomicPtr::new(core::ptr::null_mut()),
            request: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn publish(
        &self,
        coherency: &crate::memory::address_region::AddressSpaceCoherency<
            { crate::cpu::CPU_CAPACITY },
        >,
        request: crate::memory::address_region::ShootdownRequest,
    ) {
        self.state
            .compare_exchange(
                TLB_MAILBOX_EMPTY,
                TLB_MAILBOX_PUBLISHING,
                Ordering::Acquire,
                Ordering::Acquire,
            )
            .unwrap_or_else(|state| {
                panic!("TLB shootdown target already has an outstanding mailbox: {state}")
            });
        // SAFETY: this sender exclusively owns PUBLISHING. The request is
        // immutable after the following Release publication, and the handler
        // may read it only after it Acquire-observes PUBLISHED.
        #[allow(
            unsafe_code,
            reason = "the sender exclusively owns PUBLISHING until its Release publication"
        )]
        unsafe {
            (*self.request.get()).write(request);
        }
        self.coherency
            .store(core::ptr::from_ref(coherency).cast_mut(), Ordering::Relaxed);
        self.state.store(TLB_MAILBOX_PUBLISHED, Ordering::Release);
    }

    fn cancel_if_published(&self) {
        let _ = self.state.compare_exchange(
            TLB_MAILBOX_PUBLISHED,
            TLB_MAILBOX_EMPTY,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn consume(
        &self,
    ) -> Option<(
        &crate::memory::address_region::AddressSpaceCoherency<{ crate::cpu::CPU_CAPACITY }>,
        crate::memory::address_region::ShootdownRequest,
    )> {
        self.state
            .compare_exchange(
                TLB_MAILBOX_PUBLISHED,
                TLB_MAILBOX_CONSUMING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;
        let coherency = self.coherency.load(Ordering::Relaxed);
        if coherency.is_null() {
            panic!("published TLB shootdown mailbox omitted coherency domain");
        }
        // SAFETY: the successful AcqRel transition owns the immutable request
        // after the sender's Release publication. The pointer names the exact
        // stationary root-binding coherency object; binding teardown remains
        // gated by the acknowledgement completed below.
        #[allow(
            unsafe_code,
            reason = "the handler exclusively owns CONSUMING after acquire-consuming the sender publication"
        )]
        let request = unsafe { (*self.request.get()).assume_init_read() };
        #[allow(
            unsafe_code,
            reason = "the exact stationary coherency pointer is retained by its root binding until acknowledgement-gated reclaim"
        )]
        let coherency = unsafe { &*coherency };
        Some((coherency, request))
    }

    fn release_after_local_serialization(&self) {
        self.state
            .compare_exchange(
                TLB_MAILBOX_CONSUMING,
                TLB_MAILBOX_EMPTY,
                Ordering::Release,
                Ordering::Acquire,
            )
            .unwrap_or_else(|state| {
                panic!("TLB shootdown mailbox ownership drifted after local flush: {state}")
            });
    }
}

// SAFETY: the request cell is read only by the e2 CPU after acquire-consuming
// the state publication and before release-clearing its unique mailbox state.
#[allow(
    unsafe_code,
    reason = "mailbox state serializes the UnsafeCell request between one sender and one e2 handler"
)]
unsafe impl Sync for LiveTlbMailbox {}

static LIVE_TLB_MAILBOXES: [LiveTlbMailbox; crate::cpu::CPU_CAPACITY] =
    [const { LiveTlbMailbox::new() }; crate::cpu::CPU_CAPACITY];

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
        // lets the model mint its reclaim permit.
        core::hint::spin_loop();
    }
}

/// Installs the e2 receive path after the live APIC transport is available and
/// before AP runtime carriers can execute userspace mappings.
pub(crate) fn initialize_live_tlb_shootdown() {
    crate::arch::x86_64::ipi::bind_live_tlb_shootdown_handler(live_tlb_shootdown_handler)
        .unwrap_or_else(|error| panic!("could not bind live TLB shootdown handler: {error:?}"));
}

/// e2 runs after EOI with IF clear. It takes no runtime lock and no scheduler,
/// usercopy, finalization, or page-table mutation authority.
fn live_tlb_shootdown_handler() {
    let cpu = crate::arch::x86_64::syscall::current_cpu_index_for_diagnostics()
        .and_then(crate::cpu::CpuIndex::new)
        .unwrap_or_else(|| panic!("TLB shootdown arrived without CPU identity"));
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
    #[cfg(deepwyrm_i1_evidence)]
    if _acknowledgement == crate::memory::address_region::ShootdownAcknowledgement::Recorded {
        crate::test_support::observe_i1_tlb_ack(cpu, request);
    }
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
    pub(super) scratch: ActiveScratchTarget<LiveActiveScratchIo>,
    pub(super) pins: &'a UserPinTracker<E5_USER_PIN_CAPACITY>,
    pub(super) address_space: crate::memory::address_region::AddressSpaceKey,
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
                    .begin_mutation(self.address_space, start, end - start)
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
}

impl OwnedLiveUserOutput {
    pub(crate) const fn process(&self) -> crate::task::ProcessKey {
        self.process
    }
}

pub(crate) struct PinnedLiveUserPages<'tracker> {
    _pin: UserRangePin<'tracker, E5_USER_PIN_CAPACITY>,
    range: UserRange,
}

pub(crate) struct PinnedLiveUserBatch<'tracker> {
    _pins: [Option<UserRangePin<'tracker, E5_USER_PIN_CAPACITY>>; 3],
    ranges: [Option<UserRange>; 3],
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
        let pin = pins
            .pin(self.address_space, range)
            .map_err(LiveUserAccessError::Pin)?;
        for chunk in range.page_chunks() {
            if let Err(error) = self.preflight(chunk) {
                drop(pin);
                return Err(error);
            }
        }
        Ok(PinnedLiveUserPages { _pin: pin, range })
    }
}

impl<'borrow, 'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> UserPageBatchAccess
    for LiveProcessAddressSpace<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>
{
    type PinnedBatch<'a>
        = PinnedLiveUserBatch<'borrow>
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

impl PinnedLiveUserPages<'_> {
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
        self.assert_exact_copy_range(range, destination.len());
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
        self.assert_exact_copy_range(range, source.len());
        unsafe {
            core::ptr::copy_nonoverlapping(source.as_ptr(), range.start() as *mut u8, source.len());
        }
    }
}

impl PinnedUserBatchPages for PinnedLiveUserBatch<'_> {
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

    #[allow(
        unsafe_code,
        reason = "all batch ranges remain pinned and live-root preflight proved every destination page writable before exact copy"
    )]
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
        unsafe {
            core::ptr::copy_nonoverlapping(source.as_ptr(), range.start() as *mut u8, source.len());
        }
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
        let atomic = unsafe { core::sync::atomic::AtomicU32::from_ptr(start as *mut u32) };
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

    #[allow(
        unsafe_code,
        reason = "the detached tracker token keeps the fully preflighted destination mapping stable across syscall suspension"
    )]
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
        unsafe {
            core::ptr::copy_nonoverlapping(source.as_ptr(), start as *mut u8, source.len());
        }
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
            let frame = FrameAddress::new(
                physical_start + offset,
                self.selected_root().physical_limit(),
            )
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
        if address_space != self.address_space {
            return Err(crate::arch::x86_64::mm::X86AddressSpacePublishError::Identity);
        }
        let root_pointer = self.root;
        let identity = self.identity;
        let roles = &mut *self.roles;
        let target = &mut self.target;
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
    pub(crate) fn publisher_with_coherency<
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
        (
            crate::arch::x86_64::mm::X86AddressSpacePublisher<
                'publisher,
                TrackedActiveTarget<'borrow>,
                RANGE_CAPACITY,
                ROLE_CAPACITY,
                CANDIDATE_CAPACITY,
                ENTRY_CAPACITY,
                INVALIDATION_CAPACITY,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e2_mailbox_releases_only_after_local_serialization_before_exact_ack() {
        let address_space = crate::memory::address_region::AddressSpaceKey::for_test(7, 11);
        let coherency = crate::memory::address_region::AddressSpaceCoherency::<
            { crate::cpu::CPU_CAPACITY },
        >::new(address_space);
        let cpu = crate::cpu::CpuIndex::new(1).unwrap();
        let _residency = coherency.enter(cpu).unwrap();
        let transaction = coherency
            .prepare_mutation(
                crate::memory::address_region::MappingMutation::Protect,
                crate::memory::address_region::InvalidationScope::pages(0x4000, 0x1000).unwrap(),
            )
            .unwrap();
        let barrier = transaction.publish();
        let request = barrier.request();
        let mailbox = LiveTlbMailbox::new();

        mailbox.publish(&coherency, request);
        let (received_coherency, received_request) = mailbox.consume().unwrap();
        assert_eq!(received_request, request);
        assert_eq!(
            received_coherency.request_for_cpu(cpu),
            Some(request),
            "the e2 target still has a pending exact generation before acknowledgement"
        );
        mailbox.release_after_local_serialization();
        received_coherency
            .acknowledge(cpu, received_request)
            .unwrap();
        assert!(barrier.try_complete().is_ok());
        assert_eq!(mailbox.state.load(Ordering::Acquire), TLB_MAILBOX_EMPTY);
    }

    #[test]
    fn e2_mailbox_rejects_overlapping_target_publication() {
        let address_space = crate::memory::address_region::AddressSpaceKey::for_test(9, 13);
        let coherency = crate::memory::address_region::AddressSpaceCoherency::<
            { crate::cpu::CPU_CAPACITY },
        >::new(address_space);
        let cpu = crate::cpu::CpuIndex::new(1).unwrap();
        let _residency = coherency.enter(cpu).unwrap();
        let transaction = coherency
            .prepare_mutation(
                crate::memory::address_region::MappingMutation::Map,
                crate::memory::address_region::InvalidationScope::pages(0x5000, 0x1000).unwrap(),
            )
            .unwrap();
        let barrier = transaction.publish();
        let mailbox = LiveTlbMailbox::new();
        mailbox.publish(&coherency, barrier.request());
        let overlap = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            mailbox.publish(&coherency, barrier.request());
        }));
        assert!(overlap.is_err());
        mailbox.cancel_if_published();
    }
}
