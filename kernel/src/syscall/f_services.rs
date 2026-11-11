//! Shared DW0-F native service composition.
//!
//! This module wires the already-validated F adapters into one selector-neutral
//! dispatch surface.  The owning target runtime still supplies the current
//! Process/Thread, address-space access, stationary IRQ-visible authorities,
//! and typed finalizer routing.

use deepwyrm_abi::{
    DW_DEADLINE_INFINITE, DW_DEADLINE_NOW, DW_STATUS_BAD_ADDRESS, DW_STATUS_BAD_STATE,
    DW_STATUS_NO_RESOURCES, DW_STATUS_SUCCESS, DW_STATUS_TIMED_OUT, DW_STATUS_WOULD_BLOCK,
    DwDeadline, DwStatus, DwUserAddress,
};

use crate::atomic_wait::{
    AtomicWaitBegin, AtomicWaitBeginError, AtomicWaitOperationRegistry, AtomicWaitRegistry,
    AtomicWaitUnregistered, PendingAtomicWait, begin_atomic_wait, finish_atomic_wait,
    finish_terminal_atomic_wait, register_atomic_wait, settle_atomic_wait, wake_atomic_waiters,
};
use crate::device::InterruptWaitSource;
use crate::ipc::ChannelAuthority;
use crate::memory::address_region::{AddressRegionObjectAuthority, AddressSpaceAuthority};
use crate::memory::usercopy::{OwnedUserOutputAccess, UserPageBatchAccess};
use crate::object::ObjectRegistry;
use crate::task::{BlockedOperationWinner, ExecutionDomain, ProcessKey, TaskAuthority, ThreadKey};
use crate::time::{TimerAuthority, TimerDeadlineAuthority};
use crate::wait::{
    EventAuthority, WaitRegistry,
    engine::{WaitDeadline, WaitDeadlineAuthority, WaitFinishError, finish_terminal_wait},
    operation::WaitOperationRegistry,
};

use super::adapters::{
    CleanupQueue, NativeWaitControl, TerminalWaitCleanup, WaitSuspendError, atomic_wake_with,
    channel_create, channel_receive, channel_send_from_thread, clock_get_with, event_create,
    event_signal, process_create, resume_wait_thread_syscall, task_group_limit, task_status,
    timer_cancel, timer_create, timer_set, wait_many_syscall_on, wait_one_syscall_on,
};
#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(unused_imports, reason = "only the live runtime begins prepared waits")
)]
use super::adapters::{PreparedWait, WaitResultBytes, settle_wait_begin, wait_prepared_begin};
use super::native::{
    NativeIdleSuspendPoll, NativeSuspendPlan, NativeSyscallRequest, NativeSyscallResult,
};

/// Target-provided ownership of one mapping-stable atomic userspace word.
///
/// A successful pin must exclude intersecting unmap/protect/remap operations
/// until `release_atomic_u32` consumes it.  Loads must use the pinned word with
/// acquire ordering.  Stable wait identity is deliberately *not* supplied by
/// this trait: the service derives it through `AddressRegionObjectAuthority` as
/// `(MemoryObject generation, object offset)`, never from a raw virtual address.
pub(crate) trait FAtomicUserAccess: UserPageBatchAccess + OwnedUserOutputAccess {
    type AtomicPin;

    fn pin_atomic_u32(&mut self, address: DwUserAddress) -> Result<Self::AtomicPin, DwStatus>;

    fn load_atomic_u32_acquire(&mut self, pin: &Self::AtomicPin) -> u32;

    fn release_atomic_u32(&mut self, pin: Self::AtomicPin);
}

/// The user access a suspended F operation resumes against under the
/// runtime authority (D1 commit 8, design §11.2.3 family E). It touches no
/// user memory: it records the generic wait's output settlement and the
/// atomic wait's pin release, for the caller to apply after the authority.
/// The output and the pin were pinned before the wait suspended, so neither
/// step can fail once it is applied.
#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(
        dead_code,
        reason = "only the live runtime defers a resume's settlement"
    )
)]
pub(crate) struct DeferredWaitSettlement<OUTPUT, PIN> {
    output: Option<(OUTPUT, WaitResultBytes)>,
    pin: Option<PIN>,
}

#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(
        dead_code,
        reason = "only the live runtime defers a resume's settlement"
    )
)]
impl<OUTPUT, PIN> DeferredWaitSettlement<OUTPUT, PIN> {
    pub(crate) const fn new() -> Self {
        Self {
            output: None,
            pin: None,
        }
    }

    /// The recorded output settlement and pin release, at most one of which
    /// a resume produces.
    pub(crate) fn into_parts(self) -> (Option<(OUTPUT, WaitResultBytes)>, Option<PIN>) {
        assert!(
            self.output.is_none() || self.pin.is_none(),
            "one resumed F operation settled both an output and an atomic pin"
        );
        (self.output, self.pin)
    }
}

impl<OUTPUT, PIN> crate::memory::usercopy::UserPageAccess for DeferredWaitSettlement<OUTPUT, PIN> {
    type Error = crate::memory::usercopy::DeferredOutputUnavailable;
    type Pinned<'a>
        = crate::memory::usercopy::DeferredOutputPin<'a>
    where
        Self: 'a;

    fn pin(
        &mut self,
        _range: crate::memory::user_range::UserRange,
    ) -> Result<Self::Pinned<'_>, Self::Error> {
        panic!("a resumed F operation does no usercopy under the runtime authority");
    }
}

impl<OUTPUT, PIN> UserPageBatchAccess for DeferredWaitSettlement<OUTPUT, PIN> {
    type PinnedBatch<'a>
        = crate::memory::usercopy::DeferredBatchPin<'a>
    where
        Self: 'a;

    fn pin_batch(
        &mut self,
        _ranges: [Option<crate::memory::user_range::UserRange>; 3],
    ) -> Result<Self::PinnedBatch<'_>, Self::Error> {
        panic!("a resumed F operation does no usercopy under the runtime authority");
    }
}

impl<OUTPUT, PIN> OwnedUserOutputAccess for DeferredWaitSettlement<OUTPUT, PIN> {
    type OwnedOutput = OUTPUT;

    fn preflight_owned_output(
        &mut self,
        _range: crate::memory::user_range::UserRange,
    ) -> Result<Self::OwnedOutput, Self::Error> {
        panic!("a resumed wait pinned its output before it suspended");
    }

    fn commit_owned_output(&mut self, output: Self::OwnedOutput, source: &[u8]) {
        let bytes = source
            .try_into()
            .expect("a resumed wait's result has its generated size");
        assert!(
            self.output.replace((output, Some(bytes))).is_none(),
            "a resumed wait settled its output twice"
        );
    }

    fn discard_owned_output(&mut self, output: Self::OwnedOutput) {
        assert!(
            self.output.replace((output, None)).is_none(),
            "a resumed wait settled its output twice"
        );
    }
}

impl<OUTPUT, PIN> FAtomicUserAccess for DeferredWaitSettlement<OUTPUT, PIN> {
    type AtomicPin = PIN;

    fn pin_atomic_u32(&mut self, _address: DwUserAddress) -> Result<Self::AtomicPin, DwStatus> {
        panic!("a resumed atomic wait pinned its word before it suspended");
    }

    fn load_atomic_u32_acquire(&mut self, _pin: &Self::AtomicPin) -> u32 {
        panic!("a resumed atomic wait loads no user word");
    }

    fn release_atomic_u32(&mut self, pin: Self::AtomicPin) {
        assert!(
            self.pin.replace(pin).is_none(),
            "a resumed atomic wait released its pin twice"
        );
    }
}

/// The user access the live ordinary F-service dispatch passes (D1 commit 9).
/// Every F request that copies is served by a CPU-local facade helper,
/// outside the runtime authority, before it could reach this dispatch: the
/// arms that remain (EventSignal, TimerSet, TimerCancel) touch no user
/// memory. So this access holds no session and panics on any use; reaching
/// it is a routing bug, not a usercopy under T.
#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(
        dead_code,
        reason = "only the live runtime routes copying F requests elsewhere"
    )
)]
pub(crate) struct UnreachableUserAccess<OUTPUT, PIN> {
    _owned: core::marker::PhantomData<(OUTPUT, PIN)>,
}

#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(
        dead_code,
        reason = "only the live runtime routes copying F requests elsewhere"
    )
)]
impl<OUTPUT, PIN> UnreachableUserAccess<OUTPUT, PIN> {
    pub(crate) const fn new() -> Self {
        Self {
            _owned: core::marker::PhantomData,
        }
    }
}

const UNREACHABLE_USER_ACCESS: &str =
    "an F request that copies reached the ordinary dispatch under the runtime authority";

impl<OUTPUT, PIN> crate::memory::usercopy::UserPageAccess for UnreachableUserAccess<OUTPUT, PIN> {
    type Error = crate::memory::usercopy::DeferredOutputUnavailable;
    type Pinned<'a>
        = crate::memory::usercopy::DeferredOutputPin<'a>
    where
        Self: 'a;

    fn pin(
        &mut self,
        _range: crate::memory::user_range::UserRange,
    ) -> Result<Self::Pinned<'_>, Self::Error> {
        panic!("{UNREACHABLE_USER_ACCESS}");
    }
}

impl<OUTPUT, PIN> UserPageBatchAccess for UnreachableUserAccess<OUTPUT, PIN> {
    type PinnedBatch<'a>
        = crate::memory::usercopy::DeferredBatchPin<'a>
    where
        Self: 'a;

    fn pin_batch(
        &mut self,
        _ranges: [Option<crate::memory::user_range::UserRange>; 3],
    ) -> Result<Self::PinnedBatch<'_>, Self::Error> {
        panic!("{UNREACHABLE_USER_ACCESS}");
    }
}

impl<OUTPUT, PIN> OwnedUserOutputAccess for UnreachableUserAccess<OUTPUT, PIN> {
    type OwnedOutput = OUTPUT;

    fn preflight_owned_output(
        &mut self,
        _range: crate::memory::user_range::UserRange,
    ) -> Result<Self::OwnedOutput, Self::Error> {
        panic!("{UNREACHABLE_USER_ACCESS}");
    }

    fn commit_owned_output(&mut self, _output: Self::OwnedOutput, _source: &[u8]) {
        panic!("{UNREACHABLE_USER_ACCESS}");
    }

    fn discard_owned_output(&mut self, _output: Self::OwnedOutput) {
        panic!("{UNREACHABLE_USER_ACCESS}");
    }
}

impl<OUTPUT, PIN> FAtomicUserAccess for UnreachableUserAccess<OUTPUT, PIN> {
    type AtomicPin = PIN;

    fn pin_atomic_u32(&mut self, _address: DwUserAddress) -> Result<Self::AtomicPin, DwStatus> {
        panic!("{UNREACHABLE_USER_ACCESS}");
    }

    fn load_atomic_u32_acquire(&mut self, _pin: &Self::AtomicPin) -> u32 {
        panic!("{UNREACHABLE_USER_ACCESS}");
    }

    fn release_atomic_u32(&mut self, _pin: Self::AtomicPin) {
        panic!("{UNREACHABLE_USER_ACCESS}");
    }
}

/// The first hold's outcome for a live `AtomicWait32` (D1 commit 8b): the
/// registered waiter and its pin, for the caller to compare through with no
/// runtime lock held and then settle in a second hold; or the status the wait
/// returns with, and the pin it took, if any, to release after the hold.
pub(crate) type AtomicWaitHold<PIN> = Result<(PendingAtomicWait, PIN), (DwStatus, Option<PIN>)>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FServiceOperationOwner {
    GenericWait,
    AtomicWait,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FServiceOwnerError {
    Missing,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FServiceResumeError {
    Owner(FServiceOwnerError),
    GenericWait(WaitFinishError),
    AtomicWait(AtomicWaitBeginError),
    UnexpectedAtomicWinner(BlockedOperationWinner),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FServiceRoute {
    Handled(NativeSyscallResult),
    Fallthrough(NativeSyscallRequest),
}

/// One dispatch result and every typed final release it produced.
///
/// The caller obtains both together so it cannot consume only the syscall route
/// while silently abandoning deferred finalization.
#[must_use = "F service dispatch cleanup must be routed through PayloadFinalizer"]
pub(crate) struct FServiceDispatch {
    route: FServiceRoute,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FServiceDispatchPhaseError {
    ZeroRootGeneration,
    IdentityDrift,
}

/// Owned identity reservation for one F-service adapter dispatch.
///
/// It holds no user pointer, stationary authority borrow, usercopy pin, or
/// scheduler/wait guard. `begin` validates the short prepare phase before the
/// adapter work begins. The enclosing native runtime phase owns the only
/// post-dispatch live identity revalidation; this object must not pretend
/// that copied function arguments are a fresh carrier observation.
#[must_use = "an F-service dispatch must be committed or explicitly aborted"]
pub(crate) struct PreparedFServiceDispatch {
    request: NativeSyscallRequest,
    thread: ThreadKey,
    root_generation: u64,
}

impl PreparedFServiceDispatch {
    pub(crate) fn new(
        request: NativeSyscallRequest,
        thread: ThreadKey,
        root_generation: u64,
    ) -> Result<Self, FServiceDispatchPhaseError> {
        if root_generation == 0 {
            return Err(FServiceDispatchPhaseError::ZeroRootGeneration);
        }
        Ok(Self {
            request,
            thread,
            root_generation,
        })
    }

    fn begin(
        self,
        thread: ThreadKey,
        root_generation: u64,
    ) -> Result<NativeSyscallRequest, FServiceDispatchPhaseError> {
        if self.thread != thread || self.root_generation != root_generation {
            return Err(FServiceDispatchPhaseError::IdentityDrift);
        }
        Ok(self.request)
    }

    pub(crate) fn abort(self) {}
}

impl FServiceDispatch {
    pub(crate) fn into_route(self) -> FServiceRoute {
        self.route
    }
}

/// One resumed syscall result and every typed final release it produced.
#[must_use = "resumed F service cleanup must be routed through PayloadFinalizer"]
pub(crate) struct FServiceResume {
    status: DwStatus,
}

impl FServiceResume {
    pub(crate) const fn status(self) -> DwStatus {
        self.status
    }
}

/// Thread-context state shared by every F12 native-service runtime.
///
/// Large Channel staging remains caller-owned so this object does not place a
/// 64-KiB buffer on each kernel stack.  Channel/Event/Timer/wait authorities are
/// also caller-owned because the target runtime may need them in stationary
/// storage visible to the timer interrupt.
pub(crate) struct FServiceState<
    OUTPUT,
    AtomicPin,
    const OBJECTS: usize,
    const ATOMIC_WAITERS: usize,
    const EXECUTION: usize,
> {
    wait_operations: WaitOperationRegistry<OUTPUT, EXECUTION>,
    atomic_waits: AtomicWaitRegistry<ATOMIC_WAITERS>,
    atomic_operations: AtomicWaitOperationRegistry<AtomicPin, EXECUTION>,
    cleanup: CleanupQueue<OBJECTS>,
}

impl<OUTPUT, AtomicPin, const OBJECTS: usize, const ATOMIC_WAITERS: usize, const EXECUTION: usize>
    FServiceState<OUTPUT, AtomicPin, OBJECTS, ATOMIC_WAITERS, EXECUTION>
{
    pub(crate) fn new() -> Self {
        Self {
            wait_operations: WaitOperationRegistry::new(),
            atomic_waits: AtomicWaitRegistry::new(),
            atomic_operations: AtomicWaitOperationRegistry::new(),
            cleanup: CleanupQueue::new(),
        }
    }

    /// Captures only the exact current identity and decoded request before
    /// releasing the short stationary prepare phase.
    pub(crate) fn prepare_dispatch(
        &self,
        request: NativeSyscallRequest,
        thread: ThreadKey,
        root_generation: u64,
    ) -> Result<PreparedFServiceDispatch, FServiceDispatchPhaseError> {
        PreparedFServiceDispatch::new(request, thread, root_generation)
    }

    /// Routes one decoded request through the public DW0-F service families.
    ///
    /// E/basic operations and scenario-owned exit/inspection remain explicit
    /// fallthrough.  Each handled arm delegates to the existing adapter, which
    /// preserves the F0 validation/reservation/publication ordering.
    #[allow(
        clippy::too_many_arguments,
        reason = "F service composition keeps every independently-owned authority explicit"
    )]
    pub(crate) fn dispatch_prepared<
        U,
        CLOCK,
        const PAIRS: usize,
        const DEPTH: usize,
        const WAITERS: usize,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
        const EVENTS: usize,
        const TIMERS: usize,
        const REGION_OBJECTS: usize,
        const REGION_SLOTS: usize,
        const SPACES: usize,
        const REGIONS: usize,
    >(
        &mut self,
        control: &mut NativeWaitControl,
        prepared: PreparedFServiceDispatch,
        user: &mut U,
        registry: &mut ObjectRegistry<OBJECTS>,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        execution: &ExecutionDomain<EXECUTION>,
        channels: &ChannelAuthority<PAIRS, DEPTH>,
        events: &EventAuthority<EVENTS>,
        timers: &TimerAuthority<TIMERS>,
        interrupts: Option<&dyn InterruptWaitSource>,
        waits: &WaitRegistry<WAITERS>,
        regions: &mut AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
        spaces: &mut AddressSpaceAuthority<SPACES, REGIONS>,
        current_process: ProcessKey,
        current_thread: ThreadKey,
        current_cpu: crate::cpu::CpuIndex,
        current_root_generation: u64,
        wait_deadlines: Option<&mut dyn WaitDeadlineAuthority>,
        timer_deadlines: &mut dyn TimerDeadlineAuthority,
        channel_staging: &mut [u8],
        mut read_clock: CLOCK,
    ) -> FServiceDispatch
    where
        U: FAtomicUserAccess<AtomicPin = AtomicPin, OwnedOutput = OUTPUT>,
        CLOCK: FnMut() -> Result<u64, DwStatus>,
    {
        let request = prepared
            .begin(current_thread, current_root_generation)
            .unwrap_or_else(|_| panic!("F-service dispatch identity drifted before adapter work"));
        let route = match request {
            NativeSyscallRequest::ProcessCreate {
                args,
                args_size,
                out_result,
                result_size,
            } => FServiceRoute::Handled(NativeSyscallResult::returning(process_create(
                user,
                registry,
                tasks,
                regions,
                spaces,
                current_process,
                args,
                args_size,
                out_result,
                result_size,
                &mut self.cleanup,
            ))),
            NativeSyscallRequest::ChannelCreate {
                requested_rights,
                out_endpoint0,
                out_endpoint1,
            } => FServiceRoute::Handled(NativeSyscallResult::returning(channel_create(
                user,
                registry,
                channels,
                tasks,
                current_process,
                requested_rights,
                out_endpoint0,
                out_endpoint1,
            ))),
            NativeSyscallRequest::ChannelSend {
                channel,
                bytes,
                byte_len,
                transfers,
                transfer_count,
                flags,
            } => FServiceRoute::Handled(NativeSyscallResult::returning(channel_send_from_thread(
                user,
                channel_staging,
                registry,
                channels,
                waits,
                tasks,
                execution,
                current_process,
                Some(current_thread),
                channel,
                bytes,
                byte_len,
                transfers,
                transfer_count,
                flags,
                &mut self.cleanup,
            ))),
            NativeSyscallRequest::ChannelReceive {
                channel,
                out_bytes,
                byte_capacity,
                out_handles,
                handle_capacity,
                out_result,
            } => FServiceRoute::Handled(NativeSyscallResult::returning(channel_receive(
                user,
                channel_staging,
                registry,
                channels,
                waits,
                tasks,
                execution,
                current_process,
                channel,
                out_bytes,
                byte_capacity,
                out_handles,
                handle_capacity,
                out_result,
                &mut self.cleanup,
            ))),
            NativeSyscallRequest::WaitOne {
                handle,
                signals,
                deadline,
                out_result,
            } => FServiceRoute::Handled(control.accept(wait_one_syscall_on(
                user,
                registry,
                tasks,
                events,
                timers,
                channels,
                interrupts,
                waits,
                execution,
                &mut self.wait_operations,
                wait_deadlines,
                current_cpu,
                current_process,
                current_thread,
                handle,
                signals,
                deadline,
                out_result,
            ))),
            NativeSyscallRequest::WaitMany {
                items,
                item_count,
                mode,
                deadline,
                out_result,
            } => FServiceRoute::Handled(control.accept(wait_many_syscall_on(
                user,
                registry,
                tasks,
                events,
                timers,
                channels,
                interrupts,
                waits,
                execution,
                &mut self.wait_operations,
                wait_deadlines,
                current_cpu,
                current_process,
                current_thread,
                items,
                item_count,
                mode,
                deadline,
                out_result,
            ))),
            NativeSyscallRequest::EventCreate {
                requested_rights,
                out_event,
            } => FServiceRoute::Handled(NativeSyscallResult::returning(event_create(
                user,
                registry,
                events,
                tasks,
                current_process,
                requested_rights,
                out_event,
                &mut self.cleanup,
            ))),
            NativeSyscallRequest::EventSignal {
                event,
                clear_mask,
                set_mask,
            } => FServiceRoute::Handled(NativeSyscallResult::returning(event_signal(
                registry,
                events,
                waits,
                tasks,
                execution,
                current_process,
                event,
                clear_mask,
                set_mask,
                &mut self.cleanup,
            ))),
            NativeSyscallRequest::AtomicWait32 {
                address,
                expected,
                deadline,
            } => FServiceRoute::Handled(self.dispatch_atomic_wait(
                control,
                user,
                registry,
                tasks,
                execution,
                regions,
                current_process,
                current_thread,
                address,
                expected,
                deadline,
                current_cpu,
                wait_deadlines,
            )),
            NativeSyscallRequest::AtomicWake {
                address,
                count,
                out_woken,
            } => FServiceRoute::Handled(NativeSyscallResult::returning(self.dispatch_atomic_wake(
                user,
                tasks,
                execution,
                regions,
                current_process,
                address,
                count,
                out_woken,
            ))),
            NativeSyscallRequest::ClockGet {
                clock_id,
                out_nanoseconds,
            } => FServiceRoute::Handled(NativeSyscallResult::returning(clock_get_with(
                user,
                clock_id,
                out_nanoseconds,
                &mut read_clock,
            ))),
            NativeSyscallRequest::TimerCreate {
                requested_rights,
                out_timer,
            } => FServiceRoute::Handled(NativeSyscallResult::returning(timer_create(
                user,
                registry,
                timers,
                tasks,
                current_process,
                requested_rights,
                out_timer,
                &mut self.cleanup,
            ))),
            NativeSyscallRequest::TimerSet { timer, deadline } => {
                FServiceRoute::Handled(NativeSyscallResult::returning(timer_set(
                    registry,
                    timers,
                    timer_deadlines,
                    waits,
                    tasks,
                    execution,
                    current_process,
                    timer,
                    deadline,
                    &mut self.cleanup,
                )))
            }
            NativeSyscallRequest::TaskGroupLimit {
                task_group,
                class,
                limit,
            } => FServiceRoute::Handled(NativeSyscallResult::returning(task_group_limit(
                registry,
                tasks,
                current_process,
                task_group,
                class,
                limit,
                &mut self.cleanup,
            ))),
            NativeSyscallRequest::TimerCancel { timer } => {
                FServiceRoute::Handled(NativeSyscallResult::returning(timer_cancel(
                    registry,
                    timers,
                    timer_deadlines,
                    tasks,
                    current_process,
                    timer,
                    &mut self.cleanup,
                )))
            }
            request => FServiceRoute::Fallthrough(request),
        };
        FServiceDispatch { route }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "atomic wait keeps the mapping pin, stable-key resolver, scheduler, and deadline owners explicit"
    )]
    fn dispatch_atomic_wait<
        U,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
        const REGION_OBJECTS: usize,
        const REGION_SLOTS: usize,
    >(
        &mut self,
        control: &mut NativeWaitControl,
        user: &mut U,
        _registry: &mut ObjectRegistry<OBJECTS>,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        execution: &ExecutionDomain<EXECUTION>,
        regions: &AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
        process: ProcessKey,
        thread: ThreadKey,
        address: DwUserAddress,
        expected: u32,
        deadline: DwDeadline,
        cpu: crate::cpu::CpuIndex,
        wait_deadlines: Option<&mut dyn WaitDeadlineAuthority>,
    ) -> NativeSyscallResult
    where
        U: FAtomicUserAccess<AtomicPin = AtomicPin, OwnedOutput = OUTPUT>,
    {
        let pin = match user.pin_atomic_u32(address) {
            Ok(pin) => pin,
            Err(status) => return NativeSyscallResult::returning(status),
        };
        let key = match resolve_atomic_wait_key(tasks, regions, process, address) {
            Ok(key) => key,
            Err(status) => {
                user.release_atomic_u32(pin);
                return NativeSyscallResult::returning(status);
            }
        };
        let begin = begin_atomic_wait(
            pin,
            key,
            expected,
            wait_deadline(deadline),
            &self.atomic_waits,
            tasks,
            execution,
            &mut self.atomic_operations,
            wait_deadlines,
            cpu,
            process,
            thread,
            |pin| user.load_atomic_u32_acquire(pin),
        );
        match begin {
            Ok(AtomicWaitBegin::Mismatch(pin)) => {
                user.release_atomic_u32(pin);
                NativeSyscallResult::returning(DW_STATUS_WOULD_BLOCK)
            }
            Ok(AtomicWaitBegin::TimedOut(pin)) => {
                user.release_atomic_u32(pin);
                NativeSyscallResult::returning(DW_STATUS_TIMED_OUT)
            }
            Ok(AtomicWaitBegin::Ready(pin)) => {
                user.release_atomic_u32(pin);
                NativeSyscallResult::returning(DW_STATUS_SUCCESS)
            }
            Ok(AtomicWaitBegin::Suspended { wake, decision }) => {
                control.accept(super::adapters::WaitSyscallAction::Suspended(
                    super::adapters::WaitSuspendState::new(wake, decision),
                ))
            }
            Err(failure) => {
                let status = atomic_wait_status(failure.error);
                user.release_atomic_u32(failure.pin);
                NativeSyscallResult::returning(status)
            }
        }
    }

    /// The first hold of a live `AtomicWait32` (D1 commit 8b, design §11.2.3
    /// family E). `pinned` is the word's pin and the value loaded through it
    /// with no runtime lock before this hold, or the pin's failure. In the
    /// adapter's order: the pin, the stable key, the early compare, the
    /// `NOW` deadline, then the registration, whose second compare the
    /// caller makes through the pin after this hold.
    #[allow(
        clippy::too_many_arguments,
        reason = "atomic wait keeps the mapping pin, stable-key resolver, scheduler, and deadline owners explicit"
    )]
    #[cfg_attr(
        not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
        allow(dead_code, reason = "only the live runtime splits AtomicWait32")
    )]
    pub(crate) fn register_atomic_wait_pinned<
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
        const REGION_OBJECTS: usize,
        const REGION_SLOTS: usize,
    >(
        &self,
        pinned: Result<(AtomicPin, u32), DwStatus>,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        execution: &ExecutionDomain<EXECUTION>,
        regions: &AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
        process: ProcessKey,
        thread: ThreadKey,
        address: DwUserAddress,
        expected: u32,
        deadline: DwDeadline,
        cpu: crate::cpu::CpuIndex,
        wait_deadlines: Option<&mut dyn WaitDeadlineAuthority>,
    ) -> AtomicWaitHold<AtomicPin> {
        let (pin, observed) = pinned.map_err(|status| (status, None))?;
        let key = match resolve_atomic_wait_key(tasks, regions, process, address) {
            Ok(key) => key,
            Err(status) => return Err((status, Some(pin))),
        };
        let status = match register_atomic_wait(
            key,
            observed,
            expected,
            wait_deadline(deadline),
            &self.atomic_waits,
            tasks,
            execution,
            wait_deadlines,
            cpu,
            process,
            thread,
        ) {
            Ok(pending) => return Ok((pending, pin)),
            Err(AtomicWaitUnregistered::Mismatch) => DW_STATUS_WOULD_BLOCK,
            Err(AtomicWaitUnregistered::TimedOut) => DW_STATUS_TIMED_OUT,
            Err(AtomicWaitUnregistered::Failed(error)) => atomic_wait_status(error),
        };
        Err((status, Some(pin)))
    }

    /// The second hold of a live `AtomicWait32` (D1 commit 8b), on the second
    /// compare the caller made through the pin with no runtime lock held.
    /// Returns the syscall result and, unless the pin moved into a suspended
    /// operation, the pin for the caller to release after the hold.
    #[allow(
        clippy::too_many_arguments,
        reason = "atomic wait keeps the mapping pin, scheduler, operation, and deadline owners explicit"
    )]
    #[cfg_attr(
        not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
        allow(dead_code, reason = "only the live runtime splits AtomicWait32")
    )]
    pub(crate) fn settle_atomic_wait_pinned<
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &mut self,
        control: &mut NativeWaitControl,
        pending: PendingAtomicWait,
        pin: AtomicPin,
        matched: bool,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        execution: &ExecutionDomain<EXECUTION>,
        cpu: crate::cpu::CpuIndex,
        process: ProcessKey,
        thread: ThreadKey,
        wait_deadlines: Option<&mut dyn WaitDeadlineAuthority>,
    ) -> (NativeSyscallResult, Option<AtomicPin>) {
        match settle_atomic_wait(
            pending,
            pin,
            matched,
            &self.atomic_waits,
            tasks,
            execution,
            &mut self.atomic_operations,
            wait_deadlines,
            cpu,
            process,
            thread,
        ) {
            Ok(AtomicWaitBegin::Mismatch(pin)) => (
                NativeSyscallResult::returning(DW_STATUS_WOULD_BLOCK),
                Some(pin),
            ),
            Ok(AtomicWaitBegin::TimedOut(pin)) => (
                NativeSyscallResult::returning(DW_STATUS_TIMED_OUT),
                Some(pin),
            ),
            Ok(AtomicWaitBegin::Ready(pin)) => {
                (NativeSyscallResult::returning(DW_STATUS_SUCCESS), Some(pin))
            }
            Ok(AtomicWaitBegin::Suspended { wake, decision }) => (
                control.accept(super::adapters::WaitSyscallAction::Suspended(
                    super::adapters::WaitSuspendState::new(wake, decision),
                )),
                None,
            ),
            Err(failure) => (
                NativeSyscallResult::returning(atomic_wait_status(failure.error)),
                Some(failure.pin),
            ),
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "atomic wake preserves the pin/key/output/wake transaction boundary explicitly"
    )]
    fn dispatch_atomic_wake<
        U,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
        const REGION_OBJECTS: usize,
        const REGION_SLOTS: usize,
    >(
        &self,
        user: &mut U,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        execution: &ExecutionDomain<EXECUTION>,
        regions: &AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
        process: ProcessKey,
        address: DwUserAddress,
        count: u32,
        out_woken: DwUserAddress,
    ) -> DwStatus
    where
        U: FAtomicUserAccess<AtomicPin = AtomicPin, OwnedOutput = OUTPUT>,
    {
        atomic_wake_with(
            user,
            address,
            count,
            out_woken,
            |user, address| user.pin_atomic_u32(address),
            |address, _pin| resolve_atomic_wake_key(tasks, regions, process, address),
            |user, pin| user.release_atomic_u32(pin),
            |key, count| {
                wake_atomic_waiters(&self.atomic_waits, execution, key, count)
                    .map_err(atomic_wait_status)
            },
        )
    }

    /// `AtomicWake` with its address pinned, and its output preflighted,
    /// before the runtime authority (D1 commit 6b, design §11.2.3 family B).
    /// `pinned` is the early atomic pin's result. The same `atomic_wake_with`
    /// sequence runs against a deferred output, so every status and its
    /// precedence is unchanged. The pin comes back to the caller, which
    /// releases it after the authority, where the deferred output is also
    /// committed.
    #[allow(
        clippy::too_many_arguments,
        reason = "the pinned atomic wake keeps the early pin, key resolver, scheduler, and output owners explicit"
    )]
    #[cfg_attr(
        not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
        allow(dead_code, reason = "only the live runtime pins atomic wakes early")
    )]
    pub(crate) fn dispatch_atomic_wake_pinned<
        U: crate::memory::usercopy::OwnedUserOutputAccess,
        PIN,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
        const REGION_OBJECTS: usize,
        const REGION_SLOTS: usize,
    >(
        &self,
        user: &mut U,
        pinned: Result<PIN, DwStatus>,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        execution: &ExecutionDomain<EXECUTION>,
        regions: &AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
        process: ProcessKey,
        address: DwUserAddress,
        count: u32,
        out_woken: DwUserAddress,
    ) -> (DwStatus, Option<PIN>) {
        let mut released = None;
        let status = atomic_wake_with(
            user,
            address,
            count,
            out_woken,
            |_, _| pinned,
            |address, _pin| resolve_atomic_wake_key(tasks, regions, process, address),
            |_, pin| released = Some(pin),
            |key, count| {
                wake_atomic_waiters(&self.atomic_waits, execution, key, count)
                    .map_err(atomic_wait_status)
            },
        );
        (status, released)
    }

    #[allow(
        unsafe_code,
        reason = "the caller must prove the pending scheduler carrier and fixed first-run entry through the F-service facade"
    )]
    /// # Safety
    ///
    /// The pending decision must name the physically active kernel-stack
    /// carrier, and `trusted_first_run_entry` must be the architecture-owned
    /// fixed first-run entry.
    pub(crate) unsafe fn prepare_suspend<
        'owner,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &self,
        control: &mut NativeWaitControl,
        tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        execution: &'owner ExecutionDomain<EXECUTION>,
        trusted_first_run_entry: u64,
    ) -> Result<NativeSuspendPlan<'owner>, WaitSuspendError> {
        unsafe { control.prepare_suspend(tasks, execution, trusted_first_run_entry) }
    }

    #[allow(
        unsafe_code,
        reason = "the caller must prove the CPU-owned pending carrier and fixed first-run entry through the F-service facade"
    )]
    pub(crate) unsafe fn prepare_suspend_on<
        'owner,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &self,
        control: &mut NativeWaitControl,
        cpu: crate::cpu::CpuIndex,
        tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        execution: &'owner ExecutionDomain<EXECUTION>,
        trusted_first_run_entry: u64,
    ) -> Result<NativeSuspendPlan<'owner>, WaitSuspendError> {
        unsafe { control.prepare_suspend_on(cpu, tasks, execution, trusted_first_run_entry) }
    }

    #[allow(
        unsafe_code,
        reason = "the caller must prove the physically active idle carrier and fixed first-run entry through the F-service facade"
    )]
    /// # Safety
    ///
    /// The idle state must retain the physically active suspended continuation,
    /// and `trusted_first_run_entry` must be the architecture-owned fixed
    /// first-run entry.
    pub(crate) unsafe fn poll_idle_suspend<
        'owner,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &self,
        control: &mut NativeWaitControl,
        tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        execution: &'owner ExecutionDomain<EXECUTION>,
        trusted_first_run_entry: u64,
    ) -> Result<NativeIdleSuspendPoll<'owner>, WaitSuspendError> {
        unsafe { control.poll_idle(tasks, execution, trusted_first_run_entry) }
    }

    #[allow(
        unsafe_code,
        reason = "the caller must prove the CPU-owned idle carrier and fixed first-run entry through the F-service facade"
    )]
    pub(crate) unsafe fn poll_idle_suspend_on<
        'owner,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &self,
        control: &mut NativeWaitControl,
        cpu: crate::cpu::CpuIndex,
        tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        execution: &'owner ExecutionDomain<EXECUTION>,
        trusted_first_run_entry: u64,
    ) -> Result<NativeIdleSuspendPoll<'owner>, WaitSuspendError> {
        unsafe { control.poll_idle_on(cpu, tasks, execution, trusted_first_run_entry) }
    }

    pub(crate) fn operation_owner(
        &self,
        thread: ThreadKey,
    ) -> Result<FServiceOperationOwner, FServiceOwnerError> {
        match (
            self.wait_operations.contains_thread(thread),
            self.atomic_operations.wake_key_for_thread(thread).is_some(),
        ) {
            (true, false) => Ok(FServiceOperationOwner::GenericWait),
            (false, true) => Ok(FServiceOperationOwner::AtomicWait),
            (false, false) => Err(FServiceOwnerError::Missing),
            (true, true) => Err(FServiceOwnerError::Ambiguous),
        }
    }

    /// Reports whether every durable F suspension owner is empty. The physical
    /// carrier owns and checks its ephemeral native-control handoff separately.
    pub(crate) fn is_quiescent(&self) -> bool {
        self.quiescence_residue() == 0
    }

    /// Returns a stable diagnostic bitset for live completion failures without
    /// exposing or weakening any of the underlying operation owners.
    pub(crate) fn quiescence_residue(&self) -> u32 {
        u32::from(!self.wait_operations.is_empty())
            | (u32::from(!self.atomic_waits.is_empty()) << 1)
            | (u32::from(!self.atomic_operations.is_empty()) << 2)
    }

    /// Clears the ephemeral idle handoff only when it names the exact blocked
    /// generation being retired by the e1 safe point.
    pub(crate) fn retire_idle_control_for_stop(
        &self,
        control: &mut NativeWaitControl,
        thread: ThreadKey,
        execution_generation: u64,
    ) -> Result<(), WaitSuspendError> {
        control.retire_idle_for_stop(thread, execution_generation)
    }

    /// The guarded half of `WaitOne` and `WaitMany` (D1 commit 8, design
    /// §11.2.3 family E): the wait begins over input copied, and an output
    /// pinned, before the runtime authority. A returning wait hands its
    /// output back, with the result to commit into it, for the caller to
    /// settle after the authority. A suspended wait keeps it in its operation.
    #[allow(
        clippy::too_many_arguments,
        reason = "the wait begin keeps every source authority and owner explicit"
    )]
    #[cfg_attr(
        not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
        allow(dead_code, reason = "only the live runtime begins prepared waits")
    )]
    pub(crate) fn begin_prepared_wait<
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
        const EVENTS: usize,
        const TIMERS: usize,
        const PAIRS: usize,
        const DEPTH: usize,
        const WAITERS: usize,
    >(
        &mut self,
        control: &mut NativeWaitControl,
        prepared: PreparedWait<OUTPUT>,
        registry: &mut ObjectRegistry<OBJECTS>,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        events: &EventAuthority<EVENTS>,
        timers: &TimerAuthority<TIMERS>,
        channels: &ChannelAuthority<PAIRS, DEPTH>,
        interrupts: Option<&dyn InterruptWaitSource>,
        waits: &WaitRegistry<WAITERS>,
        execution: &ExecutionDomain<EXECUTION>,
        wait_deadlines: Option<&mut dyn WaitDeadlineAuthority>,
        current_cpu: crate::cpu::CpuIndex,
        process: ProcessKey,
        thread: ThreadKey,
    ) -> (NativeSyscallResult, Option<(OUTPUT, WaitResultBytes)>) {
        let (action, settlement) = settle_wait_begin(wait_prepared_begin(
            prepared,
            registry,
            tasks,
            events,
            timers,
            channels,
            interrupts,
            waits,
            execution,
            &mut self.wait_operations,
            wait_deadlines,
            current_cpu,
            process,
            thread,
        ));
        (control.accept(action), settlement)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "resume consumes the exact user-resource, wait, scheduler, deadline, and final-release owners"
    )]
    pub(crate) fn resume_suspended<
        U,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
        const WAITERS: usize,
    >(
        &mut self,
        user: &mut U,
        registry: &mut ObjectRegistry<OBJECTS>,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        waits: &WaitRegistry<WAITERS>,
        execution: &ExecutionDomain<EXECUTION>,
        thread: ThreadKey,
        wait_deadlines: Option<&mut dyn WaitDeadlineAuthority>,
    ) -> Result<FServiceResume, FServiceResumeError>
    where
        U: FAtomicUserAccess<AtomicPin = AtomicPin, OwnedOutput = OUTPUT>,
    {
        let status = match self
            .operation_owner(thread)
            .map_err(FServiceResumeError::Owner)?
        {
            FServiceOperationOwner::GenericWait => resume_wait_thread_syscall(
                user,
                registry,
                tasks,
                waits,
                execution,
                &mut self.wait_operations,
                wait_deadlines,
                thread,
                &mut self.cleanup,
            )
            .map_err(FServiceResumeError::GenericWait)?,
            FServiceOperationOwner::AtomicWait => {
                let wake = self
                    .atomic_operations
                    .wake_key_for_thread(thread)
                    .ok_or(FServiceResumeError::Owner(FServiceOwnerError::Missing))?;
                let (pin, winner) = finish_atomic_wait(
                    &self.atomic_waits,
                    tasks,
                    execution,
                    &mut self.atomic_operations,
                    wait_deadlines,
                    wake,
                )
                .map_err(FServiceResumeError::AtomicWait)?;
                user.release_atomic_u32(pin);
                match winner {
                    BlockedOperationWinner::AtomicWake => DW_STATUS_SUCCESS,
                    BlockedOperationWinner::Timeout => DW_STATUS_TIMED_OUT,
                    other => return Err(FServiceResumeError::UnexpectedAtomicWinner(other)),
                }
            }
        };
        Ok(FServiceResume { status })
    }

    /// Borrows the two durable operation registries as one terminal-teardown
    /// implementation.  The caller supplies resource consumers that route an
    /// owned output/pin back to its originating Process address space.
    pub(crate) fn terminal_cleanup<'a, DISCARD, RELEASE>(
        &'a mut self,
        wait_deadlines: Option<&'a mut dyn WaitDeadlineAuthority>,
        discard_output: DISCARD,
        release_atomic_pin: RELEASE,
    ) -> FServiceTerminalCleanup<'a, OUTPUT, AtomicPin, DISCARD, RELEASE, ATOMIC_WAITERS, EXECUTION>
    where
        DISCARD: FnMut(OUTPUT),
        RELEASE: FnMut(AtomicPin),
    {
        FServiceTerminalCleanup {
            wait_operations: &mut self.wait_operations,
            atomic_waits: &self.atomic_waits,
            atomic_operations: &mut self.atomic_operations,
            wait_deadlines,
            discard_output,
            release_atomic_pin,
        }
    }

    /// Whether this carrier has any finalizer still awaiting routing.
    ///
    /// The queue is no longer handed out by value, so observing it needs an
    /// accessor rather than a move.
    pub(crate) const fn cleanup_is_empty(&self) -> bool {
        self.cleanup.is_empty()
    }

    /// Moves this carrier's queued finalizers into `other`.
    ///
    /// Reset card R5D replaced a `take_cleanup` that returned the queue by
    /// value: at the E8 registry geometry that was a 5,128-byte copy out and
    /// another into whichever queue absorbed it, at ten call sites.
    pub(crate) fn drain_cleanup_into<const OTHER: usize>(
        &mut self,
        other: &mut CleanupQueue<OTHER>,
    ) {
        self.cleanup.drain_into(other);
    }
}

pub(crate) struct FServiceTerminalCleanup<
    'a,
    OUTPUT,
    AtomicPin,
    DISCARD,
    RELEASE,
    const ATOMIC_WAITERS: usize,
    const EXECUTION: usize,
> {
    wait_operations: &'a mut WaitOperationRegistry<OUTPUT, EXECUTION>,
    atomic_waits: &'a AtomicWaitRegistry<ATOMIC_WAITERS>,
    atomic_operations: &'a mut AtomicWaitOperationRegistry<AtomicPin, EXECUTION>,
    wait_deadlines: Option<&'a mut dyn WaitDeadlineAuthority>,
    discard_output: DISCARD,
    release_atomic_pin: RELEASE,
}

impl<
    OUTPUT,
    AtomicPin,
    DISCARD: FnMut(OUTPUT),
    RELEASE: FnMut(AtomicPin),
    const OBJECTS: usize,
    const WAITERS: usize,
    const ATOMIC_WAITERS: usize,
    const EXECUTION: usize,
> TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>
    for FServiceTerminalCleanup<'_, OUTPUT, AtomicPin, DISCARD, RELEASE, ATOMIC_WAITERS, EXECUTION>
{
    fn cleanup_terminal_wait<
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &mut self,
        registry: &mut ObjectRegistry<OBJECTS>,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        waits: &WaitRegistry<WAITERS>,
        execution: &ExecutionDomain<EXECUTION>,
        thread: ThreadKey,
        cleanup: &mut CleanupQueue<OBJECTS>,
    ) {
        let generic = self.wait_operations.contains_thread(thread);
        let atomic = self.atomic_operations.wake_key_for_thread(thread).is_some();
        assert!(
            !(generic && atomic),
            "Thread owns two suspended F operations"
        );

        let wait_deadlines = self
            .wait_deadlines
            .as_mut()
            .map(|authority| &mut **authority as &mut dyn WaitDeadlineAuthority);
        if generic {
            let result = finish_terminal_wait(
                registry,
                tasks,
                waits,
                execution,
                self.wait_operations,
                wait_deadlines,
                thread,
            )
            .unwrap_or_else(|error| panic!("terminal generic wait cleanup drifted: {error:?}"));
            let (output, releases) =
                result.expect("classified terminal generic wait retains its operation");
            for release in releases.into_releases().into_iter().flatten() {
                cleanup.push(release);
            }
            (self.discard_output)(output);
        } else if atomic {
            let pin = finish_terminal_atomic_wait(
                self.atomic_waits,
                tasks,
                execution,
                self.atomic_operations,
                wait_deadlines,
                thread,
            )
            .unwrap_or_else(|error| panic!("terminal atomic wait cleanup drifted: {error:?}"))
            .expect("classified terminal atomic wait retains its operation");
            (self.release_atomic_pin)(pin);
        } else {
            assert!(
                !execution.blocked_operations().has_thread(thread),
                "blocked terminal Thread has no F operation owner"
            );
        }
    }
}

fn wait_deadline(deadline: DwDeadline) -> WaitDeadline {
    if deadline == DW_DEADLINE_NOW {
        WaitDeadline::Now
    } else if deadline == DW_DEADLINE_INFINITE {
        WaitDeadline::Infinite
    } else {
        WaitDeadline::Finite(deadline.0)
    }
}

fn atomic_wait_status(error: AtomicWaitBeginError) -> DwStatus {
    use crate::atomic_wait::AtomicWaitError;
    use crate::wait::engine::WaitDeadlineError;

    match error {
        AtomicWaitBeginError::Registry(AtomicWaitError::Capacity)
        | AtomicWaitBeginError::Deadline(WaitDeadlineError::Capacity) => DW_STATUS_NO_RESOURCES,
        AtomicWaitBeginError::Deadline(WaitDeadlineError::Expired) => DW_STATUS_TIMED_OUT,
        AtomicWaitBeginError::Registry(_)
        | AtomicWaitBeginError::Scheduler(_)
        | AtomicWaitBeginError::Blocked(_)
        | AtomicWaitBeginError::Deadline(WaitDeadlineError::Fault) => DW_STATUS_BAD_STATE,
    }
}

#[cfg(test)]
#[path = "f_services/tests.rs"]
mod tests;

/// Resolves the stable key an `AtomicWait32` address names, under a Process
/// operation lease held only for the lookup.
fn resolve_atomic_wait_key<
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const REGION_OBJECTS: usize,
    const REGION_SLOTS: usize,
>(
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    regions: &AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
    process: ProcessKey,
    address: DwUserAddress,
) -> Result<crate::atomic_wait::AtomicWaitKey, DwStatus> {
    // As in `adapters.rs`: the blind arm this replaces reported a stale
    // handle as "not accepting operations".
    let lease = tasks
        .acquire_process_operation(process)
        .map_err(task_status)?;
    match regions.resolve_atomic_wait_key_for_operation(tasks, &lease, process, address.0) {
        Ok(key) => {
            tasks
                .release_process_operation(lease)
                .unwrap_or_else(|(error, _)| {
                    panic!("F9 key resolution leaked process lease: {error:?}")
                });
            Ok(key)
        }
        Err(_) => {
            tasks
                .release_process_operation(lease)
                .unwrap_or_else(|(error, _)| {
                    panic!("F9 key-resolution cleanup lost process lease: {error:?}")
                });
            Err(DW_STATUS_BAD_ADDRESS)
        }
    }
}

/// Resolves the stable key an `AtomicWake` address names, under a Process
/// operation lease held only for the lookup.
fn resolve_atomic_wake_key<
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const REGION_OBJECTS: usize,
    const REGION_SLOTS: usize,
>(
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    regions: &AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
    process: ProcessKey,
    address: DwUserAddress,
) -> Result<crate::atomic_wait::AtomicWaitKey, DwStatus> {
    let lease = tasks
        .acquire_process_operation(process)
        .map_err(|_| DW_STATUS_BAD_STATE)?;
    let key = regions
        .resolve_atomic_wait_key_for_operation(tasks, &lease, process, address.0)
        .map_err(|_| DW_STATUS_BAD_ADDRESS);
    tasks
        .release_process_operation(lease)
        .unwrap_or_else(|(error, _)| {
            panic!("F9 wake key resolution leaked process lease: {error:?}")
        });
    key
}
