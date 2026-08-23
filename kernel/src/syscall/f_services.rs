//! Shared DW0-F native service composition.
//!
//! This module wires the already-validated F adapters into one selector-neutral
//! dispatch surface.  The owning target runtime still supplies the current
//! Process/Thread, address-space access, stationary IRQ-visible authorities,
//! and typed finalizer routing.

use core::mem;

use deepwyrm_abi::{
    DW_DEADLINE_INFINITE, DW_DEADLINE_NOW, DW_STATUS_BAD_ADDRESS, DW_STATUS_BAD_STATE,
    DW_STATUS_NO_RESOURCES, DW_STATUS_SUCCESS, DW_STATUS_TIMED_OUT, DW_STATUS_WOULD_BLOCK,
    DwDeadline, DwStatus, DwUserAddress,
};

use crate::atomic_wait::{
    AtomicWaitBegin, AtomicWaitBeginError, AtomicWaitOperationRegistry, AtomicWaitRegistry,
    begin_atomic_wait, finish_atomic_wait, finish_terminal_atomic_wait, wake_atomic_waiters,
};
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
    channel_create, channel_receive, channel_send, clock_get_with, event_create, event_signal,
    process_create, resume_wait_thread_syscall, timer_cancel, timer_create, timer_set,
    wait_many_syscall, wait_one_syscall,
};
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
pub(crate) struct FServiceDispatch<const OBJECTS: usize> {
    route: FServiceRoute,
    cleanup: CleanupQueue<OBJECTS>,
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

impl<const OBJECTS: usize> FServiceDispatch<OBJECTS> {
    pub(crate) fn into_parts(self) -> (FServiceRoute, CleanupQueue<OBJECTS>) {
        (self.route, self.cleanup)
    }
}

/// One resumed syscall result and every typed final release it produced.
#[must_use = "resumed F service cleanup must be routed through PayloadFinalizer"]
pub(crate) struct FServiceResume<const OBJECTS: usize> {
    status: DwStatus,
    cleanup: CleanupQueue<OBJECTS>,
}

impl<const OBJECTS: usize> FServiceResume<OBJECTS> {
    pub(crate) fn into_parts(self) -> (DwStatus, CleanupQueue<OBJECTS>) {
        (self.status, self.cleanup)
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
    control: NativeWaitControl,
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
            control: NativeWaitControl::new(),
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
        prepared: PreparedFServiceDispatch,
        user: &mut U,
        registry: &mut ObjectRegistry<OBJECTS>,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        execution: &ExecutionDomain<EXECUTION>,
        channels: &ChannelAuthority<PAIRS, DEPTH>,
        events: &EventAuthority<EVENTS>,
        timers: &TimerAuthority<TIMERS>,
        waits: &WaitRegistry<WAITERS>,
        regions: &mut AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
        spaces: &mut AddressSpaceAuthority<SPACES, REGIONS>,
        current_process: ProcessKey,
        current_thread: ThreadKey,
        current_root_generation: u64,
        wait_deadlines: Option<&mut dyn WaitDeadlineAuthority>,
        timer_deadlines: &mut dyn TimerDeadlineAuthority,
        channel_staging: &mut [u8],
        mut read_clock: CLOCK,
    ) -> FServiceDispatch<OBJECTS>
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
            } => FServiceRoute::Handled(NativeSyscallResult::returning(channel_send(
                user,
                channel_staging,
                registry,
                channels,
                waits,
                tasks,
                execution,
                current_process,
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
            } => FServiceRoute::Handled(self.control.accept(wait_one_syscall(
                user,
                registry,
                tasks,
                events,
                timers,
                channels,
                waits,
                execution,
                &mut self.wait_operations,
                wait_deadlines,
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
            } => FServiceRoute::Handled(self.control.accept(wait_many_syscall(
                user,
                registry,
                tasks,
                events,
                timers,
                channels,
                waits,
                execution,
                &mut self.wait_operations,
                wait_deadlines,
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
        FServiceDispatch {
            route,
            cleanup: self.take_cleanup(),
        }
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
        wait_deadlines: Option<&mut dyn WaitDeadlineAuthority>,
    ) -> NativeSyscallResult
    where
        U: FAtomicUserAccess<AtomicPin = AtomicPin, OwnedOutput = OUTPUT>,
    {
        let pin = match user.pin_atomic_u32(address) {
            Ok(pin) => pin,
            Err(status) => return NativeSyscallResult::returning(status),
        };
        let lease = match tasks.acquire_process_operation(process) {
            Ok(lease) => lease,
            Err(_) => {
                user.release_atomic_u32(pin);
                return NativeSyscallResult::returning(DW_STATUS_BAD_STATE);
            }
        };
        let key = match regions
            .resolve_atomic_wait_key_for_operation(tasks, &lease, process, address.0)
        {
            Ok(key) => key,
            Err(_) => {
                tasks
                    .release_process_operation(lease)
                    .unwrap_or_else(|(error, _)| {
                        panic!("F9 key-resolution cleanup lost process lease: {error:?}")
                    });
                user.release_atomic_u32(pin);
                return NativeSyscallResult::returning(DW_STATUS_BAD_ADDRESS);
            }
        };
        tasks
            .release_process_operation(lease)
            .unwrap_or_else(|(error, _)| {
                panic!("F9 key resolution leaked process lease: {error:?}")
            });
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
                self.control
                    .accept(super::adapters::WaitSyscallAction::Suspended(
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
            |address, _pin| {
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
            },
            |user, pin| user.release_atomic_u32(pin),
            |key, count| {
                wake_atomic_waiters(&self.atomic_waits, execution, key, count)
                    .map_err(atomic_wait_status)
            },
        )
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
        &mut self,
        tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        execution: &'owner ExecutionDomain<EXECUTION>,
        trusted_first_run_entry: u64,
    ) -> Result<NativeSuspendPlan<'owner>, WaitSuspendError> {
        unsafe {
            self.control
                .prepare_suspend(tasks, execution, trusted_first_run_entry)
        }
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
        &mut self,
        tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        execution: &'owner ExecutionDomain<EXECUTION>,
        trusted_first_run_entry: u64,
    ) -> Result<NativeIdleSuspendPoll<'owner>, WaitSuspendError> {
        unsafe {
            self.control
                .poll_idle(tasks, execution, trusted_first_run_entry)
        }
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

    /// Reports whether every durable F suspension owner and the ephemeral
    /// native-control handoff are empty.
    pub(crate) fn is_quiescent(&self) -> bool {
        self.wait_operations.is_empty()
            && self.atomic_waits.is_empty()
            && self.atomic_operations.is_empty()
            && self.control.is_clear()
    }

    /// Clears the ephemeral idle handoff only when it names the exact blocked
    /// generation being retired by the e1 safe point.
    pub(crate) fn retire_idle_control_for_stop(
        &mut self,
        thread: ThreadKey,
        execution_generation: u64,
    ) -> Result<(), WaitSuspendError> {
        self.control
            .retire_idle_for_stop(thread, execution_generation)
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
    ) -> Result<FServiceResume<OBJECTS>, FServiceResumeError>
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
        Ok(FServiceResume {
            status,
            cleanup: self.take_cleanup(),
        })
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

    #[must_use = "deferred releases must be routed through PayloadFinalizer"]
    pub(crate) fn take_cleanup(&mut self) -> CleanupQueue<OBJECTS> {
        mem::replace(&mut self.cleanup, CleanupQueue::new())
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
