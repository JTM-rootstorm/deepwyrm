//! DW0-E5 native syscall adapters over existing C/D/E business authorities.
//!
//! This module owns scalar decoding, userspace pointer staging, copyout
//! transaction ordering, and current-Process selection. It deliberately does
//! not own x86 entry assembly, page-table policy, or typed payload finalizers.

#![allow(
    clippy::too_many_arguments,
    reason = "native syscall adapters keep independently-owned user-memory, registry, task, execution, and payload authorities explicit rather than hiding them in an unreviewable bag"
)]

use deepwyrm_abi::{
    DW_ABI_INFO_V1_SIZE, DW_BASE_PAGE_SIZE, DW_CHANNEL_MAX_HANDLES, DW_CHANNEL_MAX_PAYLOAD,
    DW_CHANNEL_RECEIVE_RESULT_V1_SIZE, DW_CLOCK_MONOTONIC_ACTIVE, DW_HANDLE_TRANSFER_MOVE,
    DW_HANDLE_TRANSFER_V1_SIZE, DW_MEMORY_OBJECT_INFO_V1_SIZE, DW_OBJECT_INFO_BASIC_V1,
    DW_OBJECT_INFO_MEMORY_OBJECT_V1, DW_OBJECT_INFO_TASK_STATE_V1, DW_OBJECT_INFO_V1_SIZE,
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_PROCESS,
    DW_OBJECT_TYPE_TASK_GROUP, DW_PROCESS_CREATE_ARGS_V1_SIZE, DW_PROCESS_CREATE_RESULT_V1_SIZE,
    DW_RECEIVED_HANDLE_INFO_V1_SIZE, DW_RIGHT_EXECUTE, DW_RIGHT_MODIFY, DW_RIGHT_READ,
    DW_RIGHT_SIGNAL, DW_RIGHT_TRANSFER, DW_RIGHT_WRITE, DW_STATUS_ACCESS_DENIED,
    DW_STATUS_BAD_ADDRESS, DW_STATUS_BAD_HANDLE, DW_STATUS_BAD_STATE, DW_STATUS_BUFFER_TOO_SMALL,
    DW_STATUS_INVALID_ARGUMENT, DW_STATUS_NO_RESOURCES, DW_STATUS_NOT_SUPPORTED,
    DW_STATUS_PEER_CLOSED, DW_STATUS_SUCCESS, DW_STATUS_TIMED_OUT, DW_STATUS_WOULD_BLOCK,
    DW_STATUS_WRONG_OBJECT_TYPE, DW_TASK_STATE_EXITED, DW_TERMINATION_AUTHORIZED,
    DW_WAIT_MANY_MAX_ITEMS, DW_WAIT_MODE_ALL, DW_WAIT_MODE_ANY, DW_WAIT_RESULT_V1_SIZE,
    DwChannelReceiveResultV1, DwClockId, DwDeadline, DwHandle, DwHandleTransferV1,
    DwProcessCreateArgsV1, DwProcessCreateResultV1, DwReceivedHandleInfoV1, DwRights, DwSignals,
    DwStatus, DwTerminationReason, DwUserAddress, DwWaitItemV1, DwWaitResultV1,
};

use crate::handle::{
    AcceptedObjectTypes, HANDLE_TRANSFER_LIMIT, HandleMovePrepareError, HandleMoveRequest,
    HandlePairReservation, HandleReservationSpec, HandleTableError, HandleTransferReservation,
    PreparedHandleMove, ResolvedHandle, TypedHandlePairReservation,
};
use crate::ipc::{ChannelAuthority, ChannelCreateError, ChannelEndpointKey, ChannelError};
use crate::memory::address_region::{
    AddressRegionObjectAuthority, AddressSpaceAuthority, PreparedRootRegion,
};
use crate::memory::object::MemoryObjectAuthority;
use crate::memory::user_range::{EmptyAddressRule, UserAccess, UserAddressSpace, UserRange};
use crate::memory::usercopy::{
    OwnedUserOutputAccess, PinnedUserOutput, PinnedUserOutputs, UserCopyError, UserPageAccess,
    UserPageBatchAccess, copy_from_user, copy_to_user, preflight_user_output,
    preflight_user_outputs, snapshot_from_user,
};
use crate::object::{FinalRelease, HandleRef, InternalRef, ObjectRegistry, ObjectRegistryError};
use crate::task::{
    BlockWakeKey, DeferredCurrentExecutionResources, ExecutionDomain, ExecutionResourceError,
    ExecutionSwitchError, IdleScheduleDecision, PreparedProcess, ProcessExitEffects, ProcessKey,
    RetiredExitPins, ScheduleDecision, SchedulerError, SchedulerThreadState, StartThreadError,
    TaskAuthority, TaskCreateError, TaskError, TaskExceptionRecord, TaskGroupKey,
    TaskGroupTerminationEffects, ThreadKey, ThreadStartState,
};
use crate::time::{TimerAuthority, TimerCreateError, TimerDeadlineAuthority, TimerError, TimerKey};
use crate::wait::{
    EventAuthority, EventCreateError, EventKey, WaitError, WaitRegistry, WakeBatch,
    engine::{
        ResolvedWaitSet, WaitBeginContext, WaitBeginError, WaitBeginOutcome, WaitDeadline,
        WaitDeadlineAuthority, WaitFinishError, WaitSetError, WaitSources, begin_registered_wait,
        finish_wait_operation,
    },
    operation::WaitOperationRegistry,
    validate_event_signal_masks,
};

use super::native::{
    NativeIdleSuspendPoll, NativeSuspendPlan, NativeSyscallResult, SyscallControl,
};

use super::abi_bytes::{
    HANDLE_TRANSFER_BYTES, PROCESS_CREATE_ARGS_BYTES, THREAD_START_BYTES, WAIT_ITEM_BYTES,
    decode_handle_transfer, decode_process_create_args, decode_thread_start, decode_wait_item,
    encode_abi_info, encode_channel_receive_result, encode_handle, encode_object_info,
    encode_process_create_result, encode_received_handle_info, encode_u32, encode_u64,
    encode_wait_result,
};

mod address_region;

use address_region::address_region_object_status;
#[cfg(test)]
use address_region::address_transaction_status;
#[allow(
    unused_imports,
    reason = "preserve the established crate-private adapter facade across the private module extraction"
)]
pub(crate) use address_region::{
    AddressRegionMutationTarget, AddressSpacePublishStatus, PreparedAddressRegionMutation,
    address_region_map, address_region_map_model, address_region_map_prepared_model,
    address_region_mutation_target, address_region_protect, address_region_protect_prepared,
    address_region_unmap, address_region_unmap_prepared, decode_map_args,
    prepare_address_region_mutation, process_handle_target,
};

/// Runs one bounded HandleTable mutation while retaining the exact process
/// operation lease. The body is expanded lexically (not invoked as a callback)
/// and must not contain an early `return`.
macro_rules! process_handle_operation {
    ($tasks:expr, $process:expr, $table:ident, $body:expr) => {{
        match $tasks.acquire_process_operation($process) {
            Ok(lease) => {
                let result = match $tasks.process_handles_mut_for_operation(&lease, $process) {
                    Ok($table) => Ok($body),
                    Err(error) => Err(error),
                };
                $tasks
                    .release_process_operation(lease)
                    .unwrap_or_else(|(error, _)| {
                        panic!("HandleTable operation leaked process lease: {error:?}")
                    });
                result
            }
            Err(error) => Err(error),
        }
    }};
}

#[must_use = "typed final releases must be routed after syscall pins/locks are dropped"]
pub(crate) struct CleanupQueue<const CAPACITY: usize> {
    releases: [Option<FinalRelease>; CAPACITY],
    len: usize,
}

impl<const CAPACITY: usize> CleanupQueue<CAPACITY> {
    pub(crate) fn new() -> Self {
        Self {
            releases: core::array::from_fn(|_| None),
            len: 0,
        }
    }

    pub(crate) fn push(&mut self, release: FinalRelease) {
        assert!(
            self.len < CAPACITY,
            "E5 cleanup queue exceeded ObjectRegistry capacity"
        );
        self.releases[self.len] = Some(release);
        self.len += 1;
    }

    pub(crate) fn push_optional(&mut self, release: Option<FinalRelease>) {
        if let Some(release) = release {
            self.push(release);
        }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn into_releases(self) -> [Option<FinalRelease>; CAPACITY] {
        self.releases
    }
}

pub(crate) trait TerminalWaitCleanup<
    const OBJECTS: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>
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
    );
}

pub(crate) struct NoTerminalWaitCleanup;

impl<const OBJECTS: usize, const WAITERS: usize, const EXECUTION: usize>
    TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION> for NoTerminalWaitCleanup
{
    fn cleanup_terminal_wait<
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &mut self,
        _registry: &mut ObjectRegistry<OBJECTS>,
        _tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        _waits: &WaitRegistry<WAITERS>,
        execution: &ExecutionDomain<EXECUTION>,
        thread: ThreadKey,
        _cleanup: &mut CleanupQueue<OBJECTS>,
    ) {
        assert!(
            !execution.blocked_operations().has_thread(thread),
            "blocked terminal Thread requires an explicit F7 wait cleanup owner"
        );
    }
}

pub(crate) struct WaitTerminalCleanup<'a, OUTPUT, DISCARD, const EXECUTION: usize> {
    operations: &'a mut WaitOperationRegistry<OUTPUT, EXECUTION>,
    deadline_authority: Option<&'a mut dyn WaitDeadlineAuthority>,
    discard: DISCARD,
}

impl<'a, OUTPUT, DISCARD, const EXECUTION: usize>
    WaitTerminalCleanup<'a, OUTPUT, DISCARD, EXECUTION>
{
    pub(crate) fn new(
        operations: &'a mut WaitOperationRegistry<OUTPUT, EXECUTION>,
        deadline_authority: Option<&'a mut dyn WaitDeadlineAuthority>,
        discard: DISCARD,
    ) -> Self {
        Self {
            operations,
            deadline_authority,
            discard,
        }
    }
}

impl<
    OUTPUT,
    DISCARD: FnMut(OUTPUT),
    const OBJECTS: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
> TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>
    for WaitTerminalCleanup<'_, OUTPUT, DISCARD, EXECUTION>
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
        let deadline_authority = self
            .deadline_authority
            .as_mut()
            .map(|authority| &mut **authority as &mut dyn WaitDeadlineAuthority);
        let result = crate::wait::engine::finish_terminal_wait(
            registry,
            tasks,
            waits,
            execution,
            self.operations,
            deadline_authority,
            thread,
        )
        .unwrap_or_else(|error| panic!("terminal wait cleanup drifted: {error:?}"));
        let Some((output, releases)) = result else {
            return;
        };
        for release in releases.into_releases().into_iter().flatten() {
            cleanup.push(release);
        }
        (self.discard)(output);
    }
}

fn user_address_space() -> UserAddressSpace {
    UserAddressSpace::x86_64_four_level(u64::from(DW_BASE_PAGE_SIZE))
        .expect("generated ABI page size satisfies the locked x86_64 user split")
}

fn user_range(
    address: DwUserAddress,
    byte_len: usize,
    alignment: u64,
    access: UserAccess,
) -> Result<UserRange, DwStatus> {
    UserRange::new(
        user_address_space(),
        address.0,
        byte_len as u64,
        alignment,
        access,
        EmptyAddressRule::Reject,
    )
    .map_err(|_| DW_STATUS_BAD_ADDRESS)
}

fn usercopy_status<E>(error: UserCopyError<E>) -> DwStatus {
    match error {
        UserCopyError::Access(_) => DW_STATUS_BAD_ADDRESS,
        UserCopyError::AccessIntent
        | UserCopyError::LengthDoesNotFitHost
        | UserCopyError::LengthMismatch
        | UserCopyError::ScratchTooSmall => {
            panic!("E5 internal usercopy shape invariant failed")
        }
    }
}

fn preflight_output<'a, U: UserPageAccess>(
    user: &'a mut U,
    address: DwUserAddress,
    byte_len: usize,
    alignment: u64,
) -> Result<PinnedUserOutput<U::Pinned<'a>>, DwStatus> {
    let range = user_range(address, byte_len, alignment, UserAccess::WRITE)?;
    preflight_user_output(user, range, byte_len).map_err(usercopy_status)
}

fn preflight_outputs<'a, U: UserPageBatchAccess>(
    user: &'a mut U,
    outputs: [Option<(UserRange, usize)>; 3],
) -> Result<PinnedUserOutputs<U::PinnedBatch<'a>>, DwStatus> {
    preflight_user_outputs(user, outputs).map_err(usercopy_status)
}

fn channel_buffer_range(
    address: DwUserAddress,
    byte_len: usize,
    alignment: u64,
    access: UserAccess,
) -> Result<UserRange, DwStatus> {
    UserRange::new(
        user_address_space(),
        address.0,
        byte_len as u64,
        alignment,
        access,
        if byte_len == 0 {
            EmptyAddressRule::NullOrUser
        } else {
            EmptyAddressRule::Reject
        },
    )
    .map_err(|_| DW_STATUS_BAD_ADDRESS)
}

fn copy_input<U: UserPageAccess, const N: usize>(
    user: &mut U,
    address: DwUserAddress,
    alignment: u64,
) -> Result<[u8; N], DwStatus> {
    let range = user_range(address, N, alignment, UserAccess::READ)?;
    let mut destination = [0_u8; N];
    let mut scratch = [0_u8; N];
    copy_from_user(user, range, &mut destination, &mut scratch).map_err(usercopy_status)?;
    Ok(destination)
}

/// Selector-specialized fixed-size diagnostic input copy. This is kept behind
/// the private test cfg so production adapters expose no additional surface.
#[cfg(deepwyrm_wyr1_evidence)]
pub(crate) fn copy_wyr1_evidence_input<U: UserPageAccess, const N: usize>(
    user: &mut U,
    address: DwUserAddress,
) -> Result<[u8; N], DwStatus> {
    copy_input(user, address, 1)
}

#[cfg(deepwyrm_wyr1b_evidence)]
pub(crate) fn copy_wyr1b_evidence_input<U: UserPageAccess, const N: usize>(
    user: &mut U,
    address: DwUserAddress,
) -> Result<[u8; N], DwStatus> {
    copy_input(user, address, 1)
}

pub(crate) fn abi_get_info<U: UserPageAccess>(
    user: &mut U,
    out_info: DwUserAddress,
    out_size: u64,
    out_required_size: DwUserAddress,
) -> DwStatus {
    let required = u64::from(DW_ABI_INFO_V1_SIZE);
    let required_range = match user_range(out_required_size, 8, 8, UserAccess::WRITE) {
        Ok(range) => range,
        Err(status) => return status,
    };
    if out_size < required {
        return match copy_to_user(user, required_range, &encode_u64(required)) {
            Ok(()) => DW_STATUS_BUFFER_TOO_SMALL,
            Err(error) => usercopy_status(error),
        };
    }
    let info_range = match user_range(out_info, DW_ABI_INFO_V1_SIZE as usize, 8, UserAccess::WRITE)
    {
        Ok(range) => range,
        Err(status) => return status,
    };
    // These calls do not mutate kernel business state. Both ranges are fully
    // checked before the first output byte is written.
    if let Err(error) = preflight_user_output(user, info_range, DW_ABI_INFO_V1_SIZE as usize) {
        return usercopy_status(error);
    }
    if let Err(error) = preflight_user_output(user, required_range, 8) {
        return usercopy_status(error);
    }
    if let Err(error) = copy_to_user(user, info_range, &encode_abi_info()) {
        return usercopy_status(error);
    }
    match copy_to_user(user, required_range, &encode_u64(required)) {
        Ok(()) => DW_STATUS_SUCCESS,
        Err(error) => usercopy_status(error),
    }
}

pub(crate) fn clock_get_with<U: UserPageAccess>(
    user: &mut U,
    clock_id: DwClockId,
    out_nanoseconds: DwUserAddress,
    read_clock: impl FnOnce() -> Result<u64, DwStatus>,
) -> DwStatus {
    if clock_id != DW_CLOCK_MONOTONIC_ACTIVE {
        return DW_STATUS_NOT_SUPPORTED;
    }
    let output = match preflight_output(user, out_nanoseconds, 8, 8) {
        Ok(output) => output,
        Err(status) => return status,
    };
    let nanoseconds = match read_clock() {
        Ok(value) => value,
        Err(status) => return status,
    };
    output.commit(&encode_u64(nanoseconds));
    DW_STATUS_SUCCESS
}

/// Runs the mutation-sensitive half of `atomic_wake` as one ordered adapter
/// transaction.
///
/// The mapping pin and stable wait key are acquired before the output is
/// preflighted, preserving the F0 address-identity ordering even for a zero
/// wake count. The wake authority is not invoked until every recoverable
/// output fault has been excluded. The live mapping pin is released before
/// the infallible copyout commit and on every failure after acquisition.
pub(crate) fn atomic_wake_with<U, PIN, KEY>(
    user: &mut U,
    address: DwUserAddress,
    count: u32,
    out_woken: DwUserAddress,
    pin_address: impl FnOnce(&mut U, DwUserAddress) -> Result<PIN, DwStatus>,
    resolve_key: impl FnOnce(DwUserAddress, &PIN) -> Result<KEY, DwStatus>,
    release_pin: impl FnOnce(&mut U, PIN),
    wake: impl FnOnce(KEY, u32) -> Result<u32, DwStatus>,
) -> DwStatus
where
    U: OwnedUserOutputAccess,
{
    let pin = match pin_address(user, address) {
        Ok(pin) => pin,
        Err(status) => return status,
    };
    let key = match resolve_key(address, &pin) {
        Ok(key) => key,
        Err(status) => {
            release_pin(user, pin);
            return status;
        }
    };
    let output_range = match user_range(
        out_woken,
        core::mem::size_of::<u32>(),
        core::mem::align_of::<u32>() as u64,
        UserAccess::WRITE,
    ) {
        Ok(range) => range,
        Err(status) => {
            release_pin(user, pin);
            return status;
        }
    };
    let output = match user.preflight_owned_output(output_range) {
        Ok(output) => output,
        Err(_) => {
            release_pin(user, pin);
            return DW_STATUS_BAD_ADDRESS;
        }
    };
    let woken = match wake(key, count) {
        Ok(woken) => woken,
        Err(status) => {
            user.discard_owned_output(output);
            release_pin(user, pin);
            return status;
        }
    };
    release_pin(user, pin);
    user.commit_owned_output(output, &encode_u32(woken));
    DW_STATUS_SUCCESS
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn clock_get<U: UserPageAccess>(
    user: &mut U,
    clock_id: DwClockId,
    out_nanoseconds: DwUserAddress,
) -> DwStatus {
    clock_get_with(user, clock_id, out_nanoseconds, || {
        crate::time::monotonic_now().map_err(|_| DW_STATUS_BAD_STATE)
    })
}

fn handle_status(error: HandleTableError) -> DwStatus {
    match error {
        HandleTableError::InvalidHandle => DW_STATUS_BAD_HANDLE,
        HandleTableError::InvalidRights => DW_STATUS_INVALID_ARGUMENT,
        HandleTableError::WrongObjectType => DW_STATUS_WRONG_OBJECT_TYPE,
        HandleTableError::AccessDenied => DW_STATUS_ACCESS_DENIED,
        HandleTableError::Capacity | HandleTableError::ReferenceCapacity => DW_STATUS_NO_RESOURCES,
    }
}

fn handle_move_status(error: HandleMovePrepareError) -> DwStatus {
    match error {
        HandleMovePrepareError::DuplicateSource => DW_STATUS_INVALID_ARGUMENT,
        HandleMovePrepareError::Table(error) => handle_status(error),
    }
}

fn task_status(error: TaskError) -> DwStatus {
    match error {
        TaskError::Capacity => DW_STATUS_NO_RESOURCES,
        TaskError::WrongObjectType => DW_STATUS_WRONG_OBJECT_TYPE,
        TaskError::BadState | TaskError::OperationsInFlight | TaskError::ParentTerminating => {
            DW_STATUS_BAD_STATE
        }
        TaskError::InvalidParent | TaskError::InvalidTask | TaskError::Reference => {
            DW_STATUS_BAD_HANDLE
        }
    }
}

fn task_create_status(error: TaskCreateError) -> DwStatus {
    match error {
        TaskCreateError::Registry(ObjectRegistryError::Capacity)
        | TaskCreateError::Registry(ObjectRegistryError::ReferenceCountExhausted) => {
            DW_STATUS_NO_RESOURCES
        }
        TaskCreateError::Registry(_) => DW_STATUS_BAD_STATE,
        TaskCreateError::Task(error) => task_status(error),
    }
}

fn wait_status(error: WaitError) -> DwStatus {
    match error {
        WaitError::Capacity => DW_STATUS_NO_RESOURCES,
        WaitError::InvalidSignals => DW_STATUS_INVALID_ARGUMENT,
        WaitError::AccessDenied => DW_STATUS_ACCESS_DENIED,
        WaitError::UnsupportedSource => DW_STATUS_NOT_SUPPORTED,
        WaitError::InvalidObject => DW_STATUS_WRONG_OBJECT_TYPE,
        WaitError::ForeignRegistration
        | WaitError::StaleRegistration
        | WaitError::EventFinalizationMismatch
        | WaitError::EventReference => DW_STATUS_BAD_STATE,
    }
}

fn event_create_status(error: EventCreateError) -> DwStatus {
    match error {
        EventCreateError::Registry(ObjectRegistryError::Capacity)
        | EventCreateError::Registry(ObjectRegistryError::ReferenceCountExhausted) => {
            DW_STATUS_NO_RESOURCES
        }
        EventCreateError::Registry(_) => DW_STATUS_BAD_STATE,
        EventCreateError::Wait(error) => wait_status(error),
    }
}

fn timer_status(error: TimerError) -> DwStatus {
    match error {
        TimerError::Capacity | TimerError::Deadline(crate::time::TimerDeadlineError::Capacity) => {
            DW_STATUS_NO_RESOURCES
        }
        TimerError::InvalidDeadline | TimerError::InvalidSignals => DW_STATUS_INVALID_ARGUMENT,
        TimerError::AccessDenied => DW_STATUS_ACCESS_DENIED,
        TimerError::InvalidObject
        | TimerError::GenerationExhausted
        | TimerError::TransitionInProgress
        | TimerError::ForeignExpiry
        | TimerError::Deadline(_)
        | TimerError::FinalizationMismatch
        | TimerError::Reference => DW_STATUS_BAD_STATE,
    }
}

fn channel_status(error: ChannelError) -> DwStatus {
    match error {
        ChannelError::Capacity => DW_STATUS_NO_RESOURCES,
        ChannelError::InvalidArgument => DW_STATUS_INVALID_ARGUMENT,
        ChannelError::WouldBlock => DW_STATUS_WOULD_BLOCK,
        ChannelError::PeerClosed => DW_STATUS_PEER_CLOSED,
        ChannelError::BufferTooSmall => DW_STATUS_BUFFER_TOO_SMALL,
        ChannelError::AccessDenied => DW_STATUS_ACCESS_DENIED,
        ChannelError::InvalidEndpoint
        | ChannelError::StalePair
        | ChannelError::FinalizationMismatch => DW_STATUS_BAD_STATE,
    }
}

fn timer_create_status(error: TimerCreateError) -> DwStatus {
    match error {
        TimerCreateError::Registry(ObjectRegistryError::Capacity)
        | TimerCreateError::Registry(ObjectRegistryError::ReferenceCountExhausted) => {
            DW_STATUS_NO_RESOURCES
        }
        TimerCreateError::Registry(_) => DW_STATUS_BAD_STATE,
        TimerCreateError::Timer(error) => timer_status(error),
    }
}

fn channel_create_status(error: ChannelCreateError) -> DwStatus {
    match error {
        ChannelCreateError::Registry(ObjectRegistryError::Capacity)
        | ChannelCreateError::Registry(ObjectRegistryError::ReferenceCountExhausted) => {
            DW_STATUS_NO_RESOURCES
        }
        ChannelCreateError::Registry(_) => DW_STATUS_BAD_STATE,
        ChannelCreateError::Channel(error) => channel_status(error),
    }
}

fn validate_created_handle_rights(
    object_type: deepwyrm_abi::DwObjectType,
    rights: DwRights,
) -> Result<(), DwStatus> {
    if rights.0 == 0
        || !deepwyrm_abi::dw_rights_are_known(rights)
        || !deepwyrm_abi::dw_rights_are_compatible(object_type, rights)
    {
        return Err(DW_STATUS_INVALID_ARGUMENT);
    }
    Ok(())
}

fn validate_running_caller<
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EXECUTION: usize,
>(
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    current_process: ProcessKey,
    current_thread: ThreadKey,
) -> Result<(), DwStatus> {
    if tasks.thread_process(current_thread).map_err(task_status)? != current_process
        || execution.scheduler_state(current_thread) != Some(SchedulerThreadState::Running)
    {
        return Err(DW_STATUS_BAD_STATE);
    }
    Ok(())
}

pub(crate) fn handle_close<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    current_process: ProcessKey,
    handle: DwHandle,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    match process_handle_operation!(tasks, current_process, table, {
        crate::service::handle_close(table, registry, handle)
    }) {
        Ok(Ok(release)) => {
            cleanup.push_optional(release);
            DW_STATUS_SUCCESS
        }
        Ok(Err(status)) => status,
        Err(error) => task_status(error),
    }
}

pub(crate) fn handle_duplicate<
    U: UserPageAccess,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    current_process: ProcessKey,
    handle: DwHandle,
    requested_rights: DwRights,
    out_handle: DwUserAddress,
) -> DwStatus {
    let output = match preflight_output(user, out_handle, 8, 8) {
        Ok(output) => output,
        Err(status) => return status,
    };
    match process_handle_operation!(tasks, current_process, table, {
        crate::service::handle_duplicate(table, registry, handle, requested_rights)
    }) {
        Ok(Ok(duplicate)) => {
            output.commit(&encode_handle(duplicate));
            DW_STATUS_SUCCESS
        }
        Ok(Err(status)) => status,
        Err(error) => task_status(error),
    }
}

pub(crate) fn object_get_info_v1<
    U: UserPageAccess,
    const OBJECTS: usize,
    const MEMORY_OBJECTS: usize,
    const LEASES: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    memory: &MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    current_process: ProcessKey,
    handle: DwHandle,
    topic: u32,
    out_info: DwUserAddress,
    out_size: u64,
    out_required_size: DwUserAddress,
) -> DwStatus {
    let required_range = match user_range(out_required_size, 8, 8, UserAccess::WRITE) {
        Ok(range) => range,
        Err(status) => return status,
    };
    if let Err(error) = preflight_user_output(user, required_range, 8) {
        return usercopy_status(error);
    }
    let table = match tasks.process_handles(current_process) {
        Ok(table) => table,
        Err(error) => return task_status(error),
    };
    let result = match crate::service::object_get_info_v1_with_tasks(
        table, registry, memory, tasks, handle, topic,
    ) {
        Ok(result) => result,
        Err(status) => return status,
    };
    let encoded = encode_object_info(result);
    let required = encoded.len() as u64;
    if out_size < required {
        return match copy_to_user(user, required_range, &encode_u64(required)) {
            Ok(()) => DW_STATUS_BUFFER_TOO_SMALL,
            Err(error) => usercopy_status(error),
        };
    }
    let info_range = match user_range(out_info, encoded.len(), 8, UserAccess::WRITE) {
        Ok(range) => range,
        Err(status) => return status,
    };
    if let Err(error) = preflight_user_output(user, info_range, encoded.len()) {
        return usercopy_status(error);
    }
    // The query is read-only. Both output ranges have been validated before
    // either destination is modified, and the BSP user-memory session excludes
    // concurrent page-table mutation.
    if let Err(error) = copy_to_user(user, info_range, encoded.bytes()) {
        return usercopy_status(error);
    }
    match copy_to_user(user, required_range, &encode_u64(required)) {
        Ok(()) => DW_STATUS_SUCCESS,
        Err(error) => usercopy_status(error),
    }
}

pub(crate) const fn object_info_required_size(topic: u32) -> Option<u64> {
    match topic {
        DW_OBJECT_INFO_BASIC_V1 => Some(DW_OBJECT_INFO_V1_SIZE as u64),
        DW_OBJECT_INFO_TASK_STATE_V1 => Some(64),
        DW_OBJECT_INFO_MEMORY_OBJECT_V1 => Some(DW_MEMORY_OBJECT_INFO_V1_SIZE as u64),
        _ => None,
    }
}

fn resolve_current<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    registry: &mut ObjectRegistry<OBJECTS>,
    current_process: ProcessKey,
    handle: DwHandle,
    object_type: deepwyrm_abi::DwObjectType,
    rights: DwRights,
) -> Result<ResolvedHandle, DwStatus> {
    let table = tasks
        .process_handles(current_process)
        .map_err(task_status)?;
    table
        .lookup(
            registry,
            handle,
            AcceptedObjectTypes::One(object_type),
            rights,
        )
        .map_err(handle_status)
}

fn resolve_current_handle<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    registry: &mut ObjectRegistry<OBJECTS>,
    current_process: ProcessKey,
    handle: DwHandle,
    object_type: deepwyrm_abi::DwObjectType,
    rights: DwRights,
) -> Result<InternalRef, DwStatus> {
    resolve_current(
        tasks,
        registry,
        current_process,
        handle,
        object_type,
        rights,
    )
    .map(ResolvedHandle::into_internal)
}

fn release_lookup_pin<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    pin: InternalRef,
    cleanup: &mut CleanupQueue<OBJECTS>,
) {
    let release = registry
        .release_internal(pin)
        .unwrap_or_else(|failure| panic!("E5 lookup pin release drifted: {:?}", failure.error()));
    cleanup.push_optional(release);
}

fn install_created_handle<const HANDLES: usize, const OBJECTS: usize>(
    table: &mut crate::handle::HandleTable<HANDLES>,
    registry: &mut ObjectRegistry<OBJECTS>,
    reference: HandleRef,
    rights: DwRights,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> Result<DwHandle, DwStatus> {
    match table.install(reference, rights) {
        Ok(handle) => Ok(handle),
        Err(error) => {
            let status = handle_status(error.error());
            let reference = error.into_reference();
            cleanup.push_optional(
                registry
                    .release_handle(reference)
                    .unwrap_or_else(|failure| {
                        panic!(
                            "E5 failed-handle publication rollback drifted: {:?}",
                            failure.error()
                        )
                    }),
            );
            Err(status)
        }
    }
}

fn collect_retired_pins<
    const OBJECTS: usize,
    const THREADS: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    pins: RetiredExitPins<THREADS>,
    cleanup: &mut CleanupQueue<OBJECTS>,
) {
    let (process, threads) = pins.into_parts();
    for pin in threads.into_iter().flatten().chain(process) {
        complete_wait_wakes(
            registry,
            execution,
            waits.take_ready(pin.id(), deepwyrm_abi::DW_SIGNAL_EXITED),
            cleanup,
        );
        cleanup.push_optional(registry.release_internal(pin).unwrap_or_else(|failure| {
            panic!(
                "F7 terminal execution pin release drifted: {:?}",
                failure.error()
            )
        }));
    }
}

pub(crate) fn complete_deferred_current_reclaim<
    const OBJECTS: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    deferred: DeferredCurrentExecutionResources,
    cleanup: &mut CleanupQueue<OBJECTS>,
) {
    let pins = execution.reclaim_deferred_current(deferred);
    collect_retired_pins(registry, execution, waits, pins, cleanup);
}

pub(crate) fn complete_deferred_current_reclaim_on<
    const OBJECTS: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    cpu: crate::cpu::CpuIndex,
    deferred: DeferredCurrentExecutionResources,
    cleanup: &mut CleanupQueue<OBJECTS>,
) {
    let pins = execution.reclaim_deferred_current_on(cpu, deferred);
    collect_retired_pins(registry, execution, waits, pins, cleanup);
}

#[derive(Clone, Copy)]
enum DeferredCurrentRetirement {
    Model(ThreadKey),
    Handoff {
        cpu: crate::cpu::CpuIndex,
        thread: ThreadKey,
    },
}

impl DeferredCurrentRetirement {
    fn thread(self) -> ThreadKey {
        match self {
            Self::Model(thread) | Self::Handoff { thread, .. } => thread,
        }
    }
}

fn collect_process_effects<
    C: TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const HANDLES: usize,
    const THREADS: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    effects: ProcessExitEffects<HANDLES, THREADS>,
    pre_retired: &mut PreRetiredTerminalThreads<THREADS>,
    defer_current: Option<DeferredCurrentRetirement>,
    remotely_stopped: &[Option<ThreadKey>],
    terminal_waits: &mut C,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> Option<DeferredCurrentExecutionResources> {
    let deferred_thread = defer_current.filter(|current| {
        effects
            .pins
            .thread_keys()
            .into_iter()
            .flatten()
            .any(|thread| thread == current.thread())
    });
    for release in effects.drained.into_final_releases().into_iter().flatten() {
        cleanup.push(release);
    }
    for thread in effects.pins.thread_keys().into_iter().flatten() {
        terminal_waits.cleanup_terminal_wait(registry, tasks, waits, execution, thread, cleanup);
    }
    let (pins, deferred) = match deferred_thread {
        Some(DeferredCurrentRetirement::Model(current)) => {
            let (pins, deferred) = execution.retire_quiesced_exit_pins_defer_current(
                effects.pins,
                current,
                pre_retired.as_mut(),
            );
            (pins, Some(deferred))
        }
        Some(DeferredCurrentRetirement::Handoff { cpu, thread }) => {
            let (pins, deferred) = execution
                .retire_quiesced_exit_pins_defer_current_after_remote_stops_on(
                    cpu,
                    effects.pins,
                    thread,
                    remotely_stopped,
                    pre_retired.as_mut(),
                );
            (pins, Some(deferred))
        }
        None if remotely_stopped.is_empty() => (
            execution.retire_quiesced_exit_pins(effects.pins, pre_retired.as_mut()),
            None,
        ),
        None => (
            execution.retire_quiesced_exit_pins_after_remote_stops(
                effects.pins,
                remotely_stopped,
                pre_retired.as_mut(),
            ),
            None,
        ),
    };
    collect_retired_pins(registry, execution, waits, pins, cleanup);
    deferred
}

/// Terminal Process effects whose execution pins have not yet been retired.
///
/// A live SMP caller may inspect the exact Thread set, stop every remote
/// physical owner, and only then pass this linear batch to
/// `complete_prepared_process_termination` for reclamation.
#[must_use = "prepared scheduler retirement must be consumed with its terminal execution pins"]
struct PreRetiredTerminalThreads<const THREADS: usize> {
    threads: [Option<ThreadKey>; THREADS],
}

impl<const THREADS: usize> PreRetiredTerminalThreads<THREADS> {
    const fn new(threads: [Option<ThreadKey>; THREADS]) -> Self {
        Self { threads }
    }

    const fn as_mut(&mut self) -> &mut [Option<ThreadKey>; THREADS] {
        &mut self.threads
    }

    fn assert_consumed(self) {
        assert!(
            self.threads.into_iter().all(|thread| thread.is_none()),
            "prepared scheduler retirement outlived its terminal pin batch"
        );
    }
}

#[must_use = "prepared Process termination must be completed after remote execution owners are stopped"]
pub(crate) struct PreparedProcessTermination<const HANDLES: usize, const THREADS: usize> {
    target: ProcessKey,
    effects: ProcessExitEffects<HANDLES, THREADS>,
    pre_retired: PreRetiredTerminalThreads<THREADS>,
}

/// Terminal Thread effects retained until every foreign physical continuation
/// owner has acknowledged the exact generation-bound stop.
#[must_use = "prepared Thread termination must be completed after remote execution owners are stopped"]
pub(crate) struct PreparedThreadTermination<const THREADS: usize> {
    target: ThreadKey,
    target_process: ProcessKey,
    pins: crate::task::ExitPins<THREADS>,
    pre_retired: PreRetiredTerminalThreads<THREADS>,
}

/// Recursive TaskGroup terminal effects retained across live remote-stop
/// acknowledgement. Logical task state is already terminal, but no execution
/// resources in this batch may be reclaimed until completion consumes it.
#[must_use = "prepared TaskGroup termination must be completed after remote execution owners are stopped"]
pub(crate) struct PreparedTaskGroupTermination<
    const PROCESSES: usize,
    const HANDLES: usize,
    const THREADS: usize,
> {
    effects: TaskGroupTerminationEffects<PROCESSES, HANDLES, THREADS>,
    pre_retired: PreRetiredTerminalThreads<THREADS>,
}

impl<const PROCESSES: usize, const HANDLES: usize, const THREADS: usize>
    PreparedTaskGroupTermination<PROCESSES, HANDLES, THREADS>
{
    pub(crate) const fn process_keys(&self) -> [Option<ProcessKey>; PROCESSES] {
        self.effects.process_keys()
    }

    pub(crate) fn thread_keys(&self) -> [Option<ThreadKey>; THREADS] {
        self.effects.thread_keys()
    }

    pub(crate) fn contains_thread(&self, thread: ThreadKey) -> bool {
        self.thread_keys().contains(&Some(thread))
    }
}

impl<const HANDLES: usize, const THREADS: usize> PreparedProcessTermination<HANDLES, THREADS> {
    pub(crate) const fn target(&self) -> ProcessKey {
        self.target
    }

    pub(crate) fn thread_keys(&self) -> [Option<ThreadKey>; THREADS] {
        self.effects.pins.thread_keys()
    }
}

impl<const THREADS: usize> PreparedThreadTermination<THREADS> {
    pub(crate) const fn target(&self) -> ThreadKey {
        self.target
    }

    pub(crate) const fn target_process(&self) -> ProcessKey {
        self.target_process
    }

    /// Returns the owning Process only when this Thread transition also made
    /// that Process terminal. The retained Process execution pin is the exact
    /// linear proof; merely observing the Process state later would not bind
    /// the result to this prepared completion.
    pub(crate) const fn exited_process(&self) -> Option<ProcessKey> {
        if self.pins.exits_process() {
            Some(self.target_process)
        } else {
            None
        }
    }

    pub(crate) fn thread_keys(&self) -> [Option<ThreadKey>; THREADS] {
        self.pins.thread_keys()
    }
}

pub(crate) fn task_group_create<
    U: UserPageAccess,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    current_process: ProcessKey,
    parent: DwHandle,
    requested_rights: DwRights,
    out_handle: DwUserAddress,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    if let Err(status) =
        validate_created_handle_rights(deepwyrm_abi::DW_OBJECT_TYPE_TASK_GROUP, requested_rights)
    {
        return status;
    }
    let output = match preflight_output(user, out_handle, 8, 8) {
        Ok(output) => output,
        Err(status) => return status,
    };
    let parent_pin = match resolve_current_handle(
        tasks,
        registry,
        current_process,
        parent,
        deepwyrm_abi::DW_OBJECT_TYPE_TASK_GROUP,
        DW_RIGHT_MODIFY,
    ) {
        Ok(pin) => pin,
        Err(status) => return status,
    };
    let created = tasks.create_child_group(registry, &parent_pin);
    release_lookup_pin(registry, parent_pin, cleanup);
    let (_key, reference) = match created {
        Ok(created) => created,
        Err(error) => return task_create_status(error),
    };
    let handle = match tasks.process_handles_mut(current_process) {
        Ok(table) => {
            match install_created_handle(table, registry, reference, requested_rights, cleanup) {
                Ok(handle) => handle,
                Err(status) => return status,
            }
        }
        Err(error) => {
            cleanup.push_optional(
                registry
                    .release_handle(reference)
                    .unwrap_or_else(|failure| {
                        panic!(
                            "E5 child-group publication rollback drifted: {:?}",
                            failure.error()
                        )
                    }),
            );
            return task_status(error);
        }
    };
    output.commit(&encode_handle(handle));
    DW_STATUS_SUCCESS
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessCreatePreparation {
    BootstrapMove,
    ProcessShell,
    ChildBootstrapSlot,
    RootRegion,
    ParentResultSlots,
}

pub(crate) trait ProcessRootReservation {
    fn reserve_child_root(
        &mut self,
        process: ProcessKey,
        address_space: crate::memory::address_region::AddressSpaceKey,
    ) -> Result<(), DwStatus>;

    fn rollback_empty_child_root(
        &mut self,
        process: ProcessKey,
        address_space: crate::memory::address_region::AddressSpaceKey,
    );
}

fn cancel_prepared_process<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    prepared: PreparedProcess,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    cleanup: &mut CleanupQueue<OBJECTS>,
) {
    cleanup.push_optional(prepared.cancel(tasks, registry));
}

fn cancel_prepared_handle_move<
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    prepared: &mut PreparedHandleMove,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    process: ProcessKey,
) {
    prepared
        .cancel(
            tasks
                .process_handles_mut(process)
                .expect("prepared MOVE source table remains live during cancellation"),
        )
        .expect("prepared MOVE permit remains exact during cancellation");
}

fn cancel_transfer_destination<
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    reservation: &mut HandleTransferReservation,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    process: ProcessKey,
) {
    reservation
        .cancel(
            tasks
                .process_handles_mut(process)
                .expect("reserved destination table remains live during cancellation"),
        )
        .expect("destination permit remains exact during cancellation");
}

fn cancel_typed_pair_destination<
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    reservation: &mut TypedHandlePairReservation,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    process: ProcessKey,
) {
    reservation
        .cancel(
            tasks
                .process_handles_mut(process)
                .expect("reserved typed-pair table remains live during cancellation"),
        )
        .expect("typed-pair permits remain exact during cancellation");
}

fn cancel_pair_destination<
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    reservation: &mut HandlePairReservation,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    process: ProcessKey,
) {
    reservation
        .cancel(
            tasks
                .process_handles_mut(process)
                .expect("reserved pair table remains live during cancellation"),
        )
        .expect("pair destination permits remain exact during cancellation");
}

#[allow(
    clippy::too_many_arguments,
    reason = "F10 cancellation keeps task, address-space, typed-region, and generic-finalizer owners explicit"
)]
fn cancel_prepared_root_and_process<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const REGION_OBJECTS: usize,
    const REGION_SLOTS: usize,
    const SPACES: usize,
    const REGIONS: usize,
>(
    root: PreparedRootRegion<REGION_SLOTS>,
    process: PreparedProcess,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    regions: &mut AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
    spaces: &mut AddressSpaceAuthority<SPACES, REGIONS>,
    cleanup: &mut CleanupQueue<OBJECTS>,
) {
    root.cancel(registry, tasks, spaces, regions);
    cancel_prepared_process(process, registry, tasks, cleanup);
}

#[must_use = "prepared process-create user input owns its output reservation"]
struct PreparedProcessCreate<OUTPUT> {
    args: DwProcessCreateArgsV1,
    output: OUTPUT,
}

/// Copies and validates all caller-controlled process-create input before any
/// stationary authority is reserved. The returned output reservation is owned
/// rather than borrowed, so the later publication phase never retains a
/// usercopy guard or pointer.
fn prepare_process_create_input<U: UserPageAccess + OwnedUserOutputAccess>(
    user: &mut U,
    args_address: DwUserAddress,
    args_size: u64,
    out_result: DwUserAddress,
    result_size: u64,
) -> Result<PreparedProcessCreate<U::OwnedOutput>, DwStatus> {
    if args_size != u64::from(DW_PROCESS_CREATE_ARGS_V1_SIZE)
        || result_size != u64::from(DW_PROCESS_CREATE_RESULT_V1_SIZE)
    {
        return Err(DW_STATUS_INVALID_ARGUMENT);
    }
    let bytes = copy_input::<U, PROCESS_CREATE_ARGS_BYTES>(user, args_address, 8)?;
    let args = decode_process_create_args(&bytes);
    if args.size != DW_PROCESS_CREATE_ARGS_V1_SIZE
        || args.version != 1
        || args.flags != 0
        || args.reserved != [0; 4]
    {
        return Err(DW_STATUS_INVALID_ARGUMENT);
    }
    for (object_type, rights) in [
        (DW_OBJECT_TYPE_PROCESS, args.process_rights),
        (DW_OBJECT_TYPE_ADDRESS_REGION, args.root_region_rights),
        (DW_OBJECT_TYPE_CHANNEL, args.child_bootstrap_rights),
    ] {
        validate_created_handle_rights(object_type, rights)?;
    }
    let output_range = user_range(
        out_result,
        DW_PROCESS_CREATE_RESULT_V1_SIZE as usize,
        8,
        UserAccess::WRITE,
    )?;
    let output = user
        .preflight_owned_output(output_range)
        .map_err(|_| DW_STATUS_BAD_ADDRESS)?;
    Ok(PreparedProcessCreate { args, output })
}

#[allow(
    clippy::too_many_arguments,
    reason = "the F10 observation barrier keeps independently-owned usercopy, object, task, HandleTable, and address-space authorities explicit"
)]
fn process_create_transaction<
    U: UserPageAccess + OwnedUserOutputAccess,
    R: FnMut(
        &mut U,
        ProcessKey,
        crate::memory::address_region::AddressSpaceKey,
    ) -> Result<(), DwStatus>,
    B: FnMut(&mut U, ProcessKey, crate::memory::address_region::AddressSpaceKey),
    I: FnMut(ProcessCreatePreparation) -> Result<(), DwStatus>,
    O: FnOnce(ProcessKey),
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const REGION_OBJECTS: usize,
    const REGION_SLOTS: usize,
    const SPACES: usize,
    const REGIONS: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    regions: &mut AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
    spaces: &mut AddressSpaceAuthority<SPACES, REGIONS>,
    current_process: ProcessKey,
    args_address: DwUserAddress,
    args_size: u64,
    out_result: DwUserAddress,
    result_size: u64,
    cleanup: &mut CleanupQueue<OBJECTS>,
    mut reserve_root: R,
    mut rollback_root: B,
    mut inject: I,
    observe_committed_process: O,
) -> DwStatus {
    let PreparedProcessCreate { args, output } = match prepare_process_create_input(
        user,
        args_address,
        args_size,
        out_result,
        result_size,
    ) {
        Ok(prepared) => prepared,
        Err(status) => return status,
    };

    macro_rules! discard_and_return {
        ($status:expr) => {{
            user.discard_owned_output(output);
            return $status;
        }};
    }

    let parent_pin = match resolve_current_handle(
        tasks,
        registry,
        current_process,
        args.task_group,
        DW_OBJECT_TYPE_TASK_GROUP,
        DW_RIGHT_MODIFY,
    ) {
        Ok(pin) => pin,
        Err(status) => discard_and_return!(status),
    };
    let bootstrap_pin = match resolve_current_handle(
        tasks,
        registry,
        current_process,
        args.bootstrap_channel,
        DW_OBJECT_TYPE_CHANNEL,
        DW_RIGHT_TRANSFER,
    ) {
        Ok(pin) => pin,
        Err(status) => {
            release_lookup_pin(registry, parent_pin, cleanup);
            discard_and_return!(status);
        }
    };

    // This function's exclusive mutable authorities are the DW0 single-owner
    // observation barrier. Owned domain/generation reservations let each
    // HandleTable and task/address-space owner be borrowed only sequentially.
    let prepared_move = match tasks.process_handles_mut(current_process) {
        Ok(table) => table.prepare_move(HandleMoveRequest {
            handle: args.bootstrap_channel,
            requested_rights: args.child_bootstrap_rights,
        }),
        Err(error) => {
            release_lookup_pin(registry, bootstrap_pin, cleanup);
            release_lookup_pin(registry, parent_pin, cleanup);
            discard_and_return!(task_status(error));
        }
    };
    let mut prepared_move = match prepared_move {
        Ok(prepared) => prepared,
        Err(error) => {
            release_lookup_pin(registry, bootstrap_pin, cleanup);
            release_lookup_pin(registry, parent_pin, cleanup);
            discard_and_return!(handle_move_status(error));
        }
    };
    if let Err(status) = inject(ProcessCreatePreparation::BootstrapMove) {
        cancel_prepared_handle_move(&mut prepared_move, tasks, current_process);
        release_lookup_pin(registry, bootstrap_pin, cleanup);
        release_lookup_pin(registry, parent_pin, cleanup);
        discard_and_return!(status);
    }

    let prepared_process = match tasks.prepare_process(registry, &parent_pin) {
        Ok(prepared) => prepared,
        Err(error) => {
            cancel_prepared_handle_move(&mut prepared_move, tasks, current_process);
            release_lookup_pin(registry, bootstrap_pin, cleanup);
            release_lookup_pin(registry, parent_pin, cleanup);
            discard_and_return!(task_create_status(error));
        }
    };
    if let Err(status) = inject(ProcessCreatePreparation::ProcessShell) {
        cancel_prepared_process(prepared_process, registry, tasks, cleanup);
        cancel_prepared_handle_move(&mut prepared_move, tasks, current_process);
        release_lookup_pin(registry, bootstrap_pin, cleanup);
        release_lookup_pin(registry, parent_pin, cleanup);
        discard_and_return!(status);
    }

    let child_reservation = match tasks.process_handles_mut(prepared_process.key()) {
        Ok(table) => table.reserve_transfer_destination(),
        Err(error) => {
            cancel_prepared_process(prepared_process, registry, tasks, cleanup);
            cancel_prepared_handle_move(&mut prepared_move, tasks, current_process);
            release_lookup_pin(registry, bootstrap_pin, cleanup);
            release_lookup_pin(registry, parent_pin, cleanup);
            discard_and_return!(task_status(error));
        }
    };
    let mut child_reservation = match child_reservation {
        Ok(reservation) => reservation,
        Err(error) => {
            cancel_prepared_process(prepared_process, registry, tasks, cleanup);
            cancel_prepared_handle_move(&mut prepared_move, tasks, current_process);
            release_lookup_pin(registry, bootstrap_pin, cleanup);
            release_lookup_pin(registry, parent_pin, cleanup);
            discard_and_return!(handle_status(error));
        }
    };
    if let Err(status) = inject(ProcessCreatePreparation::ChildBootstrapSlot) {
        cancel_transfer_destination(&mut child_reservation, tasks, prepared_process.key());
        cancel_prepared_process(prepared_process, registry, tasks, cleanup);
        cancel_prepared_handle_move(&mut prepared_move, tasks, current_process);
        release_lookup_pin(registry, bootstrap_pin, cleanup);
        release_lookup_pin(registry, parent_pin, cleanup);
        discard_and_return!(status);
    }

    let attachment = match prepared_process.reserve_root_region_attachment(tasks) {
        Ok(attachment) => attachment,
        Err(error) => {
            cancel_transfer_destination(&mut child_reservation, tasks, prepared_process.key());
            cancel_prepared_process(prepared_process, registry, tasks, cleanup);
            cancel_prepared_handle_move(&mut prepared_move, tasks, current_process);
            release_lookup_pin(registry, bootstrap_pin, cleanup);
            release_lookup_pin(registry, parent_pin, cleanup);
            discard_and_return!(task_status(error));
        }
    };
    let prepared_root = match regions.prepare_root_region(
        registry,
        tasks,
        spaces,
        prepared_process.key(),
        prepared_process.handle(),
        attachment,
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            cancel_transfer_destination(&mut child_reservation, tasks, prepared_process.key());
            cancel_prepared_process(prepared_process, registry, tasks, cleanup);
            cancel_prepared_handle_move(&mut prepared_move, tasks, current_process);
            release_lookup_pin(registry, bootstrap_pin, cleanup);
            release_lookup_pin(registry, parent_pin, cleanup);
            discard_and_return!(address_region_object_status(error));
        }
    };
    if let Err(status) = inject(ProcessCreatePreparation::RootRegion) {
        cancel_transfer_destination(&mut child_reservation, tasks, prepared_process.key());
        cancel_prepared_root_and_process(
            prepared_root,
            prepared_process,
            registry,
            tasks,
            regions,
            spaces,
            cleanup,
        );
        cancel_prepared_handle_move(&mut prepared_move, tasks, current_process);
        release_lookup_pin(registry, bootstrap_pin, cleanup);
        release_lookup_pin(registry, parent_pin, cleanup);
        discard_and_return!(status);
    }
    let child_process = prepared_process.key();
    let child_address_space = regions
        .region(prepared_root.key())
        .unwrap_or_else(|error| panic!("prepared child root disappeared: {error:?}"))
        .address_space_key();
    if let Err(status) = reserve_root(user, child_process, child_address_space) {
        cancel_transfer_destination(&mut child_reservation, tasks, child_process);
        cancel_prepared_root_and_process(
            prepared_root,
            prepared_process,
            registry,
            tasks,
            regions,
            spaces,
            cleanup,
        );
        cancel_prepared_handle_move(&mut prepared_move, tasks, current_process);
        release_lookup_pin(registry, bootstrap_pin, cleanup);
        release_lookup_pin(registry, parent_pin, cleanup);
        discard_and_return!(status);
    }

    let parent_reservation = match tasks.process_handles_mut(current_process) {
        Ok(table) => table.reserve_typed_pair([
            HandleReservationSpec {
                object_type: DW_OBJECT_TYPE_PROCESS,
                rights: args.process_rights,
            },
            HandleReservationSpec {
                object_type: DW_OBJECT_TYPE_ADDRESS_REGION,
                rights: args.root_region_rights,
            },
        ]),
        Err(error) => {
            rollback_root(user, child_process, child_address_space);
            cancel_transfer_destination(&mut child_reservation, tasks, prepared_process.key());
            cancel_prepared_root_and_process(
                prepared_root,
                prepared_process,
                registry,
                tasks,
                regions,
                spaces,
                cleanup,
            );
            cancel_prepared_handle_move(&mut prepared_move, tasks, current_process);
            release_lookup_pin(registry, bootstrap_pin, cleanup);
            release_lookup_pin(registry, parent_pin, cleanup);
            discard_and_return!(task_status(error));
        }
    };
    let mut parent_reservation = match parent_reservation {
        Ok(reservation) => reservation,
        Err(error) => {
            rollback_root(user, child_process, child_address_space);
            cancel_transfer_destination(&mut child_reservation, tasks, prepared_process.key());
            cancel_prepared_root_and_process(
                prepared_root,
                prepared_process,
                registry,
                tasks,
                regions,
                spaces,
                cleanup,
            );
            cancel_prepared_handle_move(&mut prepared_move, tasks, current_process);
            release_lookup_pin(registry, bootstrap_pin, cleanup);
            release_lookup_pin(registry, parent_pin, cleanup);
            discard_and_return!(handle_status(error));
        }
    };
    if let Err(status) = inject(ProcessCreatePreparation::ParentResultSlots) {
        rollback_root(user, child_process, child_address_space);
        cancel_typed_pair_destination(&mut parent_reservation, tasks, current_process);
        cancel_transfer_destination(&mut child_reservation, tasks, prepared_process.key());
        cancel_prepared_root_and_process(
            prepared_root,
            prepared_process,
            registry,
            tasks,
            regions,
            spaces,
            cleanup,
        );
        cancel_prepared_handle_move(&mut prepared_move, tasks, current_process);
        release_lookup_pin(registry, bootstrap_pin, cleanup);
        release_lookup_pin(registry, parent_pin, cleanup);
        discard_and_return!(status);
    }

    // No recoverable operation remains beyond this point. The source MOVE is
    // published into the child before typed hierarchy visibility, and parent
    // result handles appear together only after both typed payloads commit.
    let (mut move_rollback, transfer) = prepared_move
        .try_extract(
            tasks
                .process_handles_mut(current_process)
                .unwrap_or_else(|error| panic!("F10 source table changed at commit: {error:?}")),
        )
        .unwrap_or_else(|error| panic!("F10 source MOVE permit diverged at commit: {error:?}"));
    let child_bootstrap = child_reservation
        .try_publish(
            tasks
                .process_handles_mut(prepared_process.key())
                .unwrap_or_else(|error| panic!("F10 child table changed at commit: {error:?}")),
            transfer,
        )
        .unwrap_or_else(|failure| {
            panic!(
                "F10 child destination permit diverged at commit: {:?}",
                failure.error()
            )
        });
    move_rollback
        .try_finish(
            tasks
                .process_handles_mut(current_process)
                .unwrap_or_else(|error| {
                    panic!("F10 source table changed after extraction: {error:?}")
                }),
        )
        .unwrap_or_else(|error| panic!("F10 source MOVE finish permit diverged: {error:?}"));
    let (_root, root_reference) = prepared_root.commit(registry, tasks, regions);
    let (_process, process_reference) = prepared_process.commit(tasks);
    observe_committed_process(child_process);
    let parent_handles = parent_reservation
        .try_publish(
            tasks
                .process_handles_mut(current_process)
                .unwrap_or_else(|error| {
                    panic!("F10 parent table changed at publication: {error:?}")
                }),
            [process_reference, root_reference],
        )
        .unwrap_or_else(|failure| {
            panic!(
                "F10 parent destination permits diverged at commit: {:?}",
                failure.error()
            )
        });

    release_lookup_pin(registry, bootstrap_pin, cleanup);
    release_lookup_pin(registry, parent_pin, cleanup);
    let encoded = encode_process_create_result(DwProcessCreateResultV1 {
        size: DW_PROCESS_CREATE_RESULT_V1_SIZE,
        version: 1,
        process: parent_handles[0],
        root_address_region: parent_handles[1],
        child_bootstrap_handle: child_bootstrap.handle,
        reserved: [0; 4],
    });
    user.commit_owned_output(output, &encoded);
    DW_STATUS_SUCCESS
}

#[allow(
    clippy::too_many_arguments,
    reason = "the public F10 adapter preserves explicit transaction authority ownership"
)]
pub(crate) fn process_create<
    U: UserPageAccess + OwnedUserOutputAccess,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const REGION_OBJECTS: usize,
    const REGION_SLOTS: usize,
    const SPACES: usize,
    const REGIONS: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    regions: &mut AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
    spaces: &mut AddressSpaceAuthority<SPACES, REGIONS>,
    current_process: ProcessKey,
    args_address: DwUserAddress,
    args_size: u64,
    out_result: DwUserAddress,
    result_size: u64,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    process_create_transaction(
        user,
        registry,
        tasks,
        regions,
        spaces,
        current_process,
        args_address,
        args_size,
        out_result,
        result_size,
        cleanup,
        |_, _, _| Ok(()),
        |_, _, _| {},
        |_| Ok(()),
        |_| {},
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the live F10 adapter keeps usercopy, portable construction, and exact architecture-root reservation in one failure-atomic transaction"
)]
pub(crate) fn process_create_with_root<
    U: UserPageAccess + OwnedUserOutputAccess + ProcessRootReservation,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const REGION_OBJECTS: usize,
    const REGION_SLOTS: usize,
    const SPACES: usize,
    const REGIONS: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    regions: &mut AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
    spaces: &mut AddressSpaceAuthority<SPACES, REGIONS>,
    current_process: ProcessKey,
    args_address: DwUserAddress,
    args_size: u64,
    out_result: DwUserAddress,
    result_size: u64,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    process_create_transaction(
        user,
        registry,
        tasks,
        regions,
        spaces,
        current_process,
        args_address,
        args_size,
        out_result,
        result_size,
        cleanup,
        |access, process, address_space| access.reserve_child_root(process, address_space),
        |access, process, address_space| access.rollback_empty_child_root(process, address_space),
        |_| Ok(()),
        |_| {},
    )
}

/// Private evidence-selector live process construction with an exact
/// kernel-commit observer. The observer sees the child only after its Process
/// and root objects commit, but before parent result handles and user output
/// publish; it is not a completed-syscall notification. Any later invariant
/// failure is terminal, so the captured identity cannot reach reporter
/// authorization.
#[cfg(any(
    deepwyrm_wyr1_evidence,
    deepwyrm_dw1b_evidence,
    deepwyrm_wyr1b_evidence
))]
#[allow(
    clippy::too_many_arguments,
    reason = "the selector-local observer preserves the live F10 transaction boundaries"
)]
pub(crate) fn process_create_with_root_observed<
    U: UserPageAccess + OwnedUserOutputAccess + ProcessRootReservation,
    O: FnOnce(ProcessKey),
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const REGION_OBJECTS: usize,
    const REGION_SLOTS: usize,
    const SPACES: usize,
    const REGIONS: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    regions: &mut AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
    spaces: &mut AddressSpaceAuthority<SPACES, REGIONS>,
    current_process: ProcessKey,
    args_address: DwUserAddress,
    args_size: u64,
    out_result: DwUserAddress,
    result_size: u64,
    cleanup: &mut CleanupQueue<OBJECTS>,
    observe_committed_process: O,
) -> DwStatus {
    process_create_transaction(
        user,
        registry,
        tasks,
        regions,
        spaces,
        current_process,
        args_address,
        args_size,
        out_result,
        result_size,
        cleanup,
        |access, process, address_space| access.reserve_child_root(process, address_space),
        |access, process, address_space| access.rollback_empty_child_root(process, address_space),
        |_| Ok(()),
        observe_committed_process,
    )
}

pub(crate) fn channel_create<
    U: UserPageBatchAccess,
    const OBJECTS: usize,
    const PAIRS: usize,
    const DEPTH: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    channels: &ChannelAuthority<PAIRS, DEPTH>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    current_process: ProcessKey,
    requested_rights: DwRights,
    out_endpoint0: DwUserAddress,
    out_endpoint1: DwUserAddress,
) -> DwStatus {
    if let Err(status) = validate_created_handle_rights(DW_OBJECT_TYPE_CHANNEL, requested_rights) {
        return status;
    }
    let first_range = match user_range(out_endpoint0, 8, 8, UserAccess::WRITE) {
        Ok(range) => range,
        Err(status) => return status,
    };
    let second_range = match user_range(out_endpoint1, 8, 8, UserAccess::WRITE) {
        Ok(range) => range,
        Err(status) => return status,
    };
    let outputs = match preflight_outputs(
        user,
        [Some((first_range, 8)), Some((second_range, 8)), None],
    ) {
        Ok(outputs) => outputs,
        Err(status) => return status,
    };
    let mut reservation = match tasks.process_handles_mut(current_process) {
        Ok(table) => match table.reserve_pair(DW_OBJECT_TYPE_CHANNEL, requested_rights) {
            Ok(reservation) => reservation,
            Err(error) => return handle_status(error),
        },
        Err(error) => return task_status(error),
    };
    let (_keys, references) = match channels.create_pair(registry) {
        Ok(pair) => pair,
        Err(error) => {
            cancel_pair_destination(&mut reservation, tasks, current_process);
            return channel_create_status(error);
        }
    };
    let [first_reference, second_reference] = references;
    let handles = tasks
        .process_handles_mut(current_process)
        .unwrap_or_else(|error| {
            panic!("F5 Channel caller changed during reserved creation: {error:?}")
        })
        .try_publish_reserved_pair(&mut reservation, first_reference, second_reference)
        .unwrap_or_else(|failure| {
            panic!(
                "F5 Channel destination permits diverged at publication: {:?}",
                failure.error()
            )
        });
    let first_bytes = encode_handle(handles[0]);
    let second_bytes = encode_handle(handles[1]);
    outputs.commit([Some(&first_bytes), Some(&second_bytes), None]);
    DW_STATUS_SUCCESS
}

pub(crate) fn channel_send<
    U: UserPageAccess,
    const OBJECTS: usize,
    const PAIRS: usize,
    const DEPTH: usize,
    const WAITERS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EXECUTION: usize,
>(
    user: &mut U,
    staging: &mut [u8],
    registry: &mut ObjectRegistry<OBJECTS>,
    channels: &ChannelAuthority<PAIRS, DEPTH>,
    waits: &WaitRegistry<WAITERS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    current_process: ProcessKey,
    channel: DwHandle,
    bytes: DwUserAddress,
    byte_len: u32,
    transfers: DwUserAddress,
    transfer_count: u32,
    flags: u64,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    if byte_len > DW_CHANNEL_MAX_PAYLOAD || transfer_count > DW_CHANNEL_MAX_HANDLES || flags != 0 {
        return DW_STATUS_INVALID_ARGUMENT;
    }

    let transfer_count = transfer_count as usize;
    let transfer_byte_len = transfer_count
        .checked_mul(DW_HANDLE_TRANSFER_V1_SIZE as usize)
        .expect("generated Channel transfer count fits usize");
    let transfer_range =
        match channel_buffer_range(transfers, transfer_byte_len, 8, UserAccess::READ) {
            Ok(range) => range,
            Err(status) => return status,
        };
    let mut transfer_staging = [0_u8; HANDLE_TRANSFER_LIMIT * HANDLE_TRANSFER_BYTES];
    if let Err(error) = snapshot_from_user(
        user,
        transfer_range,
        &mut transfer_staging[..transfer_byte_len],
    ) {
        return usercopy_status(error);
    }
    let mut decoded = [DwHandleTransferV1::default(); HANDLE_TRANSFER_LIMIT];
    for (index, record) in decoded[..transfer_count].iter_mut().enumerate() {
        let start = index * HANDLE_TRANSFER_BYTES;
        let bytes: &[u8; HANDLE_TRANSFER_BYTES] = transfer_staging
            [start..start + HANDLE_TRANSFER_BYTES]
            .try_into()
            .expect("transfer staging record has generated fixed width");
        *record = decode_handle_transfer(bytes);
        if record.reserved0 != 0 || record.reserved.iter().any(|value| *value != 0) {
            return DW_STATUS_INVALID_ARGUMENT;
        }
    }
    for left in 0..transfer_count {
        for right in left + 1..transfer_count {
            if decoded[left].handle == decoded[right].handle {
                return DW_STATUS_INVALID_ARGUMENT;
            }
        }
    }
    if decoded[..transfer_count]
        .iter()
        .any(|record| record.operation != DW_HANDLE_TRANSFER_MOVE)
    {
        return DW_STATUS_INVALID_ARGUMENT;
    }

    let byte_len = byte_len as usize;
    assert!(
        staging.len() >= DW_CHANNEL_MAX_PAYLOAD as usize,
        "F6 Channel staging must hold one ABI-maximum payload"
    );
    let range = match channel_buffer_range(bytes, byte_len, 1, UserAccess::READ) {
        Ok(range) => range,
        Err(status) => return status,
    };
    if let Err(error) = snapshot_from_user(user, range, &mut staging[..byte_len]) {
        return usercopy_status(error);
    }

    let pin = match resolve_current_handle(
        tasks,
        registry,
        current_process,
        channel,
        DW_OBJECT_TYPE_CHANNEL,
        DW_RIGHT_WRITE,
    ) {
        Ok(pin) => pin,
        Err(status) => return status,
    };
    let endpoint = ChannelEndpointKey::from_object_id(pin.id());
    let mut move_requests = [HandleMoveRequest {
        handle: DwHandle(0),
        requested_rights: DwRights(0),
    }; HANDLE_TRANSFER_LIMIT];
    for index in 0..transfer_count {
        move_requests[index] = HandleMoveRequest {
            handle: decoded[index].handle,
            requested_rights: decoded[index].requested_rights,
        };
    }

    let table = match tasks.process_handles_mut(current_process) {
        Ok(table) => table,
        Err(error) => {
            release_lookup_pin(registry, pin, cleanup);
            return task_status(error);
        }
    };
    let prepared = match table.prepare_move_batch(&move_requests[..transfer_count]) {
        Ok(prepared) => prepared,
        Err(error) => {
            release_lookup_pin(registry, pin, cleanup);
            return handle_move_status(error);
        }
    };
    let peer_object = match channels.peer_object(endpoint) {
        Ok(peer) => peer,
        Err(error) => {
            drop(prepared);
            release_lookup_pin(registry, pin, cleanup);
            return channel_status(error);
        }
    };
    if prepared.contains_object(peer_object) {
        drop(prepared);
        release_lookup_pin(registry, pin, cleanup);
        return DW_STATUS_INVALID_ARGUMENT;
    }
    match channels.transfer_would_close_queue_cycle(
        endpoint,
        prepared.objects_of_type(DW_OBJECT_TYPE_CHANNEL),
    ) {
        Ok(false) => {}
        Ok(true) => {
            drop(prepared);
            release_lookup_pin(registry, pin, cleanup);
            return DW_STATUS_INVALID_ARGUMENT;
        }
        Err(error) => {
            drop(prepared);
            release_lookup_pin(registry, pin, cleanup);
            return channel_status(error);
        }
    }
    let send_reservation = match channels.reserve_send(endpoint, &staging[..byte_len]) {
        Ok(reservation) => reservation,
        Err(error) => {
            drop(prepared);
            release_lookup_pin(registry, pin, cleanup);
            return channel_status(error);
        }
    };
    let (rollback, transfer_batch) = prepared.extract();
    match channels.commit_send(send_reservation, transfer_batch, waits) {
        Ok(wakes) => {
            rollback.finish();
            release_lookup_pin(registry, pin, cleanup);
            complete_wait_wakes(registry, execution, wakes, cleanup);
            DW_STATUS_SUCCESS
        }
        Err((error, transfer_batch)) => {
            rollback.rollback(transfer_batch);
            release_lookup_pin(registry, pin, cleanup);
            channel_status(error)
        }
    }
}

fn channel_receive_result(
    required_bytes: u32,
    actual_bytes: u32,
    required_handles: u32,
    actual_handles: u32,
) -> DwChannelReceiveResultV1 {
    DwChannelReceiveResultV1 {
        size: DW_CHANNEL_RECEIVE_RESULT_V1_SIZE,
        version: 1,
        actual_bytes,
        actual_handles,
        required_bytes,
        required_handles,
        reserved: [0; 4],
    }
}

pub(crate) fn channel_receive<
    U: UserPageBatchAccess,
    const OBJECTS: usize,
    const PAIRS: usize,
    const DEPTH: usize,
    const WAITERS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EXECUTION: usize,
>(
    user: &mut U,
    staging: &mut [u8],
    registry: &mut ObjectRegistry<OBJECTS>,
    channels: &ChannelAuthority<PAIRS, DEPTH>,
    waits: &WaitRegistry<WAITERS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    current_process: ProcessKey,
    channel: DwHandle,
    out_bytes: DwUserAddress,
    byte_capacity: u32,
    out_handles: DwUserAddress,
    handle_capacity: u32,
    out_result: DwUserAddress,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    if byte_capacity > DW_CHANNEL_MAX_PAYLOAD || handle_capacity > DW_CHANNEL_MAX_HANDLES {
        return DW_STATUS_INVALID_ARGUMENT;
    }
    let result_probe = match preflight_output(
        user,
        out_result,
        DW_CHANNEL_RECEIVE_RESULT_V1_SIZE as usize,
        8,
    ) {
        Ok(output) => output,
        Err(status) => return status,
    };
    drop(result_probe);

    let pin = match resolve_current_handle(
        tasks,
        registry,
        current_process,
        channel,
        DW_OBJECT_TYPE_CHANNEL,
        DW_RIGHT_READ,
    ) {
        Ok(pin) => pin,
        Err(status) => return status,
    };
    let endpoint = ChannelEndpointKey::from_object_id(pin.id());
    let reservation = match channels.reserve_receive(endpoint) {
        Ok(reservation) => reservation,
        Err(error) => {
            release_lookup_pin(registry, pin, cleanup);
            return channel_status(error);
        }
    };
    let info = reservation.info();

    if info.required_bytes > byte_capacity || info.required_handles > handle_capacity {
        let output = match preflight_output(
            user,
            out_result,
            DW_CHANNEL_RECEIVE_RESULT_V1_SIZE as usize,
            8,
        ) {
            Ok(output) => output,
            Err(status) => {
                channels
                    .cancel_receive(reservation)
                    .unwrap_or_else(|error| {
                        panic!("F6 receive reservation cancellation drifted: {error:?}")
                    });
                release_lookup_pin(registry, pin, cleanup);
                return status;
            }
        };
        let result = channel_receive_result(info.required_bytes, 0, info.required_handles, 0);
        output.commit(&encode_channel_receive_result(result));
        channels
            .cancel_receive(reservation)
            .unwrap_or_else(|error| {
                panic!("F6 receive reservation cancellation drifted: {error:?}")
            });
        release_lookup_pin(registry, pin, cleanup);
        return DW_STATUS_BUFFER_TOO_SMALL;
    }

    let byte_bytes = info.required_bytes as usize;
    let handle_count = info.required_handles as usize;
    let handle_bytes = handle_count
        .checked_mul(DW_RECEIVED_HANDLE_INFO_V1_SIZE as usize)
        .expect("generated Channel handle capacity fits usize");
    let byte_range = match channel_buffer_range(out_bytes, byte_bytes, 1, UserAccess::WRITE) {
        Ok(range) => range,
        Err(status) => {
            channels
                .cancel_receive(reservation)
                .unwrap_or_else(|error| {
                    panic!("F6 receive reservation cancellation drifted: {error:?}")
                });
            release_lookup_pin(registry, pin, cleanup);
            return status;
        }
    };
    let handle_range = match channel_buffer_range(out_handles, handle_bytes, 8, UserAccess::WRITE) {
        Ok(range) => range,
        Err(status) => {
            channels
                .cancel_receive(reservation)
                .unwrap_or_else(|error| {
                    panic!("F6 receive reservation cancellation drifted: {error:?}")
                });
            release_lookup_pin(registry, pin, cleanup);
            return status;
        }
    };
    let result_range = match user_range(
        out_result,
        DW_CHANNEL_RECEIVE_RESULT_V1_SIZE as usize,
        8,
        UserAccess::WRITE,
    ) {
        Ok(range) => range,
        Err(status) => {
            channels
                .cancel_receive(reservation)
                .unwrap_or_else(|error| {
                    panic!("F6 receive reservation cancellation drifted: {error:?}")
                });
            release_lookup_pin(registry, pin, cleanup);
            return status;
        }
    };
    let outputs = match preflight_outputs(
        user,
        [
            Some((byte_range, byte_bytes)),
            Some((handle_range, handle_bytes)),
            Some((result_range, DW_CHANNEL_RECEIVE_RESULT_V1_SIZE as usize)),
        ],
    ) {
        Ok(outputs) => outputs,
        Err(status) => {
            channels
                .cancel_receive(reservation)
                .unwrap_or_else(|error| {
                    panic!("F6 receive reservation cancellation drifted: {error:?}")
                });
            release_lookup_pin(registry, pin, cleanup);
            return status;
        }
    };
    assert!(
        staging.len() >= DW_CHANNEL_MAX_PAYLOAD as usize,
        "F6 Channel staging must hold one ABI-maximum payload"
    );

    let table = match tasks.process_handles_mut(current_process) {
        Ok(table) => table,
        Err(error) => {
            drop(outputs);
            channels
                .cancel_receive(reservation)
                .unwrap_or_else(|channel_error| {
                    panic!("F6 receive reservation cancellation drifted: {channel_error:?}")
                });
            release_lookup_pin(registry, pin, cleanup);
            return task_status(error);
        }
    };
    let destination = match table.reserve_transfer_batch(handle_count) {
        Ok(reservation) => reservation,
        Err(error) => {
            drop(outputs);
            channels
                .cancel_receive(reservation)
                .unwrap_or_else(|channel_error| {
                    panic!("F6 receive reservation cancellation drifted: {channel_error:?}")
                });
            release_lookup_pin(registry, pin, cleanup);
            return handle_status(error);
        }
    };
    let received = match channels.receive_reserved(reservation, &mut staging[..byte_bytes], waits) {
        Ok(received) => received,
        Err(error) => {
            drop(destination);
            drop(outputs);
            release_lookup_pin(registry, pin, cleanup);
            return channel_status(error);
        }
    };
    let (actual, transfer_batch, wakes) = received.into_parts();
    let published = destination.publish(transfer_batch);

    let mut received_handle_bytes =
        [0_u8; HANDLE_TRANSFER_LIMIT * DW_RECEIVED_HANDLE_INFO_V1_SIZE as usize];
    for (index, info) in published[..handle_count]
        .iter()
        .flatten()
        .copied()
        .enumerate()
    {
        let encoded = encode_received_handle_info(DwReceivedHandleInfoV1 {
            handle: info.handle,
            rights: info.rights,
            object_type: info.object_type,
            reserved0: 0,
            reserved: [0; 2],
        });
        let start = index * DW_RECEIVED_HANDLE_INFO_V1_SIZE as usize;
        received_handle_bytes[start..start + DW_RECEIVED_HANDLE_INFO_V1_SIZE as usize]
            .copy_from_slice(&encoded);
    }
    let actual_u32 = u32::try_from(actual).expect("Channel receive length fits generated u32");
    let actual_handles = u32::try_from(handle_count).expect("Channel transfer count fits u32");
    let result = channel_receive_result(actual_u32, actual_u32, actual_handles, actual_handles);
    let result_bytes = encode_channel_receive_result(result);
    outputs.commit_prefixes([
        Some(&staging[..actual]),
        Some(&received_handle_bytes[..handle_bytes]),
        Some(&result_bytes),
    ]);
    release_lookup_pin(registry, pin, cleanup);
    complete_wait_wakes(registry, execution, wakes, cleanup);
    DW_STATUS_SUCCESS
}

pub(crate) fn complete_wait_wakes<
    const OBJECTS: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    execution: &ExecutionDomain<EXECUTION>,
    wakes: WakeBatch<WAITERS>,
    cleanup: &mut CleanupQueue<OBJECTS>,
) {
    let (wake_intents, wait_pins) = wakes.into_parts();
    for wake in wake_intents.into_iter().flatten() {
        execution
            .validate_issued_wake_key(wake.wake_key())
            .unwrap_or_else(|error| {
                panic!("wait registration carried a foreign or unissued wake key: {error:?}")
            });
        let winner = crate::task::BlockedOperationWinner::Signal {
            item_index: wake.item_index(),
            observed: wake.observed(),
        };
        match execution
            .blocked_operations()
            .try_claim_winner(wake.wake_key(), winner)
        {
            Ok(true) => match execution.wake(wake.wake_key()) {
                Ok(()) | Err(SchedulerError::StaleBlockToken) => {}
                Err(error) => {
                    panic!("waiter wake violated scheduler ownership: {error:?}")
                }
            },
            Ok(false) | Err(crate::task::BlockedOperationError::StaleReservation) => {
                // A timeout/terminal path already won this exact block
                // generation, or its resumed/terminal owner already completed
                // the ledger. `take_ready` still consumed the registrations,
                // so only their pins need deferred release below. A signal may
                // also win before `commit_block`; that path observes the winner
                // ledger and cancels the still-pending scheduler reservation.
            }
            Err(error) => panic!("blocked wait winner arbitration failed: {error:?}"),
        }
    }
    for pin in wait_pins.into_iter().flatten() {
        release_lookup_pin(registry, pin, cleanup);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WaitSuspendState {
    wake: BlockWakeKey,
    decision: ScheduleDecision,
}

impl WaitSuspendState {
    pub(crate) const fn new(wake: BlockWakeKey, decision: ScheduleDecision) -> Self {
        Self { wake, decision }
    }

    pub(crate) const fn wake_key(self) -> BlockWakeKey {
        self.wake
    }

    pub(crate) const fn decision(self) -> ScheduleDecision {
        self.decision
    }

    pub(crate) const fn cancelled_quantum(self) -> Option<crate::task::SchedulerQuantumTicket> {
        self.decision.cancelled_quantum
    }
}

#[must_use = "native wait dispatch must either return to userspace or consume the suspension state"]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WaitSyscallAction {
    Returning(DwStatus),
    Suspended(WaitSuspendState),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WaitSuspendError {
    InvalidDecision,
    Scheduler(SchedulerError),
    Switch(ExecutionSwitchError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeWaitControlState {
    Clear,
    Pending(WaitSuspendState),
    Idle(WaitSuspendState),
}

/// Ephemeral control-plane state between native wait dispatch and the raw
/// suspension trampoline. Durable output/deadline/winner ownership remains in
/// `WaitOperationRegistry`; this owner carries only the current control-flow
/// decision until it is consumed by `prepare_suspend` or the idle IRQ loop.
pub(crate) struct NativeWaitControl {
    state: NativeWaitControlState,
}

impl NativeWaitControl {
    pub(crate) const fn pending_quantum_cancellation(
        &self,
    ) -> Option<crate::task::SchedulerQuantumTicket> {
        match self.state {
            NativeWaitControlState::Pending(state) => state.cancelled_quantum(),
            NativeWaitControlState::Clear | NativeWaitControlState::Idle(_) => None,
        }
    }

    pub(crate) const fn new() -> Self {
        Self {
            state: NativeWaitControlState::Clear,
        }
    }

    #[cfg(deepwyrm_i1_evidence)]
    pub(crate) const fn pending_wake_key(&self) -> Option<BlockWakeKey> {
        match self.state {
            NativeWaitControlState::Pending(state) | NativeWaitControlState::Idle(state) => {
                Some(state.wake_key())
            }
            NativeWaitControlState::Clear => None,
        }
    }

    pub(crate) fn accept(&mut self, action: WaitSyscallAction) -> NativeSyscallResult {
        assert_eq!(
            self.state,
            NativeWaitControlState::Clear,
            "native wait control already owns an unconsumed suspension"
        );
        match action {
            WaitSyscallAction::Returning(status) => NativeSyscallResult::returning(status),
            WaitSyscallAction::Suspended(state) => {
                self.state = NativeWaitControlState::Pending(state);
                NativeSyscallResult {
                    status: DW_STATUS_SUCCESS,
                    control: SyscallControl::SuspendCurrent,
                }
            }
        }
    }

    #[allow(
        unsafe_code,
        reason = "the caller must prove the pending scheduler carrier and fixed first-run entry before plan production"
    )]
    /// # Safety
    ///
    /// The pending decision's previous Thread must own the kernel stack that is
    /// physically executing this call. `trusted_first_run_entry` must be the
    /// architecture-owned fixed first-run entry.
    pub(crate) unsafe fn prepare_suspend<
        'owner,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
        const EXECUTION: usize,
    >(
        &mut self,
        tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        execution: &'owner ExecutionDomain<EXECUTION>,
        trusted_first_run_entry: u64,
    ) -> Result<NativeSuspendPlan<'owner>, WaitSuspendError> {
        let NativeWaitControlState::Pending(state) = self.state else {
            return Err(WaitSuspendError::InvalidDecision);
        };
        let plan =
            unsafe { prepare_wait_suspend_plan(tasks, execution, state, trusted_first_run_entry) }?;
        self.state = match &plan {
            NativeSuspendPlan::IdleCurrent => NativeWaitControlState::Idle(state),
            NativeSuspendPlan::Switch(_) => NativeWaitControlState::Clear,
        };
        Ok(plan)
    }

    #[allow(
        unsafe_code,
        reason = "the caller must prove the CPU-owned pending scheduler carrier and fixed first-run entry before plan production"
    )]
    pub(crate) unsafe fn prepare_suspend_on<
        'owner,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
        const EXECUTION: usize,
    >(
        &mut self,
        cpu: crate::cpu::CpuIndex,
        tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        execution: &'owner ExecutionDomain<EXECUTION>,
        trusted_first_run_entry: u64,
    ) -> Result<NativeSuspendPlan<'owner>, WaitSuspendError> {
        let NativeWaitControlState::Pending(state) = self.state else {
            return Err(WaitSuspendError::InvalidDecision);
        };
        let plan = unsafe {
            prepare_wait_suspend_plan_on(tasks, execution, cpu, state, trusted_first_run_entry)
        }?;
        self.state = match &plan {
            NativeSuspendPlan::IdleCurrent => NativeWaitControlState::Idle(state),
            NativeSuspendPlan::Switch(_) => NativeWaitControlState::Clear,
        };
        Ok(plan)
    }

    #[allow(
        unsafe_code,
        reason = "the caller must prove the physically active idle carrier and fixed first-run entry before plan production"
    )]
    /// # Safety
    ///
    /// The idle state's previous Thread must still own the physically active
    /// suspended continuation. `trusted_first_run_entry` must be the
    /// architecture-owned fixed first-run entry.
    pub(crate) unsafe fn poll_idle<
        'owner,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
        const EXECUTION: usize,
    >(
        &mut self,
        tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        execution: &'owner ExecutionDomain<EXECUTION>,
        trusted_first_run_entry: u64,
    ) -> Result<NativeIdleSuspendPoll<'owner>, WaitSuspendError> {
        let NativeWaitControlState::Idle(state) = self.state else {
            return Err(WaitSuspendError::InvalidDecision);
        };
        let poll =
            unsafe { poll_wait_idle_suspend(tasks, execution, state, trusted_first_run_entry) }?;
        if !matches!(poll, NativeIdleSuspendPoll::Continue) {
            self.state = NativeWaitControlState::Clear;
        }
        Ok(poll)
    }

    #[allow(
        unsafe_code,
        reason = "the caller must prove the CPU-owned physically active idle carrier and fixed first-run entry before plan production"
    )]
    pub(crate) unsafe fn poll_idle_on<
        'owner,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
        const EXECUTION: usize,
    >(
        &mut self,
        cpu: crate::cpu::CpuIndex,
        tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        execution: &'owner ExecutionDomain<EXECUTION>,
        trusted_first_run_entry: u64,
    ) -> Result<NativeIdleSuspendPoll<'owner>, WaitSuspendError> {
        let NativeWaitControlState::Idle(state) = self.state else {
            return Err(WaitSuspendError::InvalidDecision);
        };
        let poll = unsafe {
            poll_wait_idle_suspend_on(tasks, execution, cpu, state, trusted_first_run_entry)
        }?;
        if !matches!(poll, NativeIdleSuspendPoll::Continue) {
            self.state = NativeWaitControlState::Clear;
        }
        Ok(poll)
    }

    pub(crate) const fn is_clear(&self) -> bool {
        matches!(self.state, NativeWaitControlState::Clear)
    }

    /// Consumes only the exact idle control handoff retained by a physical
    /// blocked continuation that an e1 safe point is about to retire.
    pub(crate) fn retire_idle_for_stop(
        &mut self,
        thread: ThreadKey,
        execution_generation: u64,
    ) -> Result<(), WaitSuspendError> {
        let NativeWaitControlState::Idle(state) = self.state else {
            return Err(WaitSuspendError::InvalidDecision);
        };
        let wake = state.wake_key();
        if wake.thread() != thread || wake.execution_generation() != execution_generation {
            return Err(WaitSuspendError::InvalidDecision);
        }
        self.state = NativeWaitControlState::Clear;
        Ok(())
    }
}

#[allow(
    unsafe_code,
    reason = "the returned lifetime-branded plan carries the execution-owner borrow through every facade to immediate F7 switch consumption"
)]
/// # Safety
///
/// `state.decision().previous` must name the Thread whose kernel stack is
/// physically executing this call. `trusted_first_run_entry` must be the fixed
/// architecture-owned first-run entry for scheduler-selected fresh Threads.
pub(crate) unsafe fn prepare_wait_suspend_plan<
    'owner,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EXECUTION: usize,
>(
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &'owner ExecutionDomain<EXECUTION>,
    state: WaitSuspendState,
    trusted_first_run_entry: u64,
) -> Result<NativeSuspendPlan<'owner>, WaitSuspendError> {
    let decision = state.decision();
    if decision.previous.is_none() {
        return Err(WaitSuspendError::InvalidDecision);
    }
    if decision.current.is_none() {
        return Ok(NativeSuspendPlan::IdleCurrent);
    }
    let plan = unsafe {
        execution.prepare_blocking_kernel_switch(tasks, decision, trusted_first_run_entry)
    }
    .map_err(WaitSuspendError::Switch)?;
    Ok(NativeSuspendPlan::Switch(plan))
}

#[allow(
    unsafe_code,
    reason = "the returned lifetime-branded plan carries the CPU-owned execution borrow to immediate switch consumption"
)]
pub(crate) unsafe fn prepare_wait_suspend_plan_on<
    'owner,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EXECUTION: usize,
>(
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &'owner ExecutionDomain<EXECUTION>,
    cpu: crate::cpu::CpuIndex,
    state: WaitSuspendState,
    trusted_first_run_entry: u64,
) -> Result<NativeSuspendPlan<'owner>, WaitSuspendError> {
    let decision = state.decision();
    if decision.previous.is_none() {
        return Err(WaitSuspendError::InvalidDecision);
    }
    if decision.current.is_none() {
        return Ok(NativeSuspendPlan::IdleCurrent);
    }
    let plan = unsafe {
        execution.prepare_blocking_kernel_switch_on(tasks, cpu, decision, trusted_first_run_entry)
    }
    .map_err(WaitSuspendError::Switch)?;
    Ok(NativeSuspendPlan::Switch(plan))
}

#[allow(
    unsafe_code,
    reason = "the idle continuation identity is runtime-proven and the returned plan brands its execution owner through immediate switch consumption"
)]
/// # Safety
///
/// The suspended Thread named by `state` must still own the physically active
/// idle continuation, even if it became logically runnable. The entry argument
/// must be the fixed architecture-owned first-run entry.
pub(crate) unsafe fn poll_wait_idle_suspend<
    'owner,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EXECUTION: usize,
>(
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &'owner ExecutionDomain<EXECUTION>,
    state: WaitSuspendState,
    trusted_first_run_entry: u64,
) -> Result<NativeIdleSuspendPoll<'owner>, WaitSuspendError> {
    let suspended = state
        .decision()
        .previous
        .ok_or(WaitSuspendError::InvalidDecision)?;
    match execution
        .schedule_from_idle(suspended)
        .map_err(WaitSuspendError::Scheduler)?
    {
        IdleScheduleDecision::ContinueIdle => Ok(NativeIdleSuspendPoll::Continue),
        IdleScheduleDecision::ResumeCurrent => Ok(NativeIdleSuspendPoll::ResumeCurrent),
        IdleScheduleDecision::Switch(decision) => {
            let plan = unsafe {
                execution.prepare_idle_blocking_kernel_switch(
                    tasks,
                    decision,
                    trusted_first_run_entry,
                )
            }
            .map_err(WaitSuspendError::Switch)?;
            Ok(NativeIdleSuspendPoll::Switch(plan))
        }
    }
}

#[allow(
    unsafe_code,
    reason = "the returned lifetime-branded idle plan retains the exact CPU-owned continuation through switch consumption"
)]
pub(crate) unsafe fn poll_wait_idle_suspend_on<
    'owner,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EXECUTION: usize,
>(
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &'owner ExecutionDomain<EXECUTION>,
    cpu: crate::cpu::CpuIndex,
    state: WaitSuspendState,
    trusted_first_run_entry: u64,
) -> Result<NativeIdleSuspendPoll<'owner>, WaitSuspendError> {
    let suspended = state
        .decision()
        .previous
        .ok_or(WaitSuspendError::InvalidDecision)?;
    match execution
        .schedule_from_idle_on(cpu, suspended)
        .map_err(WaitSuspendError::Scheduler)?
    {
        IdleScheduleDecision::ContinueIdle => Ok(NativeIdleSuspendPoll::Continue),
        IdleScheduleDecision::ResumeCurrent => Ok(NativeIdleSuspendPoll::ResumeCurrent),
        IdleScheduleDecision::Switch(decision) => {
            let plan = unsafe {
                execution.prepare_idle_blocking_kernel_switch_on(
                    tasks,
                    cpu,
                    decision,
                    trusted_first_run_entry,
                )
            }
            .map_err(WaitSuspendError::Switch)?;
            Ok(NativeIdleSuspendPoll::Switch(plan))
        }
    }
}

#[must_use = "wait begin outcomes either return the output authority or transfer it to a suspended operation"]
pub(crate) enum WaitSyscallBegin<OUTPUT> {
    Returning {
        status: DwStatus,
        output: OUTPUT,
        result: Option<[u8; DW_WAIT_RESULT_V1_SIZE as usize]>,
    },
    Suspended {
        wake: BlockWakeKey,
        decision: ScheduleDecision,
    },
}

fn wait_result(index: u32, observed: DwSignals) -> [u8; DW_WAIT_RESULT_V1_SIZE as usize] {
    encode_wait_result(DwWaitResultV1 {
        size: DW_WAIT_RESULT_V1_SIZE,
        version: 1,
        index,
        reserved0: 0,
        observed,
        reserved: [0; 3],
    })
}

fn wait_set_status(error: WaitSetError) -> DwStatus {
    match error {
        WaitSetError::Task(error) => task_status(error),
        WaitSetError::Handle(error) => handle_status(error),
        WaitSetError::Wait(WaitError::InvalidSignals) => DW_STATUS_INVALID_ARGUMENT,
        WaitSetError::Wait(WaitError::UnsupportedSource) => DW_STATUS_NOT_SUPPORTED,
        WaitSetError::Wait(_) | WaitSetError::StateDrift => DW_STATUS_BAD_STATE,
        WaitSetError::Channel(error) => channel_status(error),
        WaitSetError::Timer(error) => timer_status(error),
    }
}

fn wait_begin_status(error: WaitBeginError) -> DwStatus {
    match error {
        WaitBeginError::Set(error) => wait_set_status(error),
        WaitBeginError::Scheduler(SchedulerError::Capacity)
        | WaitBeginError::Blocked(crate::task::BlockedOperationError::Capacity)
        | WaitBeginError::Operation(crate::wait::operation::WaitOperationError::Capacity)
        | WaitBeginError::Deadline(crate::wait::engine::WaitDeadlineError::Capacity) => {
            DW_STATUS_NO_RESOURCES
        }
        WaitBeginError::Deadline(crate::wait::engine::WaitDeadlineError::Expired) => {
            DW_STATUS_TIMED_OUT
        }
        _ => DW_STATUS_BAD_STATE,
    }
}

const fn wait_deadline(deadline: DwDeadline) -> WaitDeadline {
    if deadline.0 == deepwyrm_abi::DW_DEADLINE_NOW.0 {
        WaitDeadline::Now
    } else if deadline.0 == deepwyrm_abi::DW_DEADLINE_INFINITE.0 {
        WaitDeadline::Infinite
    } else {
        WaitDeadline::Finite(deadline.0)
    }
}

fn begin_wait_set<
    OUTPUT,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EVENTS: usize,
    const TIMERS: usize,
    const CHANNEL_PAIRS: usize,
    const CHANNEL_DEPTH: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    set: ResolvedWaitSet,
    output: OUTPUT,
    deadline: DwDeadline,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    events: &EventAuthority<EVENTS>,
    timers: &TimerAuthority<TIMERS>,
    channels: &ChannelAuthority<CHANNEL_PAIRS, CHANNEL_DEPTH>,
    waits: &WaitRegistry<WAITERS>,
    execution: &ExecutionDomain<EXECUTION>,
    operations: &mut WaitOperationRegistry<OUTPUT, EXECUTION>,
    deadline_authority: Option<&mut dyn WaitDeadlineAuthority>,
    current_cpu: crate::cpu::CpuIndex,
    process: ProcessKey,
    thread: ThreadKey,
) -> WaitSyscallBegin<OUTPUT> {
    match begin_registered_wait(
        set,
        output,
        wait_deadline(deadline),
        WaitBeginContext {
            registry,
            tasks,
            sources: WaitSources {
                events,
                timers,
                channels,
                waits,
            },
            execution,
            operations,
            cpu: current_cpu,
            process,
            thread,
        },
        deadline_authority,
    ) {
        Ok(WaitBeginOutcome::Ready { output, selection }) => WaitSyscallBegin::Returning {
            status: DW_STATUS_SUCCESS,
            output,
            result: Some(wait_result(selection.index, selection.observed)),
        },
        Ok(WaitBeginOutcome::TimedOut { output }) => WaitSyscallBegin::Returning {
            status: DW_STATUS_TIMED_OUT,
            output,
            result: None,
        },
        Ok(WaitBeginOutcome::Suspended { wake, decision }) => {
            WaitSyscallBegin::Suspended { wake, decision }
        }
        Err(failure) => WaitSyscallBegin::Returning {
            status: wait_begin_status(failure.error),
            output: failure.output,
            result: None,
        },
    }
}

pub(crate) fn wait_one_begin<
    OUTPUT,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EVENTS: usize,
    const TIMERS: usize,
    const CHANNEL_PAIRS: usize,
    const CHANNEL_DEPTH: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    output: OUTPUT,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    events: &EventAuthority<EVENTS>,
    timers: &TimerAuthority<TIMERS>,
    channels: &ChannelAuthority<CHANNEL_PAIRS, CHANNEL_DEPTH>,
    waits: &WaitRegistry<WAITERS>,
    execution: &ExecutionDomain<EXECUTION>,
    operations: &mut WaitOperationRegistry<OUTPUT, EXECUTION>,
    deadline_authority: Option<&mut dyn WaitDeadlineAuthority>,
    current_cpu: crate::cpu::CpuIndex,
    process: ProcessKey,
    thread: ThreadKey,
    handle: DwHandle,
    signals: DwSignals,
    deadline: DwDeadline,
) -> WaitSyscallBegin<OUTPUT> {
    let request = [DwWaitItemV1 { handle, signals }];
    match ResolvedWaitSet::resolve(tasks, registry, process, &request) {
        Ok(set) => begin_wait_set(
            set,
            output,
            deadline,
            registry,
            tasks,
            events,
            timers,
            channels,
            waits,
            execution,
            operations,
            deadline_authority,
            current_cpu,
            process,
            thread,
        ),
        Err(error) => WaitSyscallBegin::Returning {
            status: wait_set_status(error),
            output,
            result: None,
        },
    }
}

fn validate_wait_many_shape(item_count: u32, mode: u32) -> Result<usize, DwStatus> {
    if item_count == 0 || item_count > DW_WAIT_MANY_MAX_ITEMS {
        return Err(DW_STATUS_INVALID_ARGUMENT);
    }
    if mode == DW_WAIT_MODE_ALL {
        return Err(DW_STATUS_NOT_SUPPORTED);
    }
    if mode != DW_WAIT_MODE_ANY {
        return Err(DW_STATUS_INVALID_ARGUMENT);
    }
    Ok(item_count as usize)
}

fn snapshot_wait_many_requests<U: UserPageAccess>(
    user: &mut U,
    items: DwUserAddress,
    item_count: u32,
    mode: u32,
) -> Result<([DwWaitItemV1; DW_WAIT_MANY_MAX_ITEMS as usize], usize), DwStatus> {
    let count = validate_wait_many_shape(item_count, mode)?;
    let byte_len = count * WAIT_ITEM_BYTES;
    let range = user_range(items, byte_len, 8, UserAccess::READ)?;
    let mut bytes = [0_u8; DW_WAIT_MANY_MAX_ITEMS as usize * WAIT_ITEM_BYTES];
    snapshot_from_user(user, range, &mut bytes[..byte_len]).map_err(usercopy_status)?;

    let mut requests = [DwWaitItemV1::default(); DW_WAIT_MANY_MAX_ITEMS as usize];
    for (index, request) in requests[..count].iter_mut().enumerate() {
        let start = index * WAIT_ITEM_BYTES;
        let record: &[u8; WAIT_ITEM_BYTES] = bytes[start..start + WAIT_ITEM_BYTES]
            .try_into()
            .expect("wait item staging follows generated fixed width");
        *request = decode_wait_item(record);
        if request.signals.0 == 0 || !deepwyrm_abi::dw_signals_are_known(request.signals) {
            return Err(DW_STATUS_INVALID_ARGUMENT);
        }
    }
    Ok((requests, count))
}

fn wait_many_requests_begin<
    OUTPUT,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EVENTS: usize,
    const TIMERS: usize,
    const CHANNEL_PAIRS: usize,
    const CHANNEL_DEPTH: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    output: OUTPUT,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    events: &EventAuthority<EVENTS>,
    timers: &TimerAuthority<TIMERS>,
    channels: &ChannelAuthority<CHANNEL_PAIRS, CHANNEL_DEPTH>,
    waits: &WaitRegistry<WAITERS>,
    execution: &ExecutionDomain<EXECUTION>,
    operations: &mut WaitOperationRegistry<OUTPUT, EXECUTION>,
    deadline_authority: Option<&mut dyn WaitDeadlineAuthority>,
    current_cpu: crate::cpu::CpuIndex,
    process: ProcessKey,
    thread: ThreadKey,
    requests: &[DwWaitItemV1],
    deadline: DwDeadline,
) -> WaitSyscallBegin<OUTPUT> {
    match ResolvedWaitSet::resolve(tasks, registry, process, requests) {
        Ok(set) => begin_wait_set(
            set,
            output,
            deadline,
            registry,
            tasks,
            events,
            timers,
            channels,
            waits,
            execution,
            operations,
            deadline_authority,
            current_cpu,
            process,
            thread,
        ),
        Err(error) => WaitSyscallBegin::Returning {
            status: wait_set_status(error),
            output,
            result: None,
        },
    }
}

pub(crate) fn wait_many_begin<
    U: UserPageAccess,
    OUTPUT,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EVENTS: usize,
    const TIMERS: usize,
    const CHANNEL_PAIRS: usize,
    const CHANNEL_DEPTH: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    user: &mut U,
    output: OUTPUT,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    events: &EventAuthority<EVENTS>,
    timers: &TimerAuthority<TIMERS>,
    channels: &ChannelAuthority<CHANNEL_PAIRS, CHANNEL_DEPTH>,
    waits: &WaitRegistry<WAITERS>,
    execution: &ExecutionDomain<EXECUTION>,
    operations: &mut WaitOperationRegistry<OUTPUT, EXECUTION>,
    deadline_authority: Option<&mut dyn WaitDeadlineAuthority>,
    current_cpu: crate::cpu::CpuIndex,
    process: ProcessKey,
    thread: ThreadKey,
    items: DwUserAddress,
    item_count: u32,
    mode: u32,
    deadline: DwDeadline,
) -> WaitSyscallBegin<OUTPUT> {
    let (requests, count) = match snapshot_wait_many_requests(user, items, item_count, mode) {
        Ok(requests) => requests,
        Err(status) => {
            return WaitSyscallBegin::Returning {
                status,
                output,
                result: None,
            };
        }
    };
    wait_many_requests_begin(
        output,
        registry,
        tasks,
        events,
        timers,
        channels,
        waits,
        execution,
        operations,
        deadline_authority,
        current_cpu,
        process,
        thread,
        &requests[..count],
        deadline,
    )
}

fn preflight_owned_wait_output<U: OwnedUserOutputAccess>(
    user: &mut U,
    out_result: DwUserAddress,
) -> Result<U::OwnedOutput, DwStatus> {
    let range = user_range(
        out_result,
        DW_WAIT_RESULT_V1_SIZE as usize,
        8,
        UserAccess::WRITE,
    )?;
    user.preflight_owned_output(range)
        .map_err(|_| DW_STATUS_BAD_ADDRESS)
}

fn finish_wait_begin<U: OwnedUserOutputAccess>(
    user: &mut U,
    begin: WaitSyscallBegin<U::OwnedOutput>,
) -> WaitSyscallAction {
    match begin {
        WaitSyscallBegin::Returning {
            status,
            output,
            result,
        } => {
            match result {
                Some(result) => {
                    assert_eq!(status, DW_STATUS_SUCCESS);
                    user.commit_owned_output(output, &result);
                }
                None => user.discard_owned_output(output),
            }
            WaitSyscallAction::Returning(status)
        }
        WaitSyscallBegin::Suspended { wake, decision } => {
            WaitSyscallAction::Suspended(WaitSuspendState { wake, decision })
        }
    }
}

pub(crate) fn wait_one_syscall<
    U: OwnedUserOutputAccess,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EVENTS: usize,
    const TIMERS: usize,
    const CHANNEL_PAIRS: usize,
    const CHANNEL_DEPTH: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    events: &EventAuthority<EVENTS>,
    timers: &TimerAuthority<TIMERS>,
    channels: &ChannelAuthority<CHANNEL_PAIRS, CHANNEL_DEPTH>,
    waits: &WaitRegistry<WAITERS>,
    execution: &ExecutionDomain<EXECUTION>,
    operations: &mut WaitOperationRegistry<U::OwnedOutput, EXECUTION>,
    deadline_authority: Option<&mut dyn WaitDeadlineAuthority>,
    process: ProcessKey,
    thread: ThreadKey,
    handle: DwHandle,
    signals: DwSignals,
    deadline: DwDeadline,
    out_result: DwUserAddress,
) -> WaitSyscallAction {
    wait_one_syscall_on(
        user,
        registry,
        tasks,
        events,
        timers,
        channels,
        waits,
        execution,
        operations,
        deadline_authority,
        crate::cpu::CpuIndex::BOOTSTRAP,
        process,
        thread,
        handle,
        signals,
        deadline,
        out_result,
    )
}

pub(crate) fn wait_one_syscall_on<
    U: OwnedUserOutputAccess,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EVENTS: usize,
    const TIMERS: usize,
    const CHANNEL_PAIRS: usize,
    const CHANNEL_DEPTH: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    events: &EventAuthority<EVENTS>,
    timers: &TimerAuthority<TIMERS>,
    channels: &ChannelAuthority<CHANNEL_PAIRS, CHANNEL_DEPTH>,
    waits: &WaitRegistry<WAITERS>,
    execution: &ExecutionDomain<EXECUTION>,
    operations: &mut WaitOperationRegistry<U::OwnedOutput, EXECUTION>,
    deadline_authority: Option<&mut dyn WaitDeadlineAuthority>,
    current_cpu: crate::cpu::CpuIndex,
    process: ProcessKey,
    thread: ThreadKey,
    handle: DwHandle,
    signals: DwSignals,
    deadline: DwDeadline,
    out_result: DwUserAddress,
) -> WaitSyscallAction {
    if signals.0 == 0 || !deepwyrm_abi::dw_signals_are_known(signals) {
        return WaitSyscallAction::Returning(DW_STATUS_INVALID_ARGUMENT);
    }
    let output = match preflight_owned_wait_output(user, out_result) {
        Ok(output) => output,
        Err(status) => return WaitSyscallAction::Returning(status),
    };
    finish_wait_begin(
        user,
        wait_one_begin(
            output,
            registry,
            tasks,
            events,
            timers,
            channels,
            waits,
            execution,
            operations,
            deadline_authority,
            current_cpu,
            process,
            thread,
            handle,
            signals,
            deadline,
        ),
    )
}

pub(crate) fn wait_many_syscall<
    U: OwnedUserOutputAccess,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EVENTS: usize,
    const TIMERS: usize,
    const CHANNEL_PAIRS: usize,
    const CHANNEL_DEPTH: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    events: &EventAuthority<EVENTS>,
    timers: &TimerAuthority<TIMERS>,
    channels: &ChannelAuthority<CHANNEL_PAIRS, CHANNEL_DEPTH>,
    waits: &WaitRegistry<WAITERS>,
    execution: &ExecutionDomain<EXECUTION>,
    operations: &mut WaitOperationRegistry<U::OwnedOutput, EXECUTION>,
    deadline_authority: Option<&mut dyn WaitDeadlineAuthority>,
    process: ProcessKey,
    thread: ThreadKey,
    items: DwUserAddress,
    item_count: u32,
    mode: u32,
    deadline: DwDeadline,
    out_result: DwUserAddress,
) -> WaitSyscallAction {
    wait_many_syscall_on(
        user,
        registry,
        tasks,
        events,
        timers,
        channels,
        waits,
        execution,
        operations,
        deadline_authority,
        crate::cpu::CpuIndex::BOOTSTRAP,
        process,
        thread,
        items,
        item_count,
        mode,
        deadline,
        out_result,
    )
}

pub(crate) fn wait_many_syscall_on<
    U: OwnedUserOutputAccess,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EVENTS: usize,
    const TIMERS: usize,
    const CHANNEL_PAIRS: usize,
    const CHANNEL_DEPTH: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    events: &EventAuthority<EVENTS>,
    timers: &TimerAuthority<TIMERS>,
    channels: &ChannelAuthority<CHANNEL_PAIRS, CHANNEL_DEPTH>,
    waits: &WaitRegistry<WAITERS>,
    execution: &ExecutionDomain<EXECUTION>,
    operations: &mut WaitOperationRegistry<U::OwnedOutput, EXECUTION>,
    deadline_authority: Option<&mut dyn WaitDeadlineAuthority>,
    current_cpu: crate::cpu::CpuIndex,
    process: ProcessKey,
    thread: ThreadKey,
    items: DwUserAddress,
    item_count: u32,
    mode: u32,
    deadline: DwDeadline,
    out_result: DwUserAddress,
) -> WaitSyscallAction {
    let (requests, count) = match snapshot_wait_many_requests(user, items, item_count, mode) {
        Ok(requests) => requests,
        Err(status) => return WaitSyscallAction::Returning(status),
    };
    let output = match preflight_owned_wait_output(user, out_result) {
        Ok(output) => output,
        Err(status) => return WaitSyscallAction::Returning(status),
    };
    let begin = wait_many_requests_begin(
        output,
        registry,
        tasks,
        events,
        timers,
        channels,
        waits,
        execution,
        operations,
        deadline_authority,
        current_cpu,
        process,
        thread,
        &requests[..count],
        deadline,
    );
    finish_wait_begin(user, begin)
}

pub(crate) fn resume_wait_syscall<
    U: OwnedUserOutputAccess,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    waits: &WaitRegistry<WAITERS>,
    execution: &ExecutionDomain<EXECUTION>,
    operations: &mut WaitOperationRegistry<U::OwnedOutput, EXECUTION>,
    deadline_authority: Option<&mut dyn WaitDeadlineAuthority>,
    wake: BlockWakeKey,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> Result<DwStatus, WaitFinishError> {
    let (output, winner, releases) = finish_wait_operation(
        registry,
        tasks,
        waits,
        execution,
        operations,
        deadline_authority,
        wake,
    )?;
    for release in releases.into_releases().into_iter().flatten() {
        cleanup.push(release);
    }
    match winner {
        crate::task::BlockedOperationWinner::Signal {
            item_index,
            observed,
        } => {
            let result = wait_result(item_index, observed);
            user.commit_owned_output(output, &result);
            Ok(DW_STATUS_SUCCESS)
        }
        crate::task::BlockedOperationWinner::Timeout => {
            user.discard_owned_output(output);
            Ok(DW_STATUS_TIMED_OUT)
        }
        crate::task::BlockedOperationWinner::AtomicWake => {
            user.discard_owned_output(output);
            panic!("atomic-wake winner reached generic F7 wait resume")
        }
        crate::task::BlockedOperationWinner::Cancelled
        | crate::task::BlockedOperationWinner::Terminal => {
            user.discard_owned_output(output);
            panic!("non-returning F7 wait winner reached syscall resume")
        }
    }
}

pub(crate) fn resume_wait_thread_syscall<
    U: OwnedUserOutputAccess,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    waits: &WaitRegistry<WAITERS>,
    execution: &ExecutionDomain<EXECUTION>,
    operations: &mut WaitOperationRegistry<U::OwnedOutput, EXECUTION>,
    deadline_authority: Option<&mut dyn WaitDeadlineAuthority>,
    thread: ThreadKey,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> Result<DwStatus, WaitFinishError> {
    let wake = operations
        .wake_key_for_thread(thread)
        .ok_or(WaitFinishError::Operation(
            crate::wait::operation::WaitOperationError::StaleWake,
        ))?;
    resume_wait_syscall(
        user,
        registry,
        tasks,
        waits,
        execution,
        operations,
        deadline_authority,
        wake,
        cleanup,
    )
}

pub(crate) fn event_create<
    U: UserPageAccess,
    const OBJECTS: usize,
    const EVENTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    events: &EventAuthority<EVENTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    current_process: ProcessKey,
    requested_rights: DwRights,
    out_event: DwUserAddress,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    if let Err(status) =
        validate_created_handle_rights(deepwyrm_abi::DW_OBJECT_TYPE_EVENT, requested_rights)
    {
        return status;
    }
    let output = match preflight_output(user, out_event, 8, 8) {
        Ok(output) => output,
        Err(status) => return status,
    };
    let (_key, reference) = match events.create_event(registry) {
        Ok(created) => created,
        Err(error) => return event_create_status(error),
    };
    let handle = match tasks.process_handles_mut(current_process) {
        Ok(table) => {
            match install_created_handle(table, registry, reference, requested_rights, cleanup) {
                Ok(handle) => handle,
                Err(status) => return status,
            }
        }
        Err(error) => {
            cleanup.push_optional(
                registry
                    .release_handle(reference)
                    .unwrap_or_else(|failure| {
                        panic!(
                            "F4 Event publication rollback drifted: {:?}",
                            failure.error()
                        )
                    }),
            );
            return task_status(error);
        }
    };
    output.commit(&encode_handle(handle));
    DW_STATUS_SUCCESS
}

pub(crate) fn event_signal<
    const OBJECTS: usize,
    const EVENTS: usize,
    const WAITERS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    events: &EventAuthority<EVENTS>,
    waits: &WaitRegistry<WAITERS>,
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    current_process: ProcessKey,
    event: DwHandle,
    clear_mask: deepwyrm_abi::DwSignals,
    set_mask: deepwyrm_abi::DwSignals,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    if let Err(error) = validate_event_signal_masks(clear_mask, set_mask) {
        return wait_status(error);
    }
    let pin = match resolve_current_handle(
        tasks,
        registry,
        current_process,
        event,
        deepwyrm_abi::DW_OBJECT_TYPE_EVENT,
        DW_RIGHT_SIGNAL,
    ) {
        Ok(pin) => pin,
        Err(status) => return status,
    };
    let key = EventKey::from_object_id(pin.id());
    let wakes = match events.signal(key, clear_mask, set_mask, waits) {
        Ok(wakes) => wakes,
        Err(error) => {
            release_lookup_pin(registry, pin, cleanup);
            return wait_status(error);
        }
    };
    release_lookup_pin(registry, pin, cleanup);
    complete_wait_wakes(registry, execution, wakes, cleanup);
    DW_STATUS_SUCCESS
}

pub(crate) fn timer_create<
    U: UserPageAccess,
    const OBJECTS: usize,
    const TIMERS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    timers: &TimerAuthority<TIMERS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    current_process: ProcessKey,
    requested_rights: DwRights,
    out_timer: DwUserAddress,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    if let Err(status) =
        validate_created_handle_rights(deepwyrm_abi::DW_OBJECT_TYPE_TIMER, requested_rights)
    {
        return status;
    }
    let output = match preflight_output(user, out_timer, 8, 8) {
        Ok(output) => output,
        Err(status) => return status,
    };
    let (_key, reference) = match timers.create_timer(registry) {
        Ok(created) => created,
        Err(error) => return timer_create_status(error),
    };
    let handle = match tasks.process_handles_mut(current_process) {
        Ok(table) => {
            match install_created_handle(table, registry, reference, requested_rights, cleanup) {
                Ok(handle) => handle,
                Err(status) => return status,
            }
        }
        Err(error) => {
            cleanup.push_optional(
                registry
                    .release_handle(reference)
                    .unwrap_or_else(|failure| {
                        panic!(
                            "F8 Timer publication rollback drifted: {:?}",
                            failure.error()
                        )
                    }),
            );
            return task_status(error);
        }
    };
    output.commit(&encode_handle(handle));
    DW_STATUS_SUCCESS
}

pub(crate) fn timer_set<
    const OBJECTS: usize,
    const TIMERS: usize,
    const WAITERS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    timers: &TimerAuthority<TIMERS>,
    deadlines: &mut dyn TimerDeadlineAuthority,
    waits: &WaitRegistry<WAITERS>,
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    current_process: ProcessKey,
    timer: DwHandle,
    deadline: DwDeadline,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    if deadline.0 == deepwyrm_abi::DW_DEADLINE_INFINITE.0 {
        return DW_STATUS_INVALID_ARGUMENT;
    }
    let pin = match resolve_current_handle(
        tasks,
        registry,
        current_process,
        timer,
        deepwyrm_abi::DW_OBJECT_TYPE_TIMER,
        DW_RIGHT_MODIFY,
    ) {
        Ok(pin) => pin,
        Err(status) => return status,
    };
    let key = TimerKey::from_object_id(pin.id());
    let wakes = match timers.set(key, deadline, deadlines, waits) {
        Ok(wakes) => wakes,
        Err(error) => {
            release_lookup_pin(registry, pin, cleanup);
            return timer_status(error);
        }
    };
    release_lookup_pin(registry, pin, cleanup);
    complete_wait_wakes(registry, execution, wakes, cleanup);
    DW_STATUS_SUCCESS
}

pub(crate) fn timer_cancel<
    const OBJECTS: usize,
    const TIMERS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    timers: &TimerAuthority<TIMERS>,
    deadlines: &mut dyn TimerDeadlineAuthority,
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    current_process: ProcessKey,
    timer: DwHandle,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    let pin = match resolve_current_handle(
        tasks,
        registry,
        current_process,
        timer,
        deepwyrm_abi::DW_OBJECT_TYPE_TIMER,
        DW_RIGHT_MODIFY,
    ) {
        Ok(pin) => pin,
        Err(status) => return status,
    };
    let key = TimerKey::from_object_id(pin.id());
    let status = match timers.cancel(key, deadlines) {
        Ok(()) => DW_STATUS_SUCCESS,
        Err(error) => timer_status(error),
    };
    release_lookup_pin(registry, pin, cleanup);
    status
}

pub(crate) fn thread_create<
    U: UserPageAccess,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    current_process: ProcessKey,
    process: DwHandle,
    requested_rights: DwRights,
    out_thread: DwUserAddress,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    if let Err(status) =
        validate_created_handle_rights(deepwyrm_abi::DW_OBJECT_TYPE_THREAD, requested_rights)
    {
        return status;
    }
    let output = match preflight_output(user, out_thread, 8, 8) {
        Ok(output) => output,
        Err(status) => return status,
    };
    let process_pin = match resolve_current_handle(
        tasks,
        registry,
        current_process,
        process,
        deepwyrm_abi::DW_OBJECT_TYPE_PROCESS,
        DW_RIGHT_MODIFY,
    ) {
        Ok(pin) => pin,
        Err(status) => return status,
    };
    let created = tasks.create_thread(registry, &process_pin);
    release_lookup_pin(registry, process_pin, cleanup);
    let (_key, reference) = match created {
        Ok(created) => created,
        Err(error) => return task_create_status(error),
    };
    let handle = match tasks.process_handles_mut(current_process) {
        Ok(table) => {
            match install_created_handle(table, registry, reference, requested_rights, cleanup) {
                Ok(handle) => handle,
                Err(status) => return status,
            }
        }
        Err(error) => {
            cleanup.push_optional(
                registry
                    .release_handle(reference)
                    .unwrap_or_else(|failure| {
                        panic!(
                            "E5 Thread publication rollback drifted: {:?}",
                            failure.error()
                        )
                    }),
            );
            return task_status(error);
        }
    };
    output.commit(&encode_handle(handle));
    DW_STATUS_SUCCESS
}

fn collect_group_effects<
    C: TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const HANDLES: usize,
    const THREADS: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    effects: TaskGroupTerminationEffects<PROCESSES, HANDLES, THREADS>,
    pre_retired: &mut PreRetiredTerminalThreads<THREADS>,
    defer_current: DeferredCurrentRetirement,
    remotely_stopped: &[Option<ThreadKey>],
    terminal_waits: &mut C,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> Option<DeferredCurrentExecutionResources> {
    let current_thread = defer_current.thread();
    let terminal_threads = effects.thread_keys();
    assert!(
        remotely_stopped
            .iter()
            .flatten()
            .all(|thread| terminal_threads.contains(&Some(*thread))),
        "remote-stop permit named a Thread outside the TaskGroup terminal batch"
    );
    let mut processes = effects.into_processes();
    let mut current_process = None;
    for process in &mut processes {
        let contains_current = process.as_ref().is_some_and(|effects| {
            effects
                .pins
                .thread_keys()
                .into_iter()
                .flatten()
                .any(|thread| thread == current_thread)
        });
        if contains_current {
            assert!(
                current_process.is_none(),
                "group retirement produced duplicate current-Thread process batches"
            );
            current_process = process.take();
        }
    }

    // Retire every non-current batch first so scheduler.current() continues to
    // identify the physical Thread whose stack is executing this syscall.  The
    // current batch must be the final scheduler mutation before architecture
    // code diverges onto the terminal reaper stack.
    for process in processes.into_iter().flatten() {
        let terminal_threads = process.pins.thread_keys();
        let mut batch_remote = [None; THREADS];
        let mut remote_count = 0;
        for thread in remotely_stopped.iter().flatten() {
            if terminal_threads.contains(&Some(*thread)) {
                assert!(remote_count < THREADS, "group remote-stop batch overflow");
                batch_remote[remote_count] = Some(*thread);
                remote_count += 1;
            }
        }
        let deferred = collect_process_effects(
            registry,
            tasks,
            execution,
            waits,
            process,
            pre_retired,
            Some(defer_current),
            &batch_remote,
            terminal_waits,
            cleanup,
        );
        assert!(
            deferred.is_none(),
            "non-current group batch produced deferred current resources"
        );
    }

    current_process.map(|process| {
        let terminal_threads = process.pins.thread_keys();
        let mut batch_remote = [None; THREADS];
        let mut remote_count = 0;
        for thread in remotely_stopped.iter().flatten() {
            if terminal_threads.contains(&Some(*thread)) {
                assert!(remote_count < THREADS, "group remote-stop batch overflow");
                batch_remote[remote_count] = Some(*thread);
                remote_count += 1;
            }
        }
        collect_process_effects(
            registry,
            tasks,
            execution,
            waits,
            process,
            pre_retired,
            Some(defer_current),
            &batch_remote,
            terminal_waits,
            cleanup,
        )
        .expect("current group batch did not preserve deferred execution ownership")
    })
}

fn authorized_reason(reason: DwTerminationReason) -> Result<(), DwStatus> {
    if reason == DW_TERMINATION_AUTHORIZED {
        Ok(())
    } else {
        Err(DW_STATUS_INVALID_ARGUMENT)
    }
}

fn control_after_process_state<
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    current_process: ProcessKey,
) -> SyscallControl {
    match tasks.process_info(current_process) {
        Ok(info) if info.state == DW_TASK_STATE_EXITED => SyscallControl::TerminateCurrent,
        Ok(_) => SyscallControl::ReturnToCaller,
        Err(_) => SyscallControl::TerminateCurrent,
    }
}

pub(crate) fn task_group_terminate<
    C: TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    terminal_waits: &mut C,
    current_process: ProcessKey,
    current_thread: ThreadKey,
    task_group: DwHandle,
    reason: DwTerminationReason,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> (
    DwStatus,
    SyscallControl,
    Option<DeferredCurrentExecutionResources>,
) {
    let prepared = match prepare_task_group_terminate(
        registry,
        tasks,
        execution,
        waits,
        terminal_waits,
        current_process,
        current_thread,
        task_group,
        reason,
        cleanup,
    ) {
        Ok(prepared) => prepared,
        Err(status) => return (status, SyscallControl::ReturnToCaller, None),
    };
    complete_prepared_task_group_termination(
        registry,
        tasks,
        execution,
        waits,
        terminal_waits,
        current_process,
        current_thread,
        prepared,
        cleanup,
    )
}

pub(crate) fn prepare_task_group_terminate<
    C: TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    terminal_waits: &mut C,
    current_process: ProcessKey,
    current_thread: ThreadKey,
    task_group: DwHandle,
    reason: DwTerminationReason,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> Result<PreparedTaskGroupTermination<PROCESSES, HANDLES, THREADS>, DwStatus> {
    authorized_reason(reason)?;
    validate_running_caller(tasks, execution, current_process, current_thread)?;
    let pin = resolve_current_handle(
        tasks,
        registry,
        current_process,
        task_group,
        deepwyrm_abi::DW_OBJECT_TYPE_TASK_GROUP,
        DW_RIGHT_MODIFY,
    )?;
    let key = TaskGroupKey::from_object_id(pin.id());
    let effects = match tasks.terminate_group(registry, key) {
        Ok(effects) => effects,
        Err(TaskError::OperationsInFlight) => {
            let threads = match tasks.task_group_thread_keys(key) {
                Ok(threads) => threads,
                Err(error) => {
                    release_lookup_pin(registry, pin, cleanup);
                    return Err(task_status(error));
                }
            };
            for thread in threads.into_iter().flatten() {
                terminal_waits
                    .cleanup_terminal_wait(registry, tasks, waits, execution, thread, cleanup);
            }
            match tasks.terminate_group(registry, key) {
                Ok(effects) => effects,
                Err(error) => {
                    release_lookup_pin(registry, pin, cleanup);
                    return Err(task_status(error));
                }
            }
        }
        Err(error) => {
            release_lookup_pin(registry, pin, cleanup);
            return Err(task_status(error));
        }
    };
    let pre_retired =
        PreRetiredTerminalThreads::new(execution.quiesce_terminal_threads(effects.thread_keys()));
    release_lookup_pin(registry, pin, cleanup);
    Ok(PreparedTaskGroupTermination {
        effects,
        pre_retired,
    })
}

pub(crate) fn complete_prepared_task_group_termination<
    C: TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    terminal_waits: &mut C,
    current_process: ProcessKey,
    current_thread: ThreadKey,
    prepared: PreparedTaskGroupTermination<PROCESSES, HANDLES, THREADS>,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> (
    DwStatus,
    SyscallControl,
    Option<DeferredCurrentExecutionResources>,
) {
    let PreparedTaskGroupTermination {
        effects,
        mut pre_retired,
    } = prepared;
    let deferred = collect_group_effects(
        registry,
        tasks,
        execution,
        waits,
        effects,
        &mut pre_retired,
        DeferredCurrentRetirement::Model(current_thread),
        &[],
        terminal_waits,
        cleanup,
    );
    pre_retired.assert_consumed();
    let control = control_after_process_state(tasks, current_process);
    assert_eq!(
        control == SyscallControl::TerminateCurrent,
        deferred.is_some(),
        "group terminal control and deferred current ownership diverged"
    );
    (DW_STATUS_SUCCESS, control, deferred)
}

pub(crate) fn complete_prepared_task_group_termination_after_remote_stops_on<
    C: TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    terminal_waits: &mut C,
    current_cpu: crate::cpu::CpuIndex,
    current_process: ProcessKey,
    current_thread: ThreadKey,
    prepared: PreparedTaskGroupTermination<PROCESSES, HANDLES, THREADS>,
    permits: [Option<crate::arch::x86_64::rendezvous::RemoteStopReclaimPermit>;
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> (
    DwStatus,
    SyscallControl,
    Option<DeferredCurrentExecutionResources>,
) {
    let remote_threads = permits
        .each_ref()
        .map(|permit| permit.as_ref().map(|permit| permit.thread()));
    let PreparedTaskGroupTermination {
        effects,
        mut pre_retired,
    } = prepared;
    let deferred = collect_group_effects(
        registry,
        tasks,
        execution,
        waits,
        effects,
        &mut pre_retired,
        DeferredCurrentRetirement::Handoff {
            cpu: current_cpu,
            thread: current_thread,
        },
        remote_threads.as_slice(),
        terminal_waits,
        cleanup,
    );
    pre_retired.assert_consumed();
    let control = control_after_process_state(tasks, current_process);
    assert_eq!(
        control == SyscallControl::TerminateCurrent,
        deferred.is_some(),
        "TaskGroup terminal control and deferred current ownership diverged"
    );
    (DW_STATUS_SUCCESS, control, deferred)
}

pub(crate) fn process_exit_on<
    C: TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    terminal_waits: &mut C,
    current_cpu: crate::cpu::CpuIndex,
    current_process: ProcessKey,
    current_thread: ThreadKey,
    code: u32,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> (
    DwStatus,
    SyscallControl,
    Option<DeferredCurrentExecutionResources>,
) {
    let prepared = match prepare_process_exit(
        registry,
        tasks,
        execution,
        waits,
        terminal_waits,
        current_process,
        current_thread,
        code,
        cleanup,
    ) {
        Ok(prepared) => prepared,
        Err(status) => return (status, SyscallControl::ReturnToCaller, None),
    };
    complete_prepared_process_termination_with_remote_threads(
        registry,
        tasks,
        execution,
        waits,
        terminal_waits,
        current_process,
        prepared,
        DeferredCurrentRetirement::Handoff {
            cpu: current_cpu,
            thread: current_thread,
        },
        &[],
        cleanup,
    )
}

pub(crate) fn prepare_process_exit<
    C: TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    terminal_waits: &mut C,
    current_process: ProcessKey,
    current_thread: ThreadKey,
    code: u32,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> Result<PreparedProcessTermination<HANDLES, THREADS>, DwStatus> {
    validate_running_caller(tasks, execution, current_process, current_thread)?;
    let effects = match tasks.exit_process(registry, current_process, current_thread, code) {
        Ok(effects) => effects,
        Err(TaskError::OperationsInFlight) => {
            let threads = match tasks.process_thread_keys(current_process) {
                Ok(threads) => threads,
                Err(error) => return Err(task_status(error)),
            };
            for thread in threads.into_iter().flatten() {
                terminal_waits
                    .cleanup_terminal_wait(registry, tasks, waits, execution, thread, cleanup);
            }
            match tasks.exit_process(registry, current_process, current_thread, code) {
                Ok(effects) => effects,
                Err(error) => return Err(task_status(error)),
            }
        }
        Err(error) => return Err(task_status(error)),
    };
    let pre_retired = PreRetiredTerminalThreads::new(
        execution.quiesce_terminal_threads(effects.pins.thread_keys()),
    );
    Ok(PreparedProcessTermination {
        target: current_process,
        effects,
        pre_retired,
    })
}

pub(crate) fn process_unhandled_exception<
    C: TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    terminal_waits: &mut C,
    current_process: ProcessKey,
    current_thread: ThreadKey,
    exception: TaskExceptionRecord,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> (
    DwStatus,
    SyscallControl,
    Option<DeferredCurrentExecutionResources>,
) {
    let prepared = match prepare_process_unhandled_exception(
        registry,
        tasks,
        execution,
        waits,
        terminal_waits,
        current_process,
        current_thread,
        exception,
        cleanup,
    ) {
        Ok(prepared) => prepared,
        Err(status) => return (status, SyscallControl::ReturnToCaller, None),
    };
    complete_prepared_process_termination_with_remote_threads(
        registry,
        tasks,
        execution,
        waits,
        terminal_waits,
        current_process,
        prepared,
        DeferredCurrentRetirement::Model(current_thread),
        &[],
        cleanup,
    )
}

pub(crate) fn process_unhandled_exception_on<
    C: TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    terminal_waits: &mut C,
    current_cpu: crate::cpu::CpuIndex,
    current_process: ProcessKey,
    current_thread: ThreadKey,
    exception: TaskExceptionRecord,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> (
    DwStatus,
    SyscallControl,
    Option<DeferredCurrentExecutionResources>,
) {
    let prepared = match prepare_process_unhandled_exception(
        registry,
        tasks,
        execution,
        waits,
        terminal_waits,
        current_process,
        current_thread,
        exception,
        cleanup,
    ) {
        Ok(prepared) => prepared,
        Err(status) => return (status, SyscallControl::ReturnToCaller, None),
    };
    complete_prepared_process_termination_with_remote_threads(
        registry,
        tasks,
        execution,
        waits,
        terminal_waits,
        current_process,
        prepared,
        DeferredCurrentRetirement::Handoff {
            cpu: current_cpu,
            thread: current_thread,
        },
        &[],
        cleanup,
    )
}

pub(crate) fn prepare_process_unhandled_exception<
    C: TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    terminal_waits: &mut C,
    current_process: ProcessKey,
    current_thread: ThreadKey,
    exception: TaskExceptionRecord,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> Result<PreparedProcessTermination<HANDLES, THREADS>, DwStatus> {
    validate_running_caller(tasks, execution, current_process, current_thread)?;
    let effects = match tasks.terminate_process_exception(
        registry,
        current_process,
        current_thread,
        exception.exception_type,
        exception.detail,
        exception.fault_address,
    ) {
        Ok(effects) => effects,
        Err(TaskError::OperationsInFlight) => {
            let threads = match tasks.process_thread_keys(current_process) {
                Ok(threads) => threads,
                Err(error) => return Err(task_status(error)),
            };
            for thread in threads.into_iter().flatten() {
                terminal_waits
                    .cleanup_terminal_wait(registry, tasks, waits, execution, thread, cleanup);
            }
            match tasks.terminate_process_exception(
                registry,
                current_process,
                current_thread,
                exception.exception_type,
                exception.detail,
                exception.fault_address,
            ) {
                Ok(effects) => effects,
                Err(error) => return Err(task_status(error)),
            }
        }
        Err(error) => return Err(task_status(error)),
    };
    let pre_retired = PreRetiredTerminalThreads::new(
        execution.quiesce_terminal_threads(effects.pins.thread_keys()),
    );
    Ok(PreparedProcessTermination {
        target: current_process,
        effects,
        pre_retired,
    })
}

pub(crate) fn process_terminate<
    C: TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    terminal_waits: &mut C,
    current_process: ProcessKey,
    current_thread: ThreadKey,
    process: DwHandle,
    reason: DwTerminationReason,
    detail: u32,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> (
    DwStatus,
    SyscallControl,
    Option<DeferredCurrentExecutionResources>,
) {
    let prepared = match prepare_process_terminate(
        registry,
        tasks,
        execution,
        waits,
        terminal_waits,
        current_process,
        current_thread,
        process,
        reason,
        detail,
        cleanup,
    ) {
        Ok(prepared) => prepared,
        Err(status) => return (status, SyscallControl::ReturnToCaller, None),
    };
    complete_prepared_process_termination(
        registry,
        tasks,
        execution,
        waits,
        terminal_waits,
        current_process,
        current_thread,
        prepared,
        cleanup,
    )
}

pub(crate) fn prepare_process_terminate<
    C: TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    terminal_waits: &mut C,
    current_process: ProcessKey,
    current_thread: ThreadKey,
    process: DwHandle,
    reason: DwTerminationReason,
    detail: u32,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> Result<PreparedProcessTermination<HANDLES, THREADS>, DwStatus> {
    authorized_reason(reason)?;
    validate_running_caller(tasks, execution, current_process, current_thread)?;
    let pin = resolve_current_handle(
        tasks,
        registry,
        current_process,
        process,
        deepwyrm_abi::DW_OBJECT_TYPE_PROCESS,
        DW_RIGHT_MODIFY,
    )?;
    let target = ProcessKey::from_object_id(pin.id());
    let effects = match tasks.terminate_process_authorized(registry, target, detail) {
        Ok(effects) => effects,
        Err(TaskError::OperationsInFlight) => {
            let threads = match tasks.process_thread_keys(target) {
                Ok(threads) => threads,
                Err(error) => {
                    release_lookup_pin(registry, pin, cleanup);
                    return Err(task_status(error));
                }
            };
            for thread in threads.into_iter().flatten() {
                terminal_waits
                    .cleanup_terminal_wait(registry, tasks, waits, execution, thread, cleanup);
            }
            match tasks.terminate_process_authorized(registry, target, detail) {
                Ok(effects) => effects,
                Err(error) => {
                    release_lookup_pin(registry, pin, cleanup);
                    return Err(task_status(error));
                }
            }
        }
        Err(error) => {
            release_lookup_pin(registry, pin, cleanup);
            return Err(task_status(error));
        }
    };
    let pre_retired = PreRetiredTerminalThreads::new(
        execution.quiesce_terminal_threads(effects.pins.thread_keys()),
    );
    // The Process identity is now captured by the terminal effects and the
    // caller's Handle may be released before a potentially blocking remote
    // stop. No HandleTable/registry borrow crosses that wait.
    release_lookup_pin(registry, pin, cleanup);
    Ok(PreparedProcessTermination {
        target,
        effects,
        pre_retired,
    })
}

pub(crate) fn complete_prepared_process_termination<
    C: TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    terminal_waits: &mut C,
    current_process: ProcessKey,
    current_thread: ThreadKey,
    prepared: PreparedProcessTermination<HANDLES, THREADS>,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> (
    DwStatus,
    SyscallControl,
    Option<DeferredCurrentExecutionResources>,
) {
    complete_prepared_process_termination_with_remote_threads(
        registry,
        tasks,
        execution,
        waits,
        terminal_waits,
        current_process,
        prepared,
        DeferredCurrentRetirement::Model(current_thread),
        &[],
        cleanup,
    )
}

pub(crate) fn complete_prepared_process_termination_after_remote_stops<
    C: TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    terminal_waits: &mut C,
    current_process: ProcessKey,
    current_thread: ThreadKey,
    prepared: PreparedProcessTermination<HANDLES, THREADS>,
    permits: [Option<crate::arch::x86_64::rendezvous::RemoteStopReclaimPermit>;
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> (
    DwStatus,
    SyscallControl,
    Option<DeferredCurrentExecutionResources>,
) {
    let remote_threads = permits
        .each_ref()
        .map(|permit| permit.as_ref().map(|permit| permit.thread()));
    complete_prepared_process_termination_with_remote_threads(
        registry,
        tasks,
        execution,
        waits,
        terminal_waits,
        current_process,
        prepared,
        DeferredCurrentRetirement::Model(current_thread),
        remote_threads.as_slice(),
        cleanup,
    )
}

pub(crate) fn complete_prepared_process_termination_after_remote_stops_on<
    C: TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    terminal_waits: &mut C,
    current_cpu: crate::cpu::CpuIndex,
    current_process: ProcessKey,
    current_thread: ThreadKey,
    prepared: PreparedProcessTermination<HANDLES, THREADS>,
    permits: [Option<crate::arch::x86_64::rendezvous::RemoteStopReclaimPermit>;
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> (
    DwStatus,
    SyscallControl,
    Option<DeferredCurrentExecutionResources>,
) {
    let remote_threads = permits
        .each_ref()
        .map(|permit| permit.as_ref().map(|permit| permit.thread()));
    complete_prepared_process_termination_with_remote_threads(
        registry,
        tasks,
        execution,
        waits,
        terminal_waits,
        current_process,
        prepared,
        DeferredCurrentRetirement::Handoff {
            cpu: current_cpu,
            thread: current_thread,
        },
        remote_threads.as_slice(),
        cleanup,
    )
}

fn complete_prepared_process_termination_with_remote_threads<
    C: TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    terminal_waits: &mut C,
    current_process: ProcessKey,
    prepared: PreparedProcessTermination<HANDLES, THREADS>,
    retirement: DeferredCurrentRetirement,
    remote_threads: &[Option<ThreadKey>],
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> (
    DwStatus,
    SyscallControl,
    Option<DeferredCurrentExecutionResources>,
) {
    let PreparedProcessTermination {
        target: _,
        effects,
        mut pre_retired,
    } = prepared;
    let deferred = collect_process_effects(
        registry,
        tasks,
        execution,
        waits,
        effects,
        &mut pre_retired,
        Some(retirement),
        remote_threads,
        terminal_waits,
        cleanup,
    );
    pre_retired.assert_consumed();
    let control = control_after_process_state(tasks, current_process);
    assert_eq!(
        control == SyscallControl::TerminateCurrent,
        deferred.is_some(),
        "Process terminal control and deferred current ownership diverged"
    );
    (DW_STATUS_SUCCESS, control, deferred)
}

pub(crate) fn thread_exit<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    current_process: ProcessKey,
    current_thread: ThreadKey,
    code: u32,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> (
    DwStatus,
    SyscallControl,
    Option<DeferredCurrentExecutionResources>,
) {
    if let Err(status) = validate_running_caller(tasks, execution, current_process, current_thread)
    {
        return (status, SyscallControl::ReturnToCaller, None);
    }
    let process = current_process;
    let pins = match tasks.exit_thread(current_thread, code) {
        Ok(pins) => pins,
        Err(error) => return (task_status(error), SyscallControl::ReturnToCaller, None),
    };
    if tasks
        .process_info(process)
        .is_ok_and(|info| info.state == DW_TASK_STATE_EXITED)
    {
        let drained = tasks
            .drain_exited_process_handles(registry, process)
            .unwrap_or_else(|error| {
                panic!("final Thread exit could not drain Process handles: {error:?}")
            });
        for release in drained.into_final_releases().into_iter().flatten() {
            cleanup.push(release);
        }
    }
    let (pins, deferred) = execution.retire_exit_pins_defer_current(pins, current_thread);
    collect_retired_pins(registry, execution, waits, pins, cleanup);
    (
        DW_STATUS_SUCCESS,
        SyscallControl::TerminateCurrent,
        Some(deferred),
    )
}

pub(crate) fn thread_terminate<
    C: TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    terminal_waits: &mut C,
    current_process: ProcessKey,
    current_thread: ThreadKey,
    thread: DwHandle,
    reason: DwTerminationReason,
    detail: u32,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> (
    DwStatus,
    SyscallControl,
    Option<DeferredCurrentExecutionResources>,
) {
    let prepared = match prepare_thread_terminate(
        registry,
        tasks,
        execution,
        waits,
        terminal_waits,
        current_process,
        current_thread,
        thread,
        reason,
        detail,
        cleanup,
    ) {
        Ok(prepared) => prepared,
        Err(status) => return (status, SyscallControl::ReturnToCaller, None),
    };
    let outcome = complete_prepared_thread_termination_with_remote_threads(
        registry,
        tasks,
        execution,
        waits,
        terminal_waits,
        crate::cpu::CpuIndex::BOOTSTRAP,
        current_process,
        current_thread,
        prepared,
        &[],
        cleanup,
    );
    if outcome.2.is_some() {
        let claim = execution
            .suspended_claim_on(crate::cpu::CpuIndex::BOOTSTRAP)
            .expect("BSP ThreadTerminate model handoff retains its execution claim");
        assert_eq!(claim.thread(), current_thread);
        execution
            .complete_switch_on(claim)
            .expect("BSP ThreadTerminate model handoff follows current retirement");
    }
    outcome
}

pub(crate) fn prepare_thread_terminate<
    C: TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    terminal_waits: &mut C,
    current_process: ProcessKey,
    current_thread: ThreadKey,
    thread: DwHandle,
    reason: DwTerminationReason,
    detail: u32,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> Result<PreparedThreadTermination<THREADS>, DwStatus> {
    authorized_reason(reason)?;
    validate_running_caller(tasks, execution, current_process, current_thread)?;
    let pin = resolve_current_handle(
        tasks,
        registry,
        current_process,
        thread,
        deepwyrm_abi::DW_OBJECT_TYPE_THREAD,
        DW_RIGHT_MODIFY,
    )?;
    let target = ThreadKey::from_object_id(pin.id());
    let target_process = match tasks.thread_process(target) {
        Ok(process) => process,
        Err(error) => {
            release_lookup_pin(registry, pin, cleanup);
            return Err(task_status(error));
        }
    };
    let pins = match tasks.terminate_thread_authorized(target, detail) {
        Ok(pins) => pins,
        Err(TaskError::OperationsInFlight) => {
            terminal_waits
                .cleanup_terminal_wait(registry, tasks, waits, execution, target, cleanup);
            match tasks.terminate_thread_authorized(target, detail) {
                Ok(pins) => pins,
                Err(error) => {
                    release_lookup_pin(registry, pin, cleanup);
                    return Err(task_status(error));
                }
            }
        }
        Err(error) => {
            release_lookup_pin(registry, pin, cleanup);
            return Err(task_status(error));
        }
    };
    let pre_retired =
        PreRetiredTerminalThreads::new(execution.quiesce_terminal_threads(pins.thread_keys()));
    if tasks
        .process_info(target_process)
        .is_ok_and(|info| info.state == DW_TASK_STATE_EXITED)
    {
        let drained = tasks
            .drain_exited_process_handles(registry, target_process)
            .unwrap_or_else(|error| {
                panic!(
                    "final authorized Thread termination could not drain Process handles: {error:?}"
                )
            });
        for release in drained.into_final_releases().into_iter().flatten() {
            cleanup.push(release);
        }
    }
    release_lookup_pin(registry, pin, cleanup);
    Ok(PreparedThreadTermination {
        target,
        target_process,
        pins,
        pre_retired,
    })
}

pub(crate) fn complete_prepared_thread_termination_after_remote_stops_on<
    C: TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    terminal_waits: &mut C,
    current_cpu: crate::cpu::CpuIndex,
    current_process: ProcessKey,
    current_thread: ThreadKey,
    prepared: PreparedThreadTermination<THREADS>,
    permits: [Option<crate::arch::x86_64::rendezvous::RemoteStopReclaimPermit>;
        crate::arch::x86_64::H1_RUNTIME_CPU_SLOT_COUNT],
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> (
    DwStatus,
    SyscallControl,
    Option<DeferredCurrentExecutionResources>,
) {
    let remote_threads = permits
        .each_ref()
        .map(|permit| permit.as_ref().map(|permit| permit.thread()));
    complete_prepared_thread_termination_with_remote_threads(
        registry,
        tasks,
        execution,
        waits,
        terminal_waits,
        current_cpu,
        current_process,
        current_thread,
        prepared,
        remote_threads.as_slice(),
        cleanup,
    )
}

fn complete_prepared_thread_termination_with_remote_threads<
    C: TerminalWaitCleanup<OBJECTS, WAITERS, EXECUTION>,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    waits: &WaitRegistry<WAITERS>,
    terminal_waits: &mut C,
    current_cpu: crate::cpu::CpuIndex,
    current_process: ProcessKey,
    current_thread: ThreadKey,
    prepared: PreparedThreadTermination<THREADS>,
    remote_threads: &[Option<ThreadKey>],
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> (
    DwStatus,
    SyscallControl,
    Option<DeferredCurrentExecutionResources>,
) {
    let PreparedThreadTermination {
        target,
        target_process: _,
        pins,
        mut pre_retired,
    } = prepared;
    let terminal_threads = pins.thread_keys();
    assert!(
        remote_threads
            .iter()
            .flatten()
            .all(|thread| terminal_threads.contains(&Some(*thread))),
        "remote-stop permit named a Thread outside the terminal Thread batch"
    );
    for terminal_thread in terminal_threads.into_iter().flatten() {
        terminal_waits.cleanup_terminal_wait(
            registry,
            tasks,
            waits,
            execution,
            terminal_thread,
            cleanup,
        );
    }
    let (pins, deferred) = if target == current_thread {
        let (pins, deferred) = execution
            .retire_quiesced_exit_pins_defer_current_after_remote_stops_on(
                current_cpu,
                pins,
                current_thread,
                remote_threads,
                pre_retired.as_mut(),
            );
        (pins, Some(deferred))
    } else if remote_threads.is_empty() {
        (
            execution.retire_quiesced_exit_pins(pins, pre_retired.as_mut()),
            None,
        )
    } else {
        (
            execution.retire_quiesced_exit_pins_after_remote_stops(
                pins,
                remote_threads,
                pre_retired.as_mut(),
            ),
            None,
        )
    };
    pre_retired.assert_consumed();
    collect_retired_pins(registry, execution, waits, pins, cleanup);
    let control = if target == current_thread {
        SyscallControl::TerminateCurrent
    } else {
        control_after_process_state(tasks, current_process)
    };
    assert_eq!(
        control == SyscallControl::TerminateCurrent,
        deferred.is_some(),
        "Thread terminal control and deferred current ownership diverged"
    );
    (DW_STATUS_SUCCESS, control, deferred)
}

fn start_thread_status(error: StartThreadError) -> DwStatus {
    match error {
        StartThreadError::Scheduler(SchedulerError::Capacity)
        | StartThreadError::Resource(ExecutionResourceError::Capacity) => DW_STATUS_NO_RESOURCES,
        StartThreadError::Task(error) => task_status(error),
        StartThreadError::Scheduler(_) => DW_STATUS_BAD_STATE,
        StartThreadError::Resource(_) => DW_STATUS_BAD_STATE,
    }
}

fn user_return_status(error: crate::arch::x86_64::syscall::UserReturnError) -> DwStatus {
    use crate::arch::x86_64::syscall::UserReturnError;
    match error {
        UserReturnError::NonCanonicalUserAddress
        | UserReturnError::InvalidSelector
        | UserReturnError::InstructionNotExecutable
        | UserReturnError::StackNotWritable => DW_STATUS_BAD_ADDRESS,
        UserReturnError::UnsupportedTlsPolicy | UserReturnError::UnsupportedFpSimdPolicy => {
            DW_STATUS_NOT_SUPPORTED
        }
        UserReturnError::BindingChanged => DW_STATUS_BAD_STATE,
    }
}

pub(crate) fn thread_start<
    U: UserPageAccess,
    M: crate::arch::x86_64::syscall::ProcessUserReturnMappingValidation,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EXECUTION: usize,
>(
    user: &mut U,
    mappings: &mut M,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    current_process: ProcessKey,
    args_address: DwUserAddress,
    args_size: u64,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    if args_size != THREAD_START_BYTES as u64 {
        return DW_STATUS_INVALID_ARGUMENT;
    }
    let bytes = match copy_input::<U, THREAD_START_BYTES>(user, args_address, 8) {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let args = decode_thread_start(&bytes);
    if args.size != THREAD_START_BYTES as u32
        || args.version != 1
        || args.flags != 0
        || args.reserved != [0; 3]
    {
        return DW_STATUS_INVALID_ARGUMENT;
    }
    let pin = match resolve_current_handle(
        tasks,
        registry,
        current_process,
        args.thread,
        deepwyrm_abi::DW_OBJECT_TYPE_THREAD,
        DW_RIGHT_EXECUTE,
    ) {
        Ok(pin) => pin,
        Err(status) => return status,
    };
    let thread = ThreadKey::from_object_id(pin.id());
    let target_process = match tasks.thread_process(thread) {
        Ok(process) => process,
        Err(error) => {
            release_lookup_pin(registry, pin, cleanup);
            return task_status(error);
        }
    };
    if mappings.process_key() != target_process {
        release_lookup_pin(registry, pin, cleanup);
        return DW_STATUS_BAD_STATE;
    }
    let start = ThreadStartState::from_validated_user_state(
        args.entry.0,
        args.stack_pointer.0,
        args.startup_argument0,
        args.startup_argument1,
    );
    let context = crate::task::SavedThreadContext::initial(start);
    if let Err(error) =
        crate::arch::x86_64::syscall::ValidatedUserReturn::initial(context, mappings)
    {
        release_lookup_pin(registry, pin, cleanup);
        return user_return_status(error);
    }
    let result = execution.start_thread(tasks, thread, start);
    release_lookup_pin(registry, pin, cleanup);
    match result {
        Ok(()) => DW_STATUS_SUCCESS,
        Err(error) => start_thread_status(error),
    }
}

pub(crate) trait ThreadStartMappingAccess:
    UserPageAccess + crate::arch::x86_64::syscall::ProcessUserReturnMappingValidation
{
    fn select_process_for_return_validation(&mut self, process: ProcessKey)
    -> Result<(), DwStatus>;
}

/// Decodes the ThreadStart record against the active caller first, then
/// retargets this same serialized scratch session to the child Process solely
/// for RIP/RSP mapping validation. No caller usercopy occurs after retargeting.
pub(crate) fn thread_start_with_access<
    U: ThreadStartMappingAccess,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EXECUTION: usize,
>(
    access: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    current_process: ProcessKey,
    args_address: DwUserAddress,
    args_size: u64,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    if args_size != THREAD_START_BYTES as u64 {
        return DW_STATUS_INVALID_ARGUMENT;
    }
    let bytes = match copy_input::<U, THREAD_START_BYTES>(access, args_address, 8) {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let args = decode_thread_start(&bytes);
    if args.size != THREAD_START_BYTES as u32
        || args.version != 1
        || args.flags != 0
        || args.reserved != [0; 3]
    {
        return DW_STATUS_INVALID_ARGUMENT;
    }
    let pin = match resolve_current_handle(
        tasks,
        registry,
        current_process,
        args.thread,
        deepwyrm_abi::DW_OBJECT_TYPE_THREAD,
        DW_RIGHT_EXECUTE,
    ) {
        Ok(pin) => pin,
        Err(status) => return status,
    };
    let thread = ThreadKey::from_object_id(pin.id());
    let target_process = match tasks.thread_process(thread) {
        Ok(process) => process,
        Err(error) => {
            release_lookup_pin(registry, pin, cleanup);
            return task_status(error);
        }
    };
    if let Err(status) = access.select_process_for_return_validation(target_process) {
        release_lookup_pin(registry, pin, cleanup);
        return status;
    }
    if access.process_key() != target_process {
        release_lookup_pin(registry, pin, cleanup);
        return DW_STATUS_BAD_STATE;
    }
    let start = ThreadStartState::from_validated_user_state(
        args.entry.0,
        args.stack_pointer.0,
        args.startup_argument0,
        args.startup_argument1,
    );
    let context = crate::task::SavedThreadContext::initial(start);
    if let Err(error) = crate::arch::x86_64::syscall::ValidatedUserReturn::initial(context, access)
    {
        release_lookup_pin(registry, pin, cleanup);
        return user_return_status(error);
    }
    let result = execution.start_thread(tasks, thread, start);
    release_lookup_pin(registry, pin, cleanup);
    match result {
        Ok(()) => DW_STATUS_SUCCESS,
        Err(error) => start_thread_status(error),
    }
}

#[cfg(test)]
mod tests;

pub(crate) trait MemoryObjectBackingAccess {
    fn allocate_zeroed_backing(
        &mut self,
        page_count: u64,
    ) -> Result<crate::memory::frame_roles::ObjectBackingGrant, DwStatus>;

    fn rollback_object_backing(&mut self, backing: crate::memory::frame_roles::ObjectBackingGrant);
}

fn memory_object_status(error: crate::memory::object::MemoryObjectError) -> DwStatus {
    use crate::memory::object::MemoryObjectError;
    match error {
        MemoryObjectError::Capacity
        | MemoryObjectError::LeaseCapacity
        | MemoryObjectError::GenerationExhausted => DW_STATUS_NO_RESOURCES,
        MemoryObjectError::InsufficientRights | MemoryObjectError::ProtectionCeiling => {
            DW_STATUS_ACCESS_DENIED
        }
        MemoryObjectError::UnsupportedProtection => DW_STATUS_NOT_SUPPORTED,
        MemoryObjectError::Empty
        | MemoryObjectError::Unaligned
        | MemoryObjectError::Overflow
        | MemoryObjectError::InvalidProtection
        | MemoryObjectError::WritableExecutableAlias => DW_STATUS_INVALID_ARGUMENT,
        MemoryObjectError::BackingTooSmall
        | MemoryObjectError::InvalidObjectKey
        | MemoryObjectError::InvalidLease
        | MemoryObjectError::ForeignLease
        | MemoryObjectError::DuplicateLease
        | MemoryObjectError::BackingKind
        | MemoryObjectError::ObjectIdentity
        | MemoryObjectError::FinalizationMismatch
        | MemoryObjectError::ObjectReference => DW_STATUS_BAD_STATE,
    }
}

pub(crate) fn memory_object_create<
    U: UserPageAccess,
    B: MemoryObjectBackingAccess,
    const OBJECTS: usize,
    const MEMORY_OBJECTS: usize,
    const LEASES: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    user: &mut U,
    backing_access: &mut B,
    registry: &mut ObjectRegistry<OBJECTS>,
    memory: &mut MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    current_process: ProcessKey,
    byte_len: u64,
    flags: u32,
    requested_rights: DwRights,
    out_handle: DwUserAddress,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    if byte_len == 0
        || !byte_len.is_multiple_of(u64::from(DW_BASE_PAGE_SIZE))
        || flags != 0
        || requested_rights.0 == 0
        || !deepwyrm_abi::dw_rights_are_known(requested_rights)
        || !deepwyrm_abi::dw_rights_are_compatible(
            deepwyrm_abi::DW_OBJECT_TYPE_MEMORY_OBJECT,
            requested_rights,
        )
    {
        return DW_STATUS_INVALID_ARGUMENT;
    }
    let page_count = byte_len / u64::from(DW_BASE_PAGE_SIZE);
    let output = match preflight_output(user, out_handle, 8, 8) {
        Ok(output) => output,
        Err(status) => return status,
    };
    let creation = match registry.create(deepwyrm_abi::DW_OBJECT_TYPE_MEMORY_OBJECT) {
        Ok(creation) => creation,
        Err(ObjectRegistryError::Capacity | ObjectRegistryError::ReferenceCountExhausted) => {
            return DW_STATUS_NO_RESOURCES;
        }
        Err(error) => panic!("E5 MemoryObject generic creation failed unexpectedly: {error:?}"),
    };
    let backing = match backing_access.allocate_zeroed_backing(page_count) {
        Ok(backing) => backing,
        Err(status) => {
            registry
                .cancel_creation(creation)
                .unwrap_or_else(|failure| {
                    panic!(
                        "E5 MemoryObject creation rollback drifted: {:?}",
                        failure.error()
                    )
                });
            return status;
        }
    };
    let binding = match memory.bind_backing(
        creation,
        backing,
        byte_len,
        crate::memory::object::MemoryObjectKind::PageBacked,
        crate::memory::object::MemoryProtection::READ_WRITE_EXECUTE,
    ) {
        Ok(binding) => binding,
        Err(error) => {
            let status = memory_object_status(error.error());
            let (creation, backing) = error.into_parts();
            backing_access.rollback_object_backing(backing);
            registry
                .cancel_creation(creation)
                .unwrap_or_else(|failure| {
                    panic!(
                        "E5 failed payload bind could not cancel creation: {:?}",
                        failure.error()
                    )
                });
            return status;
        }
    };
    let bound = registry
        .finish_payload_binding(binding)
        .unwrap_or_else(|failure| {
            panic!(
                "fresh E5 MemoryObject payload binding was rejected by ObjectRegistry: {:?}",
                failure.error()
            )
        });
    let reference = registry.bound_into_handle(bound).unwrap_or_else(|failure| {
        panic!(
            "fresh E5 MemoryObject bound creation could not become a handle: {:?}",
            failure.error()
        )
    });
    let handle = match tasks.process_handles_mut(current_process) {
        Ok(table) => {
            match install_created_handle(table, registry, reference, requested_rights, cleanup) {
                Ok(handle) => handle,
                Err(status) => return status,
            }
        }
        Err(error) => {
            cleanup.push_optional(
                registry
                    .release_handle(reference)
                    .unwrap_or_else(|failure| {
                        panic!(
                            "E5 MemoryObject publication rollback drifted: {:?}",
                            failure.error()
                        )
                    }),
            );
            return task_status(error);
        }
    };
    output.commit(&encode_handle(handle));
    DW_STATUS_SUCCESS
}

/// Live MemoryObject creation uses one combined address-space session for the
/// detached output pin and physical backing authority. This avoids creating
/// simultaneous mutable aliases merely to satisfy the older split adapter.
pub(crate) fn memory_object_create_owned<
    U: OwnedUserOutputAccess + MemoryObjectBackingAccess,
    const OBJECTS: usize,
    const MEMORY_OBJECTS: usize,
    const LEASES: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    access: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    memory: &mut MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    current_process: ProcessKey,
    byte_len: u64,
    flags: u32,
    requested_rights: DwRights,
    out_handle: DwUserAddress,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    if byte_len == 0
        || !byte_len.is_multiple_of(u64::from(DW_BASE_PAGE_SIZE))
        || flags != 0
        || requested_rights.0 == 0
        || !deepwyrm_abi::dw_rights_are_known(requested_rights)
        || !deepwyrm_abi::dw_rights_are_compatible(
            deepwyrm_abi::DW_OBJECT_TYPE_MEMORY_OBJECT,
            requested_rights,
        )
    {
        return DW_STATUS_INVALID_ARGUMENT;
    }
    let range = match user_range(out_handle, 8, 8, UserAccess::WRITE) {
        Ok(range) => range,
        Err(status) => return status,
    };
    let output = match access.preflight_owned_output(range) {
        Ok(output) => output,
        Err(_) => return DW_STATUS_BAD_ADDRESS,
    };
    let page_count = byte_len / u64::from(DW_BASE_PAGE_SIZE);
    let creation = match registry.create(deepwyrm_abi::DW_OBJECT_TYPE_MEMORY_OBJECT) {
        Ok(creation) => creation,
        Err(ObjectRegistryError::Capacity | ObjectRegistryError::ReferenceCountExhausted) => {
            access.discard_owned_output(output);
            return DW_STATUS_NO_RESOURCES;
        }
        Err(error) => panic!("live MemoryObject generic creation failed unexpectedly: {error:?}"),
    };
    let backing = match access.allocate_zeroed_backing(page_count) {
        Ok(backing) => backing,
        Err(status) => {
            registry
                .cancel_creation(creation)
                .unwrap_or_else(|failure| {
                    panic!(
                        "live MemoryObject creation rollback drifted: {:?}",
                        failure.error()
                    )
                });
            access.discard_owned_output(output);
            return status;
        }
    };
    let binding = match memory.bind_backing(
        creation,
        backing,
        byte_len,
        crate::memory::object::MemoryObjectKind::PageBacked,
        crate::memory::object::MemoryProtection::READ_WRITE_EXECUTE,
    ) {
        Ok(binding) => binding,
        Err(error) => {
            let status = memory_object_status(error.error());
            let (creation, backing) = error.into_parts();
            access.rollback_object_backing(backing);
            registry
                .cancel_creation(creation)
                .unwrap_or_else(|failure| {
                    panic!(
                        "live MemoryObject bind rollback drifted: {:?}",
                        failure.error()
                    )
                });
            access.discard_owned_output(output);
            return status;
        }
    };
    let bound = registry
        .finish_payload_binding(binding)
        .unwrap_or_else(|failure| {
            panic!(
                "fresh live MemoryObject binding was rejected: {:?}",
                failure.error()
            )
        });
    let reference = registry.bound_into_handle(bound).unwrap_or_else(|failure| {
        panic!(
            "fresh live MemoryObject could not become a handle: {:?}",
            failure.error()
        )
    });
    let handle = match tasks.process_handles_mut(current_process) {
        Ok(table) => {
            match install_created_handle(table, registry, reference, requested_rights, cleanup) {
                Ok(handle) => handle,
                Err(status) => {
                    access.discard_owned_output(output);
                    return status;
                }
            }
        }
        Err(error) => {
            cleanup.push_optional(
                registry
                    .release_handle(reference)
                    .unwrap_or_else(|failure| {
                        panic!(
                            "live MemoryObject publication rollback drifted: {:?}",
                            failure.error()
                        )
                    }),
            );
            access.discard_owned_output(output);
            return task_status(error);
        }
    };
    access.commit_owned_output(output, &encode_handle(handle));
    DW_STATUS_SUCCESS
}
