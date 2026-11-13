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
    DW_CHANNEL_RECEIVE_RESULT_V1_SIZE, DW_CLOCK_MONOTONIC_ACTIVE, DW_DEVICE_RESOURCE_INFO_V1_SIZE,
    DW_HANDLE_TRANSFER_MOVE, DW_HANDLE_TRANSFER_V1_SIZE, DW_INTERRUPT_INFO_V1_SIZE,
    DW_MEMORY_OBJECT_INFO_V1_SIZE, DW_OBJECT_INFO_BASIC_V1, DW_OBJECT_INFO_DEVICE_RESOURCE_V1,
    DW_OBJECT_INFO_INTERRUPT_V1, DW_OBJECT_INFO_MEMORY_OBJECT_V1, DW_OBJECT_INFO_TASK_STATE_V1,
    DW_OBJECT_INFO_V1_SIZE, DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL,
    DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_TASK_GROUP, DW_PROCESS_CREATE_ARGS_V1_SIZE,
    DW_PROCESS_CREATE_RESULT_V1_SIZE, DW_RECEIVED_HANDLE_INFO_V1_SIZE, DW_RIGHT_EXECUTE,
    DW_RIGHT_MODIFY, DW_RIGHT_READ, DW_RIGHT_SIGNAL, DW_RIGHT_TRANSFER, DW_RIGHT_WRITE,
    DW_STATUS_ACCESS_DENIED, DW_STATUS_BAD_ADDRESS, DW_STATUS_BAD_HANDLE, DW_STATUS_BAD_STATE,
    DW_STATUS_BUFFER_TOO_SMALL, DW_STATUS_INVALID_ARGUMENT, DW_STATUS_NO_RESOURCES,
    DW_STATUS_NOT_SUPPORTED, DW_STATUS_PEER_CLOSED, DW_STATUS_SUCCESS, DW_STATUS_TIMED_OUT,
    DW_STATUS_WOULD_BLOCK, DW_STATUS_WRONG_OBJECT_TYPE, DW_TASK_STATE_EXITED,
    DW_TERMINATION_AUTHORIZED, DW_WAIT_MANY_MAX_ITEMS, DW_WAIT_MODE_ALL, DW_WAIT_MODE_ANY,
    DW_WAIT_RESULT_V1_SIZE, DwChannelReceiveResultV1, DwClockId, DwDeadline, DwHandle,
    DwHandleTransferV1, DwProcessCreateArgsV1, DwProcessCreateResultV1, DwReceivedHandleInfoV1,
    DwRights, DwSignals, DwStatus, DwTerminationReason, DwUserAddress, DwWaitItemV1,
    DwWaitResultV1,
};

use crate::device::InterruptWaitSource;
use crate::device::{
    DeviceResourceAuthority, DeviceResourceDescriptor, DeviceResourceFinalizer, InterruptAuthority,
    InterruptCreateError, InterruptError, InterruptPlatform,
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
    ExecutionSwitchError, GroupTeardown, IdleScheduleDecision, PreparedProcess, ProcessKey,
    ResourceClaimMembershipError, RetiredExitPins, ScheduleDecision, SchedulerError,
    SchedulerThreadState, StartThreadError, TaskAuthority, TaskCreateError, TaskError,
    TaskExceptionRecord, TaskGroupKey, ThreadKey, ThreadStartState,
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
// Every address-region implementation item the facade could duplicate is
// imported by name, so a second definition here is E0255 rather than a silent
// shadow: the crate-private entry points through the re-export below, and the
// private release helper through this binding.
#[allow(
    unused_imports,
    reason = "binds the name so a facade duplicate of the helper cannot compile"
)]
use address_region::queue_mapping_releases;
#[allow(
    unused_imports,
    reason = "preserve the established crate-private adapter facade across the private module extraction"
)]
pub(crate) use address_region::{
    AddressRegionMutationTarget, AddressSpacePublishStatus, HeldReleases,
    PreparedAddressRegionMutation, address_region_map, address_region_map_model,
    address_region_map_prepared_model, address_region_mutation_target, address_region_protect,
    address_region_protect_prepared, address_region_unmap, address_region_unmap_prepared,
    decode_map_args, prepare_address_region_mutation, process_handle_target,
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

/// Finalizers awaiting routing, drained in place.
///
/// Reset card R5D made this a queue rather than a batch. It used to be moved by
/// value to be read -- `mem::replace` out of the carrier field, then
/// `into_releases()` again -- which cost two copies of a `CAPACITY`-sized array
/// per drain site, 5,128 bytes each at the E8 registry geometry, on the syscall
/// frames that route finalizers. `pop` reads it where it lives instead.
///
/// The `mem::replace` was never about ordering: finalization cascades, and
/// routing one release pushes more into the same queue, which a `for` loop over
/// a borrowed array cannot allow. Popping from the head with pushes at the tail
/// visits a cascade in exactly the order the snapshot-per-generation loop did.
#[must_use = "typed final releases must be routed after syscall pins/locks are dropped"]
pub(crate) struct CleanupQueue<const CAPACITY: usize> {
    releases: [Option<FinalRelease>; CAPACITY],
    head: usize,
    len: usize,
}

impl<const CAPACITY: usize> CleanupQueue<CAPACITY> {
    pub(crate) fn new() -> Self {
        Self {
            releases: core::array::from_fn(|_| None),
            head: 0,
            len: 0,
        }
    }

    pub(crate) fn push(&mut self, release: FinalRelease) {
        assert!(
            self.len < CAPACITY,
            "E5 cleanup queue exceeded ObjectRegistry capacity"
        );
        let index = (self.head + self.len) % CAPACITY;
        self.releases[index] = Some(release);
        self.len += 1;
    }

    pub(crate) fn push_optional(&mut self, release: Option<FinalRelease>) {
        if let Some(release) = release {
            self.push(release);
        }
    }

    /// Takes the oldest queued finalizer, or `None` when the queue is drained.
    ///
    /// A caller may push while draining; what it pushes is popped later in this
    /// same loop rather than left for a second pass.
    pub(crate) fn pop(&mut self) -> Option<FinalRelease> {
        if self.len == 0 {
            return None;
        }
        let release = self.releases[self.head].take();
        self.head = (self.head + 1) % CAPACITY;
        self.len -= 1;
        debug_assert!(release.is_some(), "cleanup queue lost a queued finalizer");
        release
    }

    /// Moves every queued finalizer into `other`, in order.
    ///
    /// This replaces moving the whole queue by value between owners.
    pub(crate) fn drain_into<const OTHER: usize>(&mut self, other: &mut CleanupQueue<OTHER>) {
        while let Some(release) = self.pop() {
            other.push(release);
        }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Final releases moved out of remote-stopped carriers before their stop
/// commits, held until no stopped carrier's acknowledgement is outstanding.
///
/// One termination publishes a Stop to every CPU that runs, or holds the
/// suspended continuation of, one of its Threads, and each stopped CPU stages
/// from its own safe point under its own runtime hold. Two stops can therefore
/// be staged at once. A release staged by one stopped CPU may be finalized only
/// after that CPU's post-acknowledgement continuation, so the queue merges back
/// only when the last outstanding stop finishes: finalization can be delayed,
/// never early.
pub(crate) struct StagedStopCleanup<const CAPACITY: usize> {
    queue: CleanupQueue<CAPACITY>,
    outstanding: usize,
}

impl<const CAPACITY: usize> StagedStopCleanup<CAPACITY> {
    pub(crate) fn new() -> Self {
        Self {
            queue: CleanupQueue::new(),
            outstanding: 0,
        }
    }

    /// Moves `from`'s queued releases out of finalization reach for one more
    /// stopped carrier. `limit` bounds the stops that can be in flight at once
    /// (one per CPU slot).
    pub(crate) fn stage(&mut self, from: &mut CleanupQueue<CAPACITY>, limit: usize) {
        assert!(
            self.outstanding < limit,
            "remote stop staged more cleanups than CPU slots"
        );
        from.drain_into(&mut self.queue);
        self.outstanding += 1;
    }

    /// Whether any stopped carrier still has its staged cleanup outstanding.
    pub(crate) const fn is_staged(&self) -> bool {
        self.outstanding != 0
    }

    /// Ends one stopped carrier's staging. Returns whether this was the last
    /// outstanding stop, in which case every staged release moved to `into`.
    pub(crate) fn finish(&mut self, into: &mut CleanupQueue<CAPACITY>) -> bool {
        assert!(
            self.outstanding != 0,
            "post-ack carrier omitted staged cleanup"
        );
        self.outstanding -= 1;
        if self.outstanding != 0 {
            return false;
        }
        self.queue.drain_into(into);
        true
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

/// The writable output range an adapter's `preflight_output` would pin, so
/// a deferred-output caller can preflight it early (D1 commit 6).
#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(dead_code, reason = "only the live runtime defers outputs")
)]
pub(crate) fn output_range(
    address: DwUserAddress,
    byte_len: usize,
    alignment: u64,
) -> Result<UserRange, DwStatus> {
    user_range(address, byte_len, alignment, UserAccess::WRITE)
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

pub(crate) fn abi_get_info<U: UserPageAccess>(
    user: &mut U,
    out_info: DwUserAddress,
    out_size: u64,
    out_required_size: DwUserAddress,
) -> DwStatus {
    abi_get_info_with_features(user, out_info, out_size, out_required_size, 0)
}

pub(crate) fn abi_get_info_with_features<U: UserPageAccess>(
    user: &mut U,
    out_info: DwUserAddress,
    out_size: u64,
    out_required_size: DwUserAddress,
    feature_bits: u64,
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
    if let Err(error) = copy_to_user(user, info_range, &encode_abi_info(feature_bits)) {
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

/// Canonical `TaskError` to status mapping.
///
/// `pub(super)` so a sibling syscall module reaches it instead of inventing a
/// blind `Err(_) =>` arm, which is what `f_services` did.
pub(super) fn task_status(error: TaskError) -> DwStatus {
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

/// Admits `needed` objects of `object_type` for `process` under every
/// limited TaskGroup above it, returning the tag to charge them with
/// (F4 DW1-F4-M1). Runs before creation, so a refusal has nothing to undo.
fn admit_objects<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    registry: &ObjectRegistry<OBJECTS>,
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    process: ProcessKey,
    object_type: deepwyrm_abi::DwObjectType,
    needed: usize,
) -> Result<crate::task::quota::ChargeTag, DwStatus> {
    let class = crate::task::quota::object_class(object_type)
        .expect("only limited object classes are admitted");
    let tag = tasks.charge_tag(process).map_err(quota_status)?;
    tasks
        .admit_quota(&tag, class, needed, |group| registry.charged(group, class))
        .map_err(quota_status)?;
    Ok(tag)
}

/// Admits one RAM-backed MemoryObject of `pages` pages for `process`: one
/// object under the object class, and its pages under the page class (D6),
/// against the same tag. Runs before any frame is taken.
fn admit_memory_object<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    registry: &ObjectRegistry<OBJECTS>,
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    process: ProcessKey,
    pages: u64,
) -> Result<crate::task::quota::ChargeTag, DwStatus> {
    let tag = admit_objects(
        registry,
        tasks,
        process,
        deepwyrm_abi::DW_OBJECT_TYPE_MEMORY_OBJECT,
        1,
    )?;
    let needed = usize::try_from(pages).map_err(|_| DW_STATUS_NO_RESOURCES)?;
    tasks
        .admit_quota(
            &tag,
            crate::task::quota::MEMORY_PAGES_CLASS,
            needed,
            |group| registry.charged_pages(group),
        )
        .map_err(quota_status)?;
    Ok(tag)
}

/// Refuses creation into a TaskGroup or Process outside the creator's
/// limited subtree (F4 residual: limits must follow what a limited process
/// creates). `target` is the tag the created thing will be charged with.
fn confine_creation<
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    creator: ProcessKey,
    target: Result<crate::task::quota::ChargeTag, crate::task::quota::QuotaError>,
) -> Result<(), DwStatus> {
    let creator = tasks.charge_tag(creator).map_err(quota_status)?;
    if creator.is_empty() {
        return Ok(());
    }
    let target = target.map_err(quota_status)?;
    if tasks.limits_cover(&creator, &target) {
        Ok(())
    } else {
        Err(DW_STATUS_ACCESS_DENIED)
    }
}

/// Charges a just-created, still-live object to its creator's tag.
fn charge_created<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    object: crate::object::ObjectId,
    tag: crate::task::quota::ChargeTag,
) {
    if tag.is_empty() {
        return;
    }
    registry
        .set_charge_tag(object, tag)
        .unwrap_or_else(|error| panic!("fresh object rejected its quota charge: {error:?}"));
}

/// Admits `items` more registered waits for `thread`'s process (F4
/// DW1-F4-M1). Usage is the live wait entries whose waiting thread is
/// charged to the same limited group.
fn admit_waits<
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const WAITERS: usize,
>(
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    waits: &WaitRegistry<WAITERS>,
    thread: ThreadKey,
    items: usize,
) -> Result<(), DwStatus> {
    let tag = tasks.thread_charge_tag(thread).map_err(quota_status)?;
    if tag.is_empty() {
        return Ok(());
    }
    tasks
        .admit_quota(&tag, crate::task::quota::WAIT_CLASS, items, |group| {
            waits.count_waiting(|waiter| {
                tasks
                    .thread_charge_tag(waiter)
                    .is_ok_and(|waiter_tag| waiter_tag.names(group))
            })
        })
        .map_err(quota_status)
}

fn quota_status(error: crate::task::quota::QuotaError) -> DwStatus {
    match error {
        crate::task::quota::QuotaError::Exceeded | crate::task::quota::QuotaError::TooDeep => {
            DW_STATUS_NO_RESOURCES
        }
        crate::task::quota::QuotaError::Task => DW_STATUS_BAD_STATE,
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
        // Both are "try again", and the ABI says exactly that. They are distinct
        // inside the kernel because they clear on different events -- a full peer
        // queue on that peer receiving, an exhausted payload pool on any channel
        // releasing a slot -- and a diagnosis needs to name which. *Not* giving
        // them separate ABI statuses is the deliberate decision, not a side
        // effect of this split: a caller waits and retries for both, so one
        // status is correct for it. The reader of a stalled run is not that
        // caller, and `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` §3.2 puts the
        // instance in the refusal counters rather than here.
        ChannelError::WouldBlock | ChannelError::PayloadExhausted => DW_STATUS_WOULD_BLOCK,
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
    object_get_info_v1_impl(
        user,
        registry,
        memory,
        tasks,
        None,
        None,
        current_process,
        handle,
        topic,
        out_info,
        out_size,
        out_required_size,
    )
}

pub(crate) fn object_get_info_v1_with_devices<
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
    devices: &dyn crate::device::DeviceResourceInfoProvider,
    current_process: ProcessKey,
    handle: DwHandle,
    topic: u32,
    out_info: DwUserAddress,
    out_size: u64,
    out_required_size: DwUserAddress,
) -> DwStatus {
    object_get_info_v1_impl(
        user,
        registry,
        memory,
        tasks,
        Some(devices),
        None,
        current_process,
        handle,
        topic,
        out_info,
        out_size,
        out_required_size,
    )
}

pub(crate) fn object_get_info_v1_with_device_objects<
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
    devices: &dyn crate::device::DeviceResourceInfoProvider,
    interrupts: &dyn crate::device::InterruptInfoProvider,
    current_process: ProcessKey,
    handle: DwHandle,
    topic: u32,
    out_info: DwUserAddress,
    out_size: u64,
    out_required_size: DwUserAddress,
) -> DwStatus {
    object_get_info_v1_impl(
        user,
        registry,
        memory,
        tasks,
        Some(devices),
        Some(interrupts),
        current_process,
        handle,
        topic,
        out_info,
        out_size,
        out_required_size,
    )
}

fn object_get_info_v1_impl<
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
    devices: Option<&dyn crate::device::DeviceResourceInfoProvider>,
    interrupts: Option<&dyn crate::device::InterruptInfoProvider>,
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
    let encoded = match object_info_query(
        registry,
        memory,
        tasks,
        devices,
        interrupts,
        current_process,
        handle,
        topic,
    ) {
        Ok(encoded) => encoded,
        Err(status) => return status,
    };
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

/// The read-only half of `ObjectGetInfoV1` (D1 commit 6d, design §11.2.3
/// family B): resolves the handle and encodes the topic's info, touching no
/// user memory.
#[allow(
    clippy::too_many_arguments,
    reason = "the info query keeps every authority it reads explicit"
)]
#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(dead_code, reason = "only the live runtime splits the info query")
)]
pub(crate) fn object_get_info_v1_query_with_device_objects<
    const OBJECTS: usize,
    const MEMORY_OBJECTS: usize,
    const LEASES: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    memory: &MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    devices: &dyn crate::device::DeviceResourceInfoProvider,
    interrupts: &dyn crate::device::InterruptInfoProvider,
    current_process: ProcessKey,
    handle: DwHandle,
    topic: u32,
) -> Result<super::abi_bytes::EncodedObjectInfo, DwStatus> {
    object_info_query(
        registry,
        memory,
        tasks,
        Some(devices),
        Some(interrupts),
        current_process,
        handle,
        topic,
    )
}

/// The copy-out half of `ObjectGetInfoV1` (D1 commit 6d), after the query,
/// with the required-size output already pinned as `required`. It follows
/// `object_get_info_v1_impl`'s order exactly:
/// - a buffer too small writes only the required size;
/// - otherwise the info range is formed and preflighted, the info is
///   written, and then the required size is written.
///
/// It consumes `required` on every path.
#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(dead_code, reason = "only the live runtime splits the info query")
)]
pub(crate) fn object_get_info_v1_copy_out<U: OwnedUserOutputAccess>(
    user: &mut U,
    required: U::OwnedOutput,
    encoded: &super::abi_bytes::EncodedObjectInfo,
    out_info: DwUserAddress,
    out_size: u64,
) -> DwStatus {
    let required_size = encoded.len() as u64;
    if out_size < required_size {
        user.commit_owned_output(required, &encode_u64(required_size));
        return DW_STATUS_BUFFER_TOO_SMALL;
    }
    let info_range = match user_range(out_info, encoded.len(), 8, UserAccess::WRITE) {
        Ok(range) => range,
        Err(status) => {
            user.discard_owned_output(required);
            return status;
        }
    };
    let preflight = preflight_user_output(user, info_range, encoded.len()).map(drop);
    if let Err(error) = preflight {
        user.discard_owned_output(required);
        return usercopy_status(error);
    }
    let copied = copy_to_user(user, info_range, encoded.bytes());
    if let Err(error) = copied {
        user.discard_owned_output(required);
        return usercopy_status(error);
    }
    user.commit_owned_output(required, &encode_u64(required_size));
    DW_STATUS_SUCCESS
}

#[allow(
    clippy::too_many_arguments,
    reason = "the info query keeps every authority it reads explicit"
)]
fn object_info_query<
    const OBJECTS: usize,
    const MEMORY_OBJECTS: usize,
    const LEASES: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    memory: &MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    devices: Option<&dyn crate::device::DeviceResourceInfoProvider>,
    interrupts: Option<&dyn crate::device::InterruptInfoProvider>,
    current_process: ProcessKey,
    handle: DwHandle,
    topic: u32,
) -> Result<super::abi_bytes::EncodedObjectInfo, DwStatus> {
    let table = match tasks.process_handles(current_process) {
        Ok(table) => table,
        Err(error) => return Err(task_status(error)),
    };
    let result = match (devices, interrupts) {
        (Some(devices), Some(interrupts)) => {
            crate::service::object_get_info_v1_with_tasks_and_device_objects(
                table, registry, memory, tasks, devices, interrupts, handle, topic,
            )
        }
        (Some(devices), None) => crate::service::object_get_info_v1_with_tasks_and_devices(
            table, registry, memory, tasks, devices, handle, topic,
        ),
        (None, None) => crate::service::object_get_info_v1_with_tasks(
            table, registry, memory, tasks, handle, topic,
        ),
        (None, Some(_)) => {
            panic!("Interrupt object info cannot be wired without DeviceResource info")
        }
    };
    result.map(encode_object_info)
}

pub(crate) const fn object_info_required_size(topic: u32) -> Option<u64> {
    match topic {
        DW_OBJECT_INFO_BASIC_V1 => Some(DW_OBJECT_INFO_V1_SIZE as u64),
        DW_OBJECT_INFO_TASK_STATE_V1 => Some(64),
        DW_OBJECT_INFO_MEMORY_OBJECT_V1 => Some(DW_MEMORY_OBJECT_INFO_V1_SIZE as u64),
        DW_OBJECT_INFO_DEVICE_RESOURCE_V1 => Some(DW_DEVICE_RESOURCE_INFO_V1_SIZE as u64),
        DW_OBJECT_INFO_INTERRUPT_V1 => Some(DW_INTERRUPT_INFO_V1_SIZE as u64),
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

fn inspect_current_object_id<
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    current_process: ProcessKey,
    handle: DwHandle,
    object_type: deepwyrm_abi::DwObjectType,
    rights: DwRights,
) -> Result<crate::object::ObjectId, DwStatus> {
    let table = tasks
        .process_handles(current_process)
        .map_err(task_status)?;
    table
        .inspect_object_id(handle, AcceptedObjectTypes::One(object_type), rights)
        .map_err(handle_status)
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
    mut pins: RetiredExitPins<THREADS>,
    cleanup: &mut CleanupQueue<OBJECTS>,
) {
    while let Some(pin) = pins.pop() {
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

/// Handle finalizers one bounded drain step hands back.
///
/// Deliberately not `HANDLES`: this constant is what stops a terminal frame's
/// cost from tracking per-Process handle capacity. A Process with more handles
/// than this takes more steps.
const TERMINAL_DRAIN_WINDOW: usize = 32;

/// Drains an exited Process's handles into `cleanup` one bounded window at a
/// time.
///
/// `CleanupQueue` is push-only and is consumed once, after the syscall's pins
/// and locks are dropped, so routing finalizers into it in several steps
/// instead of one array cannot change when they are actually released.
fn drain_exited_process_handles_staged<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    process: ProcessKey,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> Result<(), TaskError> {
    let mut window: [Option<FinalRelease>; TERMINAL_DRAIN_WINDOW] = core::array::from_fn(|_| None);
    let mut cursor = 0;
    loop {
        let step =
            tasks.drain_exited_process_handle_window(registry, process, cursor, &mut window)?;
        for release in window
            .iter_mut()
            .take(step.written())
            .filter_map(Option::take)
        {
            cleanup.push(release);
        }
        if step.done() {
            return Ok(());
        }
        // A step whose window is at least one wide always consumes at least one
        // slot before it can report full, so the cursor cannot stand still.
        assert!(
            step.resume() > cursor,
            "a bounded Process handle drain step made no progress"
        );
        cursor = step.resume();
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
    pins: crate::task::ExitPins<THREADS>,
    pre_retired: &mut PreRetiredTerminalThreads<THREADS>,
    defer_current: Option<DeferredCurrentRetirement>,
    remotely_stopped: &[Option<ThreadKey>],
    terminal_waits: &mut C,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> Option<DeferredCurrentExecutionResources> {
    let deferred_thread = defer_current.filter(|current| {
        pins.thread_keys()
            .into_iter()
            .flatten()
            .any(|thread| thread == current.thread())
    });
    for thread in pins.thread_keys().into_iter().flatten() {
        terminal_waits.cleanup_terminal_wait(registry, tasks, waits, execution, thread, cleanup);
    }
    let (pins, deferred) = match deferred_thread {
        Some(DeferredCurrentRetirement::Model(current)) => {
            let (pins, deferred) = execution.retire_quiesced_exit_pins_defer_current(
                pins,
                current,
                pre_retired.as_mut(),
            );
            (pins, Some(deferred))
        }
        Some(DeferredCurrentRetirement::Handoff { cpu, thread }) => {
            let (pins, deferred) = execution
                .retire_quiesced_exit_pins_defer_current_after_remote_stops_on(
                    cpu,
                    pins,
                    thread,
                    remotely_stopped,
                    pre_retired.as_mut(),
                );
            (pins, Some(deferred))
        }
        None if remotely_stopped.is_empty() => (
            execution.retire_quiesced_exit_pins(pins, pre_retired.as_mut()),
            None,
        ),
        None => (
            execution.retire_quiesced_exit_pins_after_remote_stops(
                pins,
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

    fn insert(&mut self, thread: ThreadKey) {
        if self.threads.contains(&Some(thread)) {
            return;
        }
        *self
            .threads
            .iter_mut()
            .find(|slot| slot.is_none())
            .expect("prepared scheduler retirement batch overflow") = Some(thread);
    }

    fn assert_consumed(self) {
        assert!(
            self.threads.into_iter().all(|thread| thread.is_none()),
            "prepared scheduler retirement outlived its terminal pin batch"
        );
    }
}

#[must_use = "prepared Process termination must be completed after remote execution owners are stopped"]
pub(crate) struct PreparedProcessTermination<const THREADS: usize> {
    target: ProcessKey,
    pins: crate::task::ExitPins<THREADS>,
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
pub(crate) struct PreparedTaskGroupTermination<const PROCESSES: usize, const THREADS: usize> {
    teardown: GroupTeardown<PROCESSES, THREADS>,
    pre_retired: PreRetiredTerminalThreads<THREADS>,
}

impl<const PROCESSES: usize, const THREADS: usize>
    PreparedTaskGroupTermination<PROCESSES, THREADS>
{
    pub(crate) const fn process_keys(&self) -> [Option<ProcessKey>; PROCESSES] {
        self.teardown.process_keys()
    }

    pub(crate) const fn thread_keys(&self) -> [Option<ThreadKey>; THREADS] {
        self.teardown.thread_keys()
    }

    pub(crate) fn contains_thread(&self, thread: ThreadKey) -> bool {
        self.thread_keys().contains(&Some(thread))
    }

    pub(crate) fn record_pre_retired(&mut self, thread: ThreadKey) {
        assert!(self.contains_thread(thread));
        self.pre_retired.insert(thread);
    }
}

impl<const THREADS: usize> PreparedProcessTermination<THREADS> {
    pub(crate) const fn target(&self) -> ProcessKey {
        self.target
    }

    pub(crate) fn thread_keys(&self) -> [Option<ThreadKey>; THREADS] {
        self.pins.thread_keys()
    }

    pub(crate) fn record_pre_retired(&mut self, thread: ThreadKey) {
        assert!(self.thread_keys().contains(&Some(thread)));
        self.pre_retired.insert(thread);
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

    pub(crate) fn record_pre_retired(&mut self, thread: ThreadKey) {
        assert!(self.thread_keys().contains(&Some(thread)));
        self.pre_retired.insert(thread);
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
    if requested_rights.0 & deepwyrm_abi::DW_RIGHT_RESOURCE.0 != 0 {
        return DW_STATUS_ACCESS_DENIED;
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
    let target = tasks.group_charge_tag(parent_pin.id());
    if let Err(status) = confine_creation(tasks, current_process, target) {
        release_lookup_pin(registry, parent_pin, cleanup);
        return status;
    }
    let charge = match admit_objects(
        registry,
        tasks,
        current_process,
        deepwyrm_abi::DW_OBJECT_TYPE_TASK_GROUP,
        1,
    ) {
        Ok(charge) => charge,
        Err(status) => {
            release_lookup_pin(registry, parent_pin, cleanup);
            return status;
        }
    };
    let created = tasks.create_child_group(registry, &parent_pin);
    release_lookup_pin(registry, parent_pin, cleanup);
    let (_key, reference) = match created {
        Ok(created) => created,
        Err(error) => return task_create_status(error),
    };
    charge_created(registry, reference.id(), charge);
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

#[allow(
    clippy::too_many_arguments,
    reason = "D5 claim keeps user memory, task membership, grant, registry, and typed authority ownership explicit"
)]
/// `task_group_limit` (F4 DW1-F4-M1): lowers one class's limit on a group
/// the caller holds with MODIFY.
pub(crate) fn task_group_limit<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    current_process: ProcessKey,
    task_group: DwHandle,
    class: u32,
    limit: u32,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    let pin = match resolve_current_handle(
        tasks,
        registry,
        current_process,
        task_group,
        deepwyrm_abi::DW_OBJECT_TYPE_TASK_GROUP,
        DW_RIGHT_MODIFY,
    ) {
        Ok(pin) => pin,
        Err(status) => return status,
    };
    let result = tasks.lower_group_limit(
        crate::task::TaskGroupKey::from_object_id(pin.id()),
        class,
        limit,
    );
    release_lookup_pin(registry, pin, cleanup);
    match result {
        Ok(()) => DW_STATUS_SUCCESS,
        Err(crate::task::quota::LimitError::InvalidArgument) => DW_STATUS_INVALID_ARGUMENT,
        Err(crate::task::quota::LimitError::Task(error)) => task_status(error),
    }
}

pub(crate) fn device_resource_claim<
    U: UserPageAccess,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const RESOURCES: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    grants: &crate::boot::BootResourceGrantAuthority,
    resources: &DeviceResourceAuthority<RESOURCES>,
    current_process: ProcessKey,
    resource_domain: DwHandle,
    resource_id: u64,
    requested_rights: DwRights,
    out_resource: DwUserAddress,
) -> DwStatus {
    if resource_id == 0 {
        return DW_STATUS_INVALID_ARGUMENT;
    }
    if let Err(status) = validate_created_handle_rights(
        deepwyrm_abi::DW_OBJECT_TYPE_DEVICE_RESOURCE,
        requested_rights,
    ) {
        return status;
    }
    let output = match preflight_output(user, out_resource, 8, 8) {
        Ok(output) => output,
        Err(status) => return status,
    };
    // Public handle validation outranks caller lifecycle state. This first
    // resolution is deliberately read-only; the operation-held path resolves
    // the same handle again before reserving any grant or object authority.
    let resolved = match tasks.process_handles(current_process) {
        Ok(handles) => handles.lookup(
            registry,
            resource_domain,
            AcceptedObjectTypes::One(deepwyrm_abi::DW_OBJECT_TYPE_TASK_GROUP),
            deepwyrm_abi::DW_RIGHT_RESOURCE,
        ),
        Err(error) => return task_status(error),
    };
    let resolved = match resolved {
        Ok(resolved) => resolved,
        Err(error) => return handle_status(error),
    };
    assert!(
        registry
            .release_internal(resolved.into_internal())
            .unwrap_or_else(|failure| {
                panic!("D5 precedence lookup pin drifted: {:?}", failure.error())
            })
            .is_none(),
        "D5 precedence lookup pin became final while its handle remained owned"
    );
    let lease = match tasks.acquire_process_operation(current_process) {
        Ok(lease) => lease,
        // `Err(_) => DW_STATUS_BAD_STATE` reported a stale or foreign process
        // handle as "not accepting operations". `task_status` distinguishes
        // them, and was already in this file.
        Err(error) => return task_status(error),
    };
    let result = device_resource_claim_under_operation(
        registry,
        tasks,
        grants,
        resources,
        &lease,
        current_process,
        resource_domain,
        resource_id,
        requested_rights,
        None,
    );
    tasks
        .release_process_operation(lease)
        .unwrap_or_else(|(error, _)| panic!("D5 claim leaked process operation: {error:?}"));
    match result {
        Ok(handle) => {
            output.commit(&encode_handle(handle));
            DW_STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "D5 host injection exercises the two sides of the public-handle commit boundary"
)]
enum DeviceResourceClaimCommitFailure {
    Publication,
    PostPublication,
}

#[allow(clippy::too_many_arguments)]
fn device_resource_claim_under_operation<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const RESOURCES: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    grants: &crate::boot::BootResourceGrantAuthority,
    resources: &DeviceResourceAuthority<RESOURCES>,
    operation: &crate::task::ProcessOperationLease,
    current_process: ProcessKey,
    resource_domain: DwHandle,
    resource_id: u64,
    requested_rights: DwRights,
    fail_at: Option<DeviceResourceClaimCommitFailure>,
) -> Result<DwHandle, DwStatus> {
    let resolved = tasks
        .process_handles(current_process)
        .map_err(task_status)?
        .lookup(
            registry,
            resource_domain,
            AcceptedObjectTypes::One(deepwyrm_abi::DW_OBJECT_TYPE_TASK_GROUP),
            deepwyrm_abi::DW_RIGHT_RESOURCE,
        )
        .map_err(handle_status)?;
    let supplied_domain = TaskGroupKey::from_object_id(resolved.object_id());
    assert!(
        registry
            .release_internal(resolved.into_internal())
            .unwrap_or_else(|failure| panic!("D5 domain lookup pin drifted: {:?}", failure.error()))
            .is_none(),
        "D5 domain lookup pin became final while its handle remained owned"
    );
    let owner = grants.owner_key().map_err(|_| DW_STATUS_BAD_STATE)?;
    if supplied_domain != owner {
        return Err(DW_STATUS_ACCESS_DENIED);
    }
    let membership = tasks
        .prepare_resource_claim_membership(current_process, owner)
        .map_err(resource_membership_status)?;
    let (boot, reservation) = grants.reserve(resource_id).map_err(boot_grant_status)?;
    if boot.kind == deepwyrm_abi::DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION
        && crate::device::pci::PCI_FUNCTIONS
            .function(resource_id)
            .is_none()
    {
        grants.cancel(reservation).unwrap_or_else(|rollback| {
            panic!("PCI claim rollback drifted for an unprobed function: {rollback:?}")
        });
        return Err(deepwyrm_abi::DW_STATUS_NOT_FOUND);
    }
    let descriptor = DeviceResourceDescriptor {
        resource_id,
        lease_generation: reservation.lease_generation(),
        kind: boot.kind,
        pio_base: boot.pio_base,
        pio_length: boot.pio_length,
        interrupt_source: boot.interrupt_source,
        pci_address: boot.pci_address,
        pci_ids: boot.pci_ids,
        resource_domain: owner,
    };
    let creation = match registry.create(deepwyrm_abi::DW_OBJECT_TYPE_DEVICE_RESOURCE) {
        Ok(creation) => creation,
        Err(error) => {
            grants.cancel(reservation).unwrap_or_else(|rollback| {
                panic!("D5 grant rollback drifted after registry failure: {rollback:?}")
            });
            return Err(match error {
                ObjectRegistryError::Capacity | ObjectRegistryError::ReferenceCountExhausted => {
                    DW_STATUS_NO_RESOURCES
                }
                _ => DW_STATUS_BAD_STATE,
            });
        }
    };
    let binding = match resources.bind_claim(creation, descriptor, reservation.grant_generation()) {
        Ok(binding) => binding,
        Err((error, creation)) => {
            registry
                .cancel_creation(creation)
                .unwrap_or_else(|failure| {
                    panic!(
                        "D5 generic rollback drifted after typed bind failure: {:?}",
                        failure.error()
                    )
                });
            grants.cancel(reservation).unwrap_or_else(|rollback| {
                panic!("D5 grant rollback drifted after typed bind failure: {rollback:?}")
            });
            return Err(match error {
                crate::device::DeviceResourceError::Capacity => DW_STATUS_NO_RESOURCES,
                _ => DW_STATUS_BAD_STATE,
            });
        }
    };
    let key = binding.key();
    let bound = registry
        .finish_payload_binding(binding)
        .unwrap_or_else(|failure| {
            panic!(
                "D5 fresh DeviceResource binding could not seal: {:?}",
                failure.error()
            )
        });
    let reference = registry.bound_into_handle(bound).unwrap_or_else(|failure| {
        panic!(
            "D5 fresh DeviceResource could not become a handle: {:?}",
            failure.error()
        )
    });
    let mut destination = match tasks
        .process_handles_mut_for_operation(operation, current_process)
        .map_err(task_status)?
        .reserve_transfer_destination()
    {
        Ok(destination) => destination,
        Err(error) => {
            rollback_unpublished_claim(registry, resources, grants, reservation, reference);
            return Err(handle_status(error));
        }
    };
    if let Err(error) = tasks.validate_resource_claim_membership(&membership) {
        destination
            .cancel(
                tasks
                    .process_handles_mut_for_operation(operation, current_process)
                    .expect("D5 operation keeps caller HandleTable live"),
            )
            .unwrap_or_else(|rollback| panic!("D5 destination rollback drifted: {rollback:?}"));
        rollback_unpublished_claim(registry, resources, grants, reservation, reference);
        return Err(resource_membership_status(error));
    }
    let published = destination
        .try_publish_reference(
            tasks
                .process_handles_mut_for_operation(operation, current_process)
                .expect("D5 operation keeps caller HandleTable live"),
            reference,
            requested_rights,
        )
        .unwrap_or_else(|failure| {
            panic!(
                "D5 prevalidated handle publication diverged at commit: {:?}",
                failure.error()
            )
        });
    if fail_at == Some(DeviceResourceClaimCommitFailure::Publication) {
        let final_release = tasks
            .process_handles_mut_for_operation(operation, current_process)
            .expect("D5 operation keeps caller HandleTable live")
            .close(registry, published.handle)
            .unwrap_or_else(|error| panic!("D5 injected publication close drifted: {error:?}"))
            .expect("D5 injected publication owns the only public reference");
        let finalization =
            resources
                .take_finalization(final_release)
                .unwrap_or_else(|(error, _)| {
                    panic!("D5 injected publication lost typed authority: {error:?}")
                });
        crate::device::cancel_unpublished_device_resource_claim(registry, finalization);
        grants
            .cancel(reservation)
            .unwrap_or_else(|error| panic!("D5 injected publication lost grant: {error:?}"));
        return Err(DW_STATUS_NO_RESOURCES);
    }
    grants.commit(reservation, key.object_id());
    if fail_at == Some(DeviceResourceClaimCommitFailure::PostPublication) {
        let final_release = tasks
            .process_handles_mut_for_operation(operation, current_process)
            .expect("D5 operation keeps caller HandleTable live")
            .close(registry, published.handle)
            .unwrap_or_else(|error| panic!("D5 injected post-publication close drifted: {error:?}"))
            .expect("D5 injected post-publication owns the only public reference");
        let finalization =
            resources
                .take_finalization(final_release)
                .unwrap_or_else(|(error, _)| {
                    panic!("D5 injected post-publication lost typed authority: {error:?}")
                });
        crate::device::complete_device_resource_finalization_with_grants(
            registry,
            grants,
            finalization,
        );
        return Err(DW_STATUS_NO_RESOURCES);
    }
    Ok(published.handle)
}

fn rollback_unpublished_claim<const OBJECTS: usize, const RESOURCES: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    resources: &DeviceResourceAuthority<RESOURCES>,
    grants: &crate::boot::BootResourceGrantAuthority,
    reservation: crate::boot::BootResourceLeaseReservation,
    reference: HandleRef,
) {
    let final_release = registry
        .release_handle(reference)
        .unwrap_or_else(|failure| {
            panic!(
                "D5 claim rollback lost generic authority: {:?}",
                failure.error()
            )
        })
        .expect("unpublished D5 DeviceResource owns its only generic reference");
    let finalization = resources
        .take_finalization(final_release)
        .unwrap_or_else(|(error, _)| panic!("D5 claim rollback lost typed authority: {error:?}"));
    crate::device::cancel_unpublished_device_resource_claim(registry, finalization);
    grants
        .cancel(reservation)
        .unwrap_or_else(|error| panic!("D5 claim rollback lost grant reservation: {error:?}"));
}

fn resource_membership_status(error: ResourceClaimMembershipError) -> DwStatus {
    match error {
        ResourceClaimMembershipError::AccessDenied => DW_STATUS_ACCESS_DENIED,
        ResourceClaimMembershipError::BadState => DW_STATUS_BAD_STATE,
    }
}

fn boot_grant_status(error: crate::boot::BootResourceLeaseError) -> DwStatus {
    match error {
        crate::boot::BootResourceLeaseError::UnknownResource => deepwyrm_abi::DW_STATUS_NOT_FOUND,
        crate::boot::BootResourceLeaseError::AlreadyLeased => {
            deepwyrm_abi::DW_STATUS_ALREADY_EXISTS
        }
        crate::boot::BootResourceLeaseError::GenerationExhausted => DW_STATUS_NO_RESOURCES,
        crate::boot::BootResourceLeaseError::OwnerNotBound => DW_STATUS_BAD_STATE,
        crate::boot::BootResourceLeaseError::OwnerAlreadyBound
        | crate::boot::BootResourceLeaseError::GrantNotAvailable
        | crate::boot::BootResourceLeaseError::StaleReservation
        | crate::boot::BootResourceLeaseError::FinalizationMismatch => DW_STATUS_BAD_STATE,
    }
}

pub(crate) fn device_pio_read<
    U: UserPageAccess,
    I: crate::arch::x86_64::io_port::ScalarPortIo,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const RESOURCES: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    resources: &DeviceResourceAuthority<RESOURCES>,
    io: &mut I,
    current_process: ProcessKey,
    resource: DwHandle,
    offset: u32,
    width: u32,
    out_value: DwUserAddress,
) -> DwStatus {
    let output = match preflight_output(user, out_value, 4, 4) {
        Ok(output) => output,
        Err(status) => return status,
    };
    let result = process_handle_operation!(tasks, current_process, table, {
        crate::device::pio_read(table, registry, resources, io, resource, offset, width)
    });
    match result {
        Ok(Ok(value)) => {
            output.commit(&encode_u32(value));
            DW_STATUS_SUCCESS
        }
        Ok(Err(status)) => status,
        Err(error) => task_status(error),
    }
}

pub(crate) fn device_pio_write<
    I: crate::arch::x86_64::io_port::ScalarPortIo,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const RESOURCES: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    resources: &DeviceResourceAuthority<RESOURCES>,
    io: &mut I,
    current_process: ProcessKey,
    resource: DwHandle,
    offset: u32,
    width: u32,
    value: u32,
) -> DwStatus {
    match process_handle_operation!(tasks, current_process, table, {
        crate::device::pio_write(
            table, registry, resources, io, resource, offset, width, value,
        )
    }) {
        Ok(Ok(())) => DW_STATUS_SUCCESS,
        Ok(Err(status)) => status,
        Err(error) => task_status(error),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn device_pci_config_read<
    U: UserPageAccess,
    C: crate::device::pci::ConfigSpace,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const RESOURCES: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    resources: &DeviceResourceAuthority<RESOURCES>,
    config: &mut C,
    current_process: ProcessKey,
    resource: DwHandle,
    offset: u32,
    width: u32,
    out_value: DwUserAddress,
) -> DwStatus {
    let output = match preflight_output(user, out_value, 4, 4) {
        Ok(output) => output,
        Err(status) => return status,
    };
    let result = process_handle_operation!(tasks, current_process, table, {
        crate::device::pci_config_read(table, registry, resources, config, resource, offset, width)
    });
    match result {
        Ok(Ok(value)) => {
            output.commit(&encode_u32(value));
            DW_STATUS_SUCCESS
        }
        Ok(Err(status)) => status,
        Err(error) => task_status(error),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn device_pci_command<
    C: crate::device::pci::ConfigSpace,
    D: crate::device::dma::DmaService,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const RESOURCES: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    resources: &DeviceResourceAuthority<RESOURCES>,
    config: &mut C,
    dma: &mut D,
    current_process: ProcessKey,
    resource: DwHandle,
    memory_space: u32,
    bus_master: u32,
    dma_confined: impl FnOnce(crate::device::pci::PciAddress) -> bool,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    // A process that takes over the function first loses nothing to its
    // predecessor: a domain another process created is revoked before the
    // command runs. Bus mastering is refused while another process holds a
    // BAR object of the function, since that process could program the
    // device to reach this one's DMA (storage review K2). An unusable handle
    // fails below with its own status.
    if let Some((resource_id, boot_id)) = resource_object_id(
        registry,
        tasks,
        resources,
        current_process,
        resource,
        deepwyrm_abi::DW_RIGHT_WRITE,
    ) {
        if bus_master != 0 && bars_held_by_other(boot_id, current_process) {
            return DW_STATUS_BAD_STATE;
        }
        if let Err(status) =
            revoke_foreign_dma(registry, dma, cleanup, resource_id, current_process, true)
        {
            return status;
        }
    }
    match process_handle_operation!(tasks, current_process, table, {
        crate::device::pci_command(
            table,
            registry,
            resources,
            config,
            resource,
            memory_space,
            bus_master,
            dma_confined,
        )
    }) {
        Ok(Ok(())) => DW_STATUS_SUCCESS,
        Ok(Err(status)) => status,
        Err(error) => task_status(error),
    }
}

fn dma_status(error: crate::device::dma::DmaError) -> DwStatus {
    use crate::device::dma::DmaError;
    match error {
        DmaError::InvalidRange => DW_STATUS_INVALID_ARGUMENT,
        DmaError::NotSupported => DW_STATUS_NOT_SUPPORTED,
        DmaError::NoResources => DW_STATUS_NO_RESOURCES,
        DmaError::NoAddressSpace => deepwyrm_abi::DW_STATUS_NO_MEMORY,
        DmaError::NotFound => deepwyrm_abi::DW_STATUS_NOT_FOUND,
        DmaError::FunctionBusy => DW_STATUS_BAD_STATE,
    }
}

/// The object identity behind `handle` when it names a DeviceResource with
/// `right`, and its boot resource ID when it is a PCI function; `None`
/// otherwise. The lookup pin is released at once.
fn resource_object_id<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const RESOURCES: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    resources: &DeviceResourceAuthority<RESOURCES>,
    current_process: ProcessKey,
    handle: DwHandle,
    right: DwRights,
) -> Option<(crate::object::ObjectId, Option<u64>)> {
    let resolved = tasks
        .process_handles_mut(current_process)
        .ok()?
        .lookup(
            registry,
            handle,
            crate::handle::AcceptedObjectTypes::One(deepwyrm_abi::DW_OBJECT_TYPE_DEVICE_RESOURCE),
            right,
        )
        .ok()?;
    let id = resolved.object_id();
    let boot_id = resources.pci_resource_id_for_resolved(&resolved).ok();
    release_held_lookup_pin(registry, resolved.into_internal());
    Some((id, boot_id))
}

/// Whether a process other than `current_process` holds a live BAR object
/// of the PCI function `boot_id` names (storage review K2).
fn bars_held_by_other(boot_id: Option<u64>, current_process: ProcessKey) -> bool {
    boot_id.is_some_and(|boot_id| {
        crate::device::pci::PCI_FUNCTIONS.bars_held_by_other(boot_id, current_process.object_id())
    })
}

/// Revokes `resource`'s DMA domain when a process other than
/// `current_process` owns it (storage K4 follow-up R2): bus mastering off,
/// every mapping removed and invalidated, and each released MemoryObject
/// reference queued for cleanup, since one may be the last. Only a caller
/// whose handle may drive the function's DMA (`may_revoke`: WRITE or
/// MODIFY) takes a domain over; for any other caller a foreign domain is
/// `BAD_STATE` and is left alone (storage review K3).
fn revoke_foreign_dma<D: crate::device::dma::DmaService, const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    dma: &mut D,
    cleanup: &mut CleanupQueue<OBJECTS>,
    resource: crate::object::ObjectId,
    current_process: ProcessKey,
    may_revoke: bool,
) -> Result<(), DwStatus> {
    dma.revoke_foreign(
        resource,
        current_process.object_id(),
        may_revoke,
        &mut |pin| {
            cleanup.push_optional(registry.release_internal(pin).unwrap_or_else(|failure| {
                panic!(
                    "a revoked DMA mapping reference violated generic lifetime invariants: {:?}",
                    failure.error()
                )
            }));
        },
    )
    .map_err(dma_status)
}

/// Releases a lookup pin whose handle still owns the object, so the pin is
/// never the last reference.
fn release_held_lookup_pin<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    pin: crate::object::InternalRef,
) {
    match registry.release_internal(pin) {
        Ok(None) => {}
        Ok(Some(_)) => panic!("a lookup pin became final while its handle lived"),
        Err(failure) => panic!(
            "a lookup pin violated generic lifetime invariants: {:?}",
            failure.error()
        ),
    }
}

/// Resolves a PCI_FUNCTION DeviceResource handle with MODIFY to its object
/// identity, boot resource ID and bus-0 device/function. The lookup pin is
/// released before
/// returning: a domain is keyed by the resource's identity, and the resource
/// cannot finalize while the caller's handle (and this syscall) holds it.
fn dma_resource<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const RESOURCES: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    resources: &DeviceResourceAuthority<RESOURCES>,
    current_process: ProcessKey,
    resource: DwHandle,
) -> Result<(crate::object::ObjectId, u64, u8), DwStatus> {
    let resolved = match tasks.process_handles_mut(current_process) {
        Ok(table) => table
            .lookup(
                registry,
                resource,
                crate::handle::AcceptedObjectTypes::One(
                    deepwyrm_abi::DW_OBJECT_TYPE_DEVICE_RESOURCE,
                ),
                deepwyrm_abi::DW_RIGHT_MODIFY,
            )
            .map_err(handle_status)?,
        Err(error) => return Err(task_status(error)),
    };
    let address = resources.pci_address_for_resolved(&resolved);
    let boot_id = resources.pci_resource_id_for_resolved(&resolved);
    let id = resolved.object_id();
    release_held_lookup_pin(registry, resolved.into_internal());
    let address = address.map_err(|_| DW_STATUS_INVALID_ARGUMENT)?;
    let boot_id = boot_id.map_err(|_| DW_STATUS_INVALID_ARGUMENT)?;
    if address.bus() != 0 {
        return Err(DW_STATUS_NOT_SUPPORTED);
    }
    Ok((id, boot_id, (address.device() << 3) | address.function()))
}

/// `dma_map` (storage K4): maps pages of a page-backed MemoryObject into the
/// resource's IOMMU domain. The MemoryObject lookup pin becomes the
/// mapping's reference.
#[allow(clippy::too_many_arguments)]
pub(crate) fn dma_map<
    U: UserPageAccess,
    D: crate::device::dma::DmaService,
    const OBJECTS: usize,
    const MEMORY_OBJECTS: usize,
    const LEASES: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const RESOURCES: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    memory: &MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    resources: &DeviceResourceAuthority<RESOURCES>,
    dma: &mut D,
    object_pages: &dyn crate::memory::frame_roles::ObjectPages,
    current_process: ProcessKey,
    resource: DwHandle,
    memory_object: DwHandle,
    offset: u64,
    byte_len: u64,
    access: u32,
    out_iova: DwUserAddress,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    use crate::memory::object::MemoryObjectError;
    if access == 0 || access & !deepwyrm_abi::DW_DMA_ACCESS_SUPPORTED_MASK != 0 {
        return DW_STATUS_INVALID_ARGUMENT;
    }
    let device = crate::arch::x86_64::vtd::tables::DeviceAccess {
        read: access & deepwyrm_abi::DW_DMA_ACCESS_DEVICE_READ != 0,
        write: access & deepwyrm_abi::DW_DMA_ACCESS_DEVICE_WRITE != 0,
    };
    let output = match preflight_output(user, out_iova, 8, 8) {
        Ok(output) => output,
        Err(status) => return status,
    };
    let (resource_id, boot_id, devfn) =
        match dma_resource(registry, tasks, resources, current_process, resource) {
            Ok(found) => found,
            Err(status) => return status,
        };
    // Another process's live BAR object could program the device to reach
    // these mappings (storage review K2).
    if bars_held_by_other(Some(boot_id), current_process) {
        return DW_STATUS_BAD_STATE;
    }
    if let Err(status) =
        revoke_foreign_dma(registry, dma, cleanup, resource_id, current_process, true)
    {
        return status;
    }
    let mut required = deepwyrm_abi::DW_RIGHT_READ.0;
    if device.write {
        required |= deepwyrm_abi::DW_RIGHT_WRITE.0;
    }
    let resolved = match tasks.process_handles_mut(current_process) {
        Ok(table) => match table.lookup(
            registry,
            memory_object,
            crate::handle::AcceptedObjectTypes::One(deepwyrm_abi::DW_OBJECT_TYPE_MEMORY_OBJECT),
            DwRights(required),
        ) {
            Ok(resolved) => resolved,
            Err(error) => return handle_status(error),
        },
        Err(error) => return task_status(error),
    };
    let range = match memory.dma_physical_range(&resolved, offset, byte_len, device.write) {
        Ok(range) => range,
        Err(error) => {
            release_held_lookup_pin(registry, resolved.into_internal());
            return match error {
                MemoryObjectError::BackingKind => DW_STATUS_NOT_SUPPORTED,
                MemoryObjectError::BackingTooSmall => DW_STATUS_INVALID_ARGUMENT,
                other => memory_object_status(other),
            };
        }
    };
    let pages = byte_len / crate::memory::object::PAGE_SIZE;
    // The held lookup pin keeps the object, and so its backing, alive until
    // the mapping owns it; each page is resolved through the backing's runs.
    let mut page_at = |page: u64| {
        let offset = page
            .checked_mul(crate::memory::object::PAGE_SIZE)
            .and_then(|bytes| bytes.checked_add(range.object_offset()))?;
        object_pages.object_page(range.backing_identity(), offset, device.write)
    };
    match dma.map(
        resource_id,
        current_process.object_id(),
        devfn,
        &mut page_at,
        pages,
        device,
        resolved.into_internal(),
    ) {
        Ok(iova) => {
            output.commit(&iova.to_le_bytes());
            DW_STATUS_SUCCESS
        }
        Err((error, pin)) => {
            release_held_lookup_pin(registry, pin);
            dma_status(error)
        }
    }
}

/// `dma_unmap` (storage K4): removes one whole mapping, invalidates the
/// IOTLB, and only then releases the MemoryObject reference it held.
#[allow(clippy::too_many_arguments)]
pub(crate) fn dma_unmap<
    D: crate::device::dma::DmaService,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const RESOURCES: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    resources: &DeviceResourceAuthority<RESOURCES>,
    dma: &mut D,
    current_process: ProcessKey,
    resource: DwHandle,
    iova: u64,
    byte_len: u64,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    let page = crate::memory::object::PAGE_SIZE;
    if byte_len == 0 || !byte_len.is_multiple_of(page) || !iova.is_multiple_of(page) {
        return DW_STATUS_INVALID_ARGUMENT;
    }
    let (resource_id, _, _) =
        match dma_resource(registry, tasks, resources, current_process, resource) {
            Ok(found) => found,
            Err(status) => return status,
        };
    if let Err(status) =
        revoke_foreign_dma(registry, dma, cleanup, resource_id, current_process, true)
    {
        return status;
    }
    match dma.unmap(
        resource_id,
        current_process.object_id(),
        iova,
        byte_len / page,
    ) {
        Ok(pin) => {
            cleanup.push_optional(registry.release_internal(pin).unwrap_or_else(|failure| {
                panic!(
                    "a DMA mapping reference violated generic lifetime invariants: {:?}",
                    failure.error()
                )
            }));
            DW_STATUS_SUCCESS
        }
        Err(error) => dma_status(error),
    }
}

/// `device_mmio_object_create` (storage K3): a MemoryObject over one whole
/// admitted BAR, holding the DeviceResource's lookup pin until it finalizes.
#[allow(clippy::too_many_arguments)]
pub(crate) fn device_mmio_object_create<
    U: UserPageAccess,
    D: crate::device::dma::DmaService,
    const OBJECTS: usize,
    const MEMORY_OBJECTS: usize,
    const LEASES: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const RESOURCES: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    memory: &mut MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    resources: &DeviceResourceAuthority<RESOURCES>,
    dma: &mut D,
    current_process: ProcessKey,
    resource: DwHandle,
    bar: u32,
    requested_rights: DwRights,
    out_memory_object: DwUserAddress,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    if requested_rights.0 == 0
        || requested_rights.0 & deepwyrm_abi::DW_RIGHT_EXECUTE.0 != 0
        || !deepwyrm_abi::dw_rights_are_known(requested_rights)
        || !deepwyrm_abi::dw_rights_are_compatible(
            deepwyrm_abi::DW_OBJECT_TYPE_MEMORY_OBJECT,
            requested_rights,
        )
    {
        return DW_STATUS_INVALID_ARGUMENT;
    }
    let output = match preflight_output(user, out_memory_object, 8, 8) {
        Ok(output) => output,
        Err(status) => return status,
    };
    let resolved = match tasks.process_handles_mut(current_process) {
        Ok(table) => match table.lookup(
            registry,
            resource,
            crate::handle::AcceptedObjectTypes::One(deepwyrm_abi::DW_OBJECT_TYPE_DEVICE_RESOURCE),
            deepwyrm_abi::DW_RIGHT_MAP,
        ) {
            Ok(resolved) => resolved,
            Err(error) => return handle_status(error),
        },
        Err(error) => return task_status(error),
    };
    let resource_id = resources.pci_resource_id_for_resolved(&resolved);
    let resource_object = resolved.object_id();
    // MAP alone lets a holder read the device, not drive its DMA, so it
    // cannot take a domain over from another process (storage review K3).
    let may_revoke = resolved.rights().0
        & (deepwyrm_abi::DW_RIGHT_WRITE.0 | deepwyrm_abi::DW_RIGHT_MODIFY.0)
        != 0;
    let parent = resolved.into_internal();
    // Every failure below releases the lookup pin. The caller's handle still
    // owns the resource, so the pin is never its last reference.
    let fail = |registry: &mut ObjectRegistry<OBJECTS>, parent, status| match registry
        .release_internal(parent)
    {
        Ok(None) => status,
        Ok(Some(_)) => panic!("DeviceResource lookup pin became final while its handle lived"),
        Err(failure) => panic!(
            "DeviceResource lookup pin violated generic lifetime invariants: {:?}",
            failure.error()
        ),
    };
    let resource_id = match resource_id {
        Ok(resource_id) => resource_id,
        Err(_) => return fail(registry, parent, DW_STATUS_INVALID_ARGUMENT),
    };
    // A function's BAR objects belong to one process at a time (storage
    // review K2); refuse before anything is revoked.
    if bars_held_by_other(Some(resource_id), current_process) {
        return fail(registry, parent, DW_STATUS_BAD_STATE);
    }
    // The caller's handle keeps the resource alive, so revoking here cannot
    // release the lookup pin's object.
    if let Err(status) = revoke_foreign_dma(
        registry,
        dma,
        cleanup,
        resource_object,
        current_process,
        may_revoke,
    ) {
        return fail(registry, parent, status);
    }
    let charge = match admit_objects(
        registry,
        tasks,
        current_process,
        deepwyrm_abi::DW_OBJECT_TYPE_MEMORY_OBJECT,
        1,
    ) {
        Ok(charge) => charge,
        Err(status) => return fail(registry, parent, status),
    };
    let backing = match crate::device::pci::PCI_FUNCTIONS.take_bar_backing(
        resource_id,
        bar,
        current_process.object_id(),
    ) {
        Ok(backing) => backing,
        Err(crate::device::pci::BarBackingError::NotFound) => {
            return fail(registry, parent, deepwyrm_abi::DW_STATUS_NOT_FOUND);
        }
        Err(crate::device::pci::BarBackingError::InUse) => {
            return fail(registry, parent, deepwyrm_abi::DW_STATUS_ALREADY_EXISTS);
        }
        Err(crate::device::pci::BarBackingError::HeldElsewhere) => {
            return fail(registry, parent, DW_STATUS_BAD_STATE);
        }
    };
    let creation = match registry.create(deepwyrm_abi::DW_OBJECT_TYPE_MEMORY_OBJECT) {
        Ok(creation) => creation,
        Err(ObjectRegistryError::Capacity | ObjectRegistryError::ReferenceCountExhausted) => {
            crate::device::pci::PCI_FUNCTIONS.return_bar_backing(backing);
            return fail(registry, parent, DW_STATUS_NO_RESOURCES);
        }
        Err(error) => panic!("DeviceMmio generic creation failed unexpectedly: {error:?}"),
    };
    let binding = match memory.bind_device_mmio(creation, backing, parent) {
        Ok(binding) => binding,
        Err((error, parent)) => {
            let status = memory_object_status(error.error());
            let (creation, backing) = error.into_parts();
            registry
                .cancel_creation(creation)
                .unwrap_or_else(|failure| {
                    panic!("DeviceMmio bind rollback drifted: {:?}", failure.error())
                });
            crate::device::pci::PCI_FUNCTIONS.return_bar_backing(backing);
            return fail(registry, parent, status);
        }
    };
    let bound = registry
        .finish_payload_binding(binding)
        .unwrap_or_else(|failure| {
            panic!(
                "fresh DeviceMmio binding was rejected: {:?}",
                failure.error()
            )
        });
    let reference = registry.bound_into_handle(bound).unwrap_or_else(|failure| {
        panic!(
            "fresh DeviceMmio object could not become a handle: {:?}",
            failure.error()
        )
    });
    charge_created(registry, reference.id(), charge);
    // From here a failure releases the fresh object's only reference, and its
    // finalization returns the BAR grant and the DeviceResource pin.
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
                            "DeviceMmio publication rollback drifted: {:?}",
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn interrupt_create<
    U: UserPageAccess,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const RESOURCES: usize,
    const INTERRUPTS: usize,
>(
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    resources: &DeviceResourceAuthority<RESOURCES>,
    interrupts: &InterruptAuthority<INTERRUPTS>,
    platform: &dyn InterruptPlatform,
    current_process: ProcessKey,
    resource: DwHandle,
    requested_rights: DwRights,
    out_interrupt: DwUserAddress,
) -> DwStatus {
    if let Err(status) =
        validate_created_handle_rights(deepwyrm_abi::DW_OBJECT_TYPE_INTERRUPT, requested_rights)
    {
        return status;
    }
    let output = match preflight_output(user, out_interrupt, 8, 8) {
        Ok(output) => output,
        Err(status) => return status,
    };
    let result = process_handle_operation!(tasks, current_process, table, {
        crate::device::interrupt_create(
            table,
            registry,
            resources,
            interrupts,
            platform,
            resource,
            requested_rights,
        )
    });
    match result {
        Ok(Ok((_key, handle))) => {
            output.commit(&encode_handle(handle));
            DW_STATUS_SUCCESS
        }
        Ok(Err(error)) => interrupt_create_status(error),
        Err(error) => task_status(error),
    }
}

pub(crate) fn interrupt_ack<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const INTERRUPTS: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    interrupts: &InterruptAuthority<INTERRUPTS>,
    platform: &dyn InterruptPlatform,
    current_process: ProcessKey,
    interrupt: DwHandle,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    match process_handle_operation!(tasks, current_process, table, {
        crate::device::interrupt_ack(table, registry, interrupts, platform, interrupt)
    }) {
        Ok(Ok(release)) => {
            cleanup.push_optional(release);
            DW_STATUS_SUCCESS
        }
        Ok(Err(status)) => status,
        Err(error) => task_status(error),
    }
}

fn interrupt_create_status(error: InterruptCreateError) -> DwStatus {
    match error {
        InterruptCreateError::Handle(error) => handle_status(error),
        InterruptCreateError::Registry(ObjectRegistryError::Capacity)
        | InterruptCreateError::Registry(ObjectRegistryError::ReferenceCountExhausted) => {
            DW_STATUS_NO_RESOURCES
        }
        InterruptCreateError::Registry(_) | InterruptCreateError::Publication(_) => {
            DW_STATUS_BAD_STATE
        }
        InterruptCreateError::Interrupt(error) => match error {
            InterruptError::InvalidRights => DW_STATUS_INVALID_ARGUMENT,
            InterruptError::Capacity => DW_STATUS_NO_RESOURCES,
            InterruptError::InvalidObject => DW_STATUS_BAD_STATE,
            InterruptError::IdentityInUse => deepwyrm_abi::DW_STATUS_ALREADY_EXISTS,
            InterruptError::BadState | InterruptError::FinalizationMismatch => DW_STATUS_BAD_STATE,
            InterruptError::Platform(error) => match error {
                crate::device::InterruptPlatformError::SourceInUse => {
                    deepwyrm_abi::DW_STATUS_ALREADY_EXISTS
                }
                crate::device::InterruptPlatformError::Capacity => DW_STATUS_NO_RESOURCES,
                crate::device::InterruptPlatformError::InvalidSource => DW_STATUS_INVALID_ARGUMENT,
                crate::device::InterruptPlatformError::StaleBinding
                | crate::device::InterruptPlatformError::BadState => DW_STATUS_BAD_STATE,
            },
        },
    }
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

/// The process-create result size, the one output a deferred creation
/// records.
const PROCESS_CREATE_RESULT_BYTES: usize = DW_PROCESS_CREATE_RESULT_V1_SIZE as usize;

/// `ProcessCreate`'s access while its transaction runs under the runtime
/// authority (D1 commit 7c, design §11.2.3 family D).
///
/// The input was copied, and the output pinned as an owned output, before
/// the authority was taken. The transaction still reserves the child's
/// architecture root through `inner`, a paging session taken beneath the
/// guard, which is a page-table mutation and not a usercopy. Its output
/// commit or discard is recorded here and carried out after the guard is
/// released. Any other usercopy panics: the transaction does none after its
/// input.
#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(dead_code, reason = "only the live runtime defers ProcessCreate")
)]
pub(crate) struct DeferredProcessCreateAccess<'a, R, O> {
    inner: &'a mut R,
    pending: Option<(O, Option<[u8; PROCESS_CREATE_RESULT_BYTES]>)>,
}

#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(dead_code, reason = "only the live runtime defers ProcessCreate")
)]
impl<'a, R, O> DeferredProcessCreateAccess<'a, R, O> {
    /// `inner` reserves the child's architecture root (D1 commit 9: the live
    /// runtime's page-table mutation session, which carries no usercopy).
    pub(crate) fn new(inner: &'a mut R) -> Self {
        Self {
            inner,
            pending: None,
        }
    }

    /// The pinned output, and the result to commit into it (`None` to
    /// discard). The transaction settles its output on every path.
    pub(crate) fn into_pending(self) -> (O, Option<[u8; PROCESS_CREATE_RESULT_BYTES]>) {
        self.pending
            .expect("ProcessCreate transaction left its output unsettled")
    }
}

impl<R, O> UserPageAccess for DeferredProcessCreateAccess<'_, R, O> {
    type Error = crate::memory::usercopy::DeferredOutputUnavailable;
    type Pinned<'b>
        = crate::memory::usercopy::DeferredOutputPin<'b>
    where
        Self: 'b;

    fn pin(&mut self, _range: UserRange) -> Result<Self::Pinned<'_>, Self::Error> {
        panic!("ProcessCreate does no usercopy under the runtime authority");
    }
}

impl<R, O> OwnedUserOutputAccess for DeferredProcessCreateAccess<'_, R, O> {
    type OwnedOutput = O;

    fn preflight_owned_output(
        &mut self,
        _range: UserRange,
    ) -> Result<Self::OwnedOutput, Self::Error> {
        panic!("ProcessCreate pins its output before the runtime authority");
    }

    fn commit_owned_output(&mut self, output: Self::OwnedOutput, source: &[u8]) {
        let bytes: [u8; PROCESS_CREATE_RESULT_BYTES] = source
            .try_into()
            .expect("ProcessCreate result has its generated size");
        assert!(
            self.pending.replace((output, Some(bytes))).is_none(),
            "ProcessCreate settled its output twice"
        );
    }

    fn discard_owned_output(&mut self, output: Self::OwnedOutput) {
        assert!(
            self.pending.replace((output, None)).is_none(),
            "ProcessCreate settled its output twice"
        );
    }
}

impl<R: ProcessRootReservation, O> ProcessRootReservation
    for DeferredProcessCreateAccess<'_, R, O>
{
    fn reserve_child_root(
        &mut self,
        process: ProcessKey,
        address_space: crate::memory::address_region::AddressSpaceKey,
    ) -> Result<(), DwStatus> {
        self.inner.reserve_child_root(process, address_space)
    }

    fn rollback_empty_child_root(
        &mut self,
        process: ProcessKey,
        address_space: crate::memory::address_region::AddressSpaceKey,
    ) {
        self.inner.rollback_empty_child_root(process, address_space);
    }
}

/// `ProcessCreate`'s input copy and output pin (D1 commit 7c), for the live
/// runtime to run with no runtime lock held.
#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(dead_code, reason = "only the live runtime defers ProcessCreate")
)]
pub(crate) fn process_create_input<U: UserPageAccess + OwnedUserOutputAccess>(
    user: &mut U,
    args_address: DwUserAddress,
    args_size: u64,
    out_result: DwUserAddress,
    result_size: u64,
) -> Result<PreparedProcessCreate<U::OwnedOutput>, DwStatus> {
    prepare_process_create_input(user, args_address, args_size, out_result, result_size)
}

/// `ProcessCreate`'s transaction over prepared input, reserving the child
/// root through `user` and observing the committed child (D1 commit 7c).
#[allow(
    clippy::too_many_arguments,
    reason = "the live F10 publication keeps portable construction and exact architecture-root reservation in one failure-atomic transaction"
)]
#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(dead_code, reason = "only the live runtime defers ProcessCreate")
)]
pub(crate) fn process_create_with_root_prepared<
    U: OwnedUserOutputAccess + ProcessRootReservation,
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
    prepared: PreparedProcessCreate<U::OwnedOutput>,
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    regions: &mut AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
    spaces: &mut AddressSpaceAuthority<SPACES, REGIONS>,
    current_process: ProcessKey,
    cleanup: &mut CleanupQueue<OBJECTS>,
    observe_committed_process: O,
) -> DwStatus {
    process_create_publish(
        prepared,
        user,
        registry,
        tasks,
        regions,
        spaces,
        current_process,
        cleanup,
        |access, process, address_space| access.reserve_child_root(process, address_space),
        |access, process, address_space| access.rollback_empty_child_root(process, address_space),
        |_| Ok(()),
        observe_committed_process,
    )
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
pub(crate) struct PreparedProcessCreate<OUTPUT> {
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
    reserve_root: R,
    rollback_root: B,
    inject: I,
    observe_committed_process: O,
) -> DwStatus {
    let prepared = match prepare_process_create_input(
        user,
        args_address,
        args_size,
        out_result,
        result_size,
    ) {
        Ok(prepared) => prepared,
        Err(status) => return status,
    };
    process_create_publish(
        prepared,
        user,
        registry,
        tasks,
        regions,
        spaces,
        current_process,
        cleanup,
        reserve_root,
        rollback_root,
        inject,
        observe_committed_process,
    )
}

/// `ProcessCreate` after its input is copied and its output pinned (D1
/// commit 7c): the authority transaction, ending in the output's commit or
/// discard through `user`.
#[allow(
    clippy::too_many_arguments,
    reason = "the F10 publication keeps portable construction and exact architecture-root reservation in one failure-atomic transaction"
)]
fn process_create_publish<
    U: OwnedUserOutputAccess,
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
    prepared: PreparedProcessCreate<U::OwnedOutput>,
    user: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    regions: &mut AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
    spaces: &mut AddressSpaceAuthority<SPACES, REGIONS>,
    current_process: ProcessKey,
    cleanup: &mut CleanupQueue<OBJECTS>,
    mut reserve_root: R,
    mut rollback_root: B,
    mut inject: I,
    observe_committed_process: O,
) -> DwStatus {
    let PreparedProcessCreate { args, output } = prepared;

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

    let target = tasks.group_charge_tag(parent_pin.id());
    if let Err(status) = confine_creation(tasks, current_process, target) {
        cancel_prepared_handle_move(&mut prepared_move, tasks, current_process);
        release_lookup_pin(registry, bootstrap_pin, cleanup);
        release_lookup_pin(registry, parent_pin, cleanup);
        discard_and_return!(status);
    }
    let charge = match admit_objects(
        registry,
        tasks,
        current_process,
        deepwyrm_abi::DW_OBJECT_TYPE_PROCESS,
        1,
    ) {
        Ok(charge) => charge,
        Err(status) => {
            cancel_prepared_handle_move(&mut prepared_move, tasks, current_process);
            release_lookup_pin(registry, bootstrap_pin, cleanup);
            release_lookup_pin(registry, parent_pin, cleanup);
            discard_and_return!(status);
        }
    };
    let prepared_process = match tasks.prepare_process(registry, &parent_pin) {
        Ok(prepared) => prepared,
        Err(error) => {
            cancel_prepared_handle_move(&mut prepared_move, tasks, current_process);
            release_lookup_pin(registry, bootstrap_pin, cleanup);
            release_lookup_pin(registry, parent_pin, cleanup);
            discard_and_return!(task_create_status(error));
        }
    };
    charge_created(registry, prepared_process.key().object_id(), charge);
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
    let charge = match admit_objects(registry, tasks, current_process, DW_OBJECT_TYPE_CHANNEL, 2) {
        Ok(charge) => charge,
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
    charge_created(registry, first_reference.id(), charge);
    charge_created(registry, second_reference.id(), charge);
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
    channel_send_from_thread(
        user,
        staging,
        registry,
        channels,
        waits,
        tasks,
        execution,
        current_process,
        None,
        channel,
        bytes,
        byte_len,
        transfers,
        transfer_count,
        flags,
        cleanup,
    )
}

/// F-service dispatch carries the exact current Thread. The legacy
/// crate-private adapter facade remains useful to host tests that model a
/// Channel transaction without a live syscall caller.
pub(crate) fn channel_send_from_thread<
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
    current_thread: Option<ThreadKey>,
    channel: DwHandle,
    bytes: DwUserAddress,
    byte_len: u32,
    transfers: DwUserAddress,
    transfer_count: u32,
    flags: u64,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    let inputs = match channel_send_snapshot(
        user,
        staging,
        bytes,
        byte_len,
        transfers,
        transfer_count,
        flags,
    ) {
        Ok(inputs) => inputs,
        Err(status) => return status,
    };
    channel_send_commit(
        &inputs,
        staging,
        registry,
        channels,
        waits,
        tasks,
        execution,
        current_process,
        current_thread,
        channel,
        cleanup,
    )
}

/// One `ChannelSend`'s validated transfer records and payload length, after
/// its snapshot (D1 commit 7, design §11.2.3 family D). The payload itself
/// is in the caller's staging buffer.
pub(crate) struct ChannelSendInputs {
    decoded: [DwHandleTransferV1; HANDLE_TRANSFER_LIMIT],
    transfer_count: usize,
    byte_len: usize,
}

/// The first half of `ChannelSend` (D1 commit 7): argument validation, the
/// transfer-record snapshot and its validation, then the payload snapshot
/// into `staging`, in that order. It touches no authority, so the live
/// runtime runs it with no runtime lock held.
pub(crate) fn channel_send_snapshot<U: UserPageAccess>(
    user: &mut U,
    staging: &mut [u8],
    bytes: DwUserAddress,
    byte_len: u32,
    transfers: DwUserAddress,
    transfer_count: u32,
    flags: u64,
) -> Result<ChannelSendInputs, DwStatus> {
    if byte_len > DW_CHANNEL_MAX_PAYLOAD || transfer_count > DW_CHANNEL_MAX_HANDLES || flags != 0 {
        return Err(DW_STATUS_INVALID_ARGUMENT);
    }

    let transfer_count = transfer_count as usize;
    let transfer_byte_len = transfer_count
        .checked_mul(DW_HANDLE_TRANSFER_V1_SIZE as usize)
        .expect("generated Channel transfer count fits usize");
    let transfer_range = channel_buffer_range(transfers, transfer_byte_len, 8, UserAccess::READ)?;
    let mut transfer_staging = [0_u8; HANDLE_TRANSFER_LIMIT * HANDLE_TRANSFER_BYTES];
    if let Err(error) = snapshot_from_user(
        user,
        transfer_range,
        &mut transfer_staging[..transfer_byte_len],
    ) {
        return Err(usercopy_status(error));
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
            return Err(DW_STATUS_INVALID_ARGUMENT);
        }
    }
    for left in 0..transfer_count {
        for right in left + 1..transfer_count {
            if decoded[left].handle == decoded[right].handle {
                return Err(DW_STATUS_INVALID_ARGUMENT);
            }
        }
    }
    if decoded[..transfer_count]
        .iter()
        .any(|record| record.operation != DW_HANDLE_TRANSFER_MOVE)
    {
        return Err(DW_STATUS_INVALID_ARGUMENT);
    }

    let byte_len = byte_len as usize;
    assert!(
        staging.len() >= DW_CHANNEL_MAX_PAYLOAD as usize,
        "F6 Channel staging must hold one ABI-maximum payload"
    );
    let range = channel_buffer_range(bytes, byte_len, 1, UserAccess::READ)?;
    if let Err(error) = snapshot_from_user(user, range, &mut staging[..byte_len]) {
        return Err(usercopy_status(error));
    }

    Ok(ChannelSendInputs {
        decoded,
        transfer_count,
        byte_len,
    })
}

/// The second half of `ChannelSend` (D1 commit 7): with the inputs
/// snapshotted, resolves the endpoint, prepares the handle moves, and
/// commits the send under the runtime's authorities.
#[allow(
    clippy::too_many_arguments,
    reason = "the send commit keeps every authority it mutates explicit"
)]
pub(crate) fn channel_send_commit<
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
    inputs: &ChannelSendInputs,
    staging: &[u8],
    registry: &mut ObjectRegistry<OBJECTS>,
    channels: &ChannelAuthority<PAIRS, DEPTH>,
    waits: &WaitRegistry<WAITERS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    current_process: ProcessKey,
    #[allow(unused_variables)] current_thread: Option<ThreadKey>,
    channel: DwHandle,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    let ChannelSendInputs {
        decoded,
        transfer_count,
        byte_len,
    } = *inputs;
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

/// The live runtime's two-phase `ChannelReceive` (D1 commit 7b, design
/// §11.2.8 decision 4).
///
/// It is the pieces of `channel_receive`, in its order, split at the two
/// places that need user memory once the message size is known:
/// 1. `channel_receive_precheck` (no lock): capacity validation and the
///    result probe.
/// 2. `channel_receive_reserve` (first hold): handle resolution and the head
///    reservation.
/// 3. `channel_receive_output_ranges` (no lock): the exact-size output
///    ranges, which the caller pins.
/// 4. In the second hold, exactly one of:
///    - `ChannelReceiveHold::commit`: the irreversible dequeue and handle
///      publication;
///    - `ChannelReceiveHold::too_small`: cancel, with the result to write;
///    - `ChannelReceiveHold::abandon`: cancel, with the status to return.
///
/// Between the holds the resolved endpoint stays pinned, so it cannot be
/// finalized, and its queue cannot be drained under the reservation:
/// `ChannelAuthority` removes an endpoint, and drains its queue, only at its
/// final release.
///
/// Invariant (abandonment): a hold never outlives its owner's syscall. The
/// facade keeps it in a local across the two holds. Between them the Thread
/// runs with IF clear on its own CPU and passes no safe point: no Stop poll,
/// no `sti`, no switch. So no stop, termination or teardown can run against
/// it there. Exactly one of the three consumers takes it in the second hold,
/// and dropping an unconsumed hold panics. The output pins live in the same
/// syscall frame and are released at its end, so the reservation and its
/// pins share one lifetime.
#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(dead_code, reason = "only the live runtime splits ChannelReceive")
)]
pub(crate) struct ChannelReceiveHold {
    pin: Option<InternalRef>,
    endpoint: ChannelEndpointKey,
    reservation: Option<crate::ipc::ChannelReceiveReservation>,
}

/// The exact-size output ranges a held receive pins, by `channel_receive`'s
/// output index: payload bytes, received handle records, then the result.
#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(dead_code, reason = "only the live runtime splits ChannelReceive")
)]
pub(crate) enum ChannelReceiveOutputs {
    /// The message does not fit: only the result is written.
    TooSmall(UserRange),
    /// The message fits: every range, empty ones included, with its length.
    Fits([(UserRange, usize); 3]),
}

/// What a committed receive writes after the hold, by output index.
#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(dead_code, reason = "only the live runtime splits ChannelReceive")
)]
pub(crate) struct ChannelReceiveCopyOut {
    actual: usize,
    handles: [u8; HANDLE_TRANSFER_LIMIT * DW_RECEIVED_HANDLE_INFO_V1_SIZE as usize],
    handle_len: usize,
    result: [u8; DW_CHANNEL_RECEIVE_RESULT_V1_SIZE as usize],
}

#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(dead_code, reason = "only the live runtime splits ChannelReceive")
)]
impl ChannelReceiveCopyOut {
    /// The bytes for output `index`, given the payload staging.
    pub(crate) fn output<'a>(&'a self, index: usize, staging: &'a [u8]) -> &'a [u8] {
        match index {
            0 => &staging[..self.actual],
            1 => &self.handles[..self.handle_len],
            2 => &self.result,
            _ => panic!("Channel receive has three outputs"),
        }
    }
}

/// Step 1: capacity validation and the result probe, before any authority.
#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(dead_code, reason = "only the live runtime splits ChannelReceive")
)]
pub(crate) fn channel_receive_precheck<U: UserPageAccess>(
    user: &mut U,
    byte_capacity: u32,
    handle_capacity: u32,
    out_result: DwUserAddress,
) -> Result<(), DwStatus> {
    if byte_capacity > DW_CHANNEL_MAX_PAYLOAD || handle_capacity > DW_CHANNEL_MAX_HANDLES {
        return Err(DW_STATUS_INVALID_ARGUMENT);
    }
    preflight_output(
        user,
        out_result,
        DW_CHANNEL_RECEIVE_RESULT_V1_SIZE as usize,
        8,
    )
    .map(drop)
}

/// Step 2: resolves the endpoint and reserves its head message for this
/// receiver.
#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(dead_code, reason = "only the live runtime splits ChannelReceive")
)]
pub(crate) fn channel_receive_reserve<
    const OBJECTS: usize,
    const PAIRS: usize,
    const DEPTH: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    channels: &ChannelAuthority<PAIRS, DEPTH>,
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    current_process: ProcessKey,
    channel: DwHandle,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> Result<ChannelReceiveHold, DwStatus> {
    let pin = resolve_current_handle(
        tasks,
        registry,
        current_process,
        channel,
        DW_OBJECT_TYPE_CHANNEL,
        DW_RIGHT_READ,
    )?;
    let endpoint = ChannelEndpointKey::from_object_id(pin.id());
    match channels.reserve_receive(endpoint) {
        Ok(reservation) => Ok(ChannelReceiveHold {
            pin: Some(pin),
            endpoint,
            reservation: Some(reservation),
        }),
        Err(error) => {
            release_lookup_pin(registry, pin, cleanup);
            Err(channel_status(error))
        }
    }
}

/// Step 3: the exact-size output ranges for the reserved message, formed in
/// `channel_receive`'s order. A formation failure is the status the hold is
/// abandoned with.
#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(dead_code, reason = "only the live runtime splits ChannelReceive")
)]
pub(crate) fn channel_receive_output_ranges(
    info: crate::ipc::ChannelMessageInfo,
    byte_capacity: u32,
    handle_capacity: u32,
    out_bytes: DwUserAddress,
    out_handles: DwUserAddress,
    out_result: DwUserAddress,
) -> Result<ChannelReceiveOutputs, DwStatus> {
    let result_size = DW_CHANNEL_RECEIVE_RESULT_V1_SIZE as usize;
    if info.required_bytes > byte_capacity || info.required_handles > handle_capacity {
        return user_range(out_result, result_size, 8, UserAccess::WRITE)
            .map(ChannelReceiveOutputs::TooSmall);
    }
    let byte_bytes = info.required_bytes as usize;
    let handle_bytes = (info.required_handles as usize)
        .checked_mul(DW_RECEIVED_HANDLE_INFO_V1_SIZE as usize)
        .expect("generated Channel handle capacity fits usize");
    let byte_range = channel_buffer_range(out_bytes, byte_bytes, 1, UserAccess::WRITE)?;
    let handle_range = channel_buffer_range(out_handles, handle_bytes, 8, UserAccess::WRITE)?;
    let result_range = user_range(out_result, result_size, 8, UserAccess::WRITE)?;
    Ok(ChannelReceiveOutputs::Fits([
        (byte_range, byte_bytes),
        (handle_range, handle_bytes),
        (result_range, result_size),
    ]))
}

#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(dead_code, reason = "only the live runtime splits ChannelReceive")
)]
impl ChannelReceiveHold {
    pub(crate) fn info(&self) -> crate::ipc::ChannelMessageInfo {
        self.reservation
            .as_ref()
            .expect("live Channel receive hold keeps its reservation")
            .info()
    }

    fn take(&mut self) -> (InternalRef, crate::ipc::ChannelReceiveReservation) {
        (
            self.pin
                .take()
                .expect("Channel receive hold consumed twice"),
            self.reservation
                .take()
                .expect("Channel receive hold consumed twice"),
        )
    }

    /// Cancels the reservation and returns `status`: an output range could
    /// not be formed or pinned, so nothing is dequeued.
    pub(crate) fn abandon<const OBJECTS: usize, const PAIRS: usize, const DEPTH: usize>(
        mut self,
        status: DwStatus,
        registry: &mut ObjectRegistry<OBJECTS>,
        channels: &ChannelAuthority<PAIRS, DEPTH>,
        cleanup: &mut CleanupQueue<OBJECTS>,
    ) -> DwStatus {
        let (pin, reservation) = self.take();
        channels
            .cancel_receive(reservation)
            .unwrap_or_else(|error| {
                panic!("F6 receive reservation cancellation drifted: {error:?}")
            });
        release_lookup_pin(registry, pin, cleanup);
        status
    }

    /// Cancels the reservation of a message that does not fit, returning
    /// the result to write; the status is `BUFFER_TOO_SMALL`.
    pub(crate) fn too_small<const OBJECTS: usize, const PAIRS: usize, const DEPTH: usize>(
        self,
        registry: &mut ObjectRegistry<OBJECTS>,
        channels: &ChannelAuthority<PAIRS, DEPTH>,
        cleanup: &mut CleanupQueue<OBJECTS>,
    ) -> [u8; DW_CHANNEL_RECEIVE_RESULT_V1_SIZE as usize] {
        let info = self.info();
        let result = channel_receive_result(info.required_bytes, 0, info.required_handles, 0);
        let status = self.abandon(DW_STATUS_BUFFER_TOO_SMALL, registry, channels, cleanup);
        debug_assert_eq!(status, DW_STATUS_BUFFER_TOO_SMALL);
        encode_channel_receive_result(result)
    }

    /// The irreversible dequeue into `staging`, after every output is
    /// pinned. It publishes the transferred handles and completes the wakes,
    /// returning what to copy out after the hold.
    #[allow(
        clippy::too_many_arguments,
        reason = "the receive commit keeps every authority it mutates explicit"
    )]
    pub(crate) fn commit<
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
        mut self,
        staging: &mut [u8],
        registry: &mut ObjectRegistry<OBJECTS>,
        channels: &ChannelAuthority<PAIRS, DEPTH>,
        waits: &WaitRegistry<WAITERS>,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        execution: &ExecutionDomain<EXECUTION>,
        current_process: ProcessKey,
        cleanup: &mut CleanupQueue<OBJECTS>,
    ) -> Result<ChannelReceiveCopyOut, DwStatus> {
        let info = self.info();
        let endpoint = self.endpoint;
        let (pin, reservation) = self.take();
        assert!(
            staging.len() >= DW_CHANNEL_MAX_PAYLOAD as usize,
            "F6 Channel staging must hold one ABI-maximum payload"
        );
        let byte_bytes = info.required_bytes as usize;
        let handle_count = info.required_handles as usize;
        let handle_bytes = handle_count
            .checked_mul(DW_RECEIVED_HANDLE_INFO_V1_SIZE as usize)
            .expect("generated Channel handle capacity fits usize");
        let table = match tasks.process_handles_mut(current_process) {
            Ok(table) => table,
            Err(error) => {
                channels
                    .cancel_receive(reservation)
                    .unwrap_or_else(|channel_error| {
                        panic!("F6 receive reservation cancellation drifted: {channel_error:?}")
                    });
                release_lookup_pin(registry, pin, cleanup);
                return Err(task_status(error));
            }
        };
        let destination = match table.reserve_transfer_batch(handle_count) {
            Ok(reservation) => reservation,
            Err(error) => {
                channels
                    .cancel_receive(reservation)
                    .unwrap_or_else(|channel_error| {
                        panic!("F6 receive reservation cancellation drifted: {channel_error:?}")
                    });
                release_lookup_pin(registry, pin, cleanup);
                return Err(handle_status(error));
            }
        };
        let received =
            match channels.receive_reserved(reservation, &mut staging[..byte_bytes], waits) {
                Ok(received) => received,
                Err(error) => {
                    drop(destination);
                    release_lookup_pin(registry, pin, cleanup);
                    return Err(channel_status(error));
                }
            };
        let (actual, transfer_batch, wakes) = received.into_parts();
        let published = destination.publish(transfer_batch);
        let mut handles = [0_u8; HANDLE_TRANSFER_LIMIT * DW_RECEIVED_HANDLE_INFO_V1_SIZE as usize];
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
            handles[start..start + DW_RECEIVED_HANDLE_INFO_V1_SIZE as usize]
                .copy_from_slice(&encoded);
        }
        let actual_u32 = u32::try_from(actual).expect("Channel receive length fits generated u32");
        let actual_handles = u32::try_from(handle_count).expect("Channel transfer count fits u32");
        let result = channel_receive_result(actual_u32, actual_u32, actual_handles, actual_handles);
        release_lookup_pin(registry, pin, cleanup);
        complete_channel_receive_wait_wakes(registry, execution, endpoint, wakes, cleanup);
        Ok(ChannelReceiveCopyOut {
            actual,
            handles,
            handle_len: handle_bytes,
            result: encode_channel_receive_result(result),
        })
    }
}

impl Drop for ChannelReceiveHold {
    fn drop(&mut self) {
        assert!(
            self.pin.is_none() && self.reservation.is_none(),
            "a Channel receive reservation outlived its syscall"
        );
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
    complete_channel_receive_wait_wakes(registry, execution, endpoint, wakes, cleanup);
    DW_STATUS_SUCCESS
}

/// A Channel receive is the one wake producer which can prove that capacity
/// was restored on the peer endpoint.  Keep this provenance private to the
/// adapter; generic Event/Timer/exit wake batches retain their existing path.
fn complete_channel_receive_wait_wakes<
    const OBJECTS: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    execution: &ExecutionDomain<EXECUTION>,
    drained_peer: ChannelEndpointKey,
    wakes: WakeBatch<WAITERS>,
    cleanup: &mut CleanupQueue<OBJECTS>,
) {
    complete_wait_wakes_with_channel_drain(registry, execution, wakes, cleanup, Some(drained_peer));
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
    complete_wait_wakes_with_channel_drain(registry, execution, wakes, cleanup, None);
}

fn complete_wait_wakes_with_channel_drain<
    const OBJECTS: usize,
    const WAITERS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    execution: &ExecutionDomain<EXECUTION>,
    wakes: WakeBatch<WAITERS>,
    cleanup: &mut CleanupQueue<OBJECTS>,
    #[allow(unused_variables)] drained_peer: Option<ChannelEndpointKey>,
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
                Ok(()) => {}
                Err(SchedulerError::StaleBlockToken) => {}
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
    /// The live idle poll found the suspension's winner and returned
    /// `ResumeCurrent`, but the resume has not yet completed its physical
    /// handoff, so the blocked continuation still holds this CPU's suspended
    /// claim. A remote stop that reaches its precommit in that window
    /// retires this exact suspension as it would an idle one.
    Resuming(WaitSuspendState),
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
            NativeWaitControlState::Clear
            | NativeWaitControlState::Idle(_)
            | NativeWaitControlState::Resuming(_) => None,
        }
    }

    pub(crate) const fn new() -> Self {
        Self {
            state: NativeWaitControlState::Clear,
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
        self.state = if matches!(poll, NativeIdleSuspendPoll::Continue) {
            NativeWaitControlState::Idle(state)
        } else if matches!(poll, NativeIdleSuspendPoll::ResumeCurrent) {
            // The suspended claim stays this CPU's until the resume's
            // physical handoff (`finish_idle_resume`).
            NativeWaitControlState::Resuming(state)
        } else {
            NativeWaitControlState::Clear
        };
        Ok(poll)
    }

    pub(crate) const fn is_clear(&self) -> bool {
        matches!(self.state, NativeWaitControlState::Clear)
    }

    /// Ends a live idle suspension's resume at its physical handoff: the
    /// blocked continuation gives up its suspended claim, so a remote stop
    /// can no longer find it suspended (D1, the remote-stop precommit fix).
    /// A resume after a switch finds the control already clear.
    pub(crate) fn finish_idle_resume(&mut self) {
        match self.state {
            NativeWaitControlState::Resuming(_) | NativeWaitControlState::Clear => {
                self.state = NativeWaitControlState::Clear;
            }
            NativeWaitControlState::Pending(_) | NativeWaitControlState::Idle(_) => {
                panic!("a suspended resume found an unconsumed suspension handoff")
            }
        }
    }

    /// Consumes only the exact idle control handoff retained by a physical
    /// blocked continuation that an e1 safe point is about to retire: still
    /// idle, or already resuming but short of its physical handoff.
    pub(crate) fn retire_idle_for_stop(
        &mut self,
        thread: ThreadKey,
        execution_generation: u64,
    ) -> Result<(), WaitSuspendError> {
        let (NativeWaitControlState::Idle(state) | NativeWaitControlState::Resuming(state)) =
            self.state
        else {
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
        // The live detach needs the linked per-CPU stacks and the detached
        // idle entry, which exist only in the freestanding kernel. A host test
        // build under the DW1-C evidence cfg has the variant but not those.
        #[cfg(test)]
        IdleScheduleDecision::Detach(_) => Err(WaitSuspendError::InvalidDecision),
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
        // The live detach needs the linked per-CPU stacks and the detached
        // idle entry, which exist only in the freestanding kernel. A host test
        // build under the DW1-C evidence cfg has the variant but not those.
        #[cfg(test)]
        IdleScheduleDecision::Detach(_) => Err(WaitSuspendError::InvalidDecision),
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
    interrupts: Option<&dyn InterruptWaitSource>,
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
                interrupts,
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

fn wait_one_begin_with_interrupts<
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
    interrupts: Option<&dyn InterruptWaitSource>,
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
        Ok(set) => {
            // After resolution, so a bad handle reports its own status.
            if let Err(status) = admit_waits(tasks, waits, thread, set.len()) {
                set.release(registry);
                return WaitSyscallBegin::Returning {
                    status,
                    output,
                    result: None,
                };
            }
            begin_wait_set(
                set,
                output,
                deadline,
                registry,
                tasks,
                events,
                timers,
                channels,
                interrupts,
                waits,
                execution,
                operations,
                deadline_authority,
                current_cpu,
                process,
                thread,
            )
        }
        Err(error) => WaitSyscallBegin::Returning {
            status: wait_set_status(error),
            output,
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
    wait_one_begin_with_interrupts(
        output,
        registry,
        tasks,
        events,
        timers,
        channels,
        None,
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
    )
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
    interrupts: Option<&dyn InterruptWaitSource>,
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
        Ok(set) => {
            // After resolution, so a bad handle reports its own status.
            if let Err(status) = admit_waits(tasks, waits, thread, set.len()) {
                set.release(registry);
                return WaitSyscallBegin::Returning {
                    status,
                    output,
                    result: None,
                };
            }
            begin_wait_set(
                set,
                output,
                deadline,
                registry,
                tasks,
                events,
                timers,
                channels,
                interrupts,
                waits,
                execution,
                operations,
                deadline_authority,
                current_cpu,
                process,
                thread,
            )
        }
        Err(error) => WaitSyscallBegin::Returning {
            status: wait_set_status(error),
            output,
            result: None,
        },
    }
}

fn wait_many_begin_with_interrupts<
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
    interrupts: Option<&dyn InterruptWaitSource>,
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
        interrupts,
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
    wait_many_begin_with_interrupts(
        user,
        output,
        registry,
        tasks,
        events,
        timers,
        channels,
        None,
        waits,
        execution,
        operations,
        deadline_authority,
        current_cpu,
        process,
        thread,
        items,
        item_count,
        mode,
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
    let (action, settlement) = settle_wait_begin(begin);
    if let Some((output, result)) = settlement {
        match result {
            Some(result) => user.commit_owned_output(output, &result),
            None => user.discard_owned_output(output),
        }
    }
    action
}

/// The wait result to write into a pinned output (`None` to discard it).
pub(crate) type WaitResultBytes = Option<[u8; DW_WAIT_RESULT_V1_SIZE as usize]>;

/// Splits a wait's begin into its control action and, for a returning wait,
/// the output to settle (D1 commit 8). A suspended wait's output stays in
/// its wait operation, to be settled on resume.
pub(crate) fn settle_wait_begin<OUTPUT>(
    begin: WaitSyscallBegin<OUTPUT>,
) -> (WaitSyscallAction, Option<(OUTPUT, WaitResultBytes)>) {
    match begin {
        WaitSyscallBegin::Returning {
            status,
            output,
            result,
        } => {
            if result.is_some() {
                assert_eq!(status, DW_STATUS_SUCCESS);
            }
            (WaitSyscallAction::Returning(status), Some((output, result)))
        }
        WaitSyscallBegin::Suspended { wake, decision } => (
            WaitSyscallAction::Suspended(WaitSuspendState { wake, decision }),
            None,
        ),
    }
}

/// A wait's caller-controlled input, copied and validated, and its result
/// output, pinned (D1 commit 8, design §11.2.3 family E). `WaitOne` is the
/// one-item form of `WaitMany`: both resolve their items under the runtime
/// authority, through the same wait-set begin.
#[must_use = "a prepared wait owns its pinned result output"]
pub(crate) struct PreparedWait<OUTPUT> {
    requests: [DwWaitItemV1; DW_WAIT_MANY_MAX_ITEMS as usize],
    count: usize,
    deadline: DwDeadline,
    output: OUTPUT,
}

/// `WaitOne`'s input checks and result pin, in the adapter's order: the
/// signal mask, then the output.
pub(crate) fn wait_one_input<U: OwnedUserOutputAccess>(
    user: &mut U,
    handle: DwHandle,
    signals: DwSignals,
    deadline: DwDeadline,
    out_result: DwUserAddress,
) -> Result<PreparedWait<U::OwnedOutput>, DwStatus> {
    if signals.0 == 0 || !deepwyrm_abi::dw_signals_are_known(signals) {
        return Err(DW_STATUS_INVALID_ARGUMENT);
    }
    let output = preflight_owned_wait_output(user, out_result)?;
    let mut requests = [DwWaitItemV1::default(); DW_WAIT_MANY_MAX_ITEMS as usize];
    requests[0] = DwWaitItemV1 { handle, signals };
    Ok(PreparedWait {
        requests,
        count: 1,
        deadline,
        output,
    })
}

/// `WaitMany`'s item snapshot and result pin, in the adapter's order: the
/// shape and items, then the output.
pub(crate) fn wait_many_input<U: OwnedUserOutputAccess>(
    user: &mut U,
    items: DwUserAddress,
    item_count: u32,
    mode: u32,
    deadline: DwDeadline,
    out_result: DwUserAddress,
) -> Result<PreparedWait<U::OwnedOutput>, DwStatus> {
    let (requests, count) = snapshot_wait_many_requests(user, items, item_count, mode)?;
    let output = preflight_owned_wait_output(user, out_result)?;
    Ok(PreparedWait {
        requests,
        count,
        deadline,
        output,
    })
}

/// A prepared wait's begin: resolve, register and decide on suspension. No
/// user memory is touched; a returning wait hands its output back to settle.
#[allow(
    clippy::too_many_arguments,
    reason = "the wait begin keeps every source authority and owner explicit"
)]
pub(crate) fn wait_prepared_begin<
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
    prepared: PreparedWait<OUTPUT>,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    events: &EventAuthority<EVENTS>,
    timers: &TimerAuthority<TIMERS>,
    channels: &ChannelAuthority<CHANNEL_PAIRS, CHANNEL_DEPTH>,
    interrupts: Option<&dyn InterruptWaitSource>,
    waits: &WaitRegistry<WAITERS>,
    execution: &ExecutionDomain<EXECUTION>,
    operations: &mut WaitOperationRegistry<OUTPUT, EXECUTION>,
    deadline_authority: Option<&mut dyn WaitDeadlineAuthority>,
    current_cpu: crate::cpu::CpuIndex,
    process: ProcessKey,
    thread: ThreadKey,
) -> WaitSyscallBegin<OUTPUT> {
    let PreparedWait {
        requests,
        count,
        deadline,
        output,
    } = prepared;
    wait_many_requests_begin(
        output,
        registry,
        tasks,
        events,
        timers,
        channels,
        interrupts,
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
        None,
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
    interrupts: Option<&dyn InterruptWaitSource>,
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
    let prepared = match wait_one_input(user, handle, signals, deadline, out_result) {
        Ok(prepared) => prepared,
        Err(status) => return WaitSyscallAction::Returning(status),
    };
    finish_wait_begin(
        user,
        wait_prepared_begin(
            prepared,
            registry,
            tasks,
            events,
            timers,
            channels,
            interrupts,
            waits,
            execution,
            operations,
            deadline_authority,
            current_cpu,
            process,
            thread,
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
        None,
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
    interrupts: Option<&dyn InterruptWaitSource>,
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
    let prepared = match wait_many_input(user, items, item_count, mode, deadline, out_result) {
        Ok(prepared) => prepared,
        Err(status) => return WaitSyscallAction::Returning(status),
    };
    let begin = wait_prepared_begin(
        prepared,
        registry,
        tasks,
        events,
        timers,
        channels,
        interrupts,
        waits,
        execution,
        operations,
        deadline_authority,
        current_cpu,
        process,
        thread,
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
    let charge = match admit_objects(
        registry,
        tasks,
        current_process,
        deepwyrm_abi::DW_OBJECT_TYPE_EVENT,
        1,
    ) {
        Ok(charge) => charge,
        Err(status) => return status,
    };
    let (_key, reference) = match events.create_event(registry) {
        Ok(created) => created,
        Err(error) => return event_create_status(error),
    };
    charge_created(registry, reference.id(), charge);
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
    let charge = match admit_objects(
        registry,
        tasks,
        current_process,
        deepwyrm_abi::DW_OBJECT_TYPE_TIMER,
        1,
    ) {
        Ok(charge) => charge,
        Err(status) => return status,
    };
    let (_key, reference) = match timers.create_timer(registry) {
        Ok(created) => created,
        Err(error) => return timer_create_status(error),
    };
    charge_created(registry, reference.id(), charge);
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
    let target = tasks.process_object_charge_tag(process_pin.id());
    if let Err(status) = confine_creation(tasks, current_process, target) {
        release_lookup_pin(registry, process_pin, cleanup);
        return status;
    }
    let charge = match admit_objects(
        registry,
        tasks,
        current_process,
        deepwyrm_abi::DW_OBJECT_TYPE_THREAD,
        1,
    ) {
        Ok(charge) => charge,
        Err(status) => {
            release_lookup_pin(registry, process_pin, cleanup);
            return status;
        }
    };
    let created = tasks.create_thread(registry, &process_pin);
    release_lookup_pin(registry, process_pin, cleanup);
    let (key, reference) = match created {
        Ok(created) => created,
        Err(error) => return task_create_status(error),
    };
    charge_created(registry, reference.id(), charge);
    let _ = key;
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
    teardown: GroupTeardown<PROCESSES, THREADS>,
    pre_retired: &mut PreRetiredTerminalThreads<THREADS>,
    defer_current: DeferredCurrentRetirement,
    remotely_stopped: &[Option<ThreadKey>],
    terminal_waits: &mut C,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> Option<DeferredCurrentExecutionResources> {
    let current_thread = defer_current.thread();
    let terminal_threads = teardown.thread_keys();
    assert!(
        remotely_stopped
            .iter()
            .flatten()
            .all(|thread| terminal_threads.contains(&Some(*thread))),
        "remote-stop permit named a Thread outside the TaskGroup terminal batch"
    );
    let processes = teardown.process_keys();

    // The Process the calling Thread belongs to is retired last, and only when
    // this teardown actually made that Thread terminal. Asking the authority
    // which Process owns the Thread replaces scanning per-Process pin batches
    // for it, and is exact rather than inferred from a batch's contents.
    let current_owner = terminal_threads
        .contains(&Some(current_thread))
        .then(|| tasks.thread_process(current_thread).ok())
        .flatten()
        .filter(|process| processes.contains(&Some(*process)));

    // Retire every non-current Process first so scheduler.current() continues to
    // identify the physical Thread whose stack is executing this syscall. The
    // current Process must be the final scheduler mutation before architecture
    // code diverges onto the terminal reaper stack.
    for process in processes.into_iter().flatten() {
        if Some(process) == current_owner {
            continue;
        }
        let deferred = retire_one_group_process(
            registry,
            tasks,
            execution,
            waits,
            process,
            pre_retired,
            defer_current,
            remotely_stopped,
            terminal_waits,
            cleanup,
        );
        assert!(
            deferred.is_none(),
            "non-current group Process produced deferred current resources"
        );
    }

    current_owner.map(|process| {
        retire_one_group_process(
            registry,
            tasks,
            execution,
            waits,
            process,
            pre_retired,
            defer_current,
            remotely_stopped,
            terminal_waits,
            cleanup,
        )
        .expect("current group Process did not preserve deferred execution ownership")
    })
}

/// Drains and retires exactly one terminal Process of a TaskGroup teardown.
///
/// Only this Process's pins and one drain window occupy a frame, which is what
/// replaced the `PROCESSES`-wide batch.
#[expect(
    clippy::too_many_arguments,
    reason = "the terminal path's authorities are deliberately separate borrows"
)]
fn retire_one_group_process<
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
    process: ProcessKey,
    pre_retired: &mut PreRetiredTerminalThreads<THREADS>,
    defer_current: DeferredCurrentRetirement,
    remotely_stopped: &[Option<ThreadKey>],
    terminal_waits: &mut C,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> Option<DeferredCurrentExecutionResources> {
    let pins = tasks
        .take_exited_process_exit_pins(process)
        .unwrap_or_else(|error| {
            panic!("TaskGroup teardown lost a terminal Process's execution pins: {error:?}")
        });
    drain_exited_process_handles_staged(registry, tasks, process, cleanup).unwrap_or_else(
        |error| {
            panic!("TaskGroup teardown could not drain a terminal Process's handles: {error:?}")
        },
    );
    let terminal_threads = pins.thread_keys();
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
        pins,
        pre_retired,
        Some(defer_current),
        &batch_remote,
        terminal_waits,
        cleanup,
    )
}

fn authorized_reason(reason: DwTerminationReason) -> Result<(), DwStatus> {
    if reason == DW_TERMINATION_AUTHORIZED {
        Ok(())
    } else {
        Err(DW_STATUS_INVALID_ARGUMENT)
    }
}

/// Authenticates an external Process termination target and snapshots the
/// Thread set for which termination will emit terminal execution effects. The
/// caller must retain the runtime authority that keeps the HandleTable and
/// task topology stationary until the real preparation begins.
pub(crate) fn inspect_process_termination_threads<
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
    process: DwHandle,
    reason: DwTerminationReason,
) -> Result<[Option<ThreadKey>; THREADS], DwStatus> {
    authorized_reason(reason)?;
    validate_running_caller(tasks, execution, current_process, current_thread)?;
    let target = ProcessKey::from_object_id(inspect_current_object_id(
        tasks,
        current_process,
        process,
        deepwyrm_abi::DW_OBJECT_TYPE_PROCESS,
        DW_RIGHT_MODIFY,
    )?);
    tasks
        .process_termination_thread_keys(target)
        .map_err(task_status)
}

/// Snapshots the Threads a process-wide terminal entry on the caller's own
/// Process -- ProcessExit or an unhandled exception -- makes terminal
/// (design §11.2.12): the live, non-`EXITED` members, compacted in slot
/// order. Because an attached Thread holds its execution pin iff it is not
/// `EXITED`, this equals the terminal pin batch's `ExitPins::thread_keys`. The
/// member list (`process_thread_keys`) also names exited Threads and holes,
/// which have nothing to stop.
pub(crate) fn inspect_process_exit_threads<
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    current_process: ProcessKey,
) -> Result<[Option<ThreadKey>; THREADS], TaskError> {
    tasks.process_termination_thread_keys(current_process)
}

/// Authenticates an external TaskGroup termination target and snapshots the
/// recursive Thread set for which termination will emit terminal execution
/// effects. Retained exited descendants stay inspectable but require no stop.
pub(crate) fn inspect_task_group_termination_threads<
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
    task_group: DwHandle,
    reason: DwTerminationReason,
) -> Result<[Option<ThreadKey>; THREADS], DwStatus> {
    authorized_reason(reason)?;
    validate_running_caller(tasks, execution, current_process, current_thread)?;
    let target = TaskGroupKey::from_object_id(inspect_current_object_id(
        tasks,
        current_process,
        task_group,
        deepwyrm_abi::DW_OBJECT_TYPE_TASK_GROUP,
        DW_RIGHT_MODIFY,
    )?);
    tasks
        .task_group_termination_thread_keys(target)
        .map_err(task_status)
}

/// Authenticates an external Thread termination target without changing its
/// lifecycle. The single-key array shares the remote carrier preflight used by
/// Process and TaskGroup termination.
pub(crate) fn inspect_thread_termination_threads<
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
    thread: DwHandle,
    reason: DwTerminationReason,
) -> Result<[Option<ThreadKey>; THREADS], DwStatus> {
    authorized_reason(reason)?;
    validate_running_caller(tasks, execution, current_process, current_thread)?;
    let target = ThreadKey::from_object_id(inspect_current_object_id(
        tasks,
        current_process,
        thread,
        deepwyrm_abi::DW_OBJECT_TYPE_THREAD,
        DW_RIGHT_MODIFY,
    )?);
    tasks.thread_process(target).map_err(task_status)?;
    // An exited target is refused here, with the status
    // `prepare_thread_terminate` returns for it (design §11.2.12 rule 5).
    // Until its terminal handoff the target's CPU still holds its claim, so
    // the stop plan would otherwise report a transient WOULD_BLOCK.
    if tasks.thread_info(target).map_err(task_status)?.state == DW_TASK_STATE_EXITED {
        return Err(DW_STATUS_BAD_STATE);
    }
    // The last started Thread's self termination is process-wide (rule 6):
    // it makes every never-started sibling terminal too, so the snapshot is
    // the live set, which equals that transition's pin batch (rule 1).
    if target == current_thread
        && tasks
            .is_last_started_thread(current_process, target)
            .map_err(task_status)?
    {
        return tasks
            .process_termination_thread_keys(current_process)
            .map_err(task_status);
    }
    let mut threads = [None; THREADS];
    *threads
        .first_mut()
        .expect("TaskAuthority Thread capacity is nonzero") = Some(target);
    Ok(threads)
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
) -> Result<PreparedTaskGroupTermination<PROCESSES, THREADS>, DwStatus> {
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
    let teardown = match tasks.terminate_group(key) {
        Ok(teardown) => teardown,
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
            match tasks.terminate_group(key) {
                Ok(teardown) => teardown,
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
        PreRetiredTerminalThreads::new(execution.quiesce_terminal_threads(teardown.thread_keys()));
    release_lookup_pin(registry, pin, cleanup);
    Ok(PreparedTaskGroupTermination {
        teardown,
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
    prepared: PreparedTaskGroupTermination<PROCESSES, THREADS>,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> (
    DwStatus,
    SyscallControl,
    Option<DeferredCurrentExecutionResources>,
) {
    let PreparedTaskGroupTermination {
        teardown,
        mut pre_retired,
    } = prepared;
    let deferred = collect_group_effects(
        registry,
        tasks,
        execution,
        waits,
        teardown,
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
    prepared: PreparedTaskGroupTermination<PROCESSES, THREADS>,
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
        teardown,
        mut pre_retired,
    } = prepared;
    let deferred = collect_group_effects(
        registry,
        tasks,
        execution,
        waits,
        teardown,
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
) -> Result<PreparedProcessTermination<THREADS>, DwStatus> {
    validate_running_caller(tasks, execution, current_process, current_thread)?;
    let pins = match tasks.exit_process(current_process, current_thread, code) {
        Ok(pins) => pins,
        Err(TaskError::OperationsInFlight) => {
            let threads = match tasks.process_thread_keys(current_process) {
                Ok(threads) => threads,
                Err(error) => return Err(task_status(error)),
            };
            for thread in threads.into_iter().flatten() {
                terminal_waits
                    .cleanup_terminal_wait(registry, tasks, waits, execution, thread, cleanup);
            }
            match tasks.exit_process(current_process, current_thread, code) {
                Ok(pins) => pins,
                Err(error) => return Err(task_status(error)),
            }
        }
        Err(error) => return Err(task_status(error)),
    };
    drain_exited_process_handles_staged(registry, tasks, current_process, cleanup)
        .unwrap_or_else(|error| panic!("exiting Process could not drain its handles: {error:?}"));
    let pre_retired =
        PreRetiredTerminalThreads::new(execution.quiesce_terminal_threads(pins.thread_keys()));
    Ok(PreparedProcessTermination {
        target: current_process,
        pins,
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
) -> Result<PreparedProcessTermination<THREADS>, DwStatus> {
    validate_running_caller(tasks, execution, current_process, current_thread)?;
    let pins = match tasks.terminate_process_exception(
        current_process,
        current_thread,
        exception.exception_type,
        exception.detail,
        exception.fault_address,
    ) {
        Ok(pins) => pins,
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
                current_process,
                current_thread,
                exception.exception_type,
                exception.detail,
                exception.fault_address,
            ) {
                Ok(pins) => pins,
                Err(error) => return Err(task_status(error)),
            }
        }
        Err(error) => return Err(task_status(error)),
    };
    drain_exited_process_handles_staged(registry, tasks, current_process, cleanup)
        .unwrap_or_else(|error| panic!("faulting Process could not drain its handles: {error:?}"));
    let pre_retired =
        PreRetiredTerminalThreads::new(execution.quiesce_terminal_threads(pins.thread_keys()));
    Ok(PreparedProcessTermination {
        target: current_process,
        pins,
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
) -> Result<PreparedProcessTermination<THREADS>, DwStatus> {
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
    let pins = match tasks.terminate_process_authorized(target, detail) {
        Ok(pins) => pins,
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
            match tasks.terminate_process_authorized(target, detail) {
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
    drain_exited_process_handles_staged(registry, tasks, target, cleanup).unwrap_or_else(|error| {
        panic!("terminated Process could not drain its handles: {error:?}")
    });
    let pre_retired =
        PreRetiredTerminalThreads::new(execution.quiesce_terminal_threads(pins.thread_keys()));
    // The Process identity is now captured by the terminal effects and the
    // caller's Handle may be released before a potentially blocking remote
    // stop. No HandleTable/registry borrow crosses that wait.
    release_lookup_pin(registry, pin, cleanup);
    Ok(PreparedProcessTermination {
        target,
        pins,
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
    prepared: PreparedProcessTermination<THREADS>,
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
    prepared: PreparedProcessTermination<THREADS>,
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
    prepared: PreparedProcessTermination<THREADS>,
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
    prepared: PreparedProcessTermination<THREADS>,
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
        pins,
        mut pre_retired,
    } = prepared;
    let deferred = collect_process_effects(
        registry,
        tasks,
        execution,
        waits,
        pins,
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

/// BSP model of [`thread_exit_on`], kept for the host fixtures that drive
/// one CPU: it also completes the physical switch the reaper would.
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
    let outcome = thread_exit_on(
        registry,
        tasks,
        execution,
        waits,
        &mut NoTerminalWaitCleanup,
        crate::cpu::CpuIndex::BOOTSTRAP,
        current_process,
        current_thread,
        code,
        cleanup,
    );
    if outcome.2.is_some() {
        let claim = execution
            .suspended_claim_on(crate::cpu::CpuIndex::BOOTSTRAP)
            .expect("BSP ThreadExit model handoff retains its execution claim");
        assert_eq!(claim.thread(), current_thread);
        execution
            .complete_switch_on(claim)
            .expect("BSP ThreadExit model handoff follows current retirement");
    }
    outcome
}

/// `ThreadExit` (design §11.2.11): the calling Thread exits normally with
/// `code`. Only the caller becomes terminal; when it is the Process's last
/// live Thread, the Process exits with the same `NORMAL_EXIT` record. No
/// other Thread is ever stopped, so this completes through the self-target
/// `ThreadTerminate` path with no remote Threads.
#[allow(
    clippy::too_many_arguments,
    reason = "the live terminal adapter binds every authority the self-target completion consumes"
)]
pub(crate) fn thread_exit_on<
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
    if let Err(status) = validate_running_caller(tasks, execution, current_process, current_thread)
    {
        return (status, SyscallControl::ReturnToCaller, None);
    }
    let pins = match tasks.exit_thread(current_thread, code) {
        Ok(pins) => pins,
        // Only a final exit gates on the Process's operations, exactly as
        // ProcessExit does; drain its Threads' terminal waits and retry once.
        Err(TaskError::OperationsInFlight) => {
            let threads = match tasks.process_thread_keys(current_process) {
                Ok(threads) => threads,
                Err(error) => {
                    return (task_status(error), SyscallControl::ReturnToCaller, None);
                }
            };
            for thread in threads.into_iter().flatten() {
                terminal_waits
                    .cleanup_terminal_wait(registry, tasks, waits, execution, thread, cleanup);
            }
            match tasks.exit_thread(current_thread, code) {
                Ok(pins) => pins,
                Err(error) => {
                    return (task_status(error), SyscallControl::ReturnToCaller, None);
                }
            }
        }
        Err(error) => return (task_status(error), SyscallControl::ReturnToCaller, None),
    };
    let pre_retired =
        PreRetiredTerminalThreads::new(execution.quiesce_terminal_threads(pins.thread_keys()));
    if tasks
        .process_info(current_process)
        .is_ok_and(|info| info.state == DW_TASK_STATE_EXITED)
    {
        drain_exited_process_handles_staged(registry, tasks, current_process, cleanup)
            .unwrap_or_else(|error| {
                panic!("final Thread exit could not drain Process handles: {error:?}")
            });
    }
    complete_prepared_thread_termination_with_remote_threads(
        registry,
        tasks,
        execution,
        waits,
        terminal_waits,
        current_cpu,
        current_process,
        current_thread,
        PreparedThreadTermination {
            target: current_thread,
            target_process: current_process,
            pins,
            pre_retired,
        },
        &[],
        cleanup,
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
    // The caller's own termination may be final (design §11.2.12 rule 6).
    let terminate = |tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>| {
        if target == current_thread {
            tasks.terminate_current_thread_authorized(target, detail)
        } else {
            tasks.terminate_thread_authorized(target, detail)
        }
    };
    let pins = match terminate(tasks) {
        Ok(pins) => pins,
        Err(TaskError::OperationsInFlight) => {
            // A never-started sibling owns no wait, so the target's is the
            // only one a final self termination must clean up.
            terminal_waits
                .cleanup_terminal_wait(registry, tasks, waits, execution, target, cleanup);
            match terminate(tasks) {
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
        drain_exited_process_handles_staged(registry, tasks, target_process, cleanup)
            .unwrap_or_else(|error| {
                panic!(
                    "final authorized Thread termination could not drain Process handles: {error:?}"
                )
            });
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

/// Retargets a ThreadStart validation session to the started Thread's
/// Process (D1 commit 9). Every `ThreadStartMappingAccess` can.
pub(crate) trait ThreadStartRetarget:
    crate::arch::x86_64::syscall::ProcessUserReturnMappingValidation
{
    fn retarget_for_thread_start(&mut self, process: ProcessKey) -> Result<(), DwStatus>;
}

impl<T: ThreadStartMappingAccess> ThreadStartRetarget for T {
    fn retarget_for_thread_start(&mut self, process: ProcessKey) -> Result<(), DwStatus> {
        self.select_process_for_return_validation(process)
    }
}

/// ThreadStart's argument copy-in and validation (D1 commit 9), for the live
/// runtime to run with no runtime lock held.
pub(crate) fn thread_start_input<U: UserPageAccess>(
    user: &mut U,
    args_address: DwUserAddress,
    args_size: u64,
) -> Result<deepwyrm_abi::DwThreadStartArgsV1, DwStatus> {
    if args_size != THREAD_START_BYTES as u64 {
        return Err(DW_STATUS_INVALID_ARGUMENT);
    }
    let bytes = copy_input::<U, THREAD_START_BYTES>(user, args_address, 8)?;
    let args = decode_thread_start(&bytes);
    if args.size != THREAD_START_BYTES as u32
        || args.version != 1
        || args.flags != 0
        || args.reserved != [0; 3]
    {
        return Err(DW_STATUS_INVALID_ARGUMENT);
    }
    Ok(args)
}

/// ThreadStart over copied arguments (D1 commit 9): resolve the Thread,
/// retarget `access` to its Process, validate RIP and RSP by page-table walk,
/// and start it. No user memory is touched.
pub(crate) fn thread_start_prepared<
    U: ThreadStartRetarget,
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EXECUTION: usize,
>(
    args: Result<deepwyrm_abi::DwThreadStartArgsV1, DwStatus>,
    access: &mut U,
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    current_process: ProcessKey,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    let args = match args {
        Ok(args) => args,
        Err(status) => return status,
    };
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
    if let Err(status) = access.retarget_for_thread_start(target_process) {
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
    let args = thread_start_input(access, args_address, args_size);
    thread_start_prepared(
        args,
        access,
        registry,
        tasks,
        execution,
        current_process,
        cleanup,
    )
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

/// `memory_object_create_owned`'s access with its zeroed backing allocated,
/// and its output pinned, before the runtime authority (D1 commit 6c, design
/// §11.2.3 family B).
///
/// Allocating and zeroing the backing needs the paging authority's frame
/// roles and scratch window, not the object authorities. So the caller
/// allocates it with the paging lock alone, before the runtime authority.
/// The adapter then runs under the runtime authority with this value as its
/// access and keeps its own order:
/// - `allocate_zeroed_backing` hands over the early allocation, or its early
///   failure;
/// - `rollback_object_backing` keeps the grant;
/// - output preflight and commit go to the `DeferredUserOutput`.
///
/// Afterwards `into_parts` returns the output, and any grant to roll back:
/// the early allocation if the adapter never took it, or the one it rolled
/// back. The caller rolls that back with the paging lock alone.
#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(dead_code, reason = "only the live runtime allocates backing early")
)]
pub(crate) struct DeferredMemoryObjectAccess {
    output: crate::memory::usercopy::DeferredUserOutput,
    page_count: u64,
    backing: Option<Result<crate::memory::frame_roles::ObjectBackingGrant, DwStatus>>,
    returned: Option<crate::memory::frame_roles::ObjectBackingGrant>,
}

#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(dead_code, reason = "only the live runtime allocates backing early")
)]
impl DeferredMemoryObjectAccess {
    /// `backing` is the early allocation of `page_count` pages, or `None` if
    /// none was attempted because the adapter cannot reach its allocation.
    pub(crate) fn new(
        output: crate::memory::usercopy::DeferredUserOutput,
        page_count: u64,
        backing: Option<Result<crate::memory::frame_roles::ObjectBackingGrant, DwStatus>>,
    ) -> Self {
        Self {
            output,
            page_count,
            backing,
            returned: None,
        }
    }

    /// The output, and the grant the caller must roll back, if any.
    pub(crate) fn into_parts(
        self,
    ) -> (
        crate::memory::usercopy::DeferredUserOutput,
        Option<crate::memory::frame_roles::ObjectBackingGrant>,
    ) {
        let unused = match self.backing {
            Some(Ok(grant)) => Some(grant),
            Some(Err(_)) | None => None,
        };
        assert!(
            unused.is_none() || self.returned.is_none(),
            "an early backing was both unused and rolled back"
        );
        (self.output, self.returned.or(unused))
    }
}

impl UserPageAccess for DeferredMemoryObjectAccess {
    type Error = crate::memory::usercopy::DeferredOutputUnavailable;
    type Pinned<'a>
        = crate::memory::usercopy::DeferredOutputPin<'a>
    where
        Self: 'a;

    fn pin(&mut self, range: UserRange) -> Result<Self::Pinned<'_>, Self::Error> {
        self.output.pin(range)
    }
}

impl OwnedUserOutputAccess for DeferredMemoryObjectAccess {
    type OwnedOutput = crate::memory::usercopy::DeferredOwnedOutput;

    fn preflight_owned_output(
        &mut self,
        range: UserRange,
    ) -> Result<Self::OwnedOutput, Self::Error> {
        self.output.preflight_owned_output(range)
    }

    fn commit_owned_output(&mut self, output: Self::OwnedOutput, source: &[u8]) {
        self.output.commit_owned_output(output, source);
    }

    fn discard_owned_output(&mut self, output: Self::OwnedOutput) {
        self.output.discard_owned_output(output);
    }
}

impl MemoryObjectBackingAccess for DeferredMemoryObjectAccess {
    fn allocate_zeroed_backing(
        &mut self,
        page_count: u64,
    ) -> Result<crate::memory::frame_roles::ObjectBackingGrant, DwStatus> {
        assert_eq!(
            page_count, self.page_count,
            "deferred MemoryObject backing size drifted from its early allocation"
        );
        self.backing
            .take()
            .expect("deferred MemoryObject backing was not allocated early")
    }

    fn rollback_object_backing(&mut self, backing: crate::memory::frame_roles::ObjectBackingGrant) {
        assert!(
            self.returned.replace(backing).is_none(),
            "deferred MemoryObject backing rolled back twice"
        );
    }
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

/// Whether `process` may create one more MemoryObject now. The live facade
/// asks before allocating backing frames, so a request its quota refuses
/// takes no frames; `memory_object_create_owned` admits again, under the same
/// lock as creation, and that admission is the one that counts.
#[cfg_attr(
    not(all(deepwyrm_integrated, target_os = "none", target_arch = "x86_64")),
    allow(dead_code, reason = "only the live runtime allocates backing early")
)]
pub(crate) fn memory_object_quota_allows<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    registry: &ObjectRegistry<OBJECTS>,
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    process: ProcessKey,
    pages: u64,
) -> bool {
    admit_memory_object(registry, tasks, process, pages).is_ok()
}

/// MemoryObjectCreate. One combined access provides the detached output pin
/// and the physical backing, so the two cannot alias. This is the only
/// MemoryObjectCreate transaction; host tests drive it through a shim.
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
    let charge = match admit_memory_object(registry, tasks, current_process, page_count) {
        Ok(charge) => charge,
        Err(status) => {
            // Any early backing stays with the access for the caller's
            // rollback, as when the adapter never reaches its allocation.
            access.discard_owned_output(output);
            return status;
        }
    };
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
    charge_created(registry, reference.id(), charge);
    registry
        .set_charge_pages(reference.id(), page_count)
        .unwrap_or_else(|error| panic!("fresh MemoryObject rejected its page charge: {error:?}"));
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
