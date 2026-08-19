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
    DW_ABI_INFO_V1_SIZE, DW_BASE_PAGE_SIZE, DW_MEMORY_OBJECT_INFO_V1_SIZE, DW_OBJECT_INFO_BASIC_V1,
    DW_OBJECT_INFO_MEMORY_OBJECT_V1, DW_OBJECT_INFO_TASK_STATE_V1, DW_OBJECT_INFO_V1_SIZE,
    DW_RIGHT_EXECUTE, DW_RIGHT_MODIFY, DW_STATUS_ACCESS_DENIED, DW_STATUS_BAD_ADDRESS,
    DW_STATUS_BAD_HANDLE, DW_STATUS_BAD_STATE, DW_STATUS_BUFFER_TOO_SMALL,
    DW_STATUS_INVALID_ARGUMENT, DW_STATUS_NO_RESOURCES, DW_STATUS_NOT_SUPPORTED, DW_STATUS_SUCCESS,
    DW_STATUS_WRONG_OBJECT_TYPE, DW_TASK_STATE_EXITED, DW_TERMINATION_AUTHORIZED, DwHandle,
    DwRights, DwStatus, DwTerminationReason, DwUserAddress,
};

use crate::handle::{AcceptedObjectTypes, HandleTableError, ResolvedHandle};
use crate::memory::object::MemoryObjectAuthority;
use crate::memory::user_range::{EmptyAddressRule, UserAccess, UserAddressSpace, UserRange};
use crate::memory::usercopy::{
    PinnedUserOutput, UserCopyError, UserPageAccess, copy_from_user, copy_to_user,
    preflight_user_output,
};
use crate::object::{FinalRelease, HandleRef, InternalRef, ObjectRegistry, ObjectRegistryError};
use crate::task::{
    ExecutionDomain, ExecutionResourceError, ProcessExitEffects, ProcessKey, RetiredExitPins,
    SchedulerError, StartThreadError, TaskAuthority, TaskCreateError, TaskError, TaskGroupKey,
    TaskGroupTerminationEffects, ThreadKey, ThreadStartState,
};

use super::native::SyscallControl;

use super::abi_bytes::{
    THREAD_START_BYTES, decode_thread_start, encode_abi_info, encode_handle, encode_object_info,
    encode_u64,
};

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

    pub(crate) fn into_releases(self) -> [Option<FinalRelease>; CAPACITY] {
        self.releases
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

fn handle_status(error: HandleTableError) -> DwStatus {
    match error {
        HandleTableError::InvalidHandle => DW_STATUS_BAD_HANDLE,
        HandleTableError::InvalidRights => DW_STATUS_INVALID_ARGUMENT,
        HandleTableError::WrongObjectType => DW_STATUS_WRONG_OBJECT_TYPE,
        HandleTableError::AccessDenied => DW_STATUS_ACCESS_DENIED,
        HandleTableError::Capacity | HandleTableError::ReferenceCapacity => DW_STATUS_NO_RESOURCES,
    }
}

fn task_status(error: TaskError) -> DwStatus {
    match error {
        TaskError::Capacity => DW_STATUS_NO_RESOURCES,
        TaskError::WrongObjectType => DW_STATUS_WRONG_OBJECT_TYPE,
        TaskError::BadState | TaskError::ParentTerminating => DW_STATUS_BAD_STATE,
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
    let table = match tasks.process_handles_mut(current_process) {
        Ok(table) => table,
        Err(error) => return task_status(error),
    };
    match crate::service::handle_close(table, registry, handle) {
        Ok(release) => {
            cleanup.push_optional(release);
            DW_STATUS_SUCCESS
        }
        Err(status) => status,
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
    let table = match tasks.process_handles_mut(current_process) {
        Ok(table) => table,
        Err(error) => return task_status(error),
    };
    match crate::service::handle_duplicate(table, registry, handle, requested_rights) {
        Ok(duplicate) => {
            output.commit(&encode_handle(duplicate));
            DW_STATUS_SUCCESS
        }
        Err(status) => status,
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

fn collect_retired_pins<const OBJECTS: usize, const THREADS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    pins: RetiredExitPins<THREADS>,
    cleanup: &mut CleanupQueue<OBJECTS>,
) {
    let (process, threads) = pins.into_parts();
    for pin in threads.into_iter().flatten().chain(process) {
        cleanup.push_optional(registry.release_internal(pin).unwrap_or_else(|failure| {
            panic!(
                "E5 terminal execution pin release drifted: {:?}",
                failure.error()
            )
        }));
    }
}

fn collect_process_effects<
    const OBJECTS: usize,
    const HANDLES: usize,
    const THREADS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    execution: &ExecutionDomain<EXECUTION>,
    effects: ProcessExitEffects<HANDLES, THREADS>,
    cleanup: &mut CleanupQueue<OBJECTS>,
) {
    for release in effects.drained.into_final_releases().into_iter().flatten() {
        cleanup.push(release);
    }
    collect_retired_pins(registry, execution.retire_exit_pins(effects.pins), cleanup);
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
    const OBJECTS: usize,
    const PROCESSES: usize,
    const HANDLES: usize,
    const THREADS: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    execution: &ExecutionDomain<EXECUTION>,
    effects: TaskGroupTerminationEffects<PROCESSES, HANDLES, THREADS>,
    cleanup: &mut CleanupQueue<OBJECTS>,
) {
    for process in effects.into_processes().into_iter().flatten() {
        collect_process_effects(registry, execution, process, cleanup);
    }
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
        Ok(info) if info.state == DW_TASK_STATE_EXITED => SyscallControl::Reschedule,
        Ok(_) => SyscallControl::ReturnToCaller,
        Err(_) => SyscallControl::Reschedule,
    }
}

pub(crate) fn task_group_terminate<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    current_process: ProcessKey,
    task_group: DwHandle,
    reason: DwTerminationReason,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> (DwStatus, SyscallControl) {
    if let Err(status) = authorized_reason(reason) {
        return (status, SyscallControl::ReturnToCaller);
    }
    let pin = match resolve_current_handle(
        tasks,
        registry,
        current_process,
        task_group,
        deepwyrm_abi::DW_OBJECT_TYPE_TASK_GROUP,
        DW_RIGHT_MODIFY,
    ) {
        Ok(pin) => pin,
        Err(status) => return (status, SyscallControl::ReturnToCaller),
    };
    let key = TaskGroupKey::from_object_id(pin.id());
    let effects = match tasks.terminate_group(registry, key) {
        Ok(effects) => effects,
        Err(error) => {
            release_lookup_pin(registry, pin, cleanup);
            return (task_status(error), SyscallControl::ReturnToCaller);
        }
    };
    collect_group_effects(registry, execution, effects, cleanup);
    release_lookup_pin(registry, pin, cleanup);
    (
        DW_STATUS_SUCCESS,
        control_after_process_state(tasks, current_process),
    )
}

pub(crate) fn process_exit<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    current_process: ProcessKey,
    current_thread: ThreadKey,
    code: u32,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> (DwStatus, SyscallControl) {
    let effects = match tasks.exit_process(registry, current_process, current_thread, code) {
        Ok(effects) => effects,
        Err(error) => return (task_status(error), SyscallControl::ReturnToCaller),
    };
    collect_process_effects(registry, execution, effects, cleanup);
    (DW_STATUS_SUCCESS, SyscallControl::Reschedule)
}

pub(crate) fn process_terminate<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    current_process: ProcessKey,
    process: DwHandle,
    reason: DwTerminationReason,
    detail: u32,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> (DwStatus, SyscallControl) {
    if let Err(status) = authorized_reason(reason) {
        return (status, SyscallControl::ReturnToCaller);
    }
    let pin = match resolve_current_handle(
        tasks,
        registry,
        current_process,
        process,
        deepwyrm_abi::DW_OBJECT_TYPE_PROCESS,
        DW_RIGHT_MODIFY,
    ) {
        Ok(pin) => pin,
        Err(status) => return (status, SyscallControl::ReturnToCaller),
    };
    let target = ProcessKey::from_object_id(pin.id());
    let effects = match tasks.terminate_process_authorized(registry, target, detail) {
        Ok(effects) => effects,
        Err(error) => {
            release_lookup_pin(registry, pin, cleanup);
            return (task_status(error), SyscallControl::ReturnToCaller);
        }
    };
    collect_process_effects(registry, execution, effects, cleanup);
    release_lookup_pin(registry, pin, cleanup);
    (
        DW_STATUS_SUCCESS,
        control_after_process_state(tasks, current_process),
    )
}

pub(crate) fn thread_exit<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    current_thread: ThreadKey,
    code: u32,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> (DwStatus, SyscallControl) {
    let process = match tasks.thread_process(current_thread) {
        Ok(process) => process,
        Err(error) => return (task_status(error), SyscallControl::ReturnToCaller),
    };
    let pins = match tasks.exit_thread(current_thread, code) {
        Ok(pins) => pins,
        Err(error) => return (task_status(error), SyscallControl::ReturnToCaller),
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
    collect_retired_pins(registry, execution.retire_exit_pins(pins), cleanup);
    (DW_STATUS_SUCCESS, SyscallControl::Reschedule)
}

pub(crate) fn thread_terminate<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EXECUTION: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    execution: &ExecutionDomain<EXECUTION>,
    current_process: ProcessKey,
    thread: DwHandle,
    reason: DwTerminationReason,
    detail: u32,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> (DwStatus, SyscallControl) {
    if let Err(status) = authorized_reason(reason) {
        return (status, SyscallControl::ReturnToCaller);
    }
    let pin = match resolve_current_handle(
        tasks,
        registry,
        current_process,
        thread,
        deepwyrm_abi::DW_OBJECT_TYPE_THREAD,
        DW_RIGHT_MODIFY,
    ) {
        Ok(pin) => pin,
        Err(status) => return (status, SyscallControl::ReturnToCaller),
    };
    let target = ThreadKey::from_object_id(pin.id());
    let target_process = match tasks.thread_process(target) {
        Ok(process) => process,
        Err(error) => {
            release_lookup_pin(registry, pin, cleanup);
            return (task_status(error), SyscallControl::ReturnToCaller);
        }
    };
    let pins = match tasks.terminate_thread_authorized(target, detail) {
        Ok(pins) => pins,
        Err(error) => {
            release_lookup_pin(registry, pin, cleanup);
            return (task_status(error), SyscallControl::ReturnToCaller);
        }
    };
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
    collect_retired_pins(registry, execution.retire_exit_pins(pins), cleanup);
    release_lookup_pin(registry, pin, cleanup);
    (
        DW_STATUS_SUCCESS,
        control_after_process_state(tasks, current_process),
    )
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
    M: crate::arch::x86_64::syscall::UserReturnMappingValidation,
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

fn queue_mapping_releases<const OBJECTS: usize>(
    cleanup: &mut CleanupQueue<OBJECTS>,
    releases: crate::memory::object::MappingFinalReleases<OBJECTS>,
) {
    for release in releases.into_items().into_iter().flatten() {
        cleanup.push(release);
    }
}

fn address_region_status(error: crate::memory::address_region::AddressRegionError) -> DwStatus {
    use crate::memory::address_region::AddressRegionError;
    use crate::memory::object::MemoryObjectError;
    match error {
        AddressRegionError::Empty
        | AddressRegionError::Unaligned
        | AddressRegionError::Overflow
        | AddressRegionError::InvalidProtection => DW_STATUS_INVALID_ARGUMENT,
        AddressRegionError::PageZero | AddressRegionError::OutsideRegion => DW_STATUS_BAD_ADDRESS,
        AddressRegionError::Overlap => deepwyrm_abi::DW_STATUS_ALREADY_EXISTS,
        AddressRegionError::Unmapped => deepwyrm_abi::DW_STATUS_NOT_FOUND,
        AddressRegionError::NoSpace => deepwyrm_abi::DW_STATUS_NO_MEMORY,
        AddressRegionError::Capacity => DW_STATUS_NO_RESOURCES,
        AddressRegionError::UnsupportedProtection => DW_STATUS_NOT_SUPPORTED,
        AddressRegionError::Object(MemoryObjectError::InsufficientRights)
        | AddressRegionError::Object(MemoryObjectError::ProtectionCeiling) => {
            DW_STATUS_ACCESS_DENIED
        }
        AddressRegionError::Object(MemoryObjectError::BackingTooSmall)
        | AddressRegionError::Object(MemoryObjectError::Empty)
        | AddressRegionError::Object(MemoryObjectError::Unaligned)
        | AddressRegionError::Object(MemoryObjectError::Overflow)
        | AddressRegionError::Object(MemoryObjectError::InvalidProtection)
        | AddressRegionError::Object(MemoryObjectError::WritableExecutableAlias) => {
            DW_STATUS_INVALID_ARGUMENT
        }
        AddressRegionError::Object(MemoryObjectError::UnsupportedProtection) => {
            DW_STATUS_NOT_SUPPORTED
        }
        AddressRegionError::LiveMappings
        | AddressRegionError::LiveRegions
        | AddressRegionError::PublisherIdentity
        | AddressRegionError::Object(_) => DW_STATUS_BAD_STATE,
    }
}

fn address_transaction_status<E>(
    error: &crate::memory::address_region::AddressSpaceTransactionError<E>,
) -> DwStatus {
    match error {
        crate::memory::address_region::AddressSpaceTransactionError::Model(error) => {
            address_region_status(*error)
        }
        crate::memory::address_region::AddressSpaceTransactionError::Publish(_) => {
            DW_STATUS_BAD_STATE
        }
    }
}
fn address_region_object_status(
    error: crate::memory::address_region::AddressRegionObjectError,
) -> DwStatus {
    use crate::memory::address_region::AddressRegionObjectError;
    match error {
        AddressRegionObjectError::Capacity => DW_STATUS_NO_RESOURCES,
        AddressRegionObjectError::WrongObjectType => DW_STATUS_WRONG_OBJECT_TYPE,
        AddressRegionObjectError::WrongProcess => DW_STATUS_BAD_HANDLE,
        AddressRegionObjectError::RuntimePin | AddressRegionObjectError::LiveMappings => {
            DW_STATUS_BAD_STATE
        }
        AddressRegionObjectError::Task(error) => task_status(error),
        AddressRegionObjectError::Model(error) => address_region_status(error),
        AddressRegionObjectError::Registry(ObjectRegistryError::Capacity)
        | AddressRegionObjectError::Registry(ObjectRegistryError::ReferenceCountExhausted) => {
            DW_STATUS_NO_RESOURCES
        }
        AddressRegionObjectError::Registry(_) => DW_STATUS_BAD_STATE,
    }
}

fn decode_map_args<U: UserPageAccess>(
    user: &mut U,
    args_address: DwUserAddress,
    args_size: u64,
) -> Result<deepwyrm_abi::DwAddressRegionMapArgsV1, DwStatus> {
    if args_size != u64::from(deepwyrm_abi::DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE) {
        return Err(DW_STATUS_INVALID_ARGUMENT);
    }
    let bytes =
        copy_input::<U, { super::abi_bytes::ADDRESS_REGION_MAP_BYTES }>(user, args_address, 8)?;
    let args = super::abi_bytes::decode_address_region_map(&bytes);
    if args.size != deepwyrm_abi::DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE
        || args.version != 1
        || args.reserved != [0; 4]
        || args.flags.0 & !deepwyrm_abi::DW_ADDRESS_REGION_MAP_FLAGS_SUPPORTED_MASK.0 != 0
        || args.protections.0 & !deepwyrm_abi::DW_MEMORY_PROTECTION_SUPPORTED_MASK.0 != 0
    {
        return Err(DW_STATUS_INVALID_ARGUMENT);
    }
    let fixed = args.flags.0 == deepwyrm_abi::DW_ADDRESS_REGION_MAP_FLAG_FIXED.0;
    if (!fixed && args.requested_address.0 != 0) || (fixed && args.requested_address.0 == 0) {
        return Err(DW_STATUS_INVALID_ARGUMENT);
    }
    Ok(args)
}

fn map_required_rights(protection: crate::memory::address_region::Protection) -> DwRights {
    let mut bits = deepwyrm_abi::DW_RIGHT_MAP.0 | deepwyrm_abi::DW_RIGHT_READ.0;
    if protection.writable() {
        bits |= deepwyrm_abi::DW_RIGHT_WRITE.0;
    }
    if protection.executable() {
        bits |= deepwyrm_abi::DW_RIGHT_EXECUTE.0;
    }
    DwRights(bits)
}
pub(crate) fn address_region_map<
    U: UserPageAccess,
    P: crate::memory::address_region::AddressSpacePublisher,
    const OBJECTS: usize,
    const MEMORY_OBJECTS: usize,
    const LEASES: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const REGION_OBJECTS: usize,
    const REGION_SLOTS: usize,
>(
    user: &mut U,
    publisher: &mut P,
    registry: &mut ObjectRegistry<OBJECTS>,
    memory: &mut MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    regions: &mut crate::memory::address_region::AddressRegionObjectAuthority<
        REGION_OBJECTS,
        REGION_SLOTS,
    >,
    current_process: ProcessKey,
    address_region: DwHandle,
    memory_object: DwHandle,
    args_address: DwUserAddress,
    args_size: u64,
    out_address: DwUserAddress,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    let args = match decode_map_args(user, args_address, args_size) {
        Ok(args) => args,
        Err(status) => return status,
    };
    let protection =
        match crate::memory::object::MemoryProtection::mapping(args.protections.0 as u8) {
            Ok(protection) => protection,
            Err(crate::memory::object::MemoryObjectError::UnsupportedProtection) => {
                return DW_STATUS_NOT_SUPPORTED;
            }
            Err(_) => return DW_STATUS_INVALID_ARGUMENT,
        };
    let output = match preflight_output(user, out_address, 8, 8) {
        Ok(output) => output,
        Err(status) => return status,
    };
    address_region_map_preflighted(
        output,
        publisher,
        registry,
        memory,
        tasks,
        regions,
        current_process,
        address_region,
        memory_object,
        args,
        protection,
        cleanup,
    )
}

fn address_region_map_preflighted<
    PIN: crate::memory::usercopy::PinnedUserPages,
    P: crate::memory::address_region::AddressSpacePublisher,
    const OBJECTS: usize,
    const MEMORY_OBJECTS: usize,
    const LEASES: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const REGION_OBJECTS: usize,
    const REGION_SLOTS: usize,
>(
    output: PinnedUserOutput<PIN>,
    publisher: &mut P,
    registry: &mut ObjectRegistry<OBJECTS>,
    memory: &mut MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    regions: &mut crate::memory::address_region::AddressRegionObjectAuthority<
        REGION_OBJECTS,
        REGION_SLOTS,
    >,
    current_process: ProcessKey,
    address_region: DwHandle,
    memory_object: DwHandle,
    args: deepwyrm_abi::DwAddressRegionMapArgsV1,
    protection: crate::memory::address_region::Protection,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    let region_resolved = match resolve_current(
        tasks,
        registry,
        current_process,
        address_region,
        deepwyrm_abi::DW_OBJECT_TYPE_ADDRESS_REGION,
        DwRights(deepwyrm_abi::DW_RIGHT_MAP.0 | deepwyrm_abi::DW_RIGHT_MODIFY.0),
    ) {
        Ok(resolved) => resolved,
        Err(status) => return status,
    };
    let region_key = crate::memory::address_region::AddressRegionObjectKey::from_object_id(
        region_resolved.object_id(),
    );
    let memory_resolved = match resolve_current(
        tasks,
        registry,
        current_process,
        memory_object,
        deepwyrm_abi::DW_OBJECT_TYPE_MEMORY_OBJECT,
        map_required_rights(protection),
    ) {
        Ok(resolved) => resolved,
        Err(status) => {
            release_lookup_pin(registry, region_resolved.into_internal(), cleanup);
            return status;
        }
    };
    let region = match regions.region_mut_for_live_process(tasks, region_key) {
        Ok(region) => region,
        Err(error) => {
            release_lookup_pin(registry, memory_resolved.into_internal(), cleanup);
            release_lookup_pin(registry, region_resolved.into_internal(), cleanup);
            return address_region_object_status(error);
        }
    };
    let authorization = match region.authorize_map(memory, memory_resolved, protection) {
        Ok(authorization) => authorization,
        Err(error) => {
            let (memory_error, releases) = error.release(registry);
            queue_mapping_releases(cleanup, releases);
            release_lookup_pin(registry, region_resolved.into_internal(), cleanup);
            return match memory_error {
                crate::memory::object::MemoryObjectError::InsufficientRights
                | crate::memory::object::MemoryObjectError::ProtectionCeiling => {
                    DW_STATUS_ACCESS_DENIED
                }
                crate::memory::object::MemoryObjectError::UnsupportedProtection => {
                    DW_STATUS_NOT_SUPPORTED
                }
                crate::memory::object::MemoryObjectError::BackingTooSmall
                | crate::memory::object::MemoryObjectError::Empty
                | crate::memory::object::MemoryObjectError::Unaligned
                | crate::memory::object::MemoryObjectError::Overflow
                | crate::memory::object::MemoryObjectError::InvalidProtection
                | crate::memory::object::MemoryObjectError::WritableExecutableAlias => {
                    DW_STATUS_INVALID_ARGUMENT
                }
                _ => DW_STATUS_BAD_STATE,
            };
        }
    };
    let fixed = args.flags.0 == deepwyrm_abi::DW_ADDRESS_REGION_MAP_FLAG_FIXED.0;
    let result = if fixed {
        region
            .map(
                memory,
                registry,
                publisher,
                args.requested_address.0,
                authorization,
                args.memory_object_offset.0,
                args.byte_len.0,
                protection,
            )
            .map(|releases| (args.requested_address.0, releases))
    } else {
        region.map_anywhere(
            memory,
            registry,
            publisher,
            authorization,
            args.memory_object_offset.0,
            args.byte_len.0,
            protection,
        )
    };
    release_lookup_pin(registry, region_resolved.into_internal(), cleanup);
    match result {
        Ok((address, releases)) => {
            queue_mapping_releases(cleanup, releases);
            output.commit(&encode_u64(address));
            DW_STATUS_SUCCESS
        }
        Err(failure) => {
            let (error, releases) = failure.into_parts();
            queue_mapping_releases(cleanup, releases);
            address_transaction_status(&error)
        }
    }
}
pub(crate) fn address_region_unmap<
    P: crate::memory::address_region::AddressSpacePublisher,
    const OBJECTS: usize,
    const MEMORY_OBJECTS: usize,
    const LEASES: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const REGION_OBJECTS: usize,
    const REGION_SLOTS: usize,
>(
    publisher: &mut P,
    registry: &mut ObjectRegistry<OBJECTS>,
    memory: &mut MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    regions: &mut crate::memory::address_region::AddressRegionObjectAuthority<
        REGION_OBJECTS,
        REGION_SLOTS,
    >,
    current_process: ProcessKey,
    address_region: DwHandle,
    address: DwUserAddress,
    byte_len: u64,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    let resolved = match resolve_current(
        tasks,
        registry,
        current_process,
        address_region,
        deepwyrm_abi::DW_OBJECT_TYPE_ADDRESS_REGION,
        DW_RIGHT_MODIFY,
    ) {
        Ok(resolved) => resolved,
        Err(status) => return status,
    };
    let key =
        crate::memory::address_region::AddressRegionObjectKey::from_object_id(resolved.object_id());
    let region = match regions.region_mut_for_live_process(tasks, key) {
        Ok(region) => region,
        Err(error) => {
            release_lookup_pin(registry, resolved.into_internal(), cleanup);
            return address_region_object_status(error);
        }
    };
    let result = region.unmap(memory, registry, publisher, address.0, byte_len);
    release_lookup_pin(registry, resolved.into_internal(), cleanup);
    match result {
        Ok(releases) => {
            queue_mapping_releases(cleanup, releases);
            DW_STATUS_SUCCESS
        }
        Err(failure) => {
            let (error, releases) = failure.into_parts();
            queue_mapping_releases(cleanup, releases);
            address_transaction_status(&error)
        }
    }
}
pub(crate) fn address_region_protect<
    P: crate::memory::address_region::AddressSpacePublisher,
    const OBJECTS: usize,
    const MEMORY_OBJECTS: usize,
    const LEASES: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const REGION_OBJECTS: usize,
    const REGION_SLOTS: usize,
>(
    publisher: &mut P,
    registry: &mut ObjectRegistry<OBJECTS>,
    memory: &mut MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    regions: &mut crate::memory::address_region::AddressRegionObjectAuthority<
        REGION_OBJECTS,
        REGION_SLOTS,
    >,
    current_process: ProcessKey,
    address_region: DwHandle,
    address: DwUserAddress,
    byte_len: u64,
    protections: u32,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus {
    if protections & !deepwyrm_abi::DW_MEMORY_PROTECTION_SUPPORTED_MASK.0 != 0 {
        return DW_STATUS_INVALID_ARGUMENT;
    }
    let protection = match crate::memory::object::MemoryProtection::mapping(protections as u8) {
        Ok(protection) => protection,
        Err(crate::memory::object::MemoryObjectError::UnsupportedProtection) => {
            return DW_STATUS_NOT_SUPPORTED;
        }
        Err(_) => return DW_STATUS_INVALID_ARGUMENT,
    };
    let resolved = match resolve_current(
        tasks,
        registry,
        current_process,
        address_region,
        deepwyrm_abi::DW_OBJECT_TYPE_ADDRESS_REGION,
        DW_RIGHT_MODIFY,
    ) {
        Ok(resolved) => resolved,
        Err(status) => return status,
    };
    let key =
        crate::memory::address_region::AddressRegionObjectKey::from_object_id(resolved.object_id());
    let region = match regions.region_mut_for_live_process(tasks, key) {
        Ok(region) => region,
        Err(error) => {
            release_lookup_pin(registry, resolved.into_internal(), cleanup);
            return address_region_object_status(error);
        }
    };
    let result = region.protect(memory, registry, publisher, address.0, byte_len, protection);
    release_lookup_pin(registry, resolved.into_internal(), cleanup);
    match result {
        Ok(releases) => {
            queue_mapping_releases(cleanup, releases);
            DW_STATUS_SUCCESS
        }
        Err(failure) => {
            let (error, releases) = failure.into_parts();
            queue_mapping_releases(cleanup, releases);
            address_transaction_status(&error)
        }
    }
}
