//! Address-region syscall decoding, authority preparation, and mutation adapters.
//!
//! Common usercopy, handle-pin, cleanup-queue, and task-status machinery remains
//! in the parent facade so this module owns only address-region transaction policy.

use super::*;

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

pub(crate) trait AddressSpacePublishStatus {
    fn syscall_status(&self) -> DwStatus;
}

impl AddressSpacePublishStatus for () {
    fn syscall_status(&self) -> DwStatus {
        DW_STATUS_BAD_STATE
    }
}

impl<E> AddressSpacePublishStatus for crate::arch::x86_64::mm::X86AddressSpacePublishError<E> {
    fn syscall_status(&self) -> DwStatus {
        if self.is_capacity_error() {
            DW_STATUS_NO_RESOURCES
        } else {
            DW_STATUS_BAD_STATE
        }
    }
}

impl<E: AddressSpacePublishStatus> AddressSpacePublishStatus
    for crate::memory::address_region::CoherentPublishError<E>
{
    fn syscall_status(&self) -> DwStatus {
        match self {
            Self::Publish(error) => error.syscall_status(),
            Self::Coherency(
                crate::memory::address_region::AddressSpaceCoherencyError::GenerationExhausted,
            ) => DW_STATUS_NO_RESOURCES,
            Self::Identity | Self::InvalidBatch | Self::Coherency(_) => DW_STATUS_BAD_STATE,
        }
    }
}

pub(super) fn address_transaction_status<E: AddressSpacePublishStatus>(
    error: &crate::memory::address_region::AddressSpaceTransactionError<E>,
) -> DwStatus {
    match error {
        crate::memory::address_region::AddressSpaceTransactionError::Model(error) => {
            address_region_status(*error)
        }
        crate::memory::address_region::AddressSpaceTransactionError::Publish(error) => {
            error.syscall_status()
        }
    }
}
pub(super) fn address_region_object_status(
    error: crate::memory::address_region::AddressRegionObjectError,
) -> DwStatus {
    use crate::memory::address_region::AddressRegionObjectError;
    match error {
        AddressRegionObjectError::Capacity => DW_STATUS_NO_RESOURCES,
        AddressRegionObjectError::WrongObjectType => DW_STATUS_WRONG_OBJECT_TYPE,
        AddressRegionObjectError::WrongProcess => DW_STATUS_BAD_HANDLE,
        AddressRegionObjectError::RuntimePin
        | AddressRegionObjectError::LiveMappings
        | AddressRegionObjectError::BlockedOperation(_) => DW_STATUS_BAD_STATE,
        AddressRegionObjectError::Task(error) => task_status(error),
        AddressRegionObjectError::Model(error) => address_region_status(error),
        AddressRegionObjectError::Registry(ObjectRegistryError::Capacity)
        | AddressRegionObjectError::Registry(ObjectRegistryError::ReferenceCountExhausted) => {
            DW_STATUS_NO_RESOURCES
        }
        AddressRegionObjectError::Registry(_) => DW_STATUS_BAD_STATE,
    }
}

pub(crate) fn decode_map_args<U: UserPageAccess>(
    user: &mut U,
    args_address: DwUserAddress,
    args_size: u64,
) -> Result<deepwyrm_abi::DwAddressRegionMapArgsV1, DwStatus> {
    if args_size != u64::from(deepwyrm_abi::DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE) {
        return Err(DW_STATUS_INVALID_ARGUMENT);
    }
    let bytes = copy_input::<U, { crate::syscall::abi_bytes::ADDRESS_REGION_MAP_BYTES }>(
        user,
        args_address,
        8,
    )?;
    let args = crate::syscall::abi_bytes::decode_address_region_map(&bytes);
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AddressRegionMutationTarget {
    pub(crate) process: ProcessKey,
    pub(crate) region: crate::memory::address_region::AddressRegionObjectKey,
    pub(crate) address_space: crate::memory::address_region::AddressSpaceKey,
    pub(crate) region_key: crate::memory::address_region::RegionKey,
}

/// Move-only preparation for a delegated address-region mutation.
///
/// Handle lookup and root selection are intentionally separated from the
/// later publisher work.  The commit adapter revalidates this exact target
/// before it touches a live address-space transaction, so a guard-free
/// usercopy/paging interval cannot silently retarget a mutation.
#[must_use = "prepared address-region authority must be committed or aborted"]
pub(crate) struct PreparedAddressRegionMutation {
    target: AddressRegionMutationTarget,
}

impl PreparedAddressRegionMutation {
    pub(crate) fn target(&self) -> AddressRegionMutationTarget {
        self.target
    }

    pub(super) fn revalidate<const REGION_OBJECTS: usize, const REGION_SLOTS: usize>(
        &self,
        regions: &AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
    ) -> Result<(), DwStatus> {
        let process = regions
            .region_process(self.target.region)
            .map_err(address_region_object_status)?;
        let region = regions
            .region(self.target.region)
            .map_err(address_region_object_status)?;
        if process != self.target.process
            || region.address_space_key() != self.target.address_space
            || region.region_key() != self.target.region_key
        {
            return Err(DW_STATUS_BAD_STATE);
        }
        Ok(())
    }

    pub(crate) fn abort(self) {}
}

/// Resolves delegated handle authority while preserving the target Process
/// whose operation gate and architecture root own the actual mutation.
pub(crate) fn address_region_mutation_target<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const REGION_OBJECTS: usize,
    const REGION_SLOTS: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    regions: &AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
    current_process: ProcessKey,
    address_region: DwHandle,
    required_rights: DwRights,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> Result<AddressRegionMutationTarget, DwStatus> {
    let resolved = resolve_current(
        tasks,
        registry,
        current_process,
        address_region,
        deepwyrm_abi::DW_OBJECT_TYPE_ADDRESS_REGION,
        required_rights,
    )?;
    let region_key =
        crate::memory::address_region::AddressRegionObjectKey::from_object_id(resolved.object_id());
    let target = (|| {
        let process = regions
            .region_process(region_key)
            .map_err(address_region_object_status)?;
        let region = regions
            .region(region_key)
            .map_err(address_region_object_status)?;
        Ok(AddressRegionMutationTarget {
            process,
            region: region_key,
            address_space: region.address_space_key(),
            region_key: region.region_key(),
        })
    })();
    release_lookup_pin(registry, resolved.into_internal(), cleanup);
    target
}

/// Short authority phase for delegated mapping or unmapping.
pub(crate) fn prepare_address_region_mutation<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const REGION_OBJECTS: usize,
    const REGION_SLOTS: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    regions: &AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
    current_process: ProcessKey,
    address_region: DwHandle,
    required_rights: DwRights,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> Result<PreparedAddressRegionMutation, DwStatus> {
    address_region_mutation_target(
        registry,
        tasks,
        regions,
        current_process,
        address_region,
        required_rights,
        cleanup,
    )
    .map(|target| PreparedAddressRegionMutation { target })
}

pub(crate) fn process_handle_target<
    const OBJECTS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    current_process: ProcessKey,
    process: DwHandle,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> Result<ProcessKey, DwStatus> {
    let resolved = resolve_current(
        tasks,
        registry,
        current_process,
        process,
        deepwyrm_abi::DW_OBJECT_TYPE_PROCESS,
        DW_RIGHT_MODIFY,
    )?;
    let target = ProcessKey::from_object_id(resolved.object_id());
    release_lookup_pin(registry, resolved.into_internal(), cleanup);
    Ok(target)
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
) -> DwStatus
where
    P::Error: AddressSpacePublishStatus,
{
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
) -> DwStatus
where
    P::Error: AddressSpacePublishStatus,
{
    match address_region_map_model(
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
    ) {
        Ok(address) => {
            output.commit(&encode_u64(address));
            DW_STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn address_region_map_model<
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
    memory_object: DwHandle,
    args: deepwyrm_abi::DwAddressRegionMapArgsV1,
    protection: crate::memory::address_region::Protection,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> Result<u64, DwStatus>
where
    P::Error: AddressSpacePublishStatus,
{
    let region_resolved = resolve_current(
        tasks,
        registry,
        current_process,
        address_region,
        deepwyrm_abi::DW_OBJECT_TYPE_ADDRESS_REGION,
        DwRights(deepwyrm_abi::DW_RIGHT_MAP.0 | deepwyrm_abi::DW_RIGHT_MODIFY.0),
    )?;
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
            return Err(status);
        }
    };
    let target_process = match regions.region_process(region_key) {
        Ok(process) => process,
        Err(error) => {
            release_lookup_pin(registry, memory_resolved.into_internal(), cleanup);
            release_lookup_pin(registry, region_resolved.into_internal(), cleanup);
            return Err(address_region_object_status(error));
        }
    };
    let operation_lease = match tasks.acquire_process_operation(target_process) {
        Ok(lease) => lease,
        Err(error) => {
            release_lookup_pin(registry, memory_resolved.into_internal(), cleanup);
            release_lookup_pin(registry, region_resolved.into_internal(), cleanup);
            return Err(task_status(error));
        }
    };
    let region = match regions.region_mut_for_operation(tasks, &operation_lease, region_key) {
        Ok(region) => region,
        Err(error) => {
            tasks
                .release_process_operation(operation_lease)
                .unwrap_or_else(|(release_error, _)| {
                    panic!("F11 map region lookup leaked process lease: {release_error:?}")
                });
            release_lookup_pin(registry, memory_resolved.into_internal(), cleanup);
            release_lookup_pin(registry, region_resolved.into_internal(), cleanup);
            return Err(address_region_object_status(error));
        }
    };
    let authorization = match region.authorize_map(memory, memory_resolved, protection) {
        Ok(authorization) => authorization,
        Err(error) => {
            let (memory_error, releases) = error.release(registry);
            tasks
                .release_process_operation(operation_lease)
                .unwrap_or_else(|(release_error, _)| {
                    panic!("F11 map authorization leaked process lease: {release_error:?}")
                });
            queue_mapping_releases(cleanup, releases);
            release_lookup_pin(registry, region_resolved.into_internal(), cleanup);
            return Err(match memory_error {
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
            });
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
    tasks
        .release_process_operation(operation_lease)
        .unwrap_or_else(|(error, _)| panic!("F11 map leaked process lease: {error:?}"));
    release_lookup_pin(registry, region_resolved.into_internal(), cleanup);
    match result {
        Ok((address, releases)) => {
            queue_mapping_releases(cleanup, releases);
            Ok(address)
        }
        Err(failure) => {
            let (error, releases) = failure.into_parts();
            queue_mapping_releases(cleanup, releases);
            Err(address_transaction_status(&error))
        }
    }
}

/// Commit a previously prepared map after guard-free usercopy/root work.
#[allow(clippy::too_many_arguments)]
pub(crate) fn address_region_map_prepared_model<
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
    prepared: PreparedAddressRegionMutation,
    publisher: &mut P,
    registry: &mut ObjectRegistry<OBJECTS>,
    memory: &mut MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    regions: &mut AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
    current_process: ProcessKey,
    address_region: DwHandle,
    memory_object: DwHandle,
    args: deepwyrm_abi::DwAddressRegionMapArgsV1,
    protection: crate::memory::address_region::Protection,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> Result<u64, DwStatus>
where
    P::Error: AddressSpacePublishStatus,
{
    prepared.revalidate(regions)?;
    address_region_map_model(
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
) -> DwStatus
where
    P::Error: AddressSpacePublishStatus,
{
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
    let target_process = match regions.region_process(key) {
        Ok(process) => process,
        Err(error) => {
            release_lookup_pin(registry, resolved.into_internal(), cleanup);
            return address_region_object_status(error);
        }
    };
    let operation_lease = match tasks.acquire_process_operation(target_process) {
        Ok(lease) => lease,
        Err(error) => {
            release_lookup_pin(registry, resolved.into_internal(), cleanup);
            return task_status(error);
        }
    };
    let region = match regions.region_mut_for_operation(tasks, &operation_lease, key) {
        Ok(region) => region,
        Err(error) => {
            tasks
                .release_process_operation(operation_lease)
                .unwrap_or_else(|(release_error, _)| {
                    panic!("F11 unmap region lookup leaked process lease: {release_error:?}")
                });
            release_lookup_pin(registry, resolved.into_internal(), cleanup);
            return address_region_object_status(error);
        }
    };
    let result = region.unmap(memory, registry, publisher, address.0, byte_len);
    tasks
        .release_process_operation(operation_lease)
        .unwrap_or_else(|(error, _)| panic!("F11 unmap leaked process lease: {error:?}"));
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

/// Commit a previously prepared unmap after guard-free root selection.
#[allow(clippy::too_many_arguments)]
pub(crate) fn address_region_unmap_prepared<
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
    prepared: PreparedAddressRegionMutation,
    publisher: &mut P,
    registry: &mut ObjectRegistry<OBJECTS>,
    memory: &mut MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    regions: &mut AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
    current_process: ProcessKey,
    address_region: DwHandle,
    address: DwUserAddress,
    byte_len: u64,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus
where
    P::Error: AddressSpacePublishStatus,
{
    if let Err(status) = prepared.revalidate(regions) {
        return status;
    }
    address_region_unmap(
        publisher,
        registry,
        memory,
        tasks,
        regions,
        current_process,
        address_region,
        address,
        byte_len,
        cleanup,
    )
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
) -> DwStatus
where
    P::Error: AddressSpacePublishStatus,
{
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
    let target_process = match regions.region_process(key) {
        Ok(process) => process,
        Err(error) => {
            release_lookup_pin(registry, resolved.into_internal(), cleanup);
            return address_region_object_status(error);
        }
    };
    let operation_lease = match tasks.acquire_process_operation(target_process) {
        Ok(lease) => lease,
        Err(error) => {
            release_lookup_pin(registry, resolved.into_internal(), cleanup);
            return task_status(error);
        }
    };
    let region = match regions.region_mut_for_operation(tasks, &operation_lease, key) {
        Ok(region) => region,
        Err(error) => {
            tasks
                .release_process_operation(operation_lease)
                .unwrap_or_else(|(release_error, _)| {
                    panic!("F11 protect region lookup leaked process lease: {release_error:?}")
                });
            release_lookup_pin(registry, resolved.into_internal(), cleanup);
            return address_region_object_status(error);
        }
    };
    let result = region.protect(memory, registry, publisher, address.0, byte_len, protection);
    tasks
        .release_process_operation(operation_lease)
        .unwrap_or_else(|(error, _)| panic!("F11 protect leaked process lease: {error:?}"));
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

/// Commit a previously prepared protection change after guard-free root selection.
#[allow(clippy::too_many_arguments)]
pub(crate) fn address_region_protect_prepared<
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
    prepared: PreparedAddressRegionMutation,
    publisher: &mut P,
    registry: &mut ObjectRegistry<OBJECTS>,
    memory: &mut MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
    tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    regions: &mut AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
    current_process: ProcessKey,
    address_region: DwHandle,
    address: DwUserAddress,
    byte_len: u64,
    protections: u32,
    cleanup: &mut CleanupQueue<OBJECTS>,
) -> DwStatus
where
    P::Error: AddressSpacePublishStatus,
{
    if let Err(status) = prepared.revalidate(regions) {
        return status;
    }
    address_region_protect(
        publisher,
        registry,
        memory,
        tasks,
        regions,
        current_process,
        address_region,
        address,
        byte_len,
        protections,
        cleanup,
    )
}
