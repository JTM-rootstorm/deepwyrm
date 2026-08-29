use deepwyrm_abi::{
    DW_DEVICE_RESOURCE_INFO_V1_SIZE, DW_DEVICE_RESOURCE_INFO_V1_VERSION,
    DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT, DW_OBJECT_TYPE_DEVICE_RESOURCE,
    DW_RIGHT_READ, DW_RIGHT_WRITE, DW_STATUS_ACCESS_DENIED, DW_STATUS_BAD_HANDLE,
    DW_STATUS_INVALID_ARGUMENT, DW_STATUS_NO_RESOURCES, DW_STATUS_WRONG_OBJECT_TYPE,
    DwDeviceResourceInfoV1, DwDeviceResourceKind, DwHandle, DwStatus,
};

use crate::arch::x86_64::io_port::ScalarPortIo;
use crate::handle::{
    AcceptedObjectTypes, HandleReservationError, HandleTable, HandleTableError, ResolvedHandle,
};
use crate::object::{CreationRef, FinalRelease, ObjectId, ObjectRegistry, ObjectRegistryError};
use crate::sync::SpinMutex;
use crate::task::TaskGroupKey;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeviceResourceDescriptor {
    pub(crate) resource_id: u64,
    pub(crate) lease_generation: u64,
    pub(crate) kind: DwDeviceResourceKind,
    pub(crate) pio_base: u16,
    pub(crate) pio_length: u16,
    pub(crate) interrupt_source: u32,
    pub(crate) resource_domain: TaskGroupKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeviceResourceError {
    Capacity,
    InvalidDescriptor,
    InvalidAccess,
    InvalidObject,
    IdentityInUse,
    FinalizationMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeviceResourceCreateError {
    Registry(ObjectRegistryError),
    Resource(DeviceResourceError),
    Handle(HandleTableError),
    Publication(HandleReservationError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeviceResourceKey(ObjectId);

impl DeviceResourceKey {
    pub(crate) const fn from_object_id(object: ObjectId) -> Self {
        Self(object)
    }

    pub(crate) const fn object_id(self) -> ObjectId {
        self.0
    }
}

#[must_use = "typed DeviceResource bindings must be sealed before publication"]
pub(crate) struct DeviceResourceBinding {
    creation: CreationRef,
    key: DeviceResourceKey,
}

impl DeviceResourceBinding {
    pub(crate) const fn key(&self) -> DeviceResourceKey {
        self.key
    }

    pub(crate) fn into_creation(self) -> CreationRef {
        self.creation
    }
}

#[must_use = "typed DeviceResource cleanup must be consumed by ObjectRegistry"]
pub(crate) struct DeviceResourceCleanup {
    final_release: FinalRelease,
}

impl DeviceResourceCleanup {
    pub(crate) fn into_final_release(self) -> FinalRelease {
        self.final_release
    }
}

pub(crate) struct DeviceResourceFinalization {
    final_release: FinalRelease,
    grant: Option<DeviceResourceGrantLease>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeviceResourceGrantLease {
    pub(crate) resource_id: u64,
    pub(crate) grant_generation: u64,
    pub(crate) lease_generation: u64,
    pub(crate) object: ObjectId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeviceResourceState {
    Live,
    Finalizing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeviceResourceRecord {
    object: ObjectId,
    descriptor: DeviceResourceDescriptor,
    state: DeviceResourceState,
    grant: Option<DeviceResourceGrantLease>,
}

pub(crate) trait DeviceResourceFinalizer {
    fn take_finalization(
        &self,
        final_release: FinalRelease,
    ) -> Result<DeviceResourceFinalization, (DeviceResourceError, FinalRelease)>;
}

pub(crate) trait DeviceResourceInfoProvider {
    fn object_info_for_resolved(
        &self,
        resolved: &ResolvedHandle,
    ) -> Result<DwDeviceResourceInfoV1, DeviceResourceError>;
}

pub(crate) struct DeviceResourceAuthority<const RESOURCES: usize> {
    resources: SpinMutex<[Option<DeviceResourceRecord>; RESOURCES]>,
}

impl<const RESOURCES: usize> DeviceResourceAuthority<RESOURCES> {
    pub(crate) fn new() -> Self {
        Self {
            resources: SpinMutex::new([None; RESOURCES]),
        }
    }

    pub(crate) fn create<const OBJECTS: usize, const HANDLES: usize>(
        &self,
        registry: &mut ObjectRegistry<OBJECTS>,
        table: &mut HandleTable<HANDLES>,
        descriptor: DeviceResourceDescriptor,
        rights: deepwyrm_abi::DwRights,
    ) -> Result<(DeviceResourceKey, DwHandle), DeviceResourceCreateError> {
        let mut destination = table
            .reserve_transfer_destination()
            .map_err(DeviceResourceCreateError::Handle)?;
        let creation = match registry.create(DW_OBJECT_TYPE_DEVICE_RESOURCE) {
            Ok(creation) => creation,
            Err(error) => {
                destination.cancel(table).unwrap_or_else(|reservation_error| {
                    panic!(
                        "DeviceResource destination rollback drifted after registry failure: {reservation_error:?}"
                    )
                });
                return Err(DeviceResourceCreateError::Registry(error));
            }
        };
        let binding = match self.bind(creation, descriptor, None) {
            Ok(binding) => binding,
            Err((error, creation)) => {
                registry
                    .cancel_creation(creation)
                    .unwrap_or_else(|failure| {
                        panic!(
                            "DeviceResource creation rollback lost generic authority: {:?}",
                            failure.error()
                        )
                    });
                destination.cancel(table).unwrap_or_else(|reservation_error| {
                    panic!(
                        "DeviceResource destination rollback drifted after binding failure: {reservation_error:?}"
                    )
                });
                return Err(DeviceResourceCreateError::Resource(error));
            }
        };
        let key = binding.key();
        let bound = registry
            .finish_payload_binding(binding)
            .unwrap_or_else(|failure| {
                panic!(
                    "fresh DeviceResource payload binding rejected by ObjectRegistry: {:?}",
                    failure.error()
                )
            });
        let reference = registry.bound_into_handle(bound).unwrap_or_else(|failure| {
            panic!(
                "fresh DeviceResource handle conversion failed: {:?}",
                failure.error()
            )
        });
        match destination.try_publish_reference(table, reference, rights) {
            Ok(published) => Ok((key, published.handle)),
            Err(failure) => {
                let error = failure.error();
                let reference = failure.into_reference();
                let final_release = registry
                    .release_handle(reference)
                    .unwrap_or_else(|release_error| {
                        panic!(
                            "DeviceResource publication rollback lost generic authority: {:?}",
                            release_error.error()
                        )
                    })
                    .expect("unpublished DeviceResource owns its only generic reference");
                let finalization = self
                    .take_finalization(final_release)
                    .unwrap_or_else(|(resource_error, _)| {
                        panic!(
                            "DeviceResource publication rollback lost typed authority: {resource_error:?}"
                        )
                    });
                complete_device_resource_finalization(registry, finalization);
                destination.cancel(table).unwrap_or_else(|reservation_error| {
                    panic!(
                        "DeviceResource destination rollback drifted after publication failure: {reservation_error:?}"
                    )
                });
                Err(DeviceResourceCreateError::Publication(error))
            }
        }
    }

    pub(crate) fn bind_claim(
        &self,
        creation: CreationRef,
        descriptor: DeviceResourceDescriptor,
        grant_generation: u64,
    ) -> Result<DeviceResourceBinding, (DeviceResourceError, CreationRef)> {
        if grant_generation == 0 {
            return Err((DeviceResourceError::InvalidDescriptor, creation));
        }
        let object = creation.id();
        self.bind(
            creation,
            descriptor,
            Some(DeviceResourceGrantLease {
                resource_id: descriptor.resource_id,
                grant_generation,
                lease_generation: descriptor.lease_generation,
                object,
            }),
        )
    }

    fn bind(
        &self,
        creation: CreationRef,
        descriptor: DeviceResourceDescriptor,
        grant: Option<DeviceResourceGrantLease>,
    ) -> Result<DeviceResourceBinding, (DeviceResourceError, CreationRef)> {
        if creation.object_type() != DW_OBJECT_TYPE_DEVICE_RESOURCE {
            return Err((DeviceResourceError::InvalidObject, creation));
        }
        if !valid_descriptor(descriptor) {
            return Err((DeviceResourceError::InvalidDescriptor, creation));
        }
        let key = DeviceResourceKey::from_object_id(creation.id());
        let mut resources = self.resources.lock();
        if resources.iter().flatten().any(|resource| {
            resource.descriptor.resource_id == descriptor.resource_id
                || resource.object == key.object_id()
        }) {
            return Err((DeviceResourceError::IdentityInUse, creation));
        }
        let Some(slot) = resources.iter_mut().find(|slot| slot.is_none()) else {
            return Err((DeviceResourceError::Capacity, creation));
        };
        *slot = Some(DeviceResourceRecord {
            object: key.object_id(),
            descriptor,
            state: DeviceResourceState::Live,
            grant,
        });
        Ok(DeviceResourceBinding { creation, key })
    }

    fn info_for_resolved(
        &self,
        resolved: &ResolvedHandle,
    ) -> Result<DwDeviceResourceInfoV1, DeviceResourceError> {
        let descriptor = self.descriptor_for_resolved(resolved)?;
        Ok(DwDeviceResourceInfoV1 {
            size: DW_DEVICE_RESOURCE_INFO_V1_SIZE,
            version: DW_DEVICE_RESOURCE_INFO_V1_VERSION,
            kind: descriptor.kind,
            flags: 0,
            resource_id: descriptor.resource_id,
            lease_generation: descriptor.lease_generation,
            pio_base: descriptor.pio_base,
            pio_length: descriptor.pio_length,
            interrupt_source: descriptor.interrupt_source,
            reserved: 0,
        })
    }

    fn descriptor_for_resolved(
        &self,
        resolved: &ResolvedHandle,
    ) -> Result<DeviceResourceDescriptor, DeviceResourceError> {
        if resolved.object_type() != DW_OBJECT_TYPE_DEVICE_RESOURCE {
            return Err(DeviceResourceError::InvalidObject);
        }
        let resources = self.resources.lock();
        let resource = resources
            .iter()
            .flatten()
            .find(|resource| {
                resource.object == resolved.object_id()
                    && resource.state == DeviceResourceState::Live
            })
            .ok_or(DeviceResourceError::InvalidObject)?;
        Ok(resource.descriptor)
    }

    pub(super) fn descriptor_for_interrupt(
        &self,
        resolved: &ResolvedHandle,
    ) -> Result<DeviceResourceDescriptor, DeviceResourceError> {
        self.descriptor_for_resolved(resolved)
    }

    fn access_for_resolved(
        &self,
        resolved: &ResolvedHandle,
        offset: u32,
        width: u32,
    ) -> Result<CheckedPioAccess, DeviceResourceError> {
        let descriptor = self.descriptor_for_resolved(resolved)?;
        checked_pio_access(descriptor, offset, width)
    }

    fn read_access_for_resolved(
        &self,
        resolved: &ResolvedHandle,
        offset: u32,
        width: u32,
    ) -> Result<CheckedPioAccess, DeviceResourceError> {
        self.access_for_resolved(resolved, offset, width)
    }

    fn write_access_for_resolved(
        &self,
        resolved: &ResolvedHandle,
        offset: u32,
        width: u32,
        value: u32,
    ) -> Result<CheckedPioAccess, DeviceResourceError> {
        let access = self.access_for_resolved(resolved, offset, width)?;
        if value & !access.width.value_mask() != 0 {
            return Err(DeviceResourceError::InvalidAccess);
        }
        Ok(access)
    }

    #[cfg(test)]
    pub(crate) fn live_count(&self) -> usize {
        self.resources.lock().iter().flatten().count()
    }
}

impl<const RESOURCES: usize> DeviceResourceInfoProvider for DeviceResourceAuthority<RESOURCES> {
    fn object_info_for_resolved(
        &self,
        resolved: &ResolvedHandle,
    ) -> Result<DwDeviceResourceInfoV1, DeviceResourceError> {
        self.info_for_resolved(resolved)
    }
}

impl<const RESOURCES: usize> DeviceResourceFinalizer for DeviceResourceAuthority<RESOURCES> {
    fn take_finalization(
        &self,
        final_release: FinalRelease,
    ) -> Result<DeviceResourceFinalization, (DeviceResourceError, FinalRelease)> {
        if final_release.object_type() != DW_OBJECT_TYPE_DEVICE_RESOURCE {
            return Err((DeviceResourceError::FinalizationMismatch, final_release));
        }
        let mut resources = self.resources.lock();
        let Some(slot) = resources.iter_mut().find(|slot| {
            slot.as_ref()
                .is_some_and(|resource| resource.object == final_release.id())
        }) else {
            return Err((DeviceResourceError::FinalizationMismatch, final_release));
        };
        let resource = slot
            .as_mut()
            .expect("matched DeviceResource finalization slot remains populated");
        if resource.state != DeviceResourceState::Live {
            return Err((DeviceResourceError::FinalizationMismatch, final_release));
        }
        resource.state = DeviceResourceState::Finalizing;
        let grant = resource.grant;
        *slot = None;
        Ok(DeviceResourceFinalization {
            final_release,
            grant,
        })
    }
}

pub(crate) fn complete_device_resource_finalization<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    finalization: DeviceResourceFinalization,
) {
    assert!(
        finalization.grant.is_none(),
        "boot-backed DeviceResource requires grant-aware finalization"
    );
    complete_device_resource_payload_finalization(registry, finalization);
}

pub(crate) fn complete_device_resource_finalization_with_grants<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    grants: &crate::boot::BootResourceGrantAuthority,
    finalization: DeviceResourceFinalization,
) {
    if let Some(grant) = finalization.grant {
        grants
            .release_lease(
                grant.resource_id,
                grant.grant_generation,
                grant.object,
                grant.lease_generation,
            )
            .unwrap_or_else(|error| panic!("DeviceResource grant return drifted: {error:?}"));
    }
    complete_device_resource_payload_finalization(registry, finalization);
}

pub(crate) fn cancel_unpublished_device_resource_claim<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    finalization: DeviceResourceFinalization,
) {
    assert!(
        finalization.grant.is_some(),
        "claim rollback requires exact reserved grant identity"
    );
    complete_device_resource_payload_finalization(registry, finalization);
}

fn complete_device_resource_payload_finalization<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    finalization: DeviceResourceFinalization,
) {
    registry
        .complete_payload_finalization(DeviceResourceCleanup {
            final_release: finalization.final_release,
        })
        .unwrap_or_else(|failure| {
            panic!(
                "generic DeviceResource finalization became invalid after typed cleanup: {:?}",
                failure.error()
            )
        });
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PioWidth {
    U8,
    U16,
    U32,
}

impl PioWidth {
    const fn bytes(self) -> u32 {
        match self {
            Self::U8 => 1,
            Self::U16 => 2,
            Self::U32 => 4,
        }
    }

    const fn value_mask(self) -> u32 {
        match self {
            Self::U8 => u8::MAX as u32,
            Self::U16 => u16::MAX as u32,
            Self::U32 => u32::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CheckedPioAccess {
    port: u16,
    width: PioWidth,
}

pub(super) fn checked_pio_access(
    descriptor: DeviceResourceDescriptor,
    offset: u32,
    width: u32,
) -> Result<CheckedPioAccess, DeviceResourceError> {
    if descriptor.kind != DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT {
        return Err(DeviceResourceError::InvalidAccess);
    }
    let width = match width {
        1 => PioWidth::U8,
        2 => PioWidth::U16,
        4 => PioWidth::U32,
        _ => return Err(DeviceResourceError::InvalidAccess),
    };
    let access_end = offset
        .checked_add(width.bytes())
        .ok_or(DeviceResourceError::InvalidAccess)?;
    if access_end > u32::from(descriptor.pio_length) {
        return Err(DeviceResourceError::InvalidAccess);
    }
    let port = u32::from(descriptor.pio_base)
        .checked_add(offset)
        .ok_or(DeviceResourceError::InvalidAccess)?;
    let port_end = port
        .checked_add(width.bytes())
        .filter(|end| *end <= 0x1_0000)
        .ok_or(DeviceResourceError::InvalidAccess)?;
    debug_assert!(port_end > port);
    Ok(CheckedPioAccess {
        port: u16::try_from(port).map_err(|_| DeviceResourceError::InvalidAccess)?,
        width,
    })
}

fn valid_descriptor(descriptor: DeviceResourceDescriptor) -> bool {
    let Some(pio_end) = u32::from(descriptor.pio_base)
        .checked_add(u32::from(descriptor.pio_length))
        .filter(|end| *end <= 0x1_0000)
    else {
        return false;
    };
    let overlaps_com1 = u32::from(descriptor.pio_base) < 0x400 && 0x3f8 < pio_end;
    descriptor.resource_id != 0
        && descriptor.lease_generation != 0
        && descriptor.kind == DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT
        && descriptor.pio_length != 0
        && descriptor.interrupt_source != 0
        && descriptor.interrupt_source != 4
        && !overlaps_com1
}

pub(crate) fn pio_read<const HANDLES: usize, const OBJECTS: usize, const RESOURCES: usize>(
    table: &HandleTable<HANDLES>,
    registry: &mut ObjectRegistry<OBJECTS>,
    resources: &DeviceResourceAuthority<RESOURCES>,
    io: &mut impl ScalarPortIo,
    handle: DwHandle,
    offset: u32,
    width: u32,
) -> Result<u32, DwStatus> {
    let resolved = table
        .lookup(
            registry,
            handle,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_DEVICE_RESOURCE),
            DW_RIGHT_READ,
        )
        .map_err(handle_status)?;
    let result = resources.read_access_for_resolved(&resolved, offset, width);
    release_operation_pin(registry, resolved);
    let access = result.map_err(resource_status)?;
    Ok(match access.width {
        PioWidth::U8 => u32::from(io.read_u8(access.port)),
        PioWidth::U16 => u32::from(io.read_u16(access.port)),
        PioWidth::U32 => io.read_u32(access.port),
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "PIO keeps handle, typed authority, backend, and ABI scalars explicit at the validation boundary"
)]
pub(crate) fn pio_write<const HANDLES: usize, const OBJECTS: usize, const RESOURCES: usize>(
    table: &HandleTable<HANDLES>,
    registry: &mut ObjectRegistry<OBJECTS>,
    resources: &DeviceResourceAuthority<RESOURCES>,
    io: &mut impl ScalarPortIo,
    handle: DwHandle,
    offset: u32,
    width: u32,
    value: u32,
) -> Result<(), DwStatus> {
    let resolved = table
        .lookup(
            registry,
            handle,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_DEVICE_RESOURCE),
            DW_RIGHT_WRITE,
        )
        .map_err(handle_status)?;
    let result = resources.write_access_for_resolved(&resolved, offset, width, value);
    release_operation_pin(registry, resolved);
    let access = result.map_err(resource_status)?;
    match access.width {
        PioWidth::U8 => io.write_u8(access.port, value as u8),
        PioWidth::U16 => io.write_u16(access.port, value as u16),
        PioWidth::U32 => io.write_u32(access.port, value),
    }
    Ok(())
}

fn release_operation_pin<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    resolved: ResolvedHandle,
) {
    match registry.release_internal(resolved.into_internal()) {
        Ok(None) => {}
        Ok(Some(_)) => panic!(
            "DeviceResource operation pin became final while its source handle remained owned"
        ),
        Err(error) => panic!(
            "DeviceResource operation pin violated generic lifetime invariants: {:?}",
            error.error()
        ),
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

fn resource_status(error: DeviceResourceError) -> DwStatus {
    match error {
        DeviceResourceError::InvalidDescriptor | DeviceResourceError::InvalidAccess => {
            DW_STATUS_INVALID_ARGUMENT
        }
        DeviceResourceError::InvalidObject
        | DeviceResourceError::FinalizationMismatch
        | DeviceResourceError::IdentityInUse
        | DeviceResourceError::Capacity => {
            panic!("live DeviceResource operation lost typed authority: {error:?}")
        }
    }
}
