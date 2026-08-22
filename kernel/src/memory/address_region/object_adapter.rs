use super::*;
use deepwyrm_abi::{DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_PROCESS, DW_TASK_STATE_EXITED};

use crate::object::{
    CreationRef, FinalRelease, HandleRef, InternalRef, ObjectId, ObjectRegistry,
    ObjectRegistryError,
};
use crate::task::{
    BlockedOperationError, BlockedOperationRegistry, BlockedOperationsDrained,
    PreparedRootRegionAttachment, ProcessKey, TaskAuthority, TaskError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AddressRegionObjectKey(ObjectId);

impl AddressRegionObjectKey {
    pub(crate) const fn from_object_id(object: ObjectId) -> Self {
        Self(object)
    }

    pub(crate) const fn object_id(self) -> ObjectId {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AddressRegionObjectError {
    Capacity,
    WrongObjectType,
    WrongProcess,
    RuntimePin,
    LiveMappings,
    BlockedOperation(BlockedOperationError),
    Task(TaskError),
    Model(AddressRegionError),
    Registry(ObjectRegistryError),
}

struct AddressRegionObjectRecord<const SLOTS: usize> {
    object: ObjectId,
    process: ObjectId,
    parent: InternalRef,
    runtime_pin: Option<InternalRef>,
    region: AddressRegion<SLOTS>,
    owns_address_space: bool,
}

#[must_use = "bound AddressRegion payloads must be sealed by ObjectRegistry before publication"]
pub(crate) struct AddressRegionPayloadBinding {
    creation: CreationRef,
    key: AddressRegionObjectKey,
}

impl AddressRegionPayloadBinding {
    pub(crate) const fn key(&self) -> AddressRegionObjectKey {
        self.key
    }
    pub(crate) fn into_creation(self) -> CreationRef {
        self.creation
    }
}

#[must_use = "typed AddressRegion cleanup must be consumed by ObjectRegistry"]
pub(crate) struct AddressRegionPayloadCleanup {
    final_release: FinalRelease,
}

impl AddressRegionPayloadCleanup {
    pub(crate) fn into_final_release(self) -> FinalRelease {
        self.final_release
    }
}

pub(crate) struct AddressRegionFinalization {
    final_release: FinalRelease,
    parent: InternalRef,
}

/// A root AddressRegion payload whose Process attachment is reserved but not
/// yet published. F10 commits it only after every HandleTable/transfer
/// reservation has crossed its no-fail boundary.
#[must_use = "prepared root AddressRegions must be committed or cancelled exactly once"]
pub(crate) struct PreparedRootRegion<const SLOTS: usize> {
    binding: Option<AddressRegionPayloadBinding>,
    attachment: Option<PreparedRootRegionAttachment>,
    completed: bool,
}

impl<const SLOTS: usize> Drop for PreparedRootRegion<SLOTS> {
    fn drop(&mut self) {
        assert!(
            self.completed,
            "prepared root AddressRegion dropped without commit or cancellation"
        );
    }
}

pub(crate) struct AddressRegionObjectAuthority<const OBJECTS: usize, const SLOTS: usize> {
    records: [Option<AddressRegionObjectRecord<SLOTS>>; OBJECTS],
}

impl<const OBJECTS: usize, const SLOTS: usize> AddressRegionObjectAuthority<OBJECTS, SLOTS> {
    pub(crate) fn new() -> Self {
        Self {
            records: core::array::from_fn(|_| None),
        }
    }

    fn bind_root(
        &mut self,
        creation: CreationRef,
        parent: InternalRef,
        region: AddressRegion<SLOTS>,
    ) -> Result<
        AddressRegionPayloadBinding,
        (
            AddressRegionObjectError,
            CreationRef,
            InternalRef,
            AddressRegion<SLOTS>,
        ),
    > {
        if creation.object_type() != DW_OBJECT_TYPE_ADDRESS_REGION {
            return Err((
                AddressRegionObjectError::WrongObjectType,
                creation,
                parent,
                region,
            ));
        }
        let slot = match self.records.iter().position(Option::is_none) {
            Some(slot) => slot,
            None => return Err((AddressRegionObjectError::Capacity, creation, parent, region)),
        };
        let key = AddressRegionObjectKey(creation.id());
        self.records[slot] = Some(AddressRegionObjectRecord {
            object: creation.id(),
            process: parent.id(),
            parent,
            runtime_pin: None,
            region,
            owns_address_space: true,
        });
        Ok(AddressRegionPayloadBinding { creation, key })
    }

    fn attach_runtime_pin(
        &mut self,
        key: AddressRegionObjectKey,
        pin: InternalRef,
    ) -> Result<(), AddressRegionObjectError> {
        let record = self.record_mut(key)?;
        if pin.id() != key.0
            || pin.object_type() != DW_OBJECT_TYPE_ADDRESS_REGION
            || record.runtime_pin.is_some()
        {
            return Err(AddressRegionObjectError::RuntimePin);
        }
        record.runtime_pin = Some(pin);
        Ok(())
    }

    pub(crate) fn region(
        &self,
        key: AddressRegionObjectKey,
    ) -> Result<&AddressRegion<SLOTS>, AddressRegionObjectError> {
        Ok(&self.record(key)?.region)
    }

    pub(crate) fn region_mut_for_live_process<
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &mut self,
        tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        key: AddressRegionObjectKey,
    ) -> Result<&mut AddressRegion<SLOTS>, AddressRegionObjectError> {
        let process = ProcessKey::from_object_id(self.record(key)?.process);
        if tasks
            .process_info(process)
            .map_err(AddressRegionObjectError::Task)?
            .state
            == DW_TASK_STATE_EXITED
        {
            return Err(AddressRegionObjectError::Task(TaskError::BadState));
        }
        Ok(&mut self.record_mut(key)?.region)
    }

    /// Resolves a pinned current-process virtual word without exposing the
    /// root-region payload or permitting a handle-selected foreign region.
    pub(crate) fn resolve_atomic_wait_key_for_live_process<
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &self,
        tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        process: ProcessKey,
        address: u64,
    ) -> Result<AtomicWaitKey, AddressRegionObjectError> {
        if tasks
            .process_info(process)
            .map_err(AddressRegionObjectError::Task)?
            .state
            == DW_TASK_STATE_EXITED
        {
            return Err(AddressRegionObjectError::Task(TaskError::BadState));
        }
        let root = tasks
            .root_region(process)
            .map_err(AddressRegionObjectError::Task)?
            .ok_or(AddressRegionObjectError::WrongProcess)?;
        let record = self.record(AddressRegionObjectKey::from_object_id(root))?;
        if record.process != process.object_id() || !record.owns_address_space {
            return Err(AddressRegionObjectError::WrongProcess);
        }
        record
            .region
            .resolve_atomic_wait_key(address)
            .map_err(AddressRegionObjectError::Model)
    }

    fn rollback_bound(
        &mut self,
        key: AddressRegionObjectKey,
    ) -> Result<(InternalRef, AddressRegion<SLOTS>), AddressRegionObjectError> {
        let slot = self.record_slot(key)?;
        let record = self.records[slot]
            .take()
            .expect("validated AddressRegion payload slot");
        if record.runtime_pin.is_some() {
            return Err(AddressRegionObjectError::RuntimePin);
        }
        Ok((record.parent, record.region))
    }

    pub(crate) fn region_mut_for_teardown<
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &mut self,
        tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        key: AddressRegionObjectKey,
    ) -> Result<&mut AddressRegion<SLOTS>, AddressRegionObjectError> {
        let process = ProcessKey::from_object_id(self.record(key)?.process);
        if tasks
            .process_info(process)
            .map_err(AddressRegionObjectError::Task)?
            .state
            != DW_TASK_STATE_EXITED
        {
            return Err(AddressRegionObjectError::Task(TaskError::BadState));
        }
        Ok(&mut self.record_mut(key)?.region)
    }

    pub(crate) fn retire_exited_root<
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
        const BLOCKED: usize,
    >(
        &mut self,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        process: ProcessKey,
        blocked: &BlockedOperationRegistry<BLOCKED>,
        drained: BlockedOperationsDrained,
    ) -> Result<InternalRef, AddressRegionObjectError> {
        blocked
            .validate_drained(&drained, process)
            .map_err(AddressRegionObjectError::BlockedOperation)?;
        if tasks
            .process_info(process)
            .map_err(AddressRegionObjectError::Task)?
            .state
            != DW_TASK_STATE_EXITED
        {
            return Err(AddressRegionObjectError::Task(TaskError::BadState));
        }
        let slot = self
            .records
            .iter()
            .position(|record| {
                record
                    .as_ref()
                    .is_some_and(|record| record.process == process.object_id())
            })
            .ok_or(AddressRegionObjectError::WrongProcess)?;
        let object = self.records[slot]
            .as_ref()
            .expect("located root region")
            .object;
        if self.records[slot]
            .as_ref()
            .expect("located root region")
            .region
            .mappings()
            .iter()
            .any(Option::is_some)
        {
            return Err(AddressRegionObjectError::LiveMappings);
        }
        if tasks
            .root_region(process)
            .map_err(AddressRegionObjectError::Task)?
            != Some(object)
            || self.records[slot]
                .as_ref()
                .expect("located root region")
                .runtime_pin
                .is_none()
        {
            return Err(AddressRegionObjectError::WrongProcess);
        }
        let detached = tasks
            .take_exited_root_region(process)
            .map_err(AddressRegionObjectError::Task)?;
        assert_eq!(
            detached,
            Some(object),
            "Task/AddressRegion root metadata diverged"
        );
        Ok(self.records[slot]
            .as_mut()
            .expect("located root region")
            .runtime_pin
            .take()
            .expect("checked runtime pin"))
    }

    pub(crate) fn take_finalization<const SPACES: usize, const REGIONS: usize>(
        &mut self,
        spaces: &mut AddressSpaceAuthority<SPACES, REGIONS>,
        final_release: FinalRelease,
    ) -> Result<AddressRegionFinalization, (AddressRegionObjectError, FinalRelease)> {
        if final_release.object_type() != DW_OBJECT_TYPE_ADDRESS_REGION {
            return Err((AddressRegionObjectError::WrongObjectType, final_release));
        }
        let key = AddressRegionObjectKey(final_release.id());
        let slot = match self.record_slot(key) {
            Ok(slot) => slot,
            Err(error) => return Err((error, final_release)),
        };
        let record = self.records[slot]
            .as_ref()
            .expect("validated AddressRegion payload slot");
        if record.runtime_pin.is_some() {
            return Err((AddressRegionObjectError::RuntimePin, final_release));
        }
        if record.region.mappings().iter().any(Option::is_some) {
            return Err((AddressRegionObjectError::LiveMappings, final_release));
        }
        spaces
            .release_region(&record.region)
            .unwrap_or_else(|error| {
                panic!("AddressRegion identity cleanup diverged from its typed payload: {error:?}")
            });
        if record.owns_address_space {
            spaces.release_address_space(record.region.address_space_key()).unwrap_or_else(|error| {
                panic!("root AddressRegion left a live region in its owned address space: {error:?}")
            });
        }
        let record = self.records[slot]
            .take()
            .expect("validated AddressRegion payload slot");
        Ok(AddressRegionFinalization {
            final_release,
            parent: record.parent,
        })
    }

    fn record_slot(&self, key: AddressRegionObjectKey) -> Result<usize, AddressRegionObjectError> {
        self.records
            .iter()
            .position(|record| record.as_ref().is_some_and(|record| record.object == key.0))
            .ok_or(AddressRegionObjectError::WrongProcess)
    }
    fn record(
        &self,
        key: AddressRegionObjectKey,
    ) -> Result<&AddressRegionObjectRecord<SLOTS>, AddressRegionObjectError> {
        let slot = self.record_slot(key)?;
        Ok(self.records[slot]
            .as_ref()
            .expect("validated AddressRegion payload slot"))
    }
    fn record_mut(
        &mut self,
        key: AddressRegionObjectKey,
    ) -> Result<&mut AddressRegionObjectRecord<SLOTS>, AddressRegionObjectError> {
        let slot = self.record_slot(key)?;
        Ok(self.records[slot]
            .as_mut()
            .expect("validated AddressRegion payload slot"))
    }
}

impl<const OBJECTS: usize, const SLOTS: usize> AddressRegionObjectAuthority<OBJECTS, SLOTS> {
    #[allow(
        clippy::too_many_arguments,
        reason = "root-region construction coordinates distinct generic, task, and address-space authorities without hiding ownership in a bag"
    )]
    pub(crate) fn prepare_root_region<
        const REGISTRY_OBJECTS: usize,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
        const SPACES: usize,
        const REGIONS: usize,
    >(
        &mut self,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        spaces: &mut AddressSpaceAuthority<SPACES, REGIONS>,
        process: ProcessKey,
        process_handle: &HandleRef,
        attachment: PreparedRootRegionAttachment,
    ) -> Result<PreparedRootRegion<SLOTS>, AddressRegionObjectError> {
        if attachment.process() != process {
            attachment.cancel(tasks);
            return Err(AddressRegionObjectError::WrongProcess);
        }
        if process_handle.id() != process.object_id()
            || process_handle.object_type() != DW_OBJECT_TYPE_PROCESS
        {
            attachment.cancel(tasks);
            return Err(AddressRegionObjectError::WrongProcess);
        }

        let parent = match registry.retain_internal_from_handle(process_handle) {
            Ok(parent) => parent,
            Err(error) => {
                attachment.cancel(tasks);
                return Err(AddressRegionObjectError::Registry(error));
            }
        };
        let creation = match registry.create(DW_OBJECT_TYPE_ADDRESS_REGION) {
            Ok(creation) => creation,
            Err(error) => {
                release_process_parent(registry, parent);
                attachment.cancel(tasks);
                return Err(AddressRegionObjectError::Registry(error));
            }
        };
        let address_space = match spaces.create_address_space() {
            Ok(address_space) => address_space,
            Err(error) => {
                registry
                    .cancel_creation(creation)
                    .unwrap_or_else(|failure| {
                        panic!(
                            "root-region rollback lost generic creation: {:?}",
                            failure.error()
                        )
                    });
                release_process_parent(registry, parent);
                attachment.cancel(tasks);
                return Err(AddressRegionObjectError::Model(error));
            }
        };
        let root_len = USER_CANONICAL_END - PAGE_SIZE;
        let region = match spaces.create_region::<SLOTS>(address_space, PAGE_SIZE, root_len) {
            Ok(region) => region,
            Err(error) => {
                spaces
                    .release_address_space(address_space)
                    .expect("unused fresh address space rolls back");
                registry
                    .cancel_creation(creation)
                    .unwrap_or_else(|failure| {
                        panic!(
                            "root-region rollback lost generic creation: {:?}",
                            failure.error()
                        )
                    });
                release_process_parent(registry, parent);
                attachment.cancel(tasks);
                return Err(AddressRegionObjectError::Model(error));
            }
        };
        let binding = match self.bind_root(creation, parent, region) {
            Ok(binding) => binding,
            Err((error, creation, parent, region)) => {
                spaces
                    .release_region(&region)
                    .expect("unpublished root region identity rolls back");
                spaces
                    .release_address_space(region.address_space_key())
                    .expect("empty root address space rolls back");
                registry
                    .cancel_creation(creation)
                    .unwrap_or_else(|failure| {
                        panic!(
                            "root-region rollback lost generic creation: {:?}",
                            failure.error()
                        )
                    });
                release_process_parent(registry, parent);
                attachment.cancel(tasks);
                return Err(error);
            }
        };
        Ok(PreparedRootRegion {
            binding: Some(binding),
            attachment: Some(attachment),
            completed: false,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the compatibility wrapper preserves the existing root-region factory surface"
    )]
    pub(crate) fn create_root_region<
        const REGISTRY_OBJECTS: usize,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
        const SPACES: usize,
        const REGIONS: usize,
    >(
        &mut self,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        spaces: &mut AddressSpaceAuthority<SPACES, REGIONS>,
        process: ProcessKey,
        process_handle: &HandleRef,
    ) -> Result<(AddressRegionObjectKey, HandleRef), AddressRegionObjectError> {
        let attachment = tasks
            .reserve_root_region_attachment(process)
            .map_err(AddressRegionObjectError::Task)?;
        self.prepare_root_region(registry, tasks, spaces, process, process_handle, attachment)
            .map(|prepared| prepared.commit(registry, tasks, self))
    }
}

impl<const SLOTS: usize> PreparedRootRegion<SLOTS> {
    pub(crate) fn key(&self) -> AddressRegionObjectKey {
        self.binding
            .as_ref()
            .expect("prepared root AddressRegion retains its payload binding")
            .key()
    }

    /// Seals the prepared payload, creates its uninstalled parent HandleRef,
    /// installs the runtime pin, and commits the already-reserved Process
    /// attachment. Every recoverable operation occurred in preparation.
    pub(crate) fn commit<
        const REGISTRY_OBJECTS: usize,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
        const OBJECTS: usize,
    >(
        mut self,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        regions: &mut AddressRegionObjectAuthority<OBJECTS, SLOTS>,
    ) -> (AddressRegionObjectKey, HandleRef) {
        let binding = self
            .binding
            .take()
            .expect("prepared root AddressRegion retains its payload binding");
        let key = binding.key();
        let bound = registry
            .finish_payload_binding(binding)
            .unwrap_or_else(|failure| {
                panic!(
                    "prepared root AddressRegion binding rejected at no-fail commit: {:?}",
                    failure.error()
                )
            });
        let handle = registry
            .retain_handle_from_bound(&bound)
            .unwrap_or_else(|error| {
                panic!(
                    "prepared root AddressRegion handle retain failed at no-fail commit: {error:?}"
                )
            });
        let runtime_pin = registry
            .bound_into_internal(bound)
            .unwrap_or_else(|failure| {
                panic!(
                    "prepared root AddressRegion runtime-pin conversion failed at no-fail commit: {:?}",
                    failure.error()
                )
            });
        regions
            .attach_runtime_pin(key, runtime_pin)
            .expect("prepared root AddressRegion runtime-pin attachment diverged");
        self.attachment
            .take()
            .expect("prepared root AddressRegion retains its Process attachment")
            .commit(tasks, key.object_id());
        self.completed = true;
        (key, handle)
    }

    /// Cancels the unsealed payload and returns every Process/address-space
    /// capacity to its pre-prepare state. No generic payload finalizer is
    /// needed because the creation reference was never sealed.
    pub(crate) fn cancel<
        const REGISTRY_OBJECTS: usize,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
        const OBJECTS: usize,
        const SPACES: usize,
        const REGIONS: usize,
    >(
        mut self,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        tasks: &mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        spaces: &mut AddressSpaceAuthority<SPACES, REGIONS>,
        regions: &mut AddressRegionObjectAuthority<OBJECTS, SLOTS>,
    ) {
        let binding = self
            .binding
            .take()
            .expect("prepared root AddressRegion cancellation retains its binding");
        let key = binding.key();
        let (parent, region) = regions
            .rollback_bound(key)
            .expect("prepared root AddressRegion payload rolls back exactly once");
        spaces
            .release_region(&region)
            .expect("prepared root AddressRegion identity rolls back");
        spaces
            .release_address_space(region.address_space_key())
            .expect("prepared root AddressRegion address space rolls back");
        registry
            .cancel_creation(binding.into_creation())
            .unwrap_or_else(|failure| {
                panic!(
                    "prepared root AddressRegion generic cancellation lost authority: {:?}",
                    failure.error()
                )
            });
        release_process_parent(registry, parent);
        self.attachment
            .take()
            .expect("prepared root AddressRegion cancellation retains Process attachment")
            .cancel(tasks);
        self.completed = true;
    }
}

fn release_process_parent<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    parent: InternalRef,
) {
    match registry.release_internal(parent) {
        Ok(None) => {}
        Ok(Some(_)) => panic!("root-region rollback unexpectedly finalized a live Process"),
        Err(failure) => panic!(
            "root-region rollback lost Process parent pin: {:?}",
            failure.error()
        ),
    }
}

#[cfg(deepwyrm_integrated)]
pub(crate) fn complete_address_region_finalization<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    finalization: AddressRegionFinalization,
) -> Option<FinalRelease> {
    let AddressRegionFinalization {
        final_release,
        parent,
    } = finalization;
    let parent_final = registry.release_internal(parent).unwrap_or_else(|failure| {
        panic!(
            "AddressRegion Process parent pin release violated object invariants: {:?}",
            failure.error()
        )
    });
    if let Err(failure) =
        registry.complete_payload_finalization(AddressRegionPayloadCleanup { final_release })
    {
        panic!(
            "generic AddressRegion finalization became invalid after typed cleanup: {:?}",
            failure.error()
        );
    }
    parent_final
}
