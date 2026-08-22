//! Concrete G2 adapter over the existing D/E/F kernel authorities.

use deepwyrm_abi::{
    DW_OBJECT_TYPE_MEMORY_OBJECT, DW_RIGHT_EXECUTE, DW_RIGHT_MAP, DW_RIGHT_READ, DW_RIGHT_TRANSFER,
    DW_RIGHT_WRITE, DwHandle, DwRights,
};

use crate::handle::{HandleMoveRequest, HandleTable, HandleTransferReservation};
use crate::ipc::{
    ChannelAuthority, ChannelEndpointKey, ChannelSendReservation, complete_channel_finalization,
};
use crate::memory::address_region::{
    AddressRegion, AddressRegionObjectAuthority, AddressRegionObjectError, AddressRegionObjectKey,
    AddressSpaceAuthority, PreparedRootRegion, Protection,
};
use crate::memory::frame_roles::ObjectBackingGrant;
use crate::memory::object::{
    MemoryObjectAuthority, MemoryObjectError, MemoryObjectKind, MemoryProtection,
    into_page_backed_cancellation_parts,
};
use crate::object::{HandleRef, ObjectRegistry, ObjectRegistryError};
use crate::task::{
    ExecutionDomain, PreparedProcess, PreparedThread, PreparedThreadStart, ProcessKey,
    TaskAuthority, TaskCreateError, TaskError, ThreadKey, ThreadStartState,
};
use crate::wait::WaitRegistry;

use super::{
    BOOTFS_RIGHTS, CHILD_CHANNEL_RIGHTS, INIT_BYTES, INITIAL_CAPABILITIES,
    PrimordialCapabilitySpec, PrimordialConstructionBackend, PrimordialLaunch,
    PrimordialLoadSegment, PrimordialStackLayout, SELF_ROOT_RIGHTS, STACK_BYTES,
    STARTUP_BLOCK_BYTES,
};

/// Architecture/backing operations used by the concrete authority adapter.
/// Mapping implementations must call the supplied real `AddressRegion` and
/// `MemoryObjectAuthority` transaction surfaces with an identity-bound
/// publisher; this trait exists only because target and host publishers have
/// different concrete types.
pub(crate) trait PrimordialPlatform {
    type Error;

    fn allocate_zeroed_backing(
        &mut self,
        page_count: u64,
    ) -> Result<ObjectBackingGrant, Self::Error>;
    fn write_backing(
        &mut self,
        backing: &ObjectBackingGrant,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error>;
    fn recycle_backing(&mut self, backing: ObjectBackingGrant);

    #[allow(clippy::too_many_arguments)]
    fn map<
        const SLOTS: usize,
        const MEMORY_OBJECTS: usize,
        const LEASES: usize,
        const REGISTRY_OBJECTS: usize,
    >(
        &mut self,
        region: &mut AddressRegion<SLOTS>,
        memory: &mut MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        object: &HandleRef,
        rights: DwRights,
        virtual_start: u64,
        byte_len: u64,
        protection: Protection,
    ) -> Result<(), Self::Error>;

    fn unmap<
        const SLOTS: usize,
        const MEMORY_OBJECTS: usize,
        const LEASES: usize,
        const REGISTRY_OBJECTS: usize,
    >(
        &mut self,
        region: &mut AddressRegion<SLOTS>,
        memory: &mut MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        virtual_start: u64,
        byte_len: u64,
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityPrimordialError<E> {
    Platform(E),
    Registry(ObjectRegistryError),
    Task(TaskError),
    TaskCreate(TaskCreateError),
    Region(AddressRegionObjectError),
    Memory(MemoryObjectError),
    Channel,
    Handle,
    State,
}

#[must_use = "primordial monitor authority must drive handshake and structured cleanup"]
pub(crate) struct AuthorityPrimordialMonitor {
    pub(crate) kernel_peer: HandleRef,
    pub(crate) process: HandleRef,
    pub(crate) channel_keys: [ChannelEndpointKey; 2],
    pub(crate) process_key: ProcessKey,
    pub(crate) thread_key: ThreadKey,
    pub(crate) root_key: AddressRegionObjectKey,
    pub(crate) segment_ranges: [Option<(u64, u64)>; 8],
    pub(crate) stack_range: (u64, u64),
}

/// The concrete single owner of all prepared D/E/F resources.
#[allow(clippy::type_complexity)]
pub(crate) struct AuthorityPrimordialBackend<
    'a,
    P,
    const REGISTRY_OBJECTS: usize,
    const MEMORY_OBJECTS: usize,
    const LEASES: usize,
    const CHANNEL_PAIRS: usize,
    const CHANNEL_DEPTH: usize,
    const WAITERS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const SPACES: usize,
    const REGIONS: usize,
    const REGION_OBJECTS: usize,
    const REGION_SLOTS: usize,
    const EXECUTION: usize,
> where
    P: PrimordialPlatform,
{
    platform: &'a mut P,
    registry: &'a mut ObjectRegistry<REGISTRY_OBJECTS>,
    memory: &'a mut MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
    channels: &'a ChannelAuthority<CHANNEL_PAIRS, CHANNEL_DEPTH>,
    waits: &'a WaitRegistry<WAITERS>,
    tasks: &'a mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    spaces: &'a mut AddressSpaceAuthority<SPACES, REGIONS>,
    regions: &'a mut AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
    execution: &'a ExecutionDomain<EXECUTION>,
    root_group_owner: &'a crate::object::InternalRef,
    process: Option<PreparedProcess>,
    root: Option<PreparedRootRegion<REGION_SLOTS>>,
    root_key: Option<AddressRegionObjectKey>,
    segments: [Option<HandleRef>; 8],
    segment_ranges: [Option<(u64, u64)>; 8],
    stack: Option<HandleRef>,
    stack_range: Option<(u64, u64)>,
    channel_keys: Option<[ChannelEndpointKey; 2]>,
    channel_refs: [Option<HandleRef>; 2],
    child_channel: Option<HandleTransferReservation>,
    child_handle: Option<DwHandle>,
    bootfs: Option<HandleRef>,
    capability_stage_ready: bool,
    init_reservation: Option<ChannelSendReservation>,
    thread: Option<PreparedThread>,
    thread_key: Option<ThreadKey>,
    thread_state: Option<ThreadStartState>,
    thread_start: Option<PreparedThreadStart<'a, EXECUTION>>,
    committed: bool,
    kernel_peer: Option<HandleRef>,
    process_monitor: Option<HandleRef>,
    committed_process_key: Option<ProcessKey>,
}

impl<
    'a,
    P,
    const REGISTRY_OBJECTS: usize,
    const MEMORY_OBJECTS: usize,
    const LEASES: usize,
    const CHANNEL_PAIRS: usize,
    const CHANNEL_DEPTH: usize,
    const WAITERS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const SPACES: usize,
    const REGIONS: usize,
    const REGION_OBJECTS: usize,
    const REGION_SLOTS: usize,
    const EXECUTION: usize,
>
    AuthorityPrimordialBackend<
        'a,
        P,
        REGISTRY_OBJECTS,
        MEMORY_OBJECTS,
        LEASES,
        CHANNEL_PAIRS,
        CHANNEL_DEPTH,
        WAITERS,
        GROUPS,
        PROCESSES,
        THREADS,
        HANDLES,
        SPACES,
        REGIONS,
        REGION_OBJECTS,
        REGION_SLOTS,
        EXECUTION,
    >
where
    P: PrimordialPlatform,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        platform: &'a mut P,
        registry: &'a mut ObjectRegistry<REGISTRY_OBJECTS>,
        memory: &'a mut MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
        channels: &'a ChannelAuthority<CHANNEL_PAIRS, CHANNEL_DEPTH>,
        waits: &'a WaitRegistry<WAITERS>,
        tasks: &'a mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        spaces: &'a mut AddressSpaceAuthority<SPACES, REGIONS>,
        regions: &'a mut AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
        execution: &'a ExecutionDomain<EXECUTION>,
        root_group_owner: &'a crate::object::InternalRef,
    ) -> Self {
        Self {
            platform,
            registry,
            memory,
            channels,
            waits,
            tasks,
            spaces,
            regions,
            execution,
            root_group_owner,
            process: None,
            root: None,
            root_key: None,
            segments: core::array::from_fn(|_| None),
            segment_ranges: [None; 8],
            stack: None,
            stack_range: None,
            channel_keys: None,
            channel_refs: core::array::from_fn(|_| None),
            child_channel: None,
            child_handle: None,
            bootfs: None,
            capability_stage_ready: false,
            init_reservation: None,
            thread: None,
            thread_key: None,
            thread_state: None,
            thread_start: None,
            committed: false,
            kernel_peer: None,
            process_monitor: None,
            committed_process_key: None,
        }
    }

    fn process(&self) -> Result<&PreparedProcess, AuthorityPrimordialError<P::Error>> {
        self.process.as_ref().ok_or(AuthorityPrimordialError::State)
    }

    fn root_key(&self) -> Result<AddressRegionObjectKey, AuthorityPrimordialError<P::Error>> {
        self.root_key.ok_or(AuthorityPrimordialError::State)
    }

    fn create_page_object(
        &mut self,
        logical_byte_len: u64,
        initialized_offset: u64,
        initialized_bytes: &[u8],
        protection: MemoryProtection,
    ) -> Result<HandleRef, AuthorityPrimordialError<P::Error>> {
        let page_count = logical_byte_len
            .checked_add(4095)
            .ok_or(AuthorityPrimordialError::State)?
            / 4096;
        let creation = self
            .registry
            .create(DW_OBJECT_TYPE_MEMORY_OBJECT)
            .map_err(AuthorityPrimordialError::Registry)?;
        let backing = match self.platform.allocate_zeroed_backing(page_count) {
            Ok(backing) => backing,
            Err(error) => {
                self.registry
                    .cancel_creation(creation)
                    .expect("fresh primordial object creation cancels");
                return Err(AuthorityPrimordialError::Platform(error));
            }
        };
        if let Err(error) =
            self.platform
                .write_backing(&backing, initialized_offset, initialized_bytes)
        {
            self.platform.recycle_backing(backing);
            self.registry
                .cancel_creation(creation)
                .expect("unbound primordial object creation cancels");
            return Err(AuthorityPrimordialError::Platform(error));
        }
        let binding = match self.memory.bind_backing(
            creation,
            backing,
            logical_byte_len,
            MemoryObjectKind::PageBacked,
            protection,
        ) {
            Ok(binding) => binding,
            Err(error) => {
                let memory_error = error.error();
                let (creation, backing) = error.into_parts();
                self.platform.recycle_backing(backing);
                self.registry
                    .cancel_creation(creation)
                    .expect("failed primordial payload binding cancels");
                return Err(AuthorityPrimordialError::Memory(memory_error));
            }
        };
        let bound = self
            .registry
            .finish_payload_binding(binding)
            .expect("fresh primordial MemoryObject binding seals");
        Ok(self
            .registry
            .bound_into_handle(bound)
            .expect("fresh primordial MemoryObject becomes a handle reference"))
    }

    fn cancel_memory(&mut self, reference: HandleRef) {
        let final_release = self
            .registry
            .release_handle(reference)
            .expect("primordial creator handle release remains valid")
            .expect("unmapped primordial object reaches final release");
        let finalization = self
            .memory
            .take_finalization(final_release)
            .expect("primordial MemoryObject final release retains payload");
        let (cleanup, backing) = into_page_backed_cancellation_parts(finalization);
        self.registry
            .complete_payload_finalization(cleanup)
            .unwrap_or_else(|failure| {
                panic!(
                    "cancelled primordial MemoryObject generic cleanup diverged: {:?}",
                    failure.error()
                )
            });
        self.platform.recycle_backing(backing);
    }

    pub(crate) fn take_monitor(&mut self) -> AuthorityPrimordialMonitor {
        assert!(self.committed, "primordial monitor requested before commit");
        let process = self
            .process_monitor
            .take()
            .expect("Process monitor retained after commit");
        AuthorityPrimordialMonitor {
            kernel_peer: self
                .kernel_peer
                .take()
                .expect("kernel peer retained after commit"),
            process,
            channel_keys: self
                .channel_keys
                .expect("Channel identities retained after commit"),
            process_key: self
                .committed_process_key
                .expect("committed Process identity retained"),
            thread_key: self
                .thread_key
                .expect("Thread identity retained after commit"),
            root_key: self.root_key.expect("root identity retained after commit"),
            segment_ranges: self.segment_ranges,
            stack_range: self.stack_range.expect("stack range retained after commit"),
        }
    }

    fn release_channel(&mut self, reference: HandleRef) {
        let final_release = self
            .registry
            .release_handle(reference)
            .expect("primordial Channel reference release remains valid")
            .expect("unpublished Channel endpoint reaches final release");
        let finalization = self
            .channels
            .take_finalization(final_release, self.waits)
            .unwrap_or_else(|(error, _)| panic!("primordial Channel rollback diverged: {error:?}"));
        let completion = complete_channel_finalization(self.registry, finalization);
        let (wakes, releases) = completion.into_parts();
        assert_eq!(
            wakes.len(),
            0,
            "unpublished primordial Channel woke a waiter"
        );
        assert!(
            releases.into_iter().all(|release| release.is_none()),
            "uncommitted primordial Channel rollback drained transferred handles"
        );
    }
}

#[cfg(test)]
mod tests;

fn segment_protection(segment: PrimordialLoadSegment) -> MemoryProtection {
    let permissions = segment.permissions();
    if permissions.executable() {
        MemoryProtection::READ_EXECUTE
    } else if permissions.writable() {
        MemoryProtection::READ_WRITE
    } else {
        MemoryProtection::READ
    }
}

fn mapping_rights(protection: MemoryProtection) -> DwRights {
    let mut rights = DW_RIGHT_READ.0 | DW_RIGHT_MAP.0;
    if protection.writable() {
        rights |= DW_RIGHT_WRITE.0;
    }
    if protection.executable() {
        rights |= DW_RIGHT_EXECUTE.0;
    }
    DwRights(rights)
}

impl<
    'a,
    P,
    const REGISTRY_OBJECTS: usize,
    const MEMORY_OBJECTS: usize,
    const LEASES: usize,
    const CHANNEL_PAIRS: usize,
    const CHANNEL_DEPTH: usize,
    const WAITERS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const SPACES: usize,
    const REGIONS: usize,
    const REGION_OBJECTS: usize,
    const REGION_SLOTS: usize,
    const EXECUTION: usize,
> PrimordialConstructionBackend
    for AuthorityPrimordialBackend<
        'a,
        P,
        REGISTRY_OBJECTS,
        MEMORY_OBJECTS,
        LEASES,
        CHANNEL_PAIRS,
        CHANNEL_DEPTH,
        WAITERS,
        GROUPS,
        PROCESSES,
        THREADS,
        HANDLES,
        SPACES,
        REGIONS,
        REGION_OBJECTS,
        REGION_SLOTS,
        EXECUTION,
    >
where
    P: PrimordialPlatform,
{
    type Error = AuthorityPrimordialError<P::Error>;

    fn prepare_process_root(&mut self) -> Result<(), Self::Error> {
        let process = self
            .tasks
            .prepare_process(self.registry, self.root_group_owner)
            .map_err(AuthorityPrimordialError::TaskCreate)?;
        let attachment = process
            .reserve_root_region_attachment(self.tasks)
            .map_err(AuthorityPrimordialError::Task)?;
        let root = self
            .regions
            .prepare_root_region(
                self.registry,
                self.tasks,
                self.spaces,
                process.key(),
                process.handle(),
                attachment,
            )
            .map_err(AuthorityPrimordialError::Region)?;
        self.root_key = Some(root.key());
        self.process = Some(process);
        self.root = Some(root);
        Ok(())
    }

    fn create_segment_object(
        &mut self,
        index: usize,
        segment: PrimordialLoadSegment,
        initialized_offset: u64,
        initialized_bytes: &[u8],
    ) -> Result<(), Self::Error> {
        let protection = segment_protection(segment);
        let reference = self.create_page_object(
            segment.mapped_byte_len(),
            initialized_offset,
            initialized_bytes,
            protection,
        )?;
        self.segments[index] = Some(reference);
        Ok(())
    }

    fn map_segment(
        &mut self,
        index: usize,
        segment: PrimordialLoadSegment,
    ) -> Result<(), Self::Error> {
        let protection = segment_protection(segment);
        let rights = mapping_rights(protection);
        let object = self.segments[index]
            .take()
            .ok_or(AuthorityPrimordialError::State)?;
        let key = self.root_key()?;
        let region = self
            .regions
            .region_mut_for_live_process(self.tasks, key)
            .map_err(AuthorityPrimordialError::Region)?;
        let result = self.platform.map(
            region,
            self.memory,
            self.registry,
            &object,
            rights,
            segment.page_start(),
            segment.mapped_byte_len(),
            protection,
        );
        self.segments[index] = Some(object);
        result.map_err(AuthorityPrimordialError::Platform)?;
        self.segment_ranges[index] = Some((segment.page_start(), segment.mapped_byte_len()));
        Ok(())
    }

    fn create_stack_object(&mut self, byte_len: u64) -> Result<(), Self::Error> {
        self.stack =
            Some(self.create_page_object(byte_len, 0, &[], MemoryProtection::READ_WRITE)?);
        Ok(())
    }

    fn map_stack(&mut self, layout: PrimordialStackLayout) -> Result<(), Self::Error> {
        let object = self.stack.take().ok_or(AuthorityPrimordialError::State)?;
        let key = self.root_key()?;
        let region = self
            .regions
            .region_mut_for_live_process(self.tasks, key)
            .map_err(AuthorityPrimordialError::Region)?;
        let result = self.platform.map(
            region,
            self.memory,
            self.registry,
            &object,
            mapping_rights(MemoryProtection::READ_WRITE),
            layout.mapped_start,
            STACK_BYTES,
            MemoryProtection::READ_WRITE,
        );
        self.stack = Some(object);
        result.map_err(AuthorityPrimordialError::Platform)?;
        self.stack_range = Some((layout.mapped_start, STACK_BYTES));
        Ok(())
    }

    fn write_startup_block(
        &mut self,
        object_offset: u64,
        bytes: &[u8; STARTUP_BLOCK_BYTES],
    ) -> Result<(), Self::Error> {
        let stack = self.stack.as_ref().ok_or(AuthorityPrimordialError::State)?;
        let object = crate::handle::ResolvedHandle::from_kernel_reference(
            self.registry,
            stack,
            mapping_rights(MemoryProtection::READ_WRITE),
        )
        .map_err(|_| AuthorityPrimordialError::Handle)?;
        let key = crate::memory::object::MemoryObjectKey::from_object_id(object.object_id());
        let backing = self
            .memory
            .backing_for_population(key)
            .map_err(AuthorityPrimordialError::Memory)?;
        let result = self.platform.write_backing(backing, object_offset, bytes);
        let pin = object.into_internal();
        assert!(
            self.registry
                .release_internal(pin)
                .expect("startup population pin release remains valid")
                .is_none()
        );
        result.map_err(AuthorityPrimordialError::Platform)
    }

    fn create_channel_pair(&mut self) -> Result<(), Self::Error> {
        let (keys, references) = self
            .channels
            .create_pair(self.registry)
            .map_err(|_| AuthorityPrimordialError::Channel)?;
        self.channel_keys = Some(keys);
        let [first, second] = references;
        self.channel_refs = [Some(first), Some(second)];
        Ok(())
    }

    fn install_child_channel(&mut self, rights: DwRights) -> Result<DwHandle, Self::Error> {
        if rights != CHILD_CHANNEL_RIGHTS {
            return Err(AuthorityPrimordialError::State);
        }
        let process = self.process()?.key();
        let reservation = self
            .tasks
            .process_handles_mut(process)
            .map_err(AuthorityPrimordialError::Task)?
            .reserve_transfer_destination()
            .map_err(|_| AuthorityPrimordialError::Handle)?;
        let handle = reservation.handle();
        self.child_channel = Some(reservation);
        self.child_handle = Some(handle);
        Ok(handle)
    }

    fn create_bootfs_object(
        &mut self,
        logical_byte_len: u64,
        _rounded_byte_len: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        self.bootfs =
            Some(self.create_page_object(logical_byte_len, 0, bytes, MemoryProtection::READ)?);
        Ok(())
    }

    fn stage_init_capabilities(
        &mut self,
        capabilities: &[PrimordialCapabilitySpec; 2],
    ) -> Result<(), Self::Error> {
        if capabilities != &INITIAL_CAPABILITIES {
            return Err(AuthorityPrimordialError::State);
        }
        self.capability_stage_ready = true;
        Ok(())
    }

    fn publish_init(&mut self, bytes: &[u8; 56]) -> Result<(), Self::Error> {
        if bytes != &INIT_BYTES || !self.capability_stage_ready {
            return Err(AuthorityPrimordialError::State);
        }
        let keys = self.channel_keys.ok_or(AuthorityPrimordialError::State)?;
        self.init_reservation = Some(
            self.channels
                .reserve_send(keys[0], bytes)
                .map_err(|_| AuthorityPrimordialError::Channel)?,
        );
        Ok(())
    }

    fn create_initial_thread(
        &mut self,
        entry: u64,
        stack_pointer: u64,
        argument0: u64,
        argument1: u64,
    ) -> Result<(), Self::Error> {
        let process = self
            .process
            .as_ref()
            .ok_or(AuthorityPrimordialError::State)?;
        let parent = self
            .registry
            .retain_internal_from_handle(process.handle())
            .map_err(AuthorityPrimordialError::Registry)?;
        let thread = self
            .tasks
            .prepare_thread(self.registry, &parent)
            .map_err(AuthorityPrimordialError::TaskCreate);
        assert!(
            self.registry
                .release_internal(parent)
                .expect("temporary primordial Process pin releases")
                .is_none()
        );
        let thread = thread?;
        self.thread_key = Some(thread.key());
        self.thread = Some(thread);
        let expected =
            ThreadStartState::from_validated_user_state(entry, stack_pointer, argument0, argument1);
        assert_eq!(expected.entry(), entry);
        self.thread_state = Some(expected);
        Ok(())
    }

    fn prepare_initial_thread_start(&mut self) -> Result<(), Self::Error> {
        let key = self.thread_key.ok_or(AuthorityPrimordialError::State)?;
        let start = self.thread_state.ok_or(AuthorityPrimordialError::State)?;
        let execution: &'a ExecutionDomain<EXECUTION> = self.execution;
        self.thread_start = Some(
            execution
                .prepare_thread_start(self.tasks, key, start)
                .map_err(|_| AuthorityPrimordialError::State)?,
        );
        Ok(())
    }

    fn commit_process_and_start(&mut self) -> PrimordialLaunch {
        assert!(!self.committed, "primordial transaction committed twice");
        let root = self.root.take().expect("primordial root prepared");
        let (_root_key, root_reference) = root.commit(self.registry, self.tasks, self.regions);
        let process_key = self
            .process
            .as_ref()
            .expect("primordial Process prepared")
            .key();
        let child_reference = self.channel_refs[1]
            .take()
            .expect("primordial child Channel reference retained");
        self.child_channel
            .take()
            .expect("primordial child handle slot reserved")
            .publish_reference(
                self.tasks
                    .process_handles_mut(process_key)
                    .expect("prepared Process handle table remains live"),
                child_reference,
                CHILD_CHANNEL_RIGHTS,
            );

        let mut stager = HandleTable::<2>::new();
        let root_handle = stager
            .install(
                root_reference,
                DwRights(SELF_ROOT_RIGHTS.0 | DW_RIGHT_TRANSFER.0),
            )
            .expect("fresh two-slot stager accepts root capability");
        let bootfs_handle = stager
            .install(
                self.bootfs.take().expect("primordial bootfs prepared"),
                BOOTFS_RIGHTS,
            )
            .expect("fresh two-slot stager accepts bootfs capability");
        let requests = [
            HandleMoveRequest {
                handle: root_handle,
                requested_rights: SELF_ROOT_RIGHTS,
            },
            HandleMoveRequest {
                handle: bootfs_handle,
                requested_rights: BOOTFS_RIGHTS,
            },
        ];
        let prepared = stager
            .prepare_move_batch(&requests)
            .expect("validated primordial stager moves remain admissible");
        let (rollback, transfers) = prepared.extract();
        let wakes = match self.channels.commit_send(
            self.init_reservation
                .take()
                .expect("primordial INIT send reserved"),
            transfers,
            self.waits,
        ) {
            Ok(wakes) => {
                rollback.finish();
                wakes
            }
            Err((error, transfers)) => {
                rollback.rollback(transfers);
                panic!("prepared primordial INIT commit diverged: {error:?}")
            }
        };
        assert!(
            stager.is_empty(),
            "committed primordial stager retained handles"
        );
        assert_eq!(wakes.len(), 0, "unpublished primordial child had waiters");

        let (_thread_key, thread_reference) = self
            .thread
            .take()
            .expect("primordial Thread prepared")
            .commit();
        let (_process_key, process_reference) = self
            .process
            .take()
            .expect("primordial Process prepared")
            .commit(self.tasks);
        self.committed_process_key = Some(_process_key);
        self.thread_start
            .take()
            .expect("primordial Thread start prepared")
            .commit(self.tasks);
        assert!(
            self.registry
                .release_handle(thread_reference)
                .expect("primordial Thread creator reference releases")
                .is_none(),
            "running primordial Thread creator reference was unexpectedly final"
        );
        for reference in self.segments.iter_mut().filter_map(Option::take) {
            assert!(
                self.registry
                    .release_handle(reference)
                    .expect("mapped segment creator reference releases")
                    .is_none(),
                "mapped segment lost its lease pin"
            );
        }
        assert!(
            self.registry
                .release_handle(self.stack.take().expect("primordial stack prepared"))
                .expect("mapped stack creator reference releases")
                .is_none(),
            "mapped stack lost its lease pin"
        );
        self.kernel_peer = self.channel_refs[0].take();
        self.process_monitor = Some(process_reference);
        self.committed = true;
        PrimordialLaunch
    }

    fn rollback(&mut self) {
        assert!(
            !self.committed,
            "runnable primordial Process cannot roll back"
        );
        if let Some(start) = self.thread_start.take() {
            start.cancel(self.tasks);
        }
        if let Some(thread) = self.thread.take() {
            let parent_final = thread.cancel(self.tasks, self.registry);
            assert!(
                parent_final.is_none(),
                "prepared Process parent finalized early"
            );
        }
        self.thread_key = None;
        self.thread_state = None;
        if let Some(reservation) = self.init_reservation.take() {
            self.channels
                .cancel_send(reservation)
                .expect("primordial INIT reservation cancels");
        }
        self.child_channel = None;
        self.capability_stage_ready = false;
        if let Some(reference) = self.bootfs.take() {
            self.cancel_memory(reference);
        }
        if let Some((start, len)) = self.stack_range.take() {
            let key = match self.root_key {
                Some(key) => key,
                None => panic!("mapped primordial stack lost its root"),
            };
            let region = self
                .regions
                .region_mut_for_live_process(self.tasks, key)
                .expect("prepared primordial root remains live");
            self.platform
                .unmap(region, self.memory, self.registry, start, len);
        }
        if let Some(reference) = self.stack.take() {
            self.cancel_memory(reference);
        }
        for index in (0..self.segment_ranges.len()).rev() {
            if let Some((start, len)) = self.segment_ranges[index].take() {
                let key = match self.root_key {
                    Some(key) => key,
                    None => panic!("mapped primordial segment lost its root"),
                };
                let region = self
                    .regions
                    .region_mut_for_live_process(self.tasks, key)
                    .expect("prepared primordial root remains live");
                self.platform
                    .unmap(region, self.memory, self.registry, start, len);
            }
            if let Some(reference) = self.segments[index].take() {
                self.cancel_memory(reference);
            }
        }
        for index in 0..2 {
            if let Some(reference) = self.channel_refs[index].take() {
                self.release_channel(reference);
            }
        }
        self.channel_keys = None;
        if let Some(root) = self.root.take() {
            root.cancel(self.registry, self.tasks, self.spaces, self.regions);
        }
        self.root_key = None;
        if let Some(process) = self.process.take() {
            let parent_final = process.cancel(self.tasks, self.registry);
            assert!(
                parent_final.is_none(),
                "root TaskGroup finalized during rollback"
            );
        }
    }
}

impl<
    P,
    const REGISTRY_OBJECTS: usize,
    const MEMORY_OBJECTS: usize,
    const LEASES: usize,
    const CHANNEL_PAIRS: usize,
    const CHANNEL_DEPTH: usize,
    const WAITERS: usize,
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const SPACES: usize,
    const REGIONS: usize,
    const REGION_OBJECTS: usize,
    const REGION_SLOTS: usize,
    const EXECUTION: usize,
> Drop
    for AuthorityPrimordialBackend<
        '_,
        P,
        REGISTRY_OBJECTS,
        MEMORY_OBJECTS,
        LEASES,
        CHANNEL_PAIRS,
        CHANNEL_DEPTH,
        WAITERS,
        GROUPS,
        PROCESSES,
        THREADS,
        HANDLES,
        SPACES,
        REGIONS,
        REGION_OBJECTS,
        REGION_SLOTS,
        EXECUTION,
    >
where
    P: PrimordialPlatform,
{
    fn drop(&mut self) {
        assert!(
            self.committed || (self.process.is_none() && self.root.is_none()),
            "authority-backed primordial transaction dropped without commit or rollback"
        );
        assert!(
            !self.committed || (self.kernel_peer.is_none() && self.process_monitor.is_none()),
            "committed primordial transaction dropped without monitor handoff"
        );
    }
}
