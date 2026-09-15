extern crate std;

use std::vec;
use std::vec::Vec;

use super::*;
use crate::boot::primordial::construction::{construct_primordial, tests::elf_fixture};
use crate::boot::primordial::parse_primordial_elf;
use crate::handle::ResolvedHandle;
use crate::memory::address_region::PrimordialHostPublisher;
use crate::memory::address_region::complete_address_region_finalization;
use crate::memory::frame_roles::{FrameRoleManager, synthetic_frame_role_manager};
use crate::memory::kernel_stack::KernelStackBounds;
use crate::memory::object::complete_memory_finalization;
use crate::object::{FinalRelease, HandleRef};
use crate::task::{TaskGroupKey, complete_task_finalization};
use deepwyrm_abi::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_MEMORY_OBJECT,
    DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_TASK_GROUP, DW_OBJECT_TYPE_THREAD, DW_TASK_STATE_EXITED,
    DW_TERMINATION_NORMAL_EXIT,
};

struct HostAllocation {
    physical_start: u64,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HostMapping {
    virtual_start: u64,
    byte_len: u64,
    protection: Protection,
}

struct HostPlatform {
    roles: FrameRoleManager<16, 64>,
    allocations: Vec<HostAllocation>,
    mappings: Vec<HostMapping>,
}

impl HostPlatform {
    fn new() -> Self {
        Self {
            roles: synthetic_frame_role_manager(0x10_0000, 256),
            allocations: Vec::new(),
            mappings: Vec::new(),
        }
    }
}

impl PrimordialPlatform for HostPlatform {
    type Error = &'static str;

    #[allow(
        unsafe_code,
        reason = "the host gate stores an all-zero byte carrier for every synthetic allocation"
    )]
    fn allocate_zeroed_backing(
        &mut self,
        page_count: u64,
    ) -> Result<ObjectBackingGrant, Self::Error> {
        let allocation = self.roles.allocate(page_count).map_err(|_| "allocate")?;
        let physical_start = allocation.physical_start();
        let byte_len = allocation.byte_len();
        let bytes = vec![0_u8; usize::try_from(byte_len).map_err(|_| "size")?];
        let zeroed = unsafe { self.roles.assume_zeroed(allocation) }.map_err(|_| "zero")?;
        let backing = self
            .roles
            .assign_object_backing(zeroed)
            .map_err(|_| "backing")?;
        self.allocations.push(HostAllocation {
            physical_start,
            bytes,
        });
        Ok(backing)
    }

    fn write_backing(
        &mut self,
        backing: &ObjectBackingGrant,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        let allocation = self
            .allocations
            .iter_mut()
            .find(|allocation| allocation.physical_start == backing.physical_start())
            .ok_or("missing backing")?;
        let start = usize::try_from(offset).map_err(|_| "offset")?;
        let end = start.checked_add(bytes.len()).ok_or("overflow")?;
        let destination = allocation.bytes.get_mut(start..end).ok_or("range")?;
        destination.copy_from_slice(bytes);
        Ok(())
    }

    fn recycle_backing(&mut self, backing: ObjectBackingGrant) {
        let slot = self
            .allocations
            .iter()
            .position(|allocation| allocation.physical_start == backing.physical_start())
            .expect("recycled backing retains host allocation");
        self.allocations.swap_remove(slot);
        self.roles
            .cancel_object_backing(backing)
            .expect("host backing role recycles");
    }

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
    ) -> Result<(), Self::Error> {
        let resolved = ResolvedHandle::from_kernel_reference(registry, object, rights)
            .map_err(|_| "resolve")?;
        let authorization =
            region
                .authorize_map(memory, resolved, protection)
                .map_err(|failure| {
                    let (_error, releases) = failure.release(registry);
                    assert!(releases.into_items().into_iter().all(|item| item.is_none()));
                    "authorize"
                })?;
        let mut publisher = PrimordialHostPublisher::for_region(region);
        let releases = region
            .map(
                memory,
                registry,
                &mut publisher,
                virtual_start,
                authorization,
                0,
                byte_len,
                protection,
            )
            .map_err(|failure| {
                let releases = failure.into_final_releases();
                assert!(releases.into_items().into_iter().all(|item| item.is_none()));
                "map"
            })?;
        assert!(releases.into_items().into_iter().all(|item| item.is_none()));
        self.mappings.push(HostMapping {
            virtual_start,
            byte_len,
            protection,
        });
        Ok(())
    }

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
    ) {
        let mut publisher = PrimordialHostPublisher::for_region(region);
        let releases = region
            .unmap(memory, registry, &mut publisher, virtual_start, byte_len)
            .expect("host rollback unmaps a committed primordial range");
        for release in releases.into_items().into_iter().flatten() {
            let finalization = memory.take_finalization(release).unwrap();
            let physical_start = finalization.backing_physical_start();
            complete_memory_finalization(registry, &mut self.roles, finalization);
            let slot = self
                .allocations
                .iter()
                .position(|allocation| allocation.physical_start == physical_start)
                .expect("unmapped backing retains host byte carrier");
            self.allocations.swap_remove(slot);
        }
        let slot = self
            .mappings
            .iter()
            .position(|mapping| {
                mapping.virtual_start == virtual_start && mapping.byte_len == byte_len
            })
            .expect("unmapped primordial range retains host mapping record");
        self.mappings.swap_remove(slot);
    }
}

type Registry = ObjectRegistry<64>;
type Memory = MemoryObjectAuthority<16, 32>;
type Channels = ChannelAuthority<2, 2>;
type Waits = WaitRegistry<8>;
type Tasks = TaskAuthority<2, 2, 2, 8>;
type Spaces = AddressSpaceAuthority<2, 2>;
type Regions = AddressRegionObjectAuthority<2, 16>;
type Execution = ExecutionDomain<2>;

fn execution() -> Execution {
    Execution::new([
        KernelStackBounds::new(0x1000, 0x2000, 0x6000).unwrap(),
        KernelStackBounds::new(0x7000, 0x8000, 0xc000).unwrap(),
    ])
    .unwrap()
}

#[allow(
    unsafe_code,
    reason = "the host gate owns the sole synthetic AddressSpaceAuthority"
)]
fn authorities() -> (
    HostPlatform,
    Registry,
    Memory,
    Channels,
    Waits,
    Tasks,
    Spaces,
    Regions,
    Execution,
    TaskGroupKey,
    crate::object::InternalRef,
) {
    let mut registry = Registry::new();
    let mut tasks = Tasks::new();
    let (group, owner) = tasks.create_root_group(&mut registry).unwrap();
    (
        HostPlatform::new(),
        registry,
        Memory::new(),
        Channels::new(),
        Waits::new(),
        tasks,
        unsafe { Spaces::new() },
        Regions::new(),
        execution(),
        group,
        owner,
    )
}

#[allow(clippy::too_many_arguments)]
fn finalize_known(
    platform: &mut HostPlatform,
    registry: &mut Registry,
    memory: &mut Memory,
    channels: &Channels,
    waits: &Waits,
    tasks: &mut Tasks,
    spaces: &mut Spaces,
    regions: &mut Regions,
    first: FinalRelease,
) {
    let mut pending = vec![first];
    while let Some(release) = pending.pop() {
        match release.object_type() {
            DW_OBJECT_TYPE_MEMORY_OBJECT => {
                let finalization = memory.take_finalization(release).unwrap();
                let physical_start = finalization.backing_physical_start();
                complete_memory_finalization(registry, &mut platform.roles, finalization);
                let slot = platform
                    .allocations
                    .iter()
                    .position(|allocation| allocation.physical_start == physical_start)
                    .expect("finalized backing retains host byte carrier");
                platform.allocations.swap_remove(slot);
            }
            DW_OBJECT_TYPE_CHANNEL => {
                let finalization = channels.take_finalization(release, waits).unwrap();
                let completion = complete_channel_finalization(registry, finalization);
                let (_wakes, releases) = completion.into_parts();
                pending.extend(releases.into_iter().flatten());
            }
            DW_OBJECT_TYPE_ADDRESS_REGION => {
                let finalization = regions.take_finalization(spaces, release).unwrap();
                if let Some(parent) = complete_address_region_finalization(registry, finalization) {
                    pending.push(parent);
                }
            }
            DW_OBJECT_TYPE_TASK_GROUP | DW_OBJECT_TYPE_PROCESS | DW_OBJECT_TYPE_THREAD => {
                let finalization = tasks.take_finalization(release).unwrap();
                if let Some(parent) = complete_task_finalization(registry, finalization) {
                    pending.push(parent);
                }
            }
            other => panic!("unexpected primordial final release: {other:?}"),
        }
    }
}

#[test]
fn concrete_authority_adapter_rolls_back_every_boundary_and_recovers_capacity() {
    let elf = elf_fixture();
    let plan = parse_primordial_elf(&elf).unwrap();
    for stage in crate::boot::primordial::construction::tests::stages() {
        let (
            mut platform,
            mut registry,
            mut memory,
            channels,
            waits,
            mut tasks,
            mut spaces,
            mut regions,
            execution,
            root_group,
            root_owner,
        ) = authorities();
        {
            let mut backend = AuthorityPrimordialBackend::new(
                &mut platform,
                &mut registry,
                &mut memory,
                &channels,
                &waits,
                &mut tasks,
                &mut spaces,
                &mut regions,
                &execution,
                &root_owner,
            );
            let error = construct_primordial(&plan, &elf, b"bootfs", &mut backend, |candidate| {
                candidate == stage
            })
            .unwrap_err();
            assert_eq!(
                error,
                crate::boot::primordial::construction::PrimordialConstructionError::Injected(stage)
            );
        }
        assert!(
            platform.allocations.is_empty(),
            "stage {stage:?} leaked backing"
        );
        assert!(
            platform.mappings.is_empty(),
            "stage {stage:?} leaked mapping"
        );
        assert_eq!(
            tasks.group_state(root_group).unwrap(),
            crate::task::TaskGroupState::Active
        );
        let process = tasks.prepare_process(&mut registry, &root_owner).unwrap();
        assert!(process.cancel(&mut tasks, &mut registry).is_none());
        let (_keys, references) = channels.create_pair(&mut registry).unwrap();
        for reference in references {
            let final_release = registry.release_handle(reference).unwrap().unwrap();
            let finalization = channels.take_finalization(final_release, &waits).unwrap();
            let completion = complete_channel_finalization(&mut registry, finalization);
            assert!(
                completion
                    .into_parts()
                    .1
                    .into_iter()
                    .all(|release| release.is_none())
            );
        }
    }
}

#[test]
fn concrete_authority_adapter_commits_real_init_transfer_and_exact_start_state() {
    let elf = elf_fixture();
    let plan = parse_primordial_elf(&elf).unwrap();
    let (
        mut platform,
        mut registry,
        mut memory,
        channels,
        waits,
        mut tasks,
        mut spaces,
        mut regions,
        execution,
        _root_group,
        root_owner,
    ) = authorities();
    let mut backend = AuthorityPrimordialBackend::new(
        &mut platform,
        &mut registry,
        &mut memory,
        &channels,
        &waits,
        &mut tasks,
        &mut spaces,
        &mut regions,
        &execution,
        &root_owner,
    );
    construct_primordial(&plan, &elf, b"bootfs", &mut backend, |_| false).unwrap();
    assert!(backend.committed);
    let monitor = backend.take_monitor();
    let keys = monitor.channel_keys;
    let info = channels.peek_receive(keys[1]).unwrap();
    assert_eq!(info.required_bytes, INIT_BYTES.len() as u32);
    assert_eq!(info.required_handles, 3);
    let thread = monitor.thread_key;
    assert_eq!(
        execution.scheduler_state(thread),
        Some(crate::task::SchedulerThreadState::Runnable)
    );
    let start = backend.tasks.thread_start_state(thread).unwrap().unwrap();
    assert_eq!(start.entry(), plan.entry());
    assert_eq!(start.argument1(), 1);
    assert_eq!(start.argument0(), backend.child_handle.unwrap().0);

    assert_eq!(backend.platform.allocations.len(), 4);
    assert_eq!(
        &backend.platform.allocations[0].bytes[..4],
        &[0xaa, 0xbb, 0xcc, 0xdd]
    );
    assert!(
        backend.platform.allocations[0].bytes[4..]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(
        &backend.platform.allocations[1].bytes[..8],
        &[1, 2, 3, 4, 5, 6, 7, 8]
    );
    assert!(
        backend.platform.allocations[1].bytes[8..]
            .iter()
            .all(|byte| *byte == 0)
    );
    let stack_bytes = &backend.platform.allocations[2].bytes;
    let startup_offset = stack_bytes.len() - STARTUP_BLOCK_BYTES;
    assert!(stack_bytes[..startup_offset].iter().all(|byte| *byte == 0));
    assert_eq!(
        &stack_bytes[startup_offset + 48..startup_offset + 67],
        b"wyrmroot-bootstrap\0"
    );
    assert!(
        stack_bytes[startup_offset + 67..]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(&backend.platform.allocations[3].bytes[..6], b"bootfs");
    assert!(
        backend.platform.allocations[3].bytes[6..]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(
        backend.platform.mappings,
        vec![
            HostMapping {
                virtual_start: 0x401000,
                byte_len: 0x1000,
                protection: MemoryProtection::READ_EXECUTE,
            },
            HostMapping {
                virtual_start: 0x402000,
                byte_len: 0x1000,
                protection: MemoryProtection::READ_WRITE,
            },
            HostMapping {
                virtual_start: monitor.stack_range.0,
                byte_len: monitor.stack_range.1,
                protection: MemoryProtection::READ_WRITE,
            },
        ]
    );
    let guard_start = monitor.stack_range.0 - 4096;
    assert!(backend.platform.mappings.iter().all(|mapping| {
        !(mapping.virtual_start <= guard_start
            && guard_start < mapping.virtual_start + mapping.byte_len)
    }));

    let receive = channels.reserve_receive(keys[1]).unwrap();
    let destinations = backend
        .tasks
        .process_handles_mut(monitor.process_key)
        .unwrap()
        .reserve_transfer_batch(3)
        .unwrap();
    let mut init = [0_u8; 64];
    let received = channels
        .receive_reserved(receive, &mut init, &waits)
        .unwrap();
    let (actual, transfers, init_wakes) = received.into_parts();
    assert_eq!(actual, INIT_BYTES.len());
    assert_eq!(init, INIT_BYTES);
    assert_eq!(init_wakes.len(), 0);
    let published = destinations.publish(transfers);
    let root = published[0].unwrap();
    let bootfs = published[1].unwrap();
    let task_group = published[2].unwrap();
    assert_eq!(root.object_type, DW_OBJECT_TYPE_ADDRESS_REGION);
    assert_eq!(root.rights, SELF_ROOT_RIGHTS);
    assert_eq!(bootfs.object_type, DW_OBJECT_TYPE_MEMORY_OBJECT);
    assert_eq!(bootfs.rights, BOOTFS_RIGHTS);
    assert_eq!(task_group.object_type, DW_OBJECT_TYPE_TASK_GROUP);
    assert_eq!(task_group.rights, super::super::LOADER_TASK_GROUP_RIGHTS);
    assert_ne!(root.handle, bootfs.handle);
    assert_ne!(root.handle, task_group.handle);
    assert_ne!(bootfs.handle, task_group.handle);
    assert_ne!(root.handle, backend.child_handle.unwrap());
    assert_ne!(bootfs.handle, backend.child_handle.unwrap());

    let ready_wakes = channels
        .send(keys[1], &super::super::READY_BYTES, &waits)
        .unwrap();
    assert_eq!(ready_wakes.len(), 0);
    let mut ready = [0_u8; 40];
    let (actual, wakes) = channels.receive_into(keys[0], &mut ready, &waits).unwrap();
    assert_eq!(actual, ready.len());
    assert_eq!(ready, super::super::READY_BYTES);
    assert_eq!(wakes.len(), 0);
    drop(backend);

    let effects = tasks
        .exit_process(monitor.process_key, monitor.thread_key, 0)
        .unwrap();
    let info = tasks.process_info(monitor.process_key).unwrap();
    assert_eq!(info.state, DW_TASK_STATE_EXITED);
    assert_eq!(info.reason, DW_TERMINATION_NORMAL_EXIT);
    assert_eq!(info.application_code, 0);
    let (drained, _) = tasks
        .drain_exited_process_handles_stepwise(&mut registry, monitor.process_key)
        .unwrap();
    for release in drained.into_iter().flatten() {
        finalize_known(
            &mut platform,
            &mut registry,
            &mut memory,
            &channels,
            &waits,
            &mut tasks,
            &mut spaces,
            &mut regions,
            release,
        );
    }
    let retired = execution.retire_exit_pins(effects);
    let mut retired = retired;
    while let Some(pin) = retired.pop() {
        if let Some(release) = registry.release_internal(pin).unwrap() {
            finalize_known(
                &mut platform,
                &mut registry,
                &mut memory,
                &channels,
                &waits,
                &mut tasks,
                &mut spaces,
                &mut regions,
                release,
            );
        }
    }

    let proof = tasks.process_quiescence_proof(monitor.process_key).unwrap();
    for (address, byte_len) in monitor
        .segment_ranges
        .into_iter()
        .flatten()
        .chain(core::iter::once(monitor.stack_range))
    {
        let region = regions
            .region_mut_for_quiesced_teardown(&tasks, &proof, monitor.root_key)
            .unwrap();
        platform.unmap(region, &mut memory, &mut registry, address, byte_len);
    }
    let drained = execution
        .blocked_operations_drained(&tasks, &proof)
        .unwrap();
    let root_pin = regions
        .retire_quiesced_root(
            &mut tasks,
            monitor.process_key,
            &proof,
            execution.blocked_operations(),
            drained,
        )
        .unwrap();
    let root_release = registry.release_internal(root_pin).unwrap().unwrap();
    finalize_known(
        &mut platform,
        &mut registry,
        &mut memory,
        &channels,
        &waits,
        &mut tasks,
        &mut spaces,
        &mut regions,
        root_release,
    );
    for reference in [monitor.kernel_peer, monitor.process] {
        if let Some(release) = registry.release_handle(reference).unwrap() {
            finalize_known(
                &mut platform,
                &mut registry,
                &mut memory,
                &channels,
                &waits,
                &mut tasks,
                &mut spaces,
                &mut regions,
                release,
            );
        }
    }
    assert!(platform.allocations.is_empty());
    assert!(platform.mappings.is_empty());
}
