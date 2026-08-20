#![allow(
    dead_code,
    reason = "DW0-E2 finalizer routing precedes E5 close/teardown consumers"
)]

use deepwyrm_abi::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_EVENT,
    DW_OBJECT_TYPE_MEMORY_OBJECT, DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_TASK_GROUP,
    DW_OBJECT_TYPE_THREAD,
};

use crate::ipc::{ChannelAuthority, complete_channel_finalization};
use crate::memory::address_region::{
    AddressRegionObjectAuthority, AddressSpaceAuthority, complete_address_region_finalization,
};
use crate::memory::frame_roles::FrameRoleManager;
use crate::memory::object::{MemoryObjectAuthority, complete_memory_finalization};
use crate::task::{TaskAuthority, complete_task_finalization};
use crate::wait::{EventAuthority, WaitRegistry, WakeBatch, complete_event_finalization};

use super::{FinalRelease, ObjectRegistry};

/// Integrated E2 finalizer for every payload-bearing object currently reachable
/// from production DW0-E construction.
pub(crate) struct PayloadFinalizer<
    'a,
    const REGISTRY_OBJECTS: usize,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
    const MEMORY_OBJECTS: usize,
    const LEASES: usize,
    const EVENTS: usize,
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
> {
    registry: &'a mut ObjectRegistry<REGISTRY_OBJECTS>,
    roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    memory: &'a mut MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
    events: &'a EventAuthority<EVENTS>,
    channels: &'a ChannelAuthority<CHANNEL_PAIRS, CHANNEL_DEPTH>,
    waits: &'a WaitRegistry<WAITERS>,
    tasks: &'a mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    spaces: &'a mut AddressSpaceAuthority<SPACES, REGIONS>,
    regions: &'a mut AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
}

impl<
    'a,
    const REGISTRY_OBJECTS: usize,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
    const MEMORY_OBJECTS: usize,
    const LEASES: usize,
    const EVENTS: usize,
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
>
    PayloadFinalizer<
        'a,
        REGISTRY_OBJECTS,
        RANGE_CAPACITY,
        ROLE_CAPACITY,
        MEMORY_OBJECTS,
        LEASES,
        EVENTS,
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
    >
{
    #[allow(
        clippy::too_many_arguments,
        reason = "the finalizer borrows each independently-owned typed payload authority explicitly"
    )]
    pub(crate) fn new(
        registry: &'a mut ObjectRegistry<REGISTRY_OBJECTS>,
        roles: &'a mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
        memory: &'a mut MemoryObjectAuthority<MEMORY_OBJECTS, LEASES>,
        events: &'a EventAuthority<EVENTS>,
        channels: &'a ChannelAuthority<CHANNEL_PAIRS, CHANNEL_DEPTH>,
        waits: &'a WaitRegistry<WAITERS>,
        tasks: &'a mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        spaces: &'a mut AddressSpaceAuthority<SPACES, REGIONS>,
        regions: &'a mut AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
    ) -> Self {
        Self {
            registry,
            roles,
            memory,
            events,
            channels,
            waits,
            tasks,
            spaces,
            regions,
        }
    }

    #[must_use = "typed finalization may return waiter wake intents and pins"]
    pub(crate) fn finalize_chain(&mut self, first: FinalRelease) -> WakeBatch<WAITERS> {
        let mut pending: [Option<FinalRelease>; REGISTRY_OBJECTS] = core::array::from_fn(|_| None);
        assert!(
            REGISTRY_OBJECTS > 0,
            "a final release requires registry capacity"
        );
        pending[0] = Some(first);
        let mut pending_len = 1;
        let mut wakes = WakeBatch::empty();
        while pending_len != 0 {
            pending_len -= 1;
            let final_release = pending[pending_len]
                .take()
                .expect("pending finalization slot remains populated");
            wakes.append(self.finalize_one(final_release, &mut pending, &mut pending_len));
        }
        wakes
    }

    fn finalize_one(
        &mut self,
        final_release: FinalRelease,
        pending: &mut [Option<FinalRelease>; REGISTRY_OBJECTS],
        pending_len: &mut usize,
    ) -> WakeBatch<WAITERS> {
        match final_release.object_type() {
            DW_OBJECT_TYPE_MEMORY_OBJECT => {
                let finalization =
                    self.memory
                        .take_finalization(final_release)
                        .unwrap_or_else(|failure| {
                            panic!(
                                "MemoryObject final release bypassed its typed payload: {:?}",
                                failure.error()
                            )
                        });
                complete_memory_finalization(self.registry, self.roles, finalization);
                WakeBatch::empty()
            }
            DW_OBJECT_TYPE_ADDRESS_REGION => {
                let finalization = self
                    .regions
                    .take_finalization(self.spaces, final_release)
                    .unwrap_or_else(|(error, _)| {
                        panic!("AddressRegion final release bypassed its typed payload: {error:?}")
                    });
                push_pending(
                    pending,
                    pending_len,
                    complete_address_region_finalization(self.registry, finalization),
                );
                WakeBatch::empty()
            }
            DW_OBJECT_TYPE_EVENT => {
                let finalization =
                    self.events
                        .take_finalization(final_release)
                        .unwrap_or_else(|(error, _)| {
                            panic!("Event final release bypassed its typed payload: {error:?}")
                        });
                complete_event_finalization(self.registry, finalization);
                WakeBatch::empty()
            }
            DW_OBJECT_TYPE_CHANNEL => {
                let finalization = self
                    .channels
                    .take_finalization(final_release, self.waits)
                    .unwrap_or_else(|(error, _)| {
                        panic!("Channel final release bypassed its typed payload: {error:?}")
                    });
                let completion = complete_channel_finalization(self.registry, finalization);
                let (wakes, releases) = completion.into_parts();
                for release in releases {
                    push_pending(pending, pending_len, release);
                }
                wakes
            }
            DW_OBJECT_TYPE_TASK_GROUP | DW_OBJECT_TYPE_PROCESS | DW_OBJECT_TYPE_THREAD => {
                let finalization =
                    self.tasks
                        .take_finalization(final_release)
                        .unwrap_or_else(|failure| {
                            panic!(
                                "task final release bypassed its typed payload: {:?}",
                                failure.error()
                            )
                        });
                push_pending(
                    pending,
                    pending_len,
                    complete_task_finalization(self.registry, finalization),
                );
                WakeBatch::empty()
            }
            object_type => panic!(
                "DW0-E2 finalizer received unsupported payload object type {}",
                object_type.0
            ),
        }
    }
}

fn push_pending<const CAPACITY: usize>(
    pending: &mut [Option<FinalRelease>; CAPACITY],
    len: &mut usize,
    release: Option<FinalRelease>,
) {
    let Some(release) = release else {
        return;
    };
    assert!(
        *len < CAPACITY,
        "typed finalization cascade exceeded ObjectRegistry capacity"
    );
    pending[*len] = Some(release);
    *len += 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::address_region::{AddressRegionObjectAuthority, AddressSpaceAuthority};
    use crate::memory::frame_roles::synthetic_frame_role_manager;

    #[test]
    #[allow(
        unsafe_code,
        reason = "test-local AddressSpaceAuthority uniquely owns its synthetic root identities"
    )]
    fn channel_finalization_routes_peer_close_through_central_payload_finalizer() {
        let mut registry = ObjectRegistry::<8>::new();
        let mut roles = synthetic_frame_role_manager::<1, 8>(0x30_000, 4);
        let mut memory = MemoryObjectAuthority::<1, 1>::new();
        let events = EventAuthority::<1>::new();
        let channels = ChannelAuthority::<1, 2>::new();
        let waits = WaitRegistry::<4>::new();
        let mut tasks = TaskAuthority::<1, 1, 1, 1>::new();
        let mut spaces = unsafe { AddressSpaceAuthority::<1, 1>::new() };
        let mut regions = AddressRegionObjectAuthority::<1, 1>::new();
        let (keys, handles) = channels.create_pair(&mut registry).unwrap();
        let [handle0, handle1] = handles;

        let first = registry.release_handle(handle0).unwrap().unwrap();
        {
            let mut finalizer = PayloadFinalizer::new(
                &mut registry,
                &mut roles,
                &mut memory,
                &events,
                &channels,
                &waits,
                &mut tasks,
                &mut spaces,
                &mut regions,
            );
            assert_eq!(finalizer.finalize_chain(first).len(), 0);
        }
        assert_eq!(
            channels.current_signals(keys[1]).unwrap(),
            deepwyrm_abi::DW_SIGNAL_PEER_CLOSED
        );

        let second = registry.release_handle(handle1).unwrap().unwrap();
        let mut finalizer = PayloadFinalizer::new(
            &mut registry,
            &mut roles,
            &mut memory,
            &events,
            &channels,
            &waits,
            &mut tasks,
            &mut spaces,
            &mut regions,
        );
        assert_eq!(finalizer.finalize_chain(second).len(), 0);
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "test-local AddressSpaceAuthority uniquely owns its synthetic root identities"
    )]
    fn region_finalization_cascades_through_process_without_generic_bypass() {
        let mut registry = ObjectRegistry::<8>::new();
        let mut roles = synthetic_frame_role_manager::<1, 8>(0x10_000, 4);
        let mut memory = MemoryObjectAuthority::<1, 1>::new();
        let events = EventAuthority::<1>::new();
        let channels = ChannelAuthority::<1, 2>::new();
        let waits = WaitRegistry::<4>::new();
        let mut tasks = TaskAuthority::<2, 2, 2, 2>::new();
        let mut spaces = unsafe { AddressSpaceAuthority::<1, 1>::new() };
        let mut regions = AddressRegionObjectAuthority::<1, 2>::new();

        let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
        let (process, process_handle) = tasks.create_process(&mut registry, &root_owner).unwrap();
        let (_region, region_handle) = regions
            .create_root_region(
                &mut registry,
                &mut tasks,
                &mut spaces,
                process,
                &process_handle,
            )
            .unwrap();
        assert!(registry.release_handle(region_handle).unwrap().is_none());

        let effects = tasks
            .terminate_process_authorized(&mut registry, process, 0x44)
            .unwrap();
        assert_eq!(effects.drained.final_release_count(), 0);
        let (process_pin, thread_pins, resources) = effects.pins.into_parts();
        assert!(thread_pins.into_iter().flatten().next().is_none());
        assert!(resources.into_iter().flatten().next().is_none());
        assert!(
            registry
                .release_internal(process_pin.unwrap())
                .unwrap()
                .is_none()
        );
        assert!(registry.release_handle(process_handle).unwrap().is_none());

        let blocked = crate::task::BlockedOperationRegistry::<2>::new();
        let drained = blocked.drained(process).unwrap();
        let region_pin = regions
            .retire_exited_root(&mut tasks, process, &blocked, drained)
            .unwrap();
        let region_final = registry.release_internal(region_pin).unwrap().unwrap();
        {
            let mut finalizer = PayloadFinalizer::new(
                &mut registry,
                &mut roles,
                &mut memory,
                &events,
                &channels,
                &waits,
                &mut tasks,
                &mut spaces,
                &mut regions,
            );
            assert_eq!(finalizer.finalize_chain(region_final).len(), 0);
        }

        let root_final = registry.release_internal(root_owner).unwrap().unwrap();
        let mut finalizer = PayloadFinalizer::new(
            &mut registry,
            &mut roles,
            &mut memory,
            &events,
            &channels,
            &waits,
            &mut tasks,
            &mut spaces,
            &mut regions,
        );
        assert_eq!(finalizer.finalize_chain(root_final).len(), 0);
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "test-local AddressSpaceAuthority uniquely owns its synthetic root identities"
    )]
    fn channel_teardown_routes_queued_final_reference_through_event_finalizer() {
        use crate::handle::{HandleMoveRequest, HandleTable};
        use deepwyrm_abi::{DW_RIGHT_TRANSFER, DW_RIGHT_WAIT, DwRights};

        let mut registry = ObjectRegistry::<8>::new();
        let mut roles = synthetic_frame_role_manager::<1, 8>(0x34_000, 4);
        let mut memory = MemoryObjectAuthority::<1, 1>::new();
        let events = EventAuthority::<1>::new();
        let channels = ChannelAuthority::<1, 2>::new();
        let waits = WaitRegistry::<4>::new();
        let mut tasks = TaskAuthority::<1, 1, 1, 1>::new();
        let mut spaces = unsafe { AddressSpaceAuthority::<1, 1>::new() };
        let mut regions = AddressRegionObjectAuthority::<1, 1>::new();
        let (keys, handles) = channels.create_pair(&mut registry).unwrap();
        let [handle0, handle1] = handles;

        let (_event_key, event_ref) = events.create_event(&mut registry).unwrap();
        let mut sender = HandleTable::<1>::new();
        let source = sender
            .install(event_ref, DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_TRANSFER.0))
            .unwrap();
        let prepared = sender
            .prepare_move_batch(&[HandleMoveRequest {
                handle: source,
                requested_rights: DW_RIGHT_WAIT,
            }])
            .unwrap();
        let reservation = channels.reserve_send(keys[0], &[]).unwrap();
        let (rollback, transfers) = prepared.extract();
        let wakes = match channels.commit_send(reservation, transfers, &waits) {
            Ok(wakes) => wakes,
            Err((error, transfers)) => {
                assert!(transfers.is_empty());
                panic!("fresh queued Event transfer failed: {error:?}");
            }
        };
        assert_eq!(wakes.len(), 0);
        rollback.finish();
        assert!(sender.is_empty());

        let receiver_final = registry.release_handle(handle1).unwrap().unwrap();
        {
            let mut finalizer = PayloadFinalizer::new(
                &mut registry,
                &mut roles,
                &mut memory,
                &events,
                &channels,
                &waits,
                &mut tasks,
                &mut spaces,
                &mut regions,
            );
            assert_eq!(finalizer.finalize_chain(receiver_final).len(), 0);
        }

        let (_replacement_key, replacement) = events
            .create_event(&mut registry)
            .expect("queued final Event reference was reclaimed through typed finalization");
        let peer_final = registry.release_handle(handle0).unwrap().unwrap();
        {
            let mut finalizer = PayloadFinalizer::new(
                &mut registry,
                &mut roles,
                &mut memory,
                &events,
                &channels,
                &waits,
                &mut tasks,
                &mut spaces,
                &mut regions,
            );
            assert_eq!(finalizer.finalize_chain(peer_final).len(), 0);
        }
        let replacement_final = registry.release_handle(replacement).unwrap().unwrap();
        let mut finalizer = PayloadFinalizer::new(
            &mut registry,
            &mut roles,
            &mut memory,
            &events,
            &channels,
            &waits,
            &mut tasks,
            &mut spaces,
            &mut regions,
        );
        assert_eq!(finalizer.finalize_chain(replacement_final).len(), 0);
    }
}

#[cfg(test)]
mod memory_route_tests {
    use super::*;
    use crate::memory::address_region::{AddressRegionObjectAuthority, AddressSpaceAuthority};
    use crate::memory::frame_roles::synthetic_frame_role_manager;
    use crate::memory::object::{MemoryObjectKind, MemoryProtection, PAGE_SIZE};

    #[test]
    #[allow(
        unsafe_code,
        reason = "synthetic frame manager test attests zeroing and uniquely owns its address-space identities"
    )]
    fn memory_object_finalization_routes_backing_reclamation_through_typed_cleanup() {
        let mut roles = synthetic_frame_role_manager::<1, 8>(0x20_000, 2);
        let allocation = roles.allocate(1).unwrap();
        let physical_start = allocation.physical_start();
        let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
        let backing = roles.assign_object_backing(zeroed).unwrap();

        let mut registry = ObjectRegistry::<4>::new();
        let creation = registry.create(DW_OBJECT_TYPE_MEMORY_OBJECT).unwrap();
        let mut memory = MemoryObjectAuthority::<1, 1>::new();
        let events = EventAuthority::<1>::new();
        let channels = ChannelAuthority::<1, 2>::new();
        let waits = WaitRegistry::<4>::new();
        let binding = memory
            .bind_backing(
                creation,
                backing,
                PAGE_SIZE,
                MemoryObjectKind::PageBacked,
                MemoryProtection::READ_WRITE,
            )
            .unwrap();
        let bound = registry.finish_payload_binding(binding).unwrap();
        let handle = registry.bound_into_handle(bound).unwrap();
        let final_release = registry.release_handle(handle).unwrap().unwrap();

        let mut tasks = TaskAuthority::<1, 1, 1, 1>::new();
        let mut spaces = unsafe { AddressSpaceAuthority::<1, 1>::new() };
        let mut regions = AddressRegionObjectAuthority::<1, 1>::new();
        {
            let mut finalizer = PayloadFinalizer::new(
                &mut registry,
                &mut roles,
                &mut memory,
                &events,
                &channels,
                &waits,
                &mut tasks,
                &mut spaces,
                &mut regions,
            );
            assert_eq!(finalizer.finalize_chain(final_release).len(), 0);
        }

        let recycled = roles.allocate(1).unwrap();
        assert_eq!(recycled.physical_start(), physical_start);
    }
}
