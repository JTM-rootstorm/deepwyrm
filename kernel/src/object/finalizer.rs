#![allow(
    dead_code,
    reason = "DW0-E2 finalizer routing precedes E5 close/teardown consumers"
)]

use deepwyrm_abi::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_DEVICE_RESOURCE,
    DW_OBJECT_TYPE_EVENT, DW_OBJECT_TYPE_INTERRUPT, DW_OBJECT_TYPE_MEMORY_OBJECT,
    DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_TASK_GROUP, DW_OBJECT_TYPE_THREAD, DW_OBJECT_TYPE_TIMER,
};

use crate::device::{
    DeviceResourceFinalizer, InterruptFinalizer, InterruptPlatform,
    complete_device_resource_finalization, complete_device_resource_finalization_with_grants,
    complete_interrupt_finalization,
};
use crate::ipc::{ChannelAuthority, complete_channel_finalization};
use crate::memory::address_region::{
    AddressRegionObjectAuthority, AddressSpaceAuthority, complete_address_region_finalization,
};
use crate::memory::frame_roles::FrameRoleManager;
use crate::memory::object::{MemoryObjectAuthority, complete_memory_finalization};
use crate::task::{TaskAuthority, complete_task_finalization};
use crate::time::{TimerAuthority, TimerDeadlineAuthority, complete_timer_finalization};
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
    const TIMERS: usize,
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
    timers: &'a TimerAuthority<TIMERS>,
    timer_deadlines: &'a mut dyn TimerDeadlineAuthority,
    channels: &'a ChannelAuthority<CHANNEL_PAIRS, CHANNEL_DEPTH>,
    waits: &'a WaitRegistry<WAITERS>,
    tasks: &'a mut TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    spaces: &'a mut AddressSpaceAuthority<SPACES, REGIONS>,
    regions: &'a mut AddressRegionObjectAuthority<REGION_OBJECTS, REGION_SLOTS>,
    device_resources: Option<&'a dyn DeviceResourceFinalizer>,
    boot_resource_grants: Option<&'a crate::boot::BootResourceGrantAuthority>,
    interrupts: Option<&'a dyn InterruptFinalizer>,
    interrupt_platform: Option<&'a dyn InterruptPlatform>,
}

impl<
    'a,
    const REGISTRY_OBJECTS: usize,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
    const MEMORY_OBJECTS: usize,
    const LEASES: usize,
    const EVENTS: usize,
    const TIMERS: usize,
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
        TIMERS,
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
        timers: &'a TimerAuthority<TIMERS>,
        timer_deadlines: &'a mut dyn TimerDeadlineAuthority,
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
            timers,
            timer_deadlines,
            channels,
            waits,
            tasks,
            spaces,
            regions,
            device_resources: None,
            boot_resource_grants: None,
            interrupts: None,
            interrupt_platform: None,
        }
    }

    pub(crate) fn with_device_resources(
        mut self,
        device_resources: &'a dyn DeviceResourceFinalizer,
    ) -> Self {
        self.device_resources = Some(device_resources);
        self
    }

    pub(crate) fn with_boot_resource_grants(
        mut self,
        grants: &'a crate::boot::BootResourceGrantAuthority,
    ) -> Self {
        self.boot_resource_grants = Some(grants);
        self
    }

    pub(crate) fn with_interrupts(
        mut self,
        interrupts: &'a dyn InterruptFinalizer,
        platform: &'a dyn InterruptPlatform,
    ) -> Self {
        self.interrupts = Some(interrupts);
        self.interrupt_platform = Some(platform);
        self
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

    /// Retries the one bounded DW1-E deferred Interrupt retirement at an
    /// ordinary carrier safe-point. A still-quarantined route yields no
    /// release and remains owned by the typed Interrupt authority.
    pub(crate) fn retry_deferred_interrupt(&mut self) -> Option<FinalRelease> {
        let interrupts = self.interrupts?;
        let platform = self.interrupt_platform?;
        let finalization = interrupts.retry_deferred_finalization(platform)?;
        #[cfg(deepwyrm_dw1d_evidence)]
        let (dw1d_object, dw1d_binding, dw1d_lease) = finalization.dw1d_identity();
        let parent = complete_interrupt_finalization(self.registry, finalization);
        #[cfg(deepwyrm_dw1d_evidence)]
        crate::test_support::DW1D_EVIDENCE
            .observe_interrupt_finalized(dw1d_object, dw1d_binding, dw1d_lease)
            .unwrap_or_else(|error| {
                panic!("selector-30 deferred Interrupt finalization observation failed: {error:?}")
            });
        parent
    }

    pub(crate) fn retry_deferred_interrupt_exact(
        &mut self,
        binding: crate::device::InterruptBinding,
    ) -> Option<FinalRelease> {
        let interrupts = self.interrupts?;
        let platform = self.interrupt_platform?;
        let finalization = interrupts.retry_deferred_finalization_exact(platform, binding)?;
        #[cfg(deepwyrm_dw1d_evidence)]
        let (dw1d_object, dw1d_binding, dw1d_lease) = finalization.dw1d_identity();
        let parent = complete_interrupt_finalization(self.registry, finalization);
        #[cfg(deepwyrm_dw1d_evidence)]
        crate::test_support::DW1D_EVIDENCE
            .observe_interrupt_finalized(dw1d_object, dw1d_binding, dw1d_lease)
            .unwrap_or_else(|error| {
                panic!("selector-30 exact deferred Interrupt observation failed: {error:?}")
            });
        parent
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
            DW_OBJECT_TYPE_TIMER => {
                let finalization = self
                    .timers
                    .take_finalization(final_release, self.timer_deadlines)
                    .unwrap_or_else(|(error, _)| {
                        panic!("Timer final release bypassed its typed payload: {error:?}")
                    });
                complete_timer_finalization(self.registry, finalization);
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
            DW_OBJECT_TYPE_DEVICE_RESOURCE => {
                let finalization = self
                    .device_resources
                    .unwrap_or_else(|| {
                        panic!(
                            "DeviceResource final release reached a finalizer without D2 authority"
                        )
                    })
                    .take_finalization(final_release)
                    .unwrap_or_else(|(error, _)| {
                        panic!("DeviceResource final release bypassed its typed payload: {error:?}")
                    });
                #[cfg(deepwyrm_dw1d_evidence)]
                let dw1d_grant = finalization.dw1d_grant_identity();
                if let Some(grants) = self.boot_resource_grants {
                    complete_device_resource_finalization_with_grants(
                        self.registry,
                        grants,
                        finalization,
                    );
                } else {
                    complete_device_resource_finalization(self.registry, finalization);
                }
                #[cfg(deepwyrm_dw1d_evidence)]
                if let Some((resource_id, object, lease)) = dw1d_grant {
                    crate::test_support::DW1D_EVIDENCE
                        .observe_grant_returned(resource_id, object, lease)
                        .unwrap_or_else(|error| {
                            panic!("selector-30 grant-return observation failed: {error:?}")
                        });
                }
                WakeBatch::empty()
            }
            DW_OBJECT_TYPE_INTERRUPT => {
                let finalization = self
                    .interrupts
                    .unwrap_or_else(|| {
                        panic!("Interrupt final release reached a finalizer without D3 authority")
                    })
                    .take_finalization(
                        final_release,
                        self.interrupt_platform.unwrap_or_else(|| {
                            panic!(
                                "Interrupt final release reached a finalizer without D3 platform"
                            )
                        }),
                    )
                    .unwrap_or_else(|(error, _)| {
                        panic!("Interrupt final release bypassed its typed payload: {error:?}")
                    });
                #[cfg(deepwyrm_dw1d_evidence)]
                let (dw1d_object, dw1d_binding, dw1d_lease) = finalization.dw1d_identity();
                push_pending(
                    pending,
                    pending_len,
                    complete_interrupt_finalization(self.registry, finalization),
                );
                #[cfg(deepwyrm_dw1d_evidence)]
                crate::test_support::DW1D_EVIDENCE
                    .observe_interrupt_finalized(dw1d_object, dw1d_binding, dw1d_lease)
                    .unwrap_or_else(|error| {
                        panic!("selector-30 Interrupt finalization observation failed: {error:?}")
                    });
                WakeBatch::empty()
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
struct TestTimerDeadlines<const N: usize> {
    now: u64,
    queue: crate::time::DeadlineQueue<N, crate::time::TimerExpiryToken>,
}

#[cfg(test)]
impl<const N: usize> TestTimerDeadlines<N> {
    fn new(now: u64) -> Self {
        Self {
            now,
            queue: crate::time::DeadlineQueue::new(),
        }
    }
}

#[cfg(test)]
impl<const N: usize> TimerDeadlineAuthority for TestTimerDeadlines<N> {
    fn replace_timer_deadline(
        &mut self,
        old: Option<&crate::time::DeadlineRegistration>,
        deadline_ns: u64,
        token: crate::time::TimerExpiryToken,
    ) -> Result<Option<crate::time::DeadlineRegistration>, crate::time::TimerDeadlineError> {
        if deadline_ns <= self.now {
            if let Some(old) = old {
                self.queue
                    .cancel_if_live_ref(old)
                    .map_err(|_| crate::time::TimerDeadlineError::Fault)?;
            }
            return Ok(None);
        }
        if let Some(old) = old
            && let Some(registration) = self
                .queue
                .replace_if_live(old, deadline_ns, token)
                .map_err(|_| crate::time::TimerDeadlineError::Fault)?
        {
            return Ok(Some(registration));
        }
        self.queue
            .register(deadline_ns, token)
            .map(Some)
            .map_err(|error| match error {
                crate::time::DeadlineQueueError::Capacity => {
                    crate::time::TimerDeadlineError::Capacity
                }
                _ => crate::time::TimerDeadlineError::Fault,
            })
    }

    fn cancel_timer_deadline(
        &mut self,
        registration: &crate::time::DeadlineRegistration,
    ) -> Result<(), crate::time::TimerDeadlineError> {
        self.queue
            .cancel_if_live_ref(registration)
            .map(|_| ())
            .map_err(|_| crate::time::TimerDeadlineError::Fault)
    }
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
    fn device_resource_finalization_routes_through_central_payload_finalizer() {
        let mut registry = ObjectRegistry::<8>::new();
        let mut roles = synthetic_frame_role_manager::<1, 8>(0x38_000, 4);
        let mut memory = MemoryObjectAuthority::<1, 1>::new();
        let events = EventAuthority::<1>::new();
        let timers = TimerAuthority::<1>::new();
        let mut timer_deadlines = TestTimerDeadlines::<2>::new(0);
        let channels = ChannelAuthority::<1, 2>::new();
        let waits = WaitRegistry::<4>::new();
        let mut tasks = TaskAuthority::<1, 1, 1, 1>::new();
        let mut spaces = unsafe { AddressSpaceAuthority::<1, 1>::new() };
        let mut regions = AddressRegionObjectAuthority::<1, 1>::new();
        let (domain, _owner) = tasks.create_root_group(&mut registry).unwrap();
        let devices = crate::device::DeviceResourceAuthority::<1>::new();
        let mut device_handles = crate::handle::HandleTable::<1>::new();
        let (_, handle) = devices
            .create(
                &mut registry,
                &mut device_handles,
                crate::device::DeviceResourceDescriptor {
                    resource_id: 1,
                    lease_generation: 1,
                    kind: deepwyrm_abi::DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
                    pio_base: 0x2f8,
                    pio_length: 8,
                    interrupt_source: 3,
                    resource_domain: domain,
                },
                deepwyrm_abi::DW_RIGHT_INSPECT,
            )
            .unwrap();
        let final_release = device_handles
            .close(&mut registry, handle)
            .unwrap()
            .unwrap();

        let mut finalizer = PayloadFinalizer::new(
            &mut registry,
            &mut roles,
            &mut memory,
            &events,
            &timers,
            &mut timer_deadlines,
            &channels,
            &waits,
            &mut tasks,
            &mut spaces,
            &mut regions,
        )
        .with_device_resources(&devices);
        assert_eq!(finalizer.finalize_chain(final_release).len(), 0);
        assert_eq!(devices.live_count(), 0);
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "test-local AddressSpaceAuthority uniquely owns its synthetic root identities"
    )]
    fn interrupt_finalization_unbinds_then_chains_parent_resource_iteratively() {
        let mut registry = ObjectRegistry::<8>::new();
        let mut roles = synthetic_frame_role_manager::<1, 8>(0x39_000, 4);
        let mut memory = MemoryObjectAuthority::<1, 1>::new();
        let events = EventAuthority::<1>::new();
        let timers = TimerAuthority::<1>::new();
        let mut timer_deadlines = TestTimerDeadlines::<2>::new(0);
        let channels = ChannelAuthority::<1, 2>::new();
        let waits = WaitRegistry::<4>::new();
        let mut tasks = TaskAuthority::<1, 1, 1, 1>::new();
        let mut spaces = unsafe { AddressSpaceAuthority::<1, 1>::new() };
        let mut regions = AddressRegionObjectAuthority::<1, 1>::new();
        let (domain, _owner) = tasks.create_root_group(&mut registry).unwrap();
        let devices = crate::device::DeviceResourceAuthority::<1>::new();
        let interrupts = crate::device::InterruptAuthority::<1>::new();
        let platform = crate::device::InterruptPlatformModel::<1>::new();
        let mut handles = crate::handle::HandleTable::<2>::new();
        let (_, resource) = devices
            .create(
                &mut registry,
                &mut handles,
                crate::device::DeviceResourceDescriptor {
                    resource_id: 1,
                    lease_generation: 1,
                    kind: deepwyrm_abi::DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
                    pio_base: 0x2f8,
                    pio_length: 8,
                    interrupt_source: 3,
                    resource_domain: domain,
                },
                deepwyrm_abi::dw_object_compatible_rights(
                    deepwyrm_abi::DW_OBJECT_TYPE_DEVICE_RESOURCE,
                ),
            )
            .unwrap();
        let (interrupt_key, interrupt) = crate::device::interrupt_create(
            &mut handles,
            &mut registry,
            &devices,
            &interrupts,
            &platform,
            resource,
            deepwyrm_abi::dw_object_compatible_rights(deepwyrm_abi::DW_OBJECT_TYPE_INTERRUPT),
        )
        .unwrap();
        let binding = interrupts.binding(interrupt_key);

        assert!(handles.close(&mut registry, resource).unwrap().is_none());
        let first = handles.close(&mut registry, interrupt).unwrap().unwrap();
        let mut finalizer = PayloadFinalizer::new(
            &mut registry,
            &mut roles,
            &mut memory,
            &events,
            &timers,
            &mut timer_deadlines,
            &channels,
            &waits,
            &mut tasks,
            &mut spaces,
            &mut regions,
        )
        .with_device_resources(&devices)
        .with_interrupts(&interrupts, &platform);
        assert_eq!(finalizer.finalize_chain(first).len(), 0);
        assert_eq!(interrupts.live_count(), 0);
        assert_eq!(devices.live_count(), 0);
        assert!(!platform.is_bound(binding));
    }

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
        let timers = TimerAuthority::<1>::new();
        let mut timer_deadlines = TestTimerDeadlines::<2>::new(0);
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
                &timers,
                &mut timer_deadlines,
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
            &timers,
            &mut timer_deadlines,
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
        let timers = TimerAuthority::<1>::new();
        let mut timer_deadlines = TestTimerDeadlines::<2>::new(0);
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
                &timers,
                &mut timer_deadlines,
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
            &timers,
            &mut timer_deadlines,
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
        let timers = TimerAuthority::<1>::new();
        let mut timer_deadlines = TestTimerDeadlines::<2>::new(0);
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
                &timers,
                &mut timer_deadlines,
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
                &timers,
                &mut timer_deadlines,
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
            &timers,
            &mut timer_deadlines,
            &channels,
            &waits,
            &mut tasks,
            &mut spaces,
            &mut regions,
        );
        assert_eq!(finalizer.finalize_chain(replacement_final).len(), 0);
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "test-local AddressSpaceAuthority uniquely owns its synthetic root identities"
    )]
    fn armed_timer_finalization_cancels_deadline_before_generic_release() {
        let mut registry = ObjectRegistry::<4>::new();
        let mut roles = synthetic_frame_role_manager::<1, 8>(0x40_000, 4);
        let mut memory = MemoryObjectAuthority::<1, 1>::new();
        let events = EventAuthority::<1>::new();
        let timers = TimerAuthority::<1>::new();
        let mut timer_deadlines = TestTimerDeadlines::<1>::new(10);
        let channels = ChannelAuthority::<1, 2>::new();
        let waits = WaitRegistry::<2>::new();
        let mut tasks = TaskAuthority::<1, 1, 1, 1>::new();
        let mut spaces = unsafe { AddressSpaceAuthority::<1, 1>::new() };
        let mut regions = AddressRegionObjectAuthority::<1, 1>::new();

        let (key, handle) = timers.create_timer(&mut registry).unwrap();
        let wakes = timers
            .set(
                key,
                deepwyrm_abi::DwDeadline(100),
                &mut timer_deadlines,
                &waits,
            )
            .unwrap();
        assert_eq!(wakes.len(), 0);
        let (wake_intents, pins) = wakes.into_parts();
        assert!(wake_intents.into_iter().flatten().next().is_none());
        assert!(pins.into_iter().flatten().next().is_none());
        assert_eq!(timer_deadlines.queue.earliest(), Some(100));

        let final_release = registry.release_handle(handle).unwrap().unwrap();
        {
            let mut finalizer = PayloadFinalizer::new(
                &mut registry,
                &mut roles,
                &mut memory,
                &events,
                &timers,
                &mut timer_deadlines,
                &channels,
                &waits,
                &mut tasks,
                &mut spaces,
                &mut regions,
            );
            assert_eq!(finalizer.finalize_chain(final_release).len(), 0);
        }
        assert_eq!(timer_deadlines.queue.earliest(), None);
        assert!(timers.current_signals(key).is_err());

        let (_replacement_key, replacement) = timers.create_timer(&mut registry).unwrap();
        let replacement_final = registry.release_handle(replacement).unwrap().unwrap();
        let mut finalizer = PayloadFinalizer::new(
            &mut registry,
            &mut roles,
            &mut memory,
            &events,
            &timers,
            &mut timer_deadlines,
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
        let timers = TimerAuthority::<1>::new();
        let mut timer_deadlines = TestTimerDeadlines::<2>::new(0);
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
                &timers,
                &mut timer_deadlines,
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
