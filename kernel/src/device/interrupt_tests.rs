use super::*;

use deepwyrm_abi::{
    DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT, DW_INTERRUPT_INFO_FLAG_COALESCED,
    DW_INTERRUPT_STATE_ARMED, DW_INTERRUPT_STATE_PENDING, DW_OBJECT_INFO_INTERRUPT_V1,
    DW_OBJECT_TYPE_INTERRUPT, DW_RIGHT_INSPECT, DW_RIGHT_MODIFY, DW_RIGHT_READ, DW_RIGHT_WAIT,
    DW_SIGNAL_SIGNALED, DW_STATUS_ACCESS_DENIED, DW_STATUS_BAD_HANDLE, DW_STATUS_BAD_STATE,
    DwHandle, DwRights, dw_object_compatible_rights,
};

use super::interrupt::InterruptBinding;
use crate::handle::{AcceptedObjectTypes, HandleTable, HandleTableError};
use crate::object::{FinalRelease, ObjectRegistry};
use crate::task::{CooperativeScheduler, TaskAuthority, ThreadKey};
use crate::wait::{WaitRegistry, WakeBatch};
use core::sync::atomic::{AtomicBool, Ordering};

type Registry = ObjectRegistry<32>;
type Table = HandleTable<12>;
type Resources = DeviceResourceAuthority<4>;
type Interrupts = InterruptAuthority<4>;
type Platform = InterruptPlatformModel<4>;
type Waits = WaitRegistry<8>;

struct DeferredOncePlatform {
    inner: Platform,
    defer: AtomicBool,
}

struct CommitBoundaryPlatform<'a> {
    inner: Platform,
    interrupts: &'a Interrupts,
    waits: &'a Waits,
    accepted: AtomicBool,
}

impl<'a> CommitBoundaryPlatform<'a> {
    fn new(interrupts: &'a Interrupts, waits: &'a Waits) -> Self {
        Self {
            inner: Platform::new(),
            interrupts,
            waits,
            accepted: AtomicBool::new(false),
        }
    }
}

impl InterruptPlatform for CommitBoundaryPlatform<'_> {
    fn reserve_source(
        &self,
        source: u32,
    ) -> Result<super::interrupt::InterruptSourceReservation, InterruptPlatformError> {
        self.inner.reserve_source(source)
    }

    fn cancel_source(
        &self,
        reservation: super::interrupt::InterruptSourceReservation,
    ) -> Result<(), InterruptPlatformError> {
        self.inner.cancel_source(reservation)
    }

    fn commit_source(
        &self,
        reservation: super::interrupt::InterruptSourceReservation,
    ) -> InterruptBinding {
        let binding = self.inner.commit_source(reservation);
        let delivery = self.inner.prepare_delivery(binding).unwrap();
        let (accepted, _) = self.interrupts.deliver(delivery, self.waits);
        self.accepted.store(accepted, Ordering::Release);
        binding
    }

    fn mask_source(&self, binding: InterruptBinding) {
        self.inner.mask_source(binding);
    }

    fn acknowledge_source(
        &self,
        binding: InterruptBinding,
    ) -> Result<InterruptPlatformAck, InterruptPlatformError> {
        self.inner.acknowledge_source(binding)
    }

    fn complete_ack(&self, ack: InterruptPlatformAck, outcome: InterruptAckOutcome) {
        self.inner.complete_ack(ack, outcome);
    }

    fn release_source(&self, binding: InterruptBinding) {
        self.inner.release_source(binding);
    }
}

impl DeferredOncePlatform {
    fn new() -> Self {
        Self {
            inner: Platform::new(),
            defer: AtomicBool::new(true),
        }
    }
}

impl InterruptPlatform for DeferredOncePlatform {
    fn reserve_source(
        &self,
        source: u32,
    ) -> Result<super::interrupt::InterruptSourceReservation, InterruptPlatformError> {
        self.inner.reserve_source(source)
    }

    fn cancel_source(
        &self,
        reservation: super::interrupt::InterruptSourceReservation,
    ) -> Result<(), InterruptPlatformError> {
        self.inner.cancel_source(reservation)
    }

    fn commit_source(
        &self,
        reservation: super::interrupt::InterruptSourceReservation,
    ) -> InterruptBinding {
        self.inner.commit_source(reservation)
    }

    fn mask_source(&self, binding: InterruptBinding) {
        self.inner.mask_source(binding);
    }

    fn acknowledge_source(
        &self,
        binding: InterruptBinding,
    ) -> Result<InterruptPlatformAck, InterruptPlatformError> {
        self.inner.acknowledge_source(binding)
    }

    fn complete_ack(&self, ack: InterruptPlatformAck, outcome: InterruptAckOutcome) {
        self.inner.complete_ack(ack, outcome);
    }

    fn release_source(&self, binding: InterruptBinding) {
        self.inner.release_source(binding);
    }

    fn retire_source(&self, binding: InterruptBinding) -> super::interrupt::InterruptRetirement {
        if self.defer.swap(false, Ordering::AcqRel) {
            return super::interrupt::InterruptRetirement::Deferred;
        }
        self.inner.mask_source(binding);
        self.inner.release_source(binding);
        super::interrupt::InterruptRetirement::Complete
    }
}

struct Fixture {
    registry: Registry,
    resources: Resources,
    interrupts: Interrupts,
    platform: Platform,
    waits: Waits,
    table: Table,
    descriptor: DeviceResourceDescriptor,
    resource: DwHandle,
}

impl Fixture {
    fn new(resource_rights: DwRights) -> Self {
        let mut registry = Registry::new();
        let mut tasks = TaskAuthority::<2, 1, 1, 1>::new();
        let (domain, _owner) = tasks.create_root_group(&mut registry).unwrap();
        let descriptor = DeviceResourceDescriptor {
            resource_id: 1,
            lease_generation: 11,
            kind: DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
            pio_base: 0x2f8,
            pio_length: 8,
            interrupt_source: 3,
            resource_domain: domain,
        };
        let resources = Resources::new();
        let mut table = Table::new();
        let (_, resource) = resources
            .create(&mut registry, &mut table, descriptor, resource_rights)
            .unwrap();
        Self {
            registry,
            resources,
            interrupts: Interrupts::new(),
            platform: Platform::new(),
            waits: Waits::new(),
            table,
            descriptor,
            resource,
        }
    }

    fn broad() -> Self {
        Self::new(dw_object_compatible_rights(
            deepwyrm_abi::DW_OBJECT_TYPE_DEVICE_RESOURCE,
        ))
    }

    fn create_interrupt(&mut self) -> (InterruptKey, DwHandle) {
        interrupt_create(
            &mut self.table,
            &mut self.registry,
            &self.resources,
            &self.interrupts,
            &self.platform,
            self.resource,
            dw_object_compatible_rights(DW_OBJECT_TYPE_INTERRUPT),
        )
        .unwrap()
    }

    fn deliver(&self, binding: InterruptBinding) -> WakeBatch<8> {
        let delivery = self.platform.prepare_delivery(binding).unwrap();
        let (accepted, wakes) = self.interrupts.deliver(delivery, &self.waits);
        assert!(accepted);
        wakes
    }

    fn close_interrupt(&mut self, handle: DwHandle) -> Option<FinalRelease> {
        let final_release = self
            .table
            .close(&mut self.registry, handle)
            .unwrap()
            .unwrap();
        let finalization = self
            .interrupts
            .take_finalization(final_release, &self.platform)
            .unwrap();
        complete_interrupt_finalization(&mut self.registry, finalization)
    }

    fn finish_resource(&mut self, release: Option<FinalRelease>) {
        let release = match release {
            Some(release) => release,
            None => self
                .table
                .close(&mut self.registry, self.resource)
                .unwrap()
                .unwrap(),
        };
        let finalization = self.resources.take_finalization(release).unwrap();
        complete_device_resource_finalization(&mut self.registry, finalization);
    }
}

fn thread_and_wake(registry: &mut Registry) -> (ThreadKey, crate::task::BlockWakeKey) {
    let creation = registry
        .create(deepwyrm_abi::DW_OBJECT_TYPE_THREAD)
        .unwrap();
    let thread = ThreadKey::from_object_id(creation.id());
    registry.cancel_creation(creation).unwrap();
    let scheduler = CooperativeScheduler::<2>::new();
    let reservation = scheduler.reserve(thread).unwrap();
    scheduler.commit(reservation).unwrap();
    scheduler.schedule_next().unwrap();
    let (blocked, _) = scheduler.block_current(thread).unwrap();
    (thread, blocked.into_wake_key())
}

#[test]
fn creation_binds_exact_parent_source_and_immutable_info() {
    let mut fixture = Fixture::broad();
    let (key, handle) = fixture.create_interrupt();
    let binding = fixture.interrupts.binding(key);
    assert_eq!(binding.source(), fixture.descriptor.interrupt_source);
    assert_ne!(binding.generation(), 0);
    assert!(fixture.platform.is_bound(binding));
    assert!(!fixture.platform.is_masked(binding));

    let resolved = fixture
        .table
        .lookup(
            &mut fixture.registry,
            handle,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_INTERRUPT),
            DW_RIGHT_INSPECT,
        )
        .unwrap();
    let info = fixture
        .interrupts
        .object_info_for_resolved(&resolved)
        .unwrap();
    assert_eq!(info.source, fixture.descriptor.interrupt_source);
    assert_eq!(info.state, DW_INTERRUPT_STATE_ARMED);
    assert_eq!(info.object_generation, key.object_id().generation());
    assert_eq!(info.binding_generation, binding.generation());
    assert_eq!(info.parent_resource_id, fixture.descriptor.resource_id);
    assert_eq!(
        info.parent_lease_generation,
        fixture.descriptor.lease_generation
    );
    assert_eq!(info.flags.0, 0);
    assert!(
        fixture
            .registry
            .release_internal(resolved.into_internal())
            .unwrap()
            .is_none()
    );

    assert_eq!(
        crate::service::object_get_info_v1_with_tasks_and_device_objects(
            &fixture.table,
            &mut fixture.registry,
            &crate::memory::object::MemoryObjectAuthority::<1, 1>::new(),
            &TaskAuthority::<1, 1, 1, 12>::new(),
            &fixture.resources,
            &fixture.interrupts,
            handle,
            DW_OBJECT_INFO_INTERRUPT_V1,
        ),
        Ok(crate::service::ObjectInfoResult::Interrupt(info))
    );

    assert!(fixture.close_interrupt(handle).is_none());
    fixture.finish_resource(None);
}

#[test]
fn delivery_at_platform_commit_boundary_observes_typed_armed_state() {
    let mut fixture = Fixture::broad();
    let platform = CommitBoundaryPlatform::new(&fixture.interrupts, &fixture.waits);
    let (key, handle) = interrupt_create(
        &mut fixture.table,
        &mut fixture.registry,
        &fixture.resources,
        &fixture.interrupts,
        &platform,
        fixture.resource,
        dw_object_compatible_rights(DW_OBJECT_TYPE_INTERRUPT),
    )
    .unwrap();
    assert!(platform.accepted.load(Ordering::Acquire));
    let binding = fixture.interrupts.binding(key);
    let resolved = fixture
        .table
        .lookup(
            &mut fixture.registry,
            handle,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_INTERRUPT),
            DW_RIGHT_INSPECT,
        )
        .unwrap();
    assert_eq!(
        fixture
            .interrupts
            .current_signals_for_resolved(&resolved)
            .unwrap(),
        DW_SIGNAL_SIGNALED
    );
    assert!(
        fixture
            .registry
            .release_internal(resolved.into_internal())
            .unwrap()
            .is_none()
    );
    let final_release = fixture
        .table
        .close(&mut fixture.registry, handle)
        .unwrap()
        .unwrap();
    let finalization = fixture
        .interrupts
        .take_finalization(final_release, &platform)
        .unwrap();
    assert!(complete_interrupt_finalization(&mut fixture.registry, finalization).is_none());
    assert!(!platform.inner.is_bound(binding));
    fixture.finish_resource(None);
}

#[test]
fn creation_rejects_rights_and_duplicate_source_without_leaks() {
    let mut reduced = Fixture::new(DwRights(DW_RIGHT_READ.0 | DW_RIGHT_INSPECT.0));
    assert_eq!(
        interrupt_create(
            &mut reduced.table,
            &mut reduced.registry,
            &reduced.resources,
            &reduced.interrupts,
            &reduced.platform,
            reduced.resource,
            dw_object_compatible_rights(DW_OBJECT_TYPE_INTERRUPT),
        ),
        Err(InterruptCreateError::Handle(HandleTableError::AccessDenied))
    );
    assert_eq!(reduced.interrupts.live_count(), 0);
    reduced.finish_resource(None);

    let mut fixture = Fixture::broad();
    assert!(matches!(
        interrupt_create(
            &mut fixture.table,
            &mut fixture.registry,
            &fixture.resources,
            &fixture.interrupts,
            &fixture.platform,
            fixture.resource,
            DwRights(0),
        ),
        Err(InterruptCreateError::Interrupt(
            InterruptError::InvalidRights
        ))
    ));
    let (_first_key, first) = fixture.create_interrupt();
    assert!(matches!(
        interrupt_create(
            &mut fixture.table,
            &mut fixture.registry,
            &fixture.resources,
            &fixture.interrupts,
            &fixture.platform,
            fixture.resource,
            dw_object_compatible_rights(DW_OBJECT_TYPE_INTERRUPT),
        ),
        Err(InterruptCreateError::Interrupt(InterruptError::Platform(
            InterruptPlatformError::SourceInUse
        )))
    ));
    assert_eq!(fixture.interrupts.live_count(), 1);
    assert!(fixture.close_interrupt(first).is_none());
    fixture.finish_resource(None);
}

#[test]
fn delivery_is_level_signaled_and_coalesces_without_counter_growth() {
    let mut fixture = Fixture::broad();
    let (key, handle) = fixture.create_interrupt();
    let binding = fixture.interrupts.binding(key);
    assert_eq!(fixture.deliver(binding).len(), 0);
    for _ in 0..64 {
        assert_eq!(fixture.deliver(binding).len(), 0);
    }
    let resolved = fixture
        .table
        .lookup(
            &mut fixture.registry,
            handle,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_INTERRUPT),
            DW_RIGHT_INSPECT,
        )
        .unwrap();
    let info = fixture
        .interrupts
        .object_info_for_resolved(&resolved)
        .unwrap();
    assert_eq!(info.state, DW_INTERRUPT_STATE_PENDING);
    assert_eq!(info.flags, DW_INTERRUPT_INFO_FLAG_COALESCED);
    assert_eq!(
        crate::wait::current_signals_for(
            &TaskAuthority::<1, 1, 1, 1>::new(),
            &crate::wait::EventAuthority::<1>::new(),
            &crate::time::TimerAuthority::<1>::new(),
            &crate::ipc::ChannelAuthority::<1, 1>::new(),
            Some(&fixture.interrupts),
            &resolved,
        ),
        Ok(DW_SIGNAL_SIGNALED)
    );
    assert!(
        fixture
            .registry
            .release_internal(resolved.into_internal())
            .unwrap()
            .is_none()
    );
    assert!(fixture.platform.is_masked(binding));
    assert!(fixture.close_interrupt(handle).is_none());
    fixture.finish_resource(None);
}

#[test]
fn ready_and_blocked_waits_observe_exact_signaled_level() {
    let mut fixture = Fixture::broad();
    let (key, handle) = fixture.create_interrupt();
    let binding = fixture.interrupts.binding(key);
    let (thread, wake) = thread_and_wake(&mut fixture.registry);
    let target = fixture
        .table
        .lookup(
            &mut fixture.registry,
            handle,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_INTERRUPT),
            DW_RIGHT_WAIT,
        )
        .unwrap();
    assert!(matches!(
        fixture
            .interrupts
            .register_wait(&fixture.waits, target, DW_SIGNAL_SIGNALED, 4, thread, wake)
            .unwrap(),
        InterruptWaitOutcome::Registered(_)
    ));
    let wakes = fixture.deliver(binding);
    assert_eq!(wakes.len(), 1);
    assert_eq!(wakes.pin_len(), 0);
    let (intents, pins) = wakes.into_parts();
    assert!(pins.into_iter().flatten().next().is_none());
    let intent = intents.into_iter().flatten().next().unwrap();
    assert_eq!(intent.observed(), DW_SIGNAL_SIGNALED);
    assert_eq!(intent.item_index(), 4);

    let target = fixture
        .table
        .lookup(
            &mut fixture.registry,
            handle,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_INTERRUPT),
            DW_RIGHT_WAIT,
        )
        .unwrap();
    match fixture
        .interrupts
        .register_wait(&fixture.waits, target, DW_SIGNAL_SIGNALED, 0, thread, wake)
        .unwrap()
    {
        InterruptWaitOutcome::Ready { observed, pin } => {
            assert_eq!(observed, DW_SIGNAL_SIGNALED);
            assert!(fixture.registry.release_internal(pin).unwrap().is_none());
        }
        InterruptWaitOutcome::Registered(_) => panic!("pending Interrupt must be ready"),
    }

    let (_, pins) = fixture.waits.cancel_generation(wake).into_parts();
    for pin in pins.into_iter().flatten() {
        assert!(fixture.registry.release_internal(pin).unwrap().is_none());
    }
    assert!(fixture.close_interrupt(handle).is_none());
    fixture.finish_resource(None);
}

#[test]
fn ack_requires_modify_and_pending_close_releases_the_source() {
    let mut fixture = Fixture::broad();
    let (key, handle) = interrupt_create(
        &mut fixture.table,
        &mut fixture.registry,
        &fixture.resources,
        &fixture.interrupts,
        &fixture.platform,
        fixture.resource,
        DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0),
    )
    .unwrap();
    let binding = fixture.interrupts.binding(key);
    assert_eq!(fixture.deliver(binding).len(), 0);
    assert_eq!(
        interrupt_ack(
            &fixture.table,
            &mut fixture.registry,
            &fixture.interrupts,
            &fixture.platform,
            handle,
        ),
        Err(DW_STATUS_ACCESS_DENIED)
    );
    assert!(fixture.close_interrupt(handle).is_none());
    assert!(!fixture.platform.is_bound(binding));
    fixture.finish_resource(None);
}

#[test]
fn ack_consumes_coalesced_fact_then_rearms_and_rejects_empty_state() {
    let mut fixture = Fixture::broad();
    let (key, handle) = fixture.create_interrupt();
    let binding = fixture.interrupts.binding(key);
    assert_eq!(fixture.deliver(binding).len(), 0);
    assert_eq!(fixture.deliver(binding).len(), 0);

    assert_eq!(
        interrupt_ack(
            &fixture.table,
            &mut fixture.registry,
            &fixture.interrupts,
            &fixture.platform,
            handle,
        ),
        Ok(None)
    );
    assert!(fixture.platform.is_masked(binding));
    assert_eq!(
        interrupt_ack(
            &fixture.table,
            &mut fixture.registry,
            &fixture.interrupts,
            &fixture.platform,
            handle,
        ),
        Ok(None)
    );
    assert!(!fixture.platform.is_masked(binding));
    assert_eq!(
        interrupt_ack(
            &fixture.table,
            &mut fixture.registry,
            &fixture.interrupts,
            &fixture.platform,
            handle,
        ),
        Err(DW_STATUS_BAD_STATE)
    );
    assert!(fixture.close_interrupt(handle).is_none());
    fixture.finish_resource(None);
}

#[test]
fn delivery_racing_prepared_ack_survives_and_source_remains_masked() {
    let mut fixture = Fixture::broad();
    let (key, handle) = fixture.create_interrupt();
    let binding = fixture.interrupts.binding(key);
    assert_eq!(fixture.deliver(binding).len(), 0);
    let transaction = prepare_interrupt_ack(
        &fixture.table,
        &mut fixture.registry,
        &fixture.interrupts,
        handle,
    )
    .unwrap();
    assert_eq!(transaction.binding_for_evidence(), Some(binding));
    assert_eq!(fixture.deliver(binding).len(), 0);
    assert_eq!(
        transaction.complete(
            &mut fixture.registry,
            &fixture.interrupts,
            &fixture.platform,
        ),
        Ok(None)
    );
    assert!(fixture.platform.is_masked(binding));

    let resolved = fixture
        .table
        .lookup(
            &mut fixture.registry,
            handle,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_INTERRUPT),
            DW_RIGHT_INSPECT,
        )
        .unwrap();
    assert_eq!(
        fixture
            .interrupts
            .current_signals_for_resolved(&resolved)
            .unwrap(),
        DW_SIGNAL_SIGNALED
    );
    assert!(
        fixture
            .registry
            .release_internal(resolved.into_internal())
            .unwrap()
            .is_none()
    );
    assert!(fixture.close_interrupt(handle).is_none());
    fixture.finish_resource(None);
}

#[test]
fn waiter_and_ack_pins_defer_finalization_until_exact_release() {
    let mut fixture = Fixture::broad();
    let (key, handle) = fixture.create_interrupt();
    let binding = fixture.interrupts.binding(key);
    let (thread, wake) = thread_and_wake(&mut fixture.registry);
    let target = fixture
        .table
        .lookup(
            &mut fixture.registry,
            handle,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_INTERRUPT),
            DW_RIGHT_WAIT,
        )
        .unwrap();
    assert!(matches!(
        fixture
            .interrupts
            .register_wait(&fixture.waits, target, DW_SIGNAL_SIGNALED, 0, thread, wake)
            .unwrap(),
        InterruptWaitOutcome::Registered(_)
    ));
    assert!(
        fixture
            .table
            .close(&mut fixture.registry, handle)
            .unwrap()
            .is_none()
    );
    assert!(fixture.platform.is_bound(binding));
    let (_, pins) = fixture.waits.cancel_generation(wake).into_parts();
    let final_release = fixture
        .registry
        .release_internal(pins.into_iter().flatten().next().unwrap())
        .unwrap()
        .unwrap();
    let finalization = fixture
        .interrupts
        .take_finalization(final_release, &fixture.platform)
        .unwrap();
    assert!(complete_interrupt_finalization(&mut fixture.registry, finalization).is_none());
    assert!(!fixture.platform.is_bound(binding));

    let (key, handle) = fixture.create_interrupt();
    let binding = fixture.interrupts.binding(key);
    assert_eq!(fixture.deliver(binding).len(), 0);
    let transaction = prepare_interrupt_ack(
        &fixture.table,
        &mut fixture.registry,
        &fixture.interrupts,
        handle,
    )
    .unwrap();
    assert!(
        fixture
            .table
            .close(&mut fixture.registry, handle)
            .unwrap()
            .is_none()
    );
    let final_release = transaction
        .complete(
            &mut fixture.registry,
            &fixture.interrupts,
            &fixture.platform,
        )
        .unwrap()
        .unwrap();
    let finalization = fixture
        .interrupts
        .take_finalization(final_release, &fixture.platform)
        .unwrap();
    assert!(complete_interrupt_finalization(&mut fixture.registry, finalization).is_none());
    fixture.finish_resource(None);
}

#[test]
fn parent_resource_finalizes_only_after_interrupt_unbind() {
    let mut fixture = Fixture::broad();
    let (key, handle) = fixture.create_interrupt();
    let binding = fixture.interrupts.binding(key);
    assert!(
        fixture
            .table
            .close(&mut fixture.registry, fixture.resource)
            .unwrap()
            .is_none()
    );
    let parent_release = fixture.close_interrupt(handle).unwrap();
    assert!(!fixture.platform.is_bound(binding));
    fixture.finish_resource(Some(parent_release));
}

#[test]
fn deferred_retirement_retains_final_release_and_parent_until_safe_point_retry() {
    let mut fixture = Fixture::broad();
    let platform = DeferredOncePlatform::new();
    let (key, handle) = interrupt_create(
        &mut fixture.table,
        &mut fixture.registry,
        &fixture.resources,
        &fixture.interrupts,
        &platform,
        fixture.resource,
        dw_object_compatible_rights(DW_OBJECT_TYPE_INTERRUPT),
    )
    .unwrap();
    let binding = fixture.interrupts.binding(key);
    let final_release = fixture
        .table
        .close(&mut fixture.registry, handle)
        .unwrap()
        .unwrap();
    let staged = fixture
        .interrupts
        .take_finalization(final_release, &platform)
        .unwrap();
    assert!(complete_interrupt_finalization(&mut fixture.registry, staged).is_none());
    assert!(platform.inner.is_bound(binding));
    assert_eq!(fixture.interrupts.live_count(), 1);

    let ready = fixture
        .interrupts
        .retry_deferred_finalization(&platform)
        .expect("safe-point retry completes the exact staged generation");
    assert!(complete_interrupt_finalization(&mut fixture.registry, ready).is_none());
    assert!(!platform.inner.is_bound(binding));
    assert_eq!(fixture.interrupts.live_count(), 0);
    fixture.finish_resource(None);
}

#[test]
fn stale_handle_and_late_old_delivery_cannot_mutate_reused_source() {
    let mut fixture = Fixture::broad();
    let (old_key, old_handle) = fixture.create_interrupt();
    let old_binding = fixture.interrupts.binding(old_key);
    let late_old_delivery = fixture.platform.prepare_delivery(old_binding).unwrap();
    assert!(fixture.close_interrupt(old_handle).is_none());

    let (new_key, new_handle) = fixture.create_interrupt();
    let new_binding = fixture.interrupts.binding(new_key);
    assert_ne!(new_binding.generation(), old_binding.generation());
    let (accepted, wakes) = fixture
        .interrupts
        .deliver(late_old_delivery, &fixture.waits);
    assert!(!accepted);
    assert_eq!(wakes.len(), 0);
    assert!(!fixture.platform.is_masked(new_binding));
    assert_eq!(
        interrupt_ack(
            &fixture.table,
            &mut fixture.registry,
            &fixture.interrupts,
            &fixture.platform,
            old_handle,
        ),
        Err(DW_STATUS_BAD_HANDLE)
    );
    assert!(fixture.close_interrupt(new_handle).is_none());
    fixture.finish_resource(None);
}

#[test]
fn interrupt_rights_are_nonduplicable_and_move_reduction_rolls_back_exactly() {
    let mut fixture = Fixture::broad();
    let (_key, handle) = fixture.create_interrupt();
    assert_eq!(
        fixture.table.duplicate(
            &mut fixture.registry,
            handle,
            DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0),
        ),
        Err(HandleTableError::AccessDenied)
    );
    let prepared = fixture
        .table
        .prepare_move_batch(&[crate::handle::HandleMoveRequest {
            handle,
            requested_rights: DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0),
        }])
        .unwrap();
    let (rollback, transfers) = prepared.extract();
    assert_eq!(transfers.len(), 1);
    rollback.rollback(transfers);
    assert!(fixture.close_interrupt(handle).is_none());
    fixture.finish_resource(None);
}
