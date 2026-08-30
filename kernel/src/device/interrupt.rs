use core::sync::atomic::{AtomicU64, Ordering};

use deepwyrm_abi::{
    DW_INTERRUPT_INFO_FLAG_COALESCED, DW_INTERRUPT_INFO_V1_SIZE, DW_INTERRUPT_INFO_V1_VERSION,
    DW_INTERRUPT_STATE_ARMED, DW_INTERRUPT_STATE_FINALIZING, DW_INTERRUPT_STATE_PENDING,
    DW_OBJECT_TYPE_DEVICE_RESOURCE, DW_OBJECT_TYPE_INTERRUPT, DW_RIGHT_MODIFY, DW_RIGHT_WAIT,
    DW_SIGNAL_SIGNALED, DW_STATUS_ACCESS_DENIED, DW_STATUS_ALREADY_EXISTS, DW_STATUS_BAD_HANDLE,
    DW_STATUS_BAD_STATE, DW_STATUS_INVALID_ARGUMENT, DW_STATUS_NO_RESOURCES,
    DW_STATUS_WRONG_OBJECT_TYPE, DwHandle, DwInterruptInfoFlags, DwInterruptInfoV1, DwRights,
    DwSignals, DwStatus, dw_rights_are_compatible,
};

use crate::handle::{
    AcceptedObjectTypes, HandleReservationError, HandleTable, HandleTableError, ResolvedHandle,
};
use crate::object::{
    CreationRef, FinalRelease, InternalRef, ObjectId, ObjectRegistry, ObjectRegistryError,
};
use crate::sync::IrqSpinMutex;
use crate::task::{BlockWakeKey, ThreadKey};
use crate::wait::{WaitError, WaitRegistration, WaitRegistrationSink, WakeBatch};

use super::{DeviceResourceAuthority, DeviceResourceDescriptor, DeviceResourceError};

static NEXT_PLATFORM_DOMAIN: AtomicU64 = AtomicU64::new(1);

fn mint_platform_domain() -> u64 {
    NEXT_PLATFORM_DOMAIN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |domain| {
            domain.checked_add(1).filter(|next| *next != 0)
        })
        .expect("synthetic Interrupt platform-domain space exhausted")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InterruptBinding {
    domain: u64,
    source: u32,
    generation: u64,
}

impl InterruptBinding {
    pub(crate) const fn source(self) -> u32 {
        self.source
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }

    #[cfg(test)]
    pub(crate) const fn for_test(domain: u64, source: u32, generation: u64) -> Self {
        Self {
            domain,
            source,
            generation,
        }
    }
}

#[must_use = "reserved Interrupt sources must be committed or cancelled"]
pub(crate) struct InterruptSourceReservation {
    binding: InterruptBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InterruptDelivery {
    binding: InterruptBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InterruptPlatformError {
    Capacity,
    SourceInUse,
    InvalidSource,
    StaleBinding,
    BadState,
}

pub(crate) trait InterruptPlatform {
    fn reserve_source(
        &self,
        source: u32,
    ) -> Result<InterruptSourceReservation, InterruptPlatformError>;

    fn cancel_source(
        &self,
        reservation: InterruptSourceReservation,
    ) -> Result<(), InterruptPlatformError>;

    /// Commits an exact live reservation at the creation transaction's
    /// no-fail point. Platform implementations must treat drift as a kernel
    /// invariant violation, not a recoverable device error.
    fn commit_source(&self, reservation: InterruptSourceReservation) -> InterruptBinding;

    /// Masks an exact owned source during rollback/finalization. Once the
    /// binding is retained by an Interrupt payload this operation is no-fail.
    fn mask_source(&self, binding: InterruptBinding);

    fn acknowledge_source(&self, binding: InterruptBinding) -> Result<(), InterruptPlatformError>;

    fn unmask_or_rearm(&self, binding: InterruptBinding) -> Result<(), InterruptPlatformError>;

    /// Releases an exact masked source at the final no-fail ownership point.
    fn release_source(&self, binding: InterruptBinding);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlatformSourceState {
    Reserved,
    Armed,
    Masked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PlatformSourceRecord {
    source: u32,
    generation: u64,
    state: PlatformSourceState,
}

struct PlatformSourceSlot {
    generation: u64,
    record: Option<PlatformSourceRecord>,
}

/// Bounded synthetic source owner used by D3 host/model semantics.
///
/// This authority performs no architecture-controller access. DW1-E may
/// implement the same narrow platform trait for q35 routing after its own
/// vector/controller contract is reached.
pub(crate) struct InterruptPlatformModel<const SOURCES: usize> {
    domain: u64,
    sources: IrqSpinMutex<[PlatformSourceSlot; SOURCES]>,
}

impl<const SOURCES: usize> InterruptPlatformModel<SOURCES> {
    pub(crate) fn new() -> Self {
        Self {
            domain: mint_platform_domain(),
            sources: IrqSpinMutex::new(core::array::from_fn(|_| PlatformSourceSlot {
                generation: 0,
                record: None,
            })),
        }
    }

    pub(crate) fn prepare_delivery(
        &self,
        binding: InterruptBinding,
    ) -> Result<InterruptDelivery, InterruptPlatformError> {
        let mut slots = self.sources.lock();
        let record = exact_platform_record_mut(self.domain, &mut slots, binding)?;
        match record.state {
            PlatformSourceState::Armed => record.state = PlatformSourceState::Masked,
            PlatformSourceState::Masked => {}
            PlatformSourceState::Reserved => return Err(InterruptPlatformError::BadState),
        }
        Ok(InterruptDelivery { binding })
    }

    #[cfg(test)]
    pub(crate) fn is_bound(&self, binding: InterruptBinding) -> bool {
        let mut slots = self.sources.lock();
        exact_platform_record_mut(self.domain, &mut slots, binding).is_ok()
    }

    #[cfg(test)]
    pub(crate) fn is_masked(&self, binding: InterruptBinding) -> bool {
        let mut slots = self.sources.lock();
        exact_platform_record_mut(self.domain, &mut slots, binding)
            .is_ok_and(|record| record.state == PlatformSourceState::Masked)
    }
}

impl<const SOURCES: usize> InterruptPlatform for InterruptPlatformModel<SOURCES> {
    fn reserve_source(
        &self,
        source: u32,
    ) -> Result<InterruptSourceReservation, InterruptPlatformError> {
        if source == 0 || source == 4 {
            return Err(InterruptPlatformError::InvalidSource);
        }
        let mut slots = self.sources.lock();
        if slots
            .iter()
            .any(|slot| slot.record.is_some_and(|record| record.source == source))
        {
            return Err(InterruptPlatformError::SourceInUse);
        }
        let Some(slot) = slots
            .iter_mut()
            .find(|slot| slot.record.is_none() && slot.generation != u64::MAX)
        else {
            return Err(InterruptPlatformError::Capacity);
        };
        let generation = slot
            .generation
            .checked_add(1)
            .filter(|generation| *generation != 0)
            .ok_or(InterruptPlatformError::Capacity)?;
        slot.generation = generation;
        slot.record = Some(PlatformSourceRecord {
            source,
            generation,
            state: PlatformSourceState::Reserved,
        });
        Ok(InterruptSourceReservation {
            binding: InterruptBinding {
                domain: self.domain,
                source,
                generation,
            },
        })
    }

    fn cancel_source(
        &self,
        reservation: InterruptSourceReservation,
    ) -> Result<(), InterruptPlatformError> {
        let mut slots = self.sources.lock();
        let slot = exact_platform_slot_mut(self.domain, &mut slots, reservation.binding)?;
        if !slot
            .record
            .is_some_and(|record| record.state == PlatformSourceState::Reserved)
        {
            return Err(InterruptPlatformError::BadState);
        }
        slot.record = None;
        Ok(())
    }

    fn commit_source(&self, reservation: InterruptSourceReservation) -> InterruptBinding {
        let mut slots = self.sources.lock();
        let record = exact_platform_record_mut(self.domain, &mut slots, reservation.binding)
            .expect("committed Interrupt source reservation remains exact");
        assert_eq!(record.state, PlatformSourceState::Reserved);
        record.state = PlatformSourceState::Armed;
        reservation.binding
    }

    fn mask_source(&self, binding: InterruptBinding) {
        let mut slots = self.sources.lock();
        let record = exact_platform_record_mut(self.domain, &mut slots, binding)
            .expect("owned Interrupt source remains exact while masking");
        match record.state {
            PlatformSourceState::Armed => record.state = PlatformSourceState::Masked,
            PlatformSourceState::Masked => {}
            PlatformSourceState::Reserved => {
                panic!("uncommitted Interrupt source reached no-fail mask")
            }
        }
    }

    fn acknowledge_source(&self, binding: InterruptBinding) -> Result<(), InterruptPlatformError> {
        let mut slots = self.sources.lock();
        let record = exact_platform_record_mut(self.domain, &mut slots, binding)?;
        if record.state != PlatformSourceState::Masked {
            return Err(InterruptPlatformError::BadState);
        }
        Ok(())
    }

    fn unmask_or_rearm(&self, binding: InterruptBinding) -> Result<(), InterruptPlatformError> {
        let mut slots = self.sources.lock();
        let record = exact_platform_record_mut(self.domain, &mut slots, binding)?;
        if record.state != PlatformSourceState::Masked {
            return Err(InterruptPlatformError::BadState);
        }
        record.state = PlatformSourceState::Armed;
        Ok(())
    }

    fn release_source(&self, binding: InterruptBinding) {
        let mut slots = self.sources.lock();
        let slot = exact_platform_slot_mut(self.domain, &mut slots, binding)
            .expect("owned Interrupt source remains exact while releasing");
        assert!(
            slot.record
                .is_some_and(|record| record.state == PlatformSourceState::Masked),
            "Interrupt source release requires exact masked state"
        );
        slot.record = None;
    }
}

fn exact_platform_slot_mut<const SOURCES: usize>(
    domain: u64,
    slots: &mut [PlatformSourceSlot; SOURCES],
    binding: InterruptBinding,
) -> Result<&mut PlatformSourceSlot, InterruptPlatformError> {
    if binding.domain != domain {
        return Err(InterruptPlatformError::StaleBinding);
    }
    slots
        .iter_mut()
        .find(|slot| {
            slot.record.is_some_and(|record| {
                record.source == binding.source && record.generation == binding.generation
            })
        })
        .ok_or(InterruptPlatformError::StaleBinding)
}

fn exact_platform_record_mut<const SOURCES: usize>(
    domain: u64,
    slots: &mut [PlatformSourceSlot; SOURCES],
    binding: InterruptBinding,
) -> Result<&mut PlatformSourceRecord, InterruptPlatformError> {
    exact_platform_slot_mut(domain, slots, binding)?
        .record
        .as_mut()
        .ok_or(InterruptPlatformError::StaleBinding)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InterruptKey(ObjectId);

impl InterruptKey {
    pub(crate) const fn from_object_id(object: ObjectId) -> Self {
        Self(object)
    }

    pub(crate) const fn object_id(self) -> ObjectId {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InterruptError {
    Capacity,
    InvalidObject,
    InvalidRights,
    IdentityInUse,
    BadState,
    FinalizationMismatch,
    Platform(InterruptPlatformError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InterruptCreateError {
    Handle(HandleTableError),
    Registry(ObjectRegistryError),
    Interrupt(InterruptError),
    Publication(HandleReservationError),
}

#[must_use = "typed Interrupt bindings must be sealed before publication"]
pub(crate) struct InterruptPayloadBinding {
    creation: CreationRef,
    key: InterruptKey,
}

impl InterruptPayloadBinding {
    pub(crate) const fn key(&self) -> InterruptKey {
        self.key
    }

    pub(crate) fn into_creation(self) -> CreationRef {
        self.creation
    }
}

#[must_use = "typed Interrupt cleanup must be consumed by ObjectRegistry"]
pub(crate) struct InterruptCleanup {
    final_release: FinalRelease,
}

impl InterruptCleanup {
    pub(crate) fn into_final_release(self) -> FinalRelease {
        self.final_release
    }
}

pub(crate) struct InterruptFinalization {
    final_release: FinalRelease,
    parent: InternalRef,
    #[cfg(deepwyrm_dw1d_evidence)]
    binding: InterruptBinding,
    #[cfg(deepwyrm_dw1d_evidence)]
    parent_descriptor: DeviceResourceDescriptor,
}

impl InterruptFinalization {
    #[cfg(deepwyrm_dw1d_evidence)]
    pub(crate) const fn dw1d_identity(&self) -> (ObjectId, InterruptBinding, u64) {
        (
            self.final_release.id(),
            self.binding,
            self.parent_descriptor.lease_generation,
        )
    }
}

#[derive(Debug)]
enum InterruptState {
    Creating,
    Armed,
    Pending { coalesced: bool },
    AckPrepared { raced_delivery: bool },
    Finalizing,
}

struct InterruptRecord {
    object: ObjectId,
    binding: InterruptBinding,
    parent_descriptor: DeviceResourceDescriptor,
    parent: InternalRef,
    state: InterruptState,
}

pub(crate) trait InterruptInfoProvider {
    fn object_info_for_resolved(
        &self,
        resolved: &ResolvedHandle,
    ) -> Result<DwInterruptInfoV1, InterruptError>;
}

pub(crate) trait InterruptWaitSource {
    fn current_signals_for_resolved(
        &self,
        resolved: &ResolvedHandle,
    ) -> Result<DwSignals, InterruptError>;

    fn register_wait(
        &self,
        waits: &dyn WaitRegistrationSink,
        target: ResolvedHandle,
        desired: DwSignals,
        item_index: u32,
        thread: ThreadKey,
        wake: BlockWakeKey,
    ) -> Result<InterruptWaitOutcome, InterruptWaitFailure>;
}

pub(crate) trait InterruptFinalizer {
    fn take_finalization(
        &self,
        final_release: FinalRelease,
        platform: &dyn InterruptPlatform,
    ) -> Result<InterruptFinalization, (InterruptError, FinalRelease)>;
}

pub(crate) struct InterruptAuthority<const INTERRUPTS: usize> {
    interrupts: IrqSpinMutex<[Option<InterruptRecord>; INTERRUPTS]>,
}

impl<const INTERRUPTS: usize> InterruptAuthority<INTERRUPTS> {
    pub(crate) fn new() -> Self {
        Self {
            interrupts: IrqSpinMutex::new(core::array::from_fn(|_| None)),
        }
    }

    fn bind(
        &self,
        creation: CreationRef,
        parent_descriptor: DeviceResourceDescriptor,
        parent: InternalRef,
        binding: InterruptBinding,
    ) -> Result<InterruptPayloadBinding, (InterruptError, CreationRef, InternalRef)> {
        if creation.object_type() != DW_OBJECT_TYPE_INTERRUPT
            || parent.object_type() != DW_OBJECT_TYPE_DEVICE_RESOURCE
        {
            return Err((InterruptError::InvalidObject, creation, parent));
        }
        let key = InterruptKey::from_object_id(creation.id());
        let mut interrupts = self.interrupts.lock();
        if interrupts.iter().flatten().any(|interrupt| {
            interrupt.object == key.object_id()
                || interrupt.binding.source == binding.source
                || interrupt.binding == binding
        }) {
            return Err((InterruptError::IdentityInUse, creation, parent));
        }
        let Some(slot) = interrupts.iter_mut().find(|slot| slot.is_none()) else {
            return Err((InterruptError::Capacity, creation, parent));
        };
        *slot = Some(InterruptRecord {
            object: key.object_id(),
            binding,
            parent_descriptor,
            parent,
            state: InterruptState::Creating,
        });
        Ok(InterruptPayloadBinding { creation, key })
    }

    fn commit_armed(&self, key: InterruptKey, binding: InterruptBinding) {
        let mut interrupts = self.interrupts.lock();
        let interrupt = exact_interrupt_mut(&mut interrupts, key.object_id(), binding)
            .expect("fresh Interrupt binding remains present until Armed commit");
        assert!(matches!(interrupt.state, InterruptState::Creating));
        interrupt.state = InterruptState::Armed;
    }

    fn cancel_unpublished(
        &self,
        final_release: FinalRelease,
    ) -> Result<(InterruptCleanup, InternalRef), (InterruptError, FinalRelease)> {
        if final_release.object_type() != DW_OBJECT_TYPE_INTERRUPT {
            return Err((InterruptError::FinalizationMismatch, final_release));
        }
        let mut interrupts = self.interrupts.lock();
        let Some(slot) = interrupts.iter_mut().find(|slot| {
            slot.as_ref().is_some_and(|interrupt| {
                interrupt.object == final_release.id()
                    && matches!(
                        interrupt.state,
                        InterruptState::Creating | InterruptState::Armed
                    )
            })
        }) else {
            return Err((InterruptError::FinalizationMismatch, final_release));
        };
        let interrupt = slot
            .take()
            .expect("validated unpublished Interrupt slot remains populated");
        Ok((InterruptCleanup { final_release }, interrupt.parent))
    }

    pub(crate) fn deliver<const WAITERS: usize>(
        &self,
        delivery: InterruptDelivery,
        waits: &crate::wait::WaitRegistry<WAITERS>,
    ) -> (bool, WakeBatch<WAITERS>) {
        let object = {
            let mut interrupts = self.interrupts.lock();
            let Some(interrupt) = interrupts.iter_mut().flatten().find(|interrupt| {
                interrupt.binding == delivery.binding
                    && !matches!(
                        interrupt.state,
                        InterruptState::Creating | InterruptState::Finalizing
                    )
            }) else {
                return (false, WakeBatch::empty());
            };
            match &mut interrupt.state {
                InterruptState::Armed => {
                    interrupt.state = InterruptState::Pending { coalesced: false };
                }
                InterruptState::Pending { coalesced } => *coalesced = true,
                InterruptState::AckPrepared { raced_delivery } => *raced_delivery = true,
                InterruptState::Creating | InterruptState::Finalizing => unreachable!(),
            }
            interrupt.object
        };
        (true, waits.ready_wakes(object, DW_SIGNAL_SIGNALED))
    }

    fn prepare_ack_for_resolved(
        &self,
        resolved: ResolvedHandle,
    ) -> Result<InterruptAckTransaction, (InterruptError, InternalRef)> {
        if resolved.object_type() != DW_OBJECT_TYPE_INTERRUPT {
            return Err((InterruptError::InvalidObject, resolved.into_internal()));
        }
        let object = resolved.object_id();
        let pin = resolved.into_internal();
        let mut interrupts = self.interrupts.lock();
        let Some(interrupt) = interrupts
            .iter_mut()
            .flatten()
            .find(|interrupt| interrupt.object == object)
        else {
            return Err((InterruptError::InvalidObject, pin));
        };
        match interrupt.state {
            InterruptState::Armed => Err((InterruptError::BadState, pin)),
            InterruptState::Pending { coalesced: true } => {
                interrupt.state = InterruptState::Pending { coalesced: false };
                Ok(InterruptAckTransaction {
                    operation: InterruptAckOperation::Coalesced,
                    pin,
                })
            }
            InterruptState::Pending { coalesced: false } => {
                interrupt.state = InterruptState::AckPrepared {
                    raced_delivery: false,
                };
                Ok(InterruptAckTransaction {
                    operation: InterruptAckOperation::Rearm {
                        object,
                        binding: interrupt.binding,
                    },
                    pin,
                })
            }
            InterruptState::AckPrepared { .. }
            | InterruptState::Creating
            | InterruptState::Finalizing => Err((InterruptError::BadState, pin)),
        }
    }

    fn finish_ack(&self, object: ObjectId, binding: InterruptBinding) {
        let mut interrupts = self.interrupts.lock();
        let interrupt = exact_interrupt_mut(&mut interrupts, object, binding)
            .expect("ack transaction retained exact Interrupt lifetime");
        let InterruptState::AckPrepared { raced_delivery } = interrupt.state else {
            panic!("ack transaction lost its prepared typed state");
        };
        interrupt.state = if raced_delivery {
            InterruptState::Pending { coalesced: false }
        } else {
            InterruptState::Armed
        };
    }

    fn restore_pending_after_platform_failure(&self, object: ObjectId, binding: InterruptBinding) {
        let mut interrupts = self.interrupts.lock();
        let interrupt = exact_interrupt_mut(&mut interrupts, object, binding)
            .expect("failed ack transaction retained exact Interrupt lifetime");
        if matches!(interrupt.state, InterruptState::AckPrepared { .. }) {
            interrupt.state = InterruptState::Pending { coalesced: false };
        }
    }

    fn info_for_resolved(
        &self,
        resolved: &ResolvedHandle,
    ) -> Result<DwInterruptInfoV1, InterruptError> {
        if resolved.object_type() != DW_OBJECT_TYPE_INTERRUPT {
            return Err(InterruptError::InvalidObject);
        }
        let interrupts = self.interrupts.lock();
        let interrupt = interrupts
            .iter()
            .flatten()
            .find(|interrupt| interrupt.object == resolved.object_id())
            .ok_or(InterruptError::InvalidObject)?;
        let (state, flags) = public_state(&interrupt.state);
        Ok(DwInterruptInfoV1 {
            size: DW_INTERRUPT_INFO_V1_SIZE,
            version: DW_INTERRUPT_INFO_V1_VERSION,
            source: interrupt.binding.source,
            state,
            object_generation: interrupt.object.generation(),
            binding_generation: interrupt.binding.generation,
            parent_resource_id: interrupt.parent_descriptor.resource_id,
            parent_lease_generation: interrupt.parent_descriptor.lease_generation,
            flags,
            reserved0: 0,
            reserved: 0,
        })
    }

    /// Returns the exact live source binding after ordinary handle validation.
    /// The selector-private D6 trigger consumes this only to inject the one
    /// already-authorized synthetic source; it cannot select an arbitrary IRQ.
    #[cfg(deepwyrm_dw1d_evidence)]
    pub(crate) fn binding_for_resolved(
        &self,
        resolved: &ResolvedHandle,
    ) -> Result<InterruptBinding, InterruptError> {
        if resolved.object_type() != DW_OBJECT_TYPE_INTERRUPT {
            return Err(InterruptError::InvalidObject);
        }
        self.interrupts
            .lock()
            .iter()
            .flatten()
            .find(|interrupt| {
                interrupt.object == resolved.object_id()
                    && !matches!(
                        interrupt.state,
                        InterruptState::Creating | InterruptState::Finalizing
                    )
            })
            .map(|interrupt| interrupt.binding)
            .ok_or(InterruptError::InvalidObject)
    }

    #[cfg(test)]
    pub(crate) fn binding(&self, key: InterruptKey) -> InterruptBinding {
        self.interrupts
            .lock()
            .iter()
            .flatten()
            .find(|interrupt| interrupt.object == key.object_id())
            .expect("test Interrupt remains live")
            .binding
    }

    #[cfg(any(test, deepwyrm_dw1d_evidence))]
    pub(crate) fn live_count(&self) -> usize {
        self.interrupts.lock().iter().flatten().count()
    }

    #[cfg(deepwyrm_dw1d_evidence)]
    pub(crate) fn pending_for_binding(&self, binding: InterruptBinding) -> bool {
        self.interrupts
            .lock()
            .iter()
            .flatten()
            .find(|interrupt| interrupt.binding == binding)
            .is_some_and(|interrupt| {
                matches!(
                    interrupt.state,
                    InterruptState::Pending { .. } | InterruptState::AckPrepared { .. }
                )
            })
    }
}

fn exact_interrupt_mut<const INTERRUPTS: usize>(
    interrupts: &mut [Option<InterruptRecord>; INTERRUPTS],
    object: ObjectId,
    binding: InterruptBinding,
) -> Option<&mut InterruptRecord> {
    interrupts
        .iter_mut()
        .flatten()
        .find(|interrupt| interrupt.object == object && interrupt.binding == binding)
}

fn public_state(state: &InterruptState) -> (deepwyrm_abi::DwInterruptState, DwInterruptInfoFlags) {
    match state {
        InterruptState::Creating | InterruptState::Armed => {
            (DW_INTERRUPT_STATE_ARMED, DwInterruptInfoFlags(0))
        }
        InterruptState::Pending { coalesced } => (
            DW_INTERRUPT_STATE_PENDING,
            if *coalesced {
                DW_INTERRUPT_INFO_FLAG_COALESCED
            } else {
                DwInterruptInfoFlags(0)
            },
        ),
        InterruptState::AckPrepared { .. } => (DW_INTERRUPT_STATE_PENDING, DwInterruptInfoFlags(0)),
        InterruptState::Finalizing => (DW_INTERRUPT_STATE_FINALIZING, DwInterruptInfoFlags(0)),
    }
}

impl<const INTERRUPTS: usize> InterruptInfoProvider for InterruptAuthority<INTERRUPTS> {
    fn object_info_for_resolved(
        &self,
        resolved: &ResolvedHandle,
    ) -> Result<DwInterruptInfoV1, InterruptError> {
        self.info_for_resolved(resolved)
    }
}

impl<const INTERRUPTS: usize> InterruptWaitSource for InterruptAuthority<INTERRUPTS> {
    fn current_signals_for_resolved(
        &self,
        resolved: &ResolvedHandle,
    ) -> Result<DwSignals, InterruptError> {
        if resolved.object_type() != DW_OBJECT_TYPE_INTERRUPT {
            return Err(InterruptError::InvalidObject);
        }
        let interrupts = self.interrupts.lock();
        let interrupt = interrupts
            .iter()
            .flatten()
            .find(|interrupt| interrupt.object == resolved.object_id())
            .ok_or(InterruptError::InvalidObject)?;
        Ok(match interrupt.state {
            InterruptState::Pending { .. } | InterruptState::AckPrepared { .. } => {
                DW_SIGNAL_SIGNALED
            }
            InterruptState::Creating | InterruptState::Armed | InterruptState::Finalizing => {
                DwSignals(0)
            }
        })
    }

    fn register_wait(
        &self,
        waits: &dyn WaitRegistrationSink,
        target: ResolvedHandle,
        desired: DwSignals,
        item_index: u32,
        thread: ThreadKey,
        wake: BlockWakeKey,
    ) -> Result<InterruptWaitOutcome, InterruptWaitFailure> {
        if target.object_type() != DW_OBJECT_TYPE_INTERRUPT
            || target.rights().0 & DW_RIGHT_WAIT.0 != DW_RIGHT_WAIT.0
            || desired != DW_SIGNAL_SIGNALED
        {
            return Err(InterruptWaitFailure {
                error: if target.rights().0 & DW_RIGHT_WAIT.0 == 0 {
                    WaitError::AccessDenied
                } else {
                    WaitError::InvalidObject
                },
                pin: target.into_internal(),
            });
        }
        let interrupts = self.interrupts.lock();
        let Some(interrupt) = interrupts
            .iter()
            .flatten()
            .find(|interrupt| interrupt.object == target.object_id())
        else {
            return Err(InterruptWaitFailure {
                error: WaitError::InvalidObject,
                pin: target.into_internal(),
            });
        };
        if matches!(
            interrupt.state,
            InterruptState::Pending { .. } | InterruptState::AckPrepared { .. }
        ) {
            return Ok(InterruptWaitOutcome::Ready {
                observed: DW_SIGNAL_SIGNALED,
                pin: target.into_internal(),
            });
        }
        if matches!(
            interrupt.state,
            InterruptState::Creating | InterruptState::Finalizing
        ) {
            return Err(InterruptWaitFailure {
                error: WaitError::InvalidObject,
                pin: target.into_internal(),
            });
        }
        waits
            .register(target.into_internal(), desired, item_index, thread, wake)
            .map(InterruptWaitOutcome::Registered)
            .map_err(|failure| InterruptWaitFailure {
                error: failure.error(),
                pin: failure.into_pin(),
            })
    }
}

impl<const INTERRUPTS: usize> InterruptFinalizer for InterruptAuthority<INTERRUPTS> {
    fn take_finalization(
        &self,
        final_release: FinalRelease,
        platform: &dyn InterruptPlatform,
    ) -> Result<InterruptFinalization, (InterruptError, FinalRelease)> {
        if final_release.object_type() != DW_OBJECT_TYPE_INTERRUPT {
            return Err((InterruptError::FinalizationMismatch, final_release));
        }
        let binding = {
            let mut interrupts = self.interrupts.lock();
            let Some(interrupt) = interrupts
                .iter_mut()
                .flatten()
                .find(|interrupt| interrupt.object == final_release.id())
            else {
                return Err((InterruptError::FinalizationMismatch, final_release));
            };
            if matches!(
                interrupt.state,
                InterruptState::Creating | InterruptState::Finalizing
            ) {
                return Err((InterruptError::FinalizationMismatch, final_release));
            }
            interrupt.state = InterruptState::Finalizing;
            interrupt.binding
        };

        platform.mask_source(binding);
        platform.release_source(binding);

        let finalized_interrupt = {
            let mut interrupts = self.interrupts.lock();
            let Some(slot) = interrupts.iter_mut().find(|slot| {
                slot.as_ref().is_some_and(|interrupt| {
                    interrupt.object == final_release.id()
                        && interrupt.binding == binding
                        && matches!(interrupt.state, InterruptState::Finalizing)
                })
            }) else {
                panic!("Interrupt finalization lost its exact typed record after platform unbind");
            };
            slot.take()
                .expect("validated Interrupt finalization slot remains populated")
        };
        let parent = finalized_interrupt.parent;
        #[cfg(deepwyrm_dw1d_evidence)]
        let parent_descriptor = finalized_interrupt.parent_descriptor;
        Ok(InterruptFinalization {
            final_release,
            parent,
            #[cfg(deepwyrm_dw1d_evidence)]
            binding,
            #[cfg(deepwyrm_dw1d_evidence)]
            parent_descriptor,
        })
    }
}

#[must_use = "Interrupt wait outcomes retain one exact generic pin"]
pub(crate) enum InterruptWaitOutcome {
    Ready {
        observed: DwSignals,
        pin: InternalRef,
    },
    Registered(WaitRegistration),
}

#[derive(Debug)]
pub(crate) struct InterruptWaitFailure {
    pub(crate) error: WaitError,
    pub(crate) pin: InternalRef,
}

#[must_use = "prepared Interrupt acknowledgements retain exact object lifetime"]
pub(crate) struct InterruptAckTransaction {
    operation: InterruptAckOperation,
    pin: InternalRef,
}

enum InterruptAckOperation {
    Coalesced,
    Rearm {
        object: ObjectId,
        binding: InterruptBinding,
    },
}

impl InterruptAckTransaction {
    pub(crate) fn complete<const OBJECTS: usize, const INTERRUPTS: usize>(
        self,
        registry: &mut ObjectRegistry<OBJECTS>,
        interrupts: &InterruptAuthority<INTERRUPTS>,
        platform: &dyn InterruptPlatform,
    ) -> Result<Option<FinalRelease>, DwStatus> {
        if let InterruptAckOperation::Rearm { object, binding } = self.operation {
            if let Err(error) = platform
                .acknowledge_source(binding)
                .and_then(|()| platform.unmask_or_rearm(binding))
            {
                interrupts.restore_pending_after_platform_failure(object, binding);
                let release = registry
                    .release_internal(self.pin)
                    .unwrap_or_else(|failure| {
                        panic!(
                            "failed Interrupt ack lost its operation pin: {:?}",
                            failure.error()
                        )
                    });
                assert!(release.is_none(), "failed ack unexpectedly became final");
                return Err(platform_status(error));
            }
            interrupts.finish_ack(object, binding);
            if interrupts
                .current_signals_for_object(object)
                .is_some_and(|signals| signals == DW_SIGNAL_SIGNALED)
            {
                platform.mask_source(binding);
            }
        }
        registry.release_internal(self.pin).map_err(|failure| {
            panic!(
                "completed Interrupt ack lost its operation pin: {:?}",
                failure.error()
            )
        })
    }

    #[cfg(any(test, deepwyrm_dw1d_evidence))]
    pub(crate) const fn binding_for_evidence(&self) -> Option<InterruptBinding> {
        match self.operation {
            InterruptAckOperation::Coalesced => None,
            InterruptAckOperation::Rearm { binding, .. } => Some(binding),
        }
    }
}

impl<const INTERRUPTS: usize> InterruptAuthority<INTERRUPTS> {
    fn current_signals_for_object(&self, object: ObjectId) -> Option<DwSignals> {
        self.interrupts
            .lock()
            .iter()
            .flatten()
            .find(|interrupt| interrupt.object == object)
            .map(|interrupt| match interrupt.state {
                InterruptState::Pending { .. } | InterruptState::AckPrepared { .. } => {
                    DW_SIGNAL_SIGNALED
                }
                _ => DwSignals(0),
            })
    }
}

pub(crate) fn interrupt_create<
    const HANDLES: usize,
    const OBJECTS: usize,
    const RESOURCES: usize,
    const INTERRUPTS: usize,
>(
    table: &mut HandleTable<HANDLES>,
    registry: &mut ObjectRegistry<OBJECTS>,
    resources: &DeviceResourceAuthority<RESOURCES>,
    interrupts: &InterruptAuthority<INTERRUPTS>,
    platform: &dyn InterruptPlatform,
    resource: DwHandle,
    requested_rights: DwRights,
) -> Result<(InterruptKey, DwHandle), InterruptCreateError> {
    if requested_rights.0 == 0
        || !dw_rights_are_compatible(DW_OBJECT_TYPE_INTERRUPT, requested_rights)
    {
        return Err(InterruptCreateError::Interrupt(
            InterruptError::InvalidRights,
        ));
    }
    let resolved = table
        .lookup(
            registry,
            resource,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_DEVICE_RESOURCE),
            DW_RIGHT_MODIFY,
        )
        .map_err(InterruptCreateError::Handle)?;
    let parent_descriptor = match resources.descriptor_for_interrupt(&resolved) {
        Ok(descriptor) => descriptor,
        Err(error) => {
            release_parent_pin_exact(registry, resolved.into_internal());
            return Err(InterruptCreateError::Interrupt(resource_interrupt_error(
                error,
            )));
        }
    };
    let parent = resolved.into_internal();
    let source_reservation = match platform.reserve_source(parent_descriptor.interrupt_source) {
        Ok(reservation) => reservation,
        Err(error) => {
            release_parent_pin_exact(registry, parent);
            return Err(InterruptCreateError::Interrupt(InterruptError::Platform(
                error,
            )));
        }
    };
    let binding = source_reservation.binding;
    let mut destination = match table.reserve_transfer_destination() {
        Ok(destination) => destination,
        Err(error) => {
            platform.cancel_source(source_reservation).unwrap_or_else(|rollback| {
                panic!("Interrupt source rollback drifted after handle capacity failure: {rollback:?}")
            });
            release_parent_pin_exact(registry, parent);
            return Err(InterruptCreateError::Handle(error));
        }
    };
    let creation = match registry.create(DW_OBJECT_TYPE_INTERRUPT) {
        Ok(creation) => creation,
        Err(error) => {
            destination.cancel(table).unwrap_or_else(|rollback| {
                panic!(
                    "Interrupt destination rollback drifted after registry failure: {rollback:?}"
                )
            });
            platform
                .cancel_source(source_reservation)
                .unwrap_or_else(|rollback| {
                    panic!("Interrupt source rollback drifted after registry failure: {rollback:?}")
                });
            release_parent_pin_exact(registry, parent);
            return Err(InterruptCreateError::Registry(error));
        }
    };
    let typed = match interrupts.bind(creation, parent_descriptor, parent, binding) {
        Ok(binding) => binding,
        Err((error, creation, parent)) => {
            registry
                .cancel_creation(creation)
                .unwrap_or_else(|failure| {
                    panic!("Interrupt generic rollback drifted: {:?}", failure.error())
                });
            destination.cancel(table).unwrap_or_else(|rollback| {
                panic!("Interrupt destination rollback drifted after typed failure: {rollback:?}")
            });
            platform
                .cancel_source(source_reservation)
                .unwrap_or_else(|rollback| {
                    panic!("Interrupt source rollback drifted after typed failure: {rollback:?}")
                });
            release_parent_pin_exact(registry, parent);
            return Err(InterruptCreateError::Interrupt(error));
        }
    };
    let key = typed.key();
    let bound = registry
        .finish_payload_binding(typed)
        .unwrap_or_else(|failure| {
            panic!(
                "fresh Interrupt payload binding rejected: {:?}",
                failure.error()
            )
        });
    let reference = registry.bound_into_handle(bound).unwrap_or_else(|failure| {
        panic!(
            "fresh Interrupt handle conversion failed: {:?}",
            failure.error()
        )
    });
    // The destination, object, typed payload, rights, and source reservation
    // have all been validated. Commit the exact source at this no-fail point,
    // then publish the already-guaranteed handle so no userspace-visible
    // Interrupt can observe Creating or an unarmed platform source.
    let committed = platform.commit_source(source_reservation);
    interrupts.commit_armed(key, committed);
    let published = match destination.try_publish_reference(table, reference, requested_rights) {
        Ok(published) => published,
        Err(failure) => {
            let error = failure.error();
            let final_release = registry
                .release_handle(failure.into_reference())
                .unwrap_or_else(|release| {
                    panic!(
                        "Interrupt publication rollback lost generic authority: {:?}",
                        release.error()
                    )
                })
                .expect("unpublished Interrupt owns its only generic reference");
            let (cleanup, parent) =
                interrupts
                    .cancel_unpublished(final_release)
                    .unwrap_or_else(|(typed, _)| {
                        panic!("Interrupt publication rollback lost typed authority: {typed:?}")
                    });
            registry
                .complete_payload_finalization(cleanup)
                .unwrap_or_else(|failure| {
                    panic!(
                        "Interrupt publication rollback lost finalization authority: {:?}",
                        failure.error()
                    )
                });
            release_parent_pin_exact(registry, parent);
            platform.mask_source(committed);
            platform.release_source(committed);
            destination.cancel(table).unwrap_or_else(|rollback| {
                panic!(
                    "Interrupt destination rollback drifted after publication failure: {rollback:?}"
                )
            });
            return Err(InterruptCreateError::Publication(error));
        }
    };
    Ok((key, published.handle))
}

pub(crate) fn interrupt_ack<const HANDLES: usize, const OBJECTS: usize, const INTERRUPTS: usize>(
    table: &HandleTable<HANDLES>,
    registry: &mut ObjectRegistry<OBJECTS>,
    interrupts: &InterruptAuthority<INTERRUPTS>,
    platform: &dyn InterruptPlatform,
    handle: DwHandle,
) -> Result<Option<FinalRelease>, DwStatus> {
    prepare_interrupt_ack(table, registry, interrupts, handle)?
        .complete(registry, interrupts, platform)
}

pub(crate) fn prepare_interrupt_ack<
    const HANDLES: usize,
    const OBJECTS: usize,
    const INTERRUPTS: usize,
>(
    table: &HandleTable<HANDLES>,
    registry: &mut ObjectRegistry<OBJECTS>,
    interrupts: &InterruptAuthority<INTERRUPTS>,
    handle: DwHandle,
) -> Result<InterruptAckTransaction, DwStatus> {
    let resolved = table
        .lookup(
            registry,
            handle,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_INTERRUPT),
            DW_RIGHT_MODIFY,
        )
        .map_err(handle_status)?;
    match interrupts.prepare_ack_for_resolved(resolved) {
        Ok(transaction) => Ok(transaction),
        Err((error, pin)) => {
            release_interrupt_operation_pin(registry, pin);
            Err(interrupt_status(error))
        }
    }
}

pub(crate) fn complete_interrupt_finalization<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    finalization: InterruptFinalization,
) -> Option<FinalRelease> {
    let parent_release = registry
        .release_internal(finalization.parent)
        .unwrap_or_else(|failure| {
            panic!(
                "Interrupt finalization lost its parent DeviceResource pin: {:?}",
                failure.error()
            )
        });
    registry
        .complete_payload_finalization(InterruptCleanup {
            final_release: finalization.final_release,
        })
        .unwrap_or_else(|failure| {
            panic!(
                "generic Interrupt finalization became invalid after typed cleanup: {:?}",
                failure.error()
            )
        });
    parent_release
}

fn release_parent_pin_exact<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    parent: InternalRef,
) {
    assert!(
        registry.release_internal(parent).unwrap().is_none(),
        "Interrupt creation rollback unexpectedly finalized its parent handle"
    );
}

fn release_interrupt_operation_pin<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    pin: InternalRef,
) {
    assert!(
        registry.release_internal(pin).unwrap().is_none(),
        "Interrupt operation pin unexpectedly became final while its handle remained owned"
    );
}

fn resource_interrupt_error(error: DeviceResourceError) -> InterruptError {
    match error {
        DeviceResourceError::InvalidObject => InterruptError::InvalidObject,
        DeviceResourceError::InvalidDescriptor | DeviceResourceError::InvalidAccess => {
            InterruptError::InvalidObject
        }
        DeviceResourceError::Capacity
        | DeviceResourceError::IdentityInUse
        | DeviceResourceError::FinalizationMismatch => {
            panic!("live DeviceResource lost typed authority during Interrupt creation: {error:?}")
        }
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

fn interrupt_status(error: InterruptError) -> DwStatus {
    match error {
        InterruptError::InvalidRights => DW_STATUS_INVALID_ARGUMENT,
        InterruptError::InvalidObject => DW_STATUS_BAD_HANDLE,
        InterruptError::BadState => DW_STATUS_BAD_STATE,
        InterruptError::Capacity => DW_STATUS_NO_RESOURCES,
        InterruptError::IdentityInUse => DW_STATUS_ALREADY_EXISTS,
        InterruptError::Platform(error) => platform_status(error),
        InterruptError::FinalizationMismatch => {
            panic!("live Interrupt operation lost typed finalization authority")
        }
    }
}

fn platform_status(error: InterruptPlatformError) -> DwStatus {
    match error {
        InterruptPlatformError::SourceInUse => DW_STATUS_ALREADY_EXISTS,
        InterruptPlatformError::Capacity => DW_STATUS_NO_RESOURCES,
        InterruptPlatformError::InvalidSource => DW_STATUS_INVALID_ARGUMENT,
        InterruptPlatformError::StaleBinding | InterruptPlatformError::BadState => {
            DW_STATUS_BAD_STATE
        }
    }
}
