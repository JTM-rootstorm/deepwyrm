//! DW0-F4 typed wait-source and manual-reset Event foundation.
//!
//! Generic object lifetime remains owned by `ObjectRegistry`. Wait
//! registrations temporarily own one `InternalRef` so closing a source handle
//! cannot race typed finalization while a waiter remains published.

use core::sync::atomic::{AtomicU64, Ordering};

use deepwyrm_abi::{
    DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_EVENT, DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_THREAD,
    DW_RIGHT_WAIT, DW_SIGNAL_EXITED, DW_SIGNAL_SIGNALED, DW_TASK_STATE_EXITED, DwSignals,
    dw_signals_are_compatible,
};

use crate::handle::ResolvedHandle;
use crate::ipc::{ChannelAuthority, ChannelEndpointKey};
use crate::object::{
    CreationRef, FinalRelease, HandleRef, InternalRef, ObjectId, ObjectRegistry,
    ObjectRegistryError,
};
use crate::sync::SpinMutex;
use crate::task::{BlockWakeKey, ProcessKey, TaskAuthority, ThreadKey};

static NEXT_WAIT_DOMAIN: AtomicU64 = AtomicU64::new(1);

fn mint_wait_domain() -> u64 {
    NEXT_WAIT_DOMAIN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |domain| {
            domain.checked_add(1).filter(|next| *next != 0)
        })
        .expect("wait-registry domain space exhausted")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WaitError {
    Capacity,
    InvalidObject,
    InvalidSignals,
    AccessDenied,
    UnsupportedSource,
    ForeignRegistration,
    StaleRegistration,
    EventFinalizationMismatch,
    EventReference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventCreateError {
    Registry(ObjectRegistryError),
    Wait(WaitError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EventKey(ObjectId);

impl EventKey {
    pub(crate) const fn from_object_id(object: ObjectId) -> Self {
        Self(object)
    }

    pub(crate) const fn object_id(self) -> ObjectId {
        self.0
    }
}

#[must_use = "typed Event bindings must be sealed by ObjectRegistry before publication"]
pub(crate) struct EventPayloadBinding {
    creation: CreationRef,
    key: EventKey,
}

impl EventPayloadBinding {
    pub(crate) const fn key(&self) -> EventKey {
        self.key
    }

    pub(crate) fn into_creation(self) -> CreationRef {
        self.creation
    }
}

#[must_use = "typed Event cleanup must be consumed by ObjectRegistry"]
pub(crate) struct EventPayloadCleanup {
    final_release: FinalRelease,
}

impl EventPayloadCleanup {
    pub(crate) fn into_final_release(self) -> FinalRelease {
        self.final_release
    }
}

pub(crate) struct EventFinalization {
    final_release: FinalRelease,
}

#[derive(Clone, Copy)]
struct EventRecord {
    object: ObjectId,
    signaled: bool,
}

pub(crate) struct EventAuthority<const EVENTS: usize> {
    events: SpinMutex<[Option<EventRecord>; EVENTS]>,
}

impl<const EVENTS: usize> EventAuthority<EVENTS> {
    pub(crate) fn new() -> Self {
        Self {
            events: SpinMutex::new([None; EVENTS]),
        }
    }

    fn bind_event(
        &self,
        creation: CreationRef,
    ) -> Result<EventPayloadBinding, (WaitError, CreationRef)> {
        if creation.object_type() != DW_OBJECT_TYPE_EVENT {
            return Err((WaitError::InvalidObject, creation));
        }
        let key = EventKey(creation.id());
        let mut events = self.events.lock();
        if events
            .iter()
            .flatten()
            .any(|event| event.object == key.object_id())
        {
            return Err((WaitError::EventReference, creation));
        }
        let Some(slot) = events.iter_mut().find(|slot| slot.is_none()) else {
            return Err((WaitError::Capacity, creation));
        };
        *slot = Some(EventRecord {
            object: key.object_id(),
            signaled: false,
        });
        Ok(EventPayloadBinding { creation, key })
    }

    pub(crate) fn create_event<const OBJECTS: usize>(
        &self,
        registry: &mut ObjectRegistry<OBJECTS>,
    ) -> Result<(EventKey, HandleRef), EventCreateError> {
        let creation = registry
            .create(DW_OBJECT_TYPE_EVENT)
            .map_err(EventCreateError::Registry)?;
        let binding = match self.bind_event(creation) {
            Ok(binding) => binding,
            Err((error, creation)) => {
                registry
                    .cancel_creation(creation)
                    .unwrap_or_else(|failure| {
                        panic!(
                            "Event creation rollback lost generic authority: {:?}",
                            failure.error()
                        )
                    });
                return Err(EventCreateError::Wait(error));
            }
        };
        let key = binding.key();
        let bound = registry
            .finish_payload_binding(binding)
            .unwrap_or_else(|failure| {
                panic!(
                    "fresh Event payload binding rejected by ObjectRegistry: {:?}",
                    failure.error()
                )
            });
        let handle = registry.bound_into_handle(bound).unwrap_or_else(|failure| {
            panic!(
                "fresh Event handle conversion failed: {:?}",
                failure.error()
            )
        });
        Ok((key, handle))
    }

    pub(crate) fn current_signals(&self, key: EventKey) -> Result<DwSignals, WaitError> {
        let events = self.events.lock();
        let event = events
            .iter()
            .flatten()
            .find(|event| event.object == key.object_id())
            .ok_or(WaitError::InvalidObject)?;
        Ok(if event.signaled {
            DW_SIGNAL_SIGNALED
        } else {
            DwSignals(0)
        })
    }

    pub(crate) fn signal<const WAITERS: usize>(
        &self,
        key: EventKey,
        clear_mask: DwSignals,
        set_mask: DwSignals,
        waits: &WaitRegistry<WAITERS>,
    ) -> Result<WakeBatch<WAITERS>, WaitError> {
        validate_event_signal_masks(clear_mask, set_mask)?;
        let mut events = self.events.lock();
        let event = events
            .iter_mut()
            .flatten()
            .find(|event| event.object == key.object_id())
            .ok_or(WaitError::InvalidObject)?;
        event.signaled = set_mask == DW_SIGNAL_SIGNALED;
        if event.signaled {
            Ok(waits.take_ready(key.object_id(), DW_SIGNAL_SIGNALED))
        } else {
            Ok(WakeBatch::empty())
        }
    }

    pub(crate) fn register_wait<const WAITERS: usize>(
        &self,
        waits: &WaitRegistry<WAITERS>,
        target: ResolvedHandle,
        desired: DwSignals,
        item_index: u32,
        thread: ThreadKey,
        wake: BlockWakeKey,
    ) -> Result<EventWaitOutcome, EventWaitFailure> {
        if target.object_type() != DW_OBJECT_TYPE_EVENT {
            return Err(EventWaitFailure {
                error: WaitError::InvalidObject,
                pin: target.into_internal(),
            });
        }
        if target.rights().0 & DW_RIGHT_WAIT.0 != DW_RIGHT_WAIT.0 {
            return Err(EventWaitFailure {
                error: WaitError::AccessDenied,
                pin: target.into_internal(),
            });
        }
        if let Err(error) = validate_wait_signals(target.object_type(), desired) {
            return Err(EventWaitFailure {
                error,
                pin: target.into_internal(),
            });
        }

        // Holding Event state while publishing the registration is the F0/F4
        // linearization barrier. A concurrent set either precedes this lock and
        // is observed here, or follows registration and discovers it while
        // scanning the wait registry. There is no lost-wakeup gap.
        let events = self.events.lock();
        let event = match events
            .iter()
            .flatten()
            .find(|event| event.object == target.object_id())
        {
            Some(event) => event,
            None => {
                return Err(EventWaitFailure {
                    error: WaitError::InvalidObject,
                    pin: target.into_internal(),
                });
            }
        };
        if event.signaled {
            return Ok(EventWaitOutcome::Ready {
                observed: DW_SIGNAL_SIGNALED,
                pin: target.into_internal(),
            });
        }
        match waits.register(target.into_internal(), desired, item_index, thread, wake) {
            Ok(registration) => Ok(EventWaitOutcome::Registered(registration)),
            Err(failure) => Err(EventWaitFailure {
                error: failure.error,
                pin: failure.pin,
            }),
        }
    }

    pub(crate) fn take_finalization(
        &self,
        final_release: FinalRelease,
    ) -> Result<EventFinalization, (WaitError, FinalRelease)> {
        if final_release.object_type() != DW_OBJECT_TYPE_EVENT {
            return Err((WaitError::EventFinalizationMismatch, final_release));
        }
        let mut events = self.events.lock();
        let Some(slot) = events.iter_mut().find(|slot| {
            slot.as_ref()
                .is_some_and(|event| event.object == final_release.id())
        }) else {
            return Err((WaitError::EventFinalizationMismatch, final_release));
        };
        *slot = None;
        Ok(EventFinalization { final_release })
    }
}

pub(crate) fn complete_event_finalization<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    finalization: EventFinalization,
) {
    registry
        .complete_payload_finalization(EventPayloadCleanup {
            final_release: finalization.final_release,
        })
        .unwrap_or_else(|failure| {
            panic!(
                "generic Event finalization became invalid after typed cleanup: {:?}",
                failure.error()
            )
        });
}

pub(crate) fn validate_event_signal_masks(
    clear_mask: DwSignals,
    set_mask: DwSignals,
) -> Result<(), WaitError> {
    let known = DW_SIGNAL_SIGNALED.0;
    if clear_mask.0 & !known != 0
        || set_mask.0 & !known != 0
        || clear_mask.0 & set_mask.0 != 0
        || (clear_mask.0 == 0 && set_mask.0 == 0)
    {
        return Err(WaitError::InvalidSignals);
    }
    if (clear_mask == DW_SIGNAL_SIGNALED && set_mask.0 == 0)
        || (clear_mask.0 == 0 && set_mask == DW_SIGNAL_SIGNALED)
    {
        Ok(())
    } else {
        Err(WaitError::InvalidSignals)
    }
}

pub(crate) const fn validate_wait_signals(
    object_type: deepwyrm_abi::DwObjectType,
    desired: DwSignals,
) -> Result<(), WaitError> {
    if desired.0 == 0 || !dw_signals_are_compatible(object_type, desired) {
        return Err(WaitError::InvalidSignals);
    }
    Ok(())
}

pub(crate) fn current_signals_for<
    const GROUPS: usize,
    const PROCESSES: usize,
    const THREADS: usize,
    const HANDLES: usize,
    const EVENTS: usize,
    const CHANNEL_PAIRS: usize,
    const CHANNEL_DEPTH: usize,
>(
    tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    events: &EventAuthority<EVENTS>,
    channels: &ChannelAuthority<CHANNEL_PAIRS, CHANNEL_DEPTH>,
    target: &ResolvedHandle,
) -> Result<DwSignals, WaitError> {
    match target.object_type() {
        DW_OBJECT_TYPE_PROCESS => tasks
            .process_info(ProcessKey::from_object_id(target.object_id()))
            .map(|info| {
                if info.state == DW_TASK_STATE_EXITED {
                    DW_SIGNAL_EXITED
                } else {
                    DwSignals(0)
                }
            })
            .map_err(|_| WaitError::InvalidObject),
        DW_OBJECT_TYPE_THREAD => tasks
            .thread_info(ThreadKey::from_object_id(target.object_id()))
            .map(|info| {
                if info.state == DW_TASK_STATE_EXITED {
                    DW_SIGNAL_EXITED
                } else {
                    DwSignals(0)
                }
            })
            .map_err(|_| WaitError::InvalidObject),
        DW_OBJECT_TYPE_EVENT => {
            events.current_signals(EventKey::from_object_id(target.object_id()))
        }
        DW_OBJECT_TYPE_CHANNEL => channels
            .current_signals(ChannelEndpointKey::from_object_id(target.object_id()))
            .map_err(|_| WaitError::InvalidObject),
        object_type if deepwyrm_abi::dw_object_compatible_signals(object_type).0 != 0 => {
            Err(WaitError::UnsupportedSource)
        }
        _ => Err(WaitError::InvalidObject),
    }
}

#[derive(Clone, Copy)]
struct WaitEntryIdentity {
    object: ObjectId,
    thread: ThreadKey,
    wake: BlockWakeKey,
}

struct WaitEntry {
    identity: WaitEntryIdentity,
    desired: DwSignals,
    item_index: u32,
    pin: InternalRef,
}

struct WaitSlot {
    generation: u32,
    entry: Option<WaitEntry>,
}

#[must_use = "published wait registrations must be cancelled or completed by a wake"]
pub(crate) struct WaitRegistration {
    domain: u64,
    slot: u16,
    generation: u32,
    identity: WaitEntryIdentity,
}

#[derive(Debug)]
pub(crate) struct WaitRegistrationFailure {
    error: WaitError,
    pin: InternalRef,
}

impl WaitRegistrationFailure {
    pub(crate) const fn error(&self) -> WaitError {
        self.error
    }

    pub(crate) fn into_pin(self) -> InternalRef {
        self.pin
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WakeIntent {
    wake: BlockWakeKey,
    observed: DwSignals,
    item_index: u32,
}

impl WakeIntent {
    pub(crate) const fn wake_key(&self) -> BlockWakeKey {
        self.wake
    }

    pub(crate) const fn observed(&self) -> DwSignals {
        self.observed
    }

    pub(crate) const fn item_index(&self) -> u32 {
        self.item_index
    }
}

#[must_use = "wake batches must be drained so every wait pin is released"]
#[derive(Debug)]
pub(crate) struct WakeBatch<const CAPACITY: usize> {
    wakes: [Option<WakeIntent>; CAPACITY],
    wake_len: usize,
    pins: [Option<InternalRef>; CAPACITY],
    pin_len: usize,
}

impl<const CAPACITY: usize> WakeBatch<CAPACITY> {
    pub(crate) fn empty() -> Self {
        Self {
            wakes: core::array::from_fn(|_| None),
            wake_len: 0,
            pins: core::array::from_fn(|_| None),
            pin_len: 0,
        }
    }

    fn push_wake(&mut self, wake: WakeIntent) {
        assert!(self.wake_len < CAPACITY, "wait wake batch overflow");
        self.wakes[self.wake_len] = Some(wake);
        self.wake_len += 1;
    }

    fn push_pin(&mut self, pin: InternalRef) {
        assert!(self.pin_len < CAPACITY, "wait pin batch overflow");
        self.pins[self.pin_len] = Some(pin);
        self.pin_len += 1;
    }

    pub(crate) const fn len(&self) -> usize {
        self.wake_len
    }

    pub(crate) fn append(&mut self, other: Self) {
        let (wakes, pins) = other.into_parts();
        for wake in wakes.into_iter().flatten() {
            self.push_wake(wake);
        }
        for pin in pins.into_iter().flatten() {
            self.push_pin(pin);
        }
    }

    #[cfg(test)]
    pub(crate) const fn pin_len(&self) -> usize {
        self.pin_len
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        [Option<WakeIntent>; CAPACITY],
        [Option<InternalRef>; CAPACITY],
    ) {
        (self.wakes, self.pins)
    }
}

pub(crate) struct WaitRegistry<const CAPACITY: usize> {
    domain: u64,
    slots: SpinMutex<[WaitSlot; CAPACITY]>,
}

impl<const CAPACITY: usize> WaitRegistry<CAPACITY> {
    pub(crate) fn new() -> Self {
        Self {
            domain: mint_wait_domain(),
            slots: SpinMutex::new(core::array::from_fn(|_| WaitSlot {
                generation: 0,
                entry: None,
            })),
        }
    }

    pub(crate) fn register(
        &self,
        pin: InternalRef,
        desired: DwSignals,
        item_index: u32,
        thread: ThreadKey,
        wake: BlockWakeKey,
    ) -> Result<WaitRegistration, WaitRegistrationFailure> {
        if let Err(error) = validate_wait_signals(pin.object_type(), desired) {
            return Err(WaitRegistrationFailure { error, pin });
        }
        let identity = WaitEntryIdentity {
            object: pin.id(),
            thread,
            wake,
        };
        let mut slots = self.slots.lock();
        let Some((index, slot)) = slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.entry.is_none())
        else {
            return Err(WaitRegistrationFailure {
                error: WaitError::Capacity,
                pin,
            });
        };
        let Some(generation) = slot.generation.checked_add(1).filter(|next| *next != 0) else {
            return Err(WaitRegistrationFailure {
                error: WaitError::Capacity,
                pin,
            });
        };
        let Ok(slot_index) = u16::try_from(index) else {
            return Err(WaitRegistrationFailure {
                error: WaitError::Capacity,
                pin,
            });
        };
        slot.generation = generation;
        slot.entry = Some(WaitEntry {
            identity,
            desired,
            item_index,
            pin,
        });
        Ok(WaitRegistration {
            domain: self.domain,
            slot: slot_index,
            generation,
            identity,
        })
    }

    pub(crate) fn cancel(&self, registration: WaitRegistration) -> Result<InternalRef, WaitError> {
        if registration.domain != self.domain {
            return Err(WaitError::ForeignRegistration);
        }
        let mut slots = self.slots.lock();
        let slot = slots
            .get_mut(usize::from(registration.slot))
            .ok_or(WaitError::StaleRegistration)?;
        if slot.generation != registration.generation
            || !slot.entry.as_ref().is_some_and(|entry| {
                entry.identity.object == registration.identity.object
                    && entry.identity.thread == registration.identity.thread
                    && entry.identity.wake == registration.identity.wake
            })
        {
            return Err(WaitError::StaleRegistration);
        }
        Ok(slot
            .entry
            .take()
            .expect("validated wait registration owns one entry")
            .pin)
    }

    /// Removes every registration owned by one exact block generation.
    ///
    /// Timeout and terminal retirement use this after they win arbitration so
    /// no sibling registration can later attempt a stale scheduler wake. Pins
    /// are returned for deferred ObjectRegistry release outside the wait lock.
    pub(crate) fn cancel_generation(&self, wake: BlockWakeKey) -> WakeBatch<CAPACITY> {
        let mut slots = self.slots.lock();
        let mut batch = WakeBatch::empty();
        for slot in slots.iter_mut() {
            if !slot
                .entry
                .as_ref()
                .is_some_and(|entry| entry.identity.wake == wake)
            {
                continue;
            }
            let entry = slot
                .entry
                .take()
                .expect("matching wait generation entry remains present");
            batch.push_pin(entry.pin);
        }
        batch
    }

    /// Claims signal wins by block generation, not by individual registration.
    ///
    /// A `wait_many` operation may own several registrations with one exact
    /// `BlockWakeKey`. Once any one source wins, every sibling registration for
    /// that generation is consumed under the same registry lock. This gives the
    /// scheduler exactly one wake intent while returning every held object pin
    /// for deferred release. Among simultaneously ready duplicate views of the
    /// triggering object, the lowest ABI input index wins deterministically.
    pub(crate) fn take_ready(&self, object: ObjectId, observed: DwSignals) -> WakeBatch<CAPACITY> {
        let mut slots = self.slots.lock();
        let mut batch = WakeBatch::empty();

        for candidate_index in 0..CAPACITY {
            let Some(candidate) = slots[candidate_index].entry.as_ref() else {
                continue;
            };
            if candidate.identity.object != object || candidate.desired.0 & observed.0 == 0 {
                continue;
            }
            let wake = candidate.identity.wake;
            let winning_index = slots
                .iter()
                .filter_map(|slot| slot.entry.as_ref())
                .filter(|entry| {
                    entry.identity.wake == wake
                        && entry.identity.object == object
                        && entry.desired.0 & observed.0 != 0
                })
                .map(|entry| entry.item_index)
                .min()
                .expect("ready wait generation has at least one matching registration");

            batch.push_wake(WakeIntent {
                wake,
                observed,
                item_index: winning_index,
            });
            for slot in slots.iter_mut() {
                if !slot
                    .entry
                    .as_ref()
                    .is_some_and(|entry| entry.identity.wake == wake)
                {
                    continue;
                }
                let entry = slot
                    .entry
                    .take()
                    .expect("matching wait generation entry remains present");
                batch.push_pin(entry.pin);
            }
        }
        batch
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.slots
            .lock()
            .iter()
            .filter(|slot| slot.entry.is_some())
            .count()
    }
}

#[must_use = "ready Event pins and registrations must be released by the blocking operation owner"]
pub(crate) enum EventWaitOutcome {
    Ready {
        observed: DwSignals,
        pin: InternalRef,
    },
    Registered(WaitRegistration),
}

#[derive(Debug)]
pub(crate) struct EventWaitFailure {
    pub(crate) error: WaitError,
    pub(crate) pin: InternalRef,
}

pub(crate) mod engine;
pub(crate) mod operation;
#[cfg(test)]
mod tests;
