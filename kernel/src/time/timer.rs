use core::sync::atomic::{AtomicU64, Ordering};

use deepwyrm_abi::{
    DW_DEADLINE_INFINITE, DW_OBJECT_TYPE_TIMER, DW_RIGHT_WAIT, DW_SIGNAL_SIGNALED, DwDeadline,
    DwSignals,
};

use crate::handle::ResolvedHandle;
use crate::object::{
    CreationRef, FinalRelease, HandleRef, InternalRef, ObjectId, ObjectRegistry,
    ObjectRegistryError,
};
use crate::sync::IrqSpinMutex;
use crate::task::{BlockWakeKey, ThreadKey};
use crate::wait::{WaitError, WaitRegistration, WaitRegistry, WakeBatch, validate_wait_signals};

use super::DeadlineRegistration;

static NEXT_TIMER_DOMAIN: AtomicU64 = AtomicU64::new(1);

fn mint_timer_domain() -> u64 {
    NEXT_TIMER_DOMAIN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1).filter(|next| *next != 0)
        })
        .expect("timer authority domain space exhausted")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TimerDeadlineError {
    Expired,
    Capacity,
    Fault,
}

pub(crate) trait TimerDeadlineAuthority {
    fn replace_timer_deadline(
        &mut self,
        old: Option<&DeadlineRegistration>,
        deadline_ns: u64,
        token: TimerExpiryToken,
    ) -> Result<Option<DeadlineRegistration>, TimerDeadlineError>;

    fn cancel_timer_deadline(
        &mut self,
        registration: DeadlineRegistration,
    ) -> Result<(), TimerDeadlineError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TimerError {
    Capacity,
    InvalidObject,
    InvalidDeadline,
    InvalidSignals,
    AccessDenied,
    GenerationExhausted,
    ForeignExpiry,
    Deadline(TimerDeadlineError),
    FinalizationMismatch,
    Reference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TimerCreateError {
    Registry(ObjectRegistryError),
    Timer(TimerError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TimerKey(ObjectId);

impl TimerKey {
    pub(crate) const fn from_object_id(object: ObjectId) -> Self {
        Self(object)
    }

    pub(crate) const fn object_id(self) -> ObjectId {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TimerExpiryToken {
    domain: u64,
    object: ObjectId,
    generation: u32,
}

#[must_use = "typed Timer bindings must be sealed by ObjectRegistry before publication"]
pub(crate) struct TimerPayloadBinding {
    creation: CreationRef,
    key: TimerKey,
}

impl TimerPayloadBinding {
    pub(crate) const fn key(&self) -> TimerKey {
        self.key
    }

    pub(crate) fn into_creation(self) -> CreationRef {
        self.creation
    }
}

#[must_use = "typed Timer cleanup must be consumed by ObjectRegistry"]
pub(crate) struct TimerPayloadCleanup {
    final_release: FinalRelease,
}

impl TimerPayloadCleanup {
    pub(crate) fn into_final_release(self) -> FinalRelease {
        self.final_release
    }
}

pub(crate) struct TimerFinalization {
    final_release: FinalRelease,
}

struct TimerArm {
    registration: DeadlineRegistration,
}

struct TimerRecord {
    object: ObjectId,
    arm_generation: u32,
    arm: Option<TimerArm>,
    signaled: bool,
}

pub(crate) struct TimerAuthority<const TIMERS: usize> {
    domain: u64,
    timers: IrqSpinMutex<[Option<TimerRecord>; TIMERS]>,
}

impl<const TIMERS: usize> TimerAuthority<TIMERS> {
    pub(crate) fn new() -> Self {
        Self {
            domain: mint_timer_domain(),
            timers: IrqSpinMutex::new(core::array::from_fn(|_| None)),
        }
    }

    fn bind_timer(
        &self,
        creation: CreationRef,
    ) -> Result<TimerPayloadBinding, (TimerError, CreationRef)> {
        if creation.object_type() != DW_OBJECT_TYPE_TIMER {
            return Err((TimerError::InvalidObject, creation));
        }
        let key = TimerKey(creation.id());
        let mut timers = self.timers.lock();
        if timers
            .iter()
            .flatten()
            .any(|timer| timer.object == key.object_id())
        {
            return Err((TimerError::Reference, creation));
        }
        let Some(slot) = timers.iter_mut().find(|slot| slot.is_none()) else {
            return Err((TimerError::Capacity, creation));
        };
        *slot = Some(TimerRecord {
            object: key.object_id(),
            arm_generation: 0,
            arm: None,
            signaled: false,
        });
        Ok(TimerPayloadBinding { creation, key })
    }

    pub(crate) fn create_timer<const OBJECTS: usize>(
        &self,
        registry: &mut ObjectRegistry<OBJECTS>,
    ) -> Result<(TimerKey, HandleRef), TimerCreateError> {
        let creation = registry
            .create(DW_OBJECT_TYPE_TIMER)
            .map_err(TimerCreateError::Registry)?;
        let binding = match self.bind_timer(creation) {
            Ok(binding) => binding,
            Err((error, creation)) => {
                registry
                    .cancel_creation(creation)
                    .unwrap_or_else(|failure| {
                        panic!(
                            "Timer creation rollback lost generic authority: {:?}",
                            failure.error()
                        )
                    });
                return Err(TimerCreateError::Timer(error));
            }
        };
        let key = binding.key();
        let bound = registry
            .finish_payload_binding(binding)
            .unwrap_or_else(|failure| {
                panic!(
                    "fresh Timer payload binding rejected by ObjectRegistry: {:?}",
                    failure.error()
                )
            });
        let handle = registry.bound_into_handle(bound).unwrap_or_else(|failure| {
            panic!(
                "fresh Timer handle conversion failed: {:?}",
                failure.error()
            )
        });
        Ok((key, handle))
    }

    pub(crate) fn current_signals(&self, key: TimerKey) -> Result<DwSignals, TimerError> {
        let timers = self.timers.lock();
        let timer = timers
            .iter()
            .flatten()
            .find(|timer| timer.object == key.object_id())
            .ok_or(TimerError::InvalidObject)?;
        Ok(if timer.signaled {
            DW_SIGNAL_SIGNALED
        } else {
            DwSignals(0)
        })
    }

    pub(crate) fn set<const WAITERS: usize>(
        &self,
        key: TimerKey,
        deadline: DwDeadline,
        deadlines: &mut dyn TimerDeadlineAuthority,
        waits: &WaitRegistry<WAITERS>,
    ) -> Result<WakeBatch<WAITERS>, TimerError> {
        self.set_with_readiness_hook(key, deadline, deadlines, waits, || {})
    }

    fn set_with_readiness_hook<const WAITERS: usize>(
        &self,
        key: TimerKey,
        deadline: DwDeadline,
        deadlines: &mut dyn TimerDeadlineAuthority,
        waits: &WaitRegistry<WAITERS>,
        before_readiness: impl FnOnce(),
    ) -> Result<WakeBatch<WAITERS>, TimerError> {
        if deadline.0 == DW_DEADLINE_INFINITE.0 {
            return Err(TimerError::InvalidDeadline);
        }

        let mut timers = self.timers.lock();
        let timer = timers
            .iter_mut()
            .flatten()
            .find(|timer| timer.object == key.object_id())
            .ok_or(TimerError::InvalidObject)?;
        let generation = timer
            .arm_generation
            .checked_add(1)
            .filter(|generation| *generation != 0)
            .ok_or(TimerError::GenerationExhausted)?;
        let token = TimerExpiryToken {
            domain: self.domain,
            object: key.object_id(),
            generation,
        };

        let registration = deadlines
            .replace_timer_deadline(
                timer.arm.as_ref().map(|arm| &arm.registration),
                deadline.0,
                token,
            )
            .map_err(TimerError::Deadline)?;

        timer.arm_generation = generation;
        timer.signaled = registration.is_none();
        timer.arm = registration.map(|registration| TimerArm { registration });
        let became_signaled = timer.signaled;
        let wakes = if became_signaled {
            before_readiness();
            waits.take_ready(key.object_id(), DW_SIGNAL_SIGNALED)
        } else {
            WakeBatch::empty()
        };
        drop(timers);
        Ok(wakes)
    }

    pub(crate) fn cancel(
        &self,
        key: TimerKey,
        deadlines: &mut dyn TimerDeadlineAuthority,
    ) -> Result<(), TimerError> {
        let mut timers = self.timers.lock();
        let timer = timers
            .iter_mut()
            .flatten()
            .find(|timer| timer.object == key.object_id())
            .ok_or(TimerError::InvalidObject)?;
        let next_generation = if timer.arm.is_some() {
            Some(
                timer
                    .arm_generation
                    .checked_add(1)
                    .filter(|generation| *generation != 0)
                    .ok_or(TimerError::GenerationExhausted)?,
            )
        } else {
            None
        };
        let old_arm = timer.arm.take();
        if let Some(generation) = next_generation {
            timer.arm_generation = generation;
        }
        timer.signaled = false;
        drop(timers);

        if let Some(old_arm) = old_arm {
            deadlines
                .cancel_timer_deadline(old_arm.registration)
                .unwrap_or_else(|error| {
                    panic!("cancelled Timer deadline authority drifted: {error:?}")
                });
        }
        Ok(())
    }

    /// Commits one exact Timer arm expiry. Stale/replaced/cancelled generations
    /// are successful no-ops. Registrations remain owned by sleeping Threads;
    /// the returned IRQ-safe wake intents do not carry generic object pins.
    pub(crate) fn expire<const WAITERS: usize>(
        &self,
        token: TimerExpiryToken,
        waits: &WaitRegistry<WAITERS>,
    ) -> Result<WakeBatch<WAITERS>, TimerError> {
        self.expire_with_readiness_hook(token, waits, || {})
    }

    fn expire_with_readiness_hook<const WAITERS: usize>(
        &self,
        token: TimerExpiryToken,
        waits: &WaitRegistry<WAITERS>,
        before_readiness: impl FnOnce(),
    ) -> Result<WakeBatch<WAITERS>, TimerError> {
        if token.domain != self.domain {
            return Err(TimerError::ForeignExpiry);
        }
        let mut timers = self.timers.lock();
        let Some(timer) = timers
            .iter_mut()
            .flatten()
            .find(|timer| timer.object == token.object)
        else {
            return Ok(WakeBatch::empty());
        };
        if timer.arm_generation != token.generation || timer.arm.is_none() {
            return Ok(WakeBatch::empty());
        }
        timer.arm = None;
        timer.signaled = true;
        let object = timer.object;
        before_readiness();
        let wakes = waits.ready_wakes(object, DW_SIGNAL_SIGNALED);
        drop(timers);
        Ok(wakes)
    }

    pub(crate) fn register_wait<const WAITERS: usize>(
        &self,
        waits: &WaitRegistry<WAITERS>,
        target: ResolvedHandle,
        desired: DwSignals,
        item_index: u32,
        thread: ThreadKey,
        wake: BlockWakeKey,
    ) -> Result<TimerWaitOutcome, TimerWaitFailure> {
        if target.object_type() != DW_OBJECT_TYPE_TIMER {
            return Err(TimerWaitFailure {
                error: TimerError::InvalidObject,
                pin: target.into_internal(),
            });
        }
        if target.rights().0 & DW_RIGHT_WAIT.0 != DW_RIGHT_WAIT.0 {
            return Err(TimerWaitFailure {
                error: TimerError::AccessDenied,
                pin: target.into_internal(),
            });
        }
        if let Err(error) = validate_wait_signals(target.object_type(), desired) {
            return Err(TimerWaitFailure {
                error: map_wait_error(error),
                pin: target.into_internal(),
            });
        }
        let timers = self.timers.lock();
        let Some(timer) = timers
            .iter()
            .flatten()
            .find(|timer| timer.object == target.object_id())
        else {
            return Err(TimerWaitFailure {
                error: TimerError::InvalidObject,
                pin: target.into_internal(),
            });
        };
        if timer.signaled {
            return Ok(TimerWaitOutcome::Ready {
                observed: DW_SIGNAL_SIGNALED,
                pin: target.into_internal(),
            });
        }
        match waits.register(target.into_internal(), desired, item_index, thread, wake) {
            Ok(registration) => Ok(TimerWaitOutcome::Registered(registration)),
            Err(failure) => Err(TimerWaitFailure {
                error: map_wait_error(failure.error()),
                pin: failure.into_pin(),
            }),
        }
    }

    pub(crate) fn take_finalization(
        &self,
        final_release: FinalRelease,
        deadlines: &mut dyn TimerDeadlineAuthority,
    ) -> Result<TimerFinalization, (TimerError, FinalRelease)> {
        if final_release.object_type() != DW_OBJECT_TYPE_TIMER {
            return Err((TimerError::FinalizationMismatch, final_release));
        }
        let mut timers = self.timers.lock();
        let Some(slot) = timers.iter_mut().find(|slot| {
            slot.as_ref()
                .is_some_and(|timer| timer.object == final_release.id())
        }) else {
            return Err((TimerError::FinalizationMismatch, final_release));
        };
        let old_arm = slot.as_mut().and_then(|timer| timer.arm.take());
        if let Some(old_arm) = old_arm {
            deadlines
                .cancel_timer_deadline(old_arm.registration)
                .unwrap_or_else(|error| {
                    panic!("final Timer deadline authority drifted: {error:?}")
                });
        }
        *slot = None;
        Ok(TimerFinalization { final_release })
    }
}

fn map_wait_error(error: WaitError) -> TimerError {
    match error {
        WaitError::Capacity => TimerError::Capacity,
        WaitError::AccessDenied => TimerError::AccessDenied,
        WaitError::InvalidSignals => TimerError::InvalidSignals,
        _ => TimerError::InvalidObject,
    }
}

pub(crate) fn complete_timer_finalization<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    finalization: TimerFinalization,
) {
    registry
        .complete_payload_finalization(TimerPayloadCleanup {
            final_release: finalization.final_release,
        })
        .unwrap_or_else(|failure| {
            panic!(
                "generic Timer finalization became invalid after typed cleanup: {:?}",
                failure.error()
            )
        });
}

#[must_use = "ready Timer pins and registrations must be released by the blocking operation owner"]
pub(crate) enum TimerWaitOutcome {
    Ready {
        observed: DwSignals,
        pin: InternalRef,
    },
    Registered(WaitRegistration),
}

#[derive(Debug)]
pub(crate) struct TimerWaitFailure {
    pub(crate) error: TimerError,
    pub(crate) pin: InternalRef,
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::object::ObjectRegistry;
    use crate::task::{
        BlockedOperation, BlockedOperationRegistry, BlockedOperationWinner, CooperativeScheduler,
        ProcessKey, ThreadKey,
    };
    use crate::time::{DeadlineQueue, DeadlineQueueError};
    use deepwyrm_abi::{
        DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_THREAD, DW_SIGNAL_SIGNALED,
        dw_object_compatible_rights,
    };
    use std::sync::{Mutex, mpsc};
    use std::time::Duration;

    struct HostDeadlines<const N: usize> {
        now: u64,
        queue: DeadlineQueue<N, TimerExpiryToken>,
    }

    impl<const N: usize> HostDeadlines<N> {
        fn new(now: u64) -> Self {
            Self {
                now,
                queue: DeadlineQueue::new(),
            }
        }

        fn expire(&mut self, now: u64) -> ([Option<TimerExpiryToken>; N], usize) {
            self.now = now;
            let mut output = [None; N];
            let count = self.queue.expire(now, &mut output);
            (output, count)
        }
    }

    impl<const N: usize> TimerDeadlineAuthority for HostDeadlines<N> {
        fn replace_timer_deadline(
            &mut self,
            old: Option<&DeadlineRegistration>,
            deadline_ns: u64,
            token: TimerExpiryToken,
        ) -> Result<Option<DeadlineRegistration>, TimerDeadlineError> {
            if deadline_ns <= self.now {
                if let Some(old) = old {
                    self.queue
                        .cancel_if_live_ref(old)
                        .map_err(|_| TimerDeadlineError::Fault)?;
                }
                return Ok(None);
            }
            if let Some(old) = old
                && let Some(registration) = self
                    .queue
                    .replace_if_live(old, deadline_ns, token)
                    .map_err(|error| match error {
                        DeadlineQueueError::Capacity => TimerDeadlineError::Capacity,
                        _ => TimerDeadlineError::Fault,
                    })?
            {
                return Ok(Some(registration));
            }
            self.queue
                .register(deadline_ns, token)
                .map(Some)
                .map_err(|error| match error {
                    DeadlineQueueError::Capacity => TimerDeadlineError::Capacity,
                    _ => TimerDeadlineError::Fault,
                })
        }

        fn cancel_timer_deadline(
            &mut self,
            registration: DeadlineRegistration,
        ) -> Result<(), TimerDeadlineError> {
            self.queue
                .cancel_if_live(registration)
                .map(|_| ())
                .map_err(|_| TimerDeadlineError::Fault)
        }
    }

    struct LockedHostDeadlines<'a, const N: usize>(&'a Mutex<HostDeadlines<N>>);

    impl<const N: usize> TimerDeadlineAuthority for LockedHostDeadlines<'_, N> {
        fn replace_timer_deadline(
            &mut self,
            old: Option<&DeadlineRegistration>,
            deadline_ns: u64,
            token: TimerExpiryToken,
        ) -> Result<Option<DeadlineRegistration>, TimerDeadlineError> {
            self.0
                .lock()
                .unwrap()
                .replace_timer_deadline(old, deadline_ns, token)
        }

        fn cancel_timer_deadline(
            &mut self,
            registration: DeadlineRegistration,
        ) -> Result<(), TimerDeadlineError> {
            self.0.lock().unwrap().cancel_timer_deadline(registration)
        }
    }

    fn block_wake() -> (ThreadKey, BlockWakeKey) {
        let mut objects = ObjectRegistry::<1>::new();
        let creation = objects.create(DW_OBJECT_TYPE_THREAD).unwrap();
        let thread = ThreadKey::from_object_id(creation.id());
        objects.cancel_creation(creation).unwrap();
        let scheduler = CooperativeScheduler::<1>::new();
        let reservation = scheduler.reserve(thread).unwrap();
        scheduler.commit(reservation).unwrap();
        assert_eq!(scheduler.schedule_next().unwrap().current, Some(thread));
        let (blocked, decision) = scheduler.block_current(thread).unwrap();
        assert_eq!(decision.current, None);
        (thread, blocked.into_wake_key())
    }

    #[derive(Clone, Copy, Debug)]
    enum TimerTraceAction {
        ArmFuture { timer: usize, delta: u64 },
        ArmNow { timer: usize },
        Cancel { timer: usize },
        DequeueExpired { advance: u64 },
        DeliverPending,
    }

    #[derive(Clone, Copy, Debug)]
    struct TimerTraceState {
        generation: u32,
        armed: bool,
        queued: bool,
        deadline: Option<u64>,
        signaled: bool,
    }

    impl TimerTraceState {
        const EMPTY: Self = Self {
            generation: 0,
            armed: false,
            queued: false,
            deadline: None,
            signaled: false,
        };
    }

    fn next_trace_word(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state
    }

    #[test]
    fn fixed_seed_timer_transactions_preserve_generation_capacity_and_copy_tokens() {
        // Keep this deliberately small: the one-slot deadline authority makes
        // every replacement, stale delivery, and capacity outcome observable.
        for seed in [0x14a5_d3e7_91c2_b6f0_u64, 0x7e11_0bad_f00d_cafe] {
            let mut random = seed;
            let mut registry = ObjectRegistry::<4>::new();
            let timers = TimerAuthority::<2>::new();
            let waits = WaitRegistry::<1>::new();
            let mut deadlines = HostDeadlines::<1>::new(10);
            let (first, first_handle) = timers.create_timer(&mut registry).unwrap();
            let (second, second_handle) = timers.create_timer(&mut registry).unwrap();
            let keys = [first, second];
            let mut model = [TimerTraceState::EMPTY; 2];
            let mut queue_owner = None;
            let mut pending: Option<(usize, u32, TimerExpiryToken)> = None;
            let mut saw_stale_delivery = false;
            let mut saw_capacity = false;

            for step in 0..69 {
                let action = match step {
                    // This fixed prefix places an old token between dequeue and
                    // delivery, then proves a replacement generation wins.
                    0 => TimerTraceAction::ArmFuture {
                        timer: 0,
                        delta: 10,
                    },
                    1 => TimerTraceAction::DequeueExpired { advance: 10 },
                    2 => TimerTraceAction::ArmFuture {
                        timer: 0,
                        delta: 20,
                    },
                    3 => TimerTraceAction::ArmFuture {
                        timer: 1,
                        delta: 30,
                    },
                    4 => TimerTraceAction::DeliverPending,
                    _ => match next_trace_word(&mut random) % 5 {
                        0 => TimerTraceAction::ArmFuture {
                            timer: usize::try_from(next_trace_word(&mut random) & 1).unwrap(),
                            delta: 1 + next_trace_word(&mut random) % 31,
                        },
                        1 => TimerTraceAction::ArmNow {
                            timer: usize::try_from(next_trace_word(&mut random) & 1).unwrap(),
                        },
                        2 => TimerTraceAction::Cancel {
                            timer: usize::try_from(next_trace_word(&mut random) & 1).unwrap(),
                        },
                        3 => TimerTraceAction::DequeueExpired {
                            advance: 1 + next_trace_word(&mut random) % 19,
                        },
                        _ => TimerTraceAction::DeliverPending,
                    },
                };
                let context = std::format!("seed={seed:#018x} step={step} action={action:?}");

                match action {
                    TimerTraceAction::ArmFuture { timer, delta } => {
                        let deadline = deadlines.now + delta;
                        let succeeds = queue_owner.is_none() || queue_owner == Some(timer);
                        let result =
                            timers.set(keys[timer], DwDeadline(deadline), &mut deadlines, &waits);
                        if succeeds {
                            assert_eq!(result.unwrap().len(), 0, "{context}");
                            model[timer].generation += 1;
                            model[timer].armed = true;
                            model[timer].queued = true;
                            model[timer].deadline = Some(deadline);
                            model[timer].signaled = false;
                            queue_owner = Some(timer);
                        } else {
                            assert!(
                                matches!(
                                    result,
                                    Err(TimerError::Deadline(TimerDeadlineError::Capacity))
                                ),
                                "{context}: a distinct queued timer must consume the sole slot"
                            );
                            saw_capacity = true;
                        }
                    }
                    TimerTraceAction::ArmNow { timer } => {
                        assert_eq!(
                            timers
                                .set(
                                    keys[timer],
                                    DwDeadline(deadlines.now),
                                    &mut deadlines,
                                    &waits
                                )
                                .unwrap()
                                .len(),
                            0,
                            "{context}"
                        );
                        model[timer].generation += 1;
                        model[timer].armed = false;
                        model[timer].queued = false;
                        model[timer].deadline = None;
                        model[timer].signaled = true;
                        if queue_owner == Some(timer) {
                            queue_owner = None;
                        }
                    }
                    TimerTraceAction::Cancel { timer } => {
                        timers.cancel(keys[timer], &mut deadlines).unwrap();
                        if model[timer].armed {
                            model[timer].generation += 1;
                        }
                        model[timer].armed = false;
                        model[timer].queued = false;
                        model[timer].deadline = None;
                        model[timer].signaled = false;
                        if queue_owner == Some(timer) {
                            queue_owner = None;
                        }
                    }
                    TimerTraceAction::DequeueExpired { advance } => {
                        if pending.is_none() {
                            deadlines.now += advance;
                            let (expired, count) = deadlines.expire(deadlines.now);
                            let expected = queue_owner
                                .and_then(|timer| model[timer].deadline)
                                .is_some_and(|deadline| deadline <= deadlines.now);
                            assert_eq!(count, usize::from(expected), "{context}");
                            if expected {
                                let timer = queue_owner.take().unwrap();
                                let token = expired[0].expect("queued Timer has an expiry token");
                                pending = Some((timer, model[timer].generation, token));
                                model[timer].queued = false;
                            }
                        }
                    }
                    TimerTraceAction::DeliverPending => {
                        if let Some((timer, generation, token)) = pending.take() {
                            // TimerExpiryToken is intentionally Copy identity,
                            // not an owning cleanup capability. Both deliveries
                            // therefore remain safe exact-generation probes.
                            let copied_token = token;
                            assert_eq!(copied_token, token, "{context}");
                            assert_eq!(timers.expire(token, &waits).unwrap().len(), 0, "{context}");
                            let live = model[timer].armed && model[timer].generation == generation;
                            if !live {
                                saw_stale_delivery = true;
                            } else {
                                model[timer].armed = false;
                                model[timer].deadline = None;
                                model[timer].signaled = true;
                            }
                            assert_eq!(
                                timers.expire(copied_token, &waits).unwrap().len(),
                                0,
                                "{context}: repeated Copy-token delivery is idempotent"
                            );
                        }
                    }
                }

                let expected_deadline = queue_owner.and_then(|timer| model[timer].deadline);
                assert_eq!(deadlines.queue.earliest(), expected_deadline, "{context}");
                for timer in 0..2 {
                    assert_eq!(
                        timers.current_signals(keys[timer]).unwrap(),
                        if model[timer].signaled {
                            DW_SIGNAL_SIGNALED
                        } else {
                            DwSignals(0)
                        },
                        "{context}: timer={timer}"
                    );
                }
            }

            assert!(
                saw_stale_delivery,
                "seed={seed:#018x}: stale token path was not exercised"
            );
            assert!(
                saw_capacity,
                "seed={seed:#018x}: bounded deadline capacity was not exercised"
            );
            for handle in [first_handle, second_handle] {
                let release = registry.release_handle(handle).unwrap().unwrap();
                let finalization = timers.take_finalization(release, &mut deadlines).unwrap();
                complete_timer_finalization(&mut registry, finalization);
            }
        }
    }

    #[test]
    fn timer_set_replace_and_cancel_are_generation_exact() {
        let mut registry = ObjectRegistry::<4>::new();
        let timers = TimerAuthority::<1>::new();
        let waits = WaitRegistry::<4>::new();
        let mut deadlines = HostDeadlines::<1>::new(10);
        let (key, handle) = timers.create_timer(&mut registry).unwrap();

        assert!(
            timers
                .set(key, DwDeadline(100), &mut deadlines, &waits)
                .unwrap()
                .len()
                == 0
        );
        assert_eq!(timers.current_signals(key), Ok(DwSignals(0)));
        assert_eq!(deadlines.queue.earliest(), Some(100));

        // Re-arm while the only deadline slot is still occupied by this Timer.
        // Exact replacement must reuse the live slot rather than require spare capacity.
        assert_eq!(
            timers
                .set(key, DwDeadline(150), &mut deadlines, &waits)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(deadlines.queue.earliest(), Some(150));

        // Model an IRQ removing the old deadline before its payload callback
        // runs. Re-arm publishes a new generation; late delivery is stale.
        let (old, count) = deadlines.expire(150);
        assert_eq!(count, 1);
        let old = old[0].expect("old arm expiry token exists");
        assert!(
            timers
                .set(key, DwDeadline(200), &mut deadlines, &waits)
                .unwrap()
                .len()
                == 0
        );
        assert_eq!(timers.expire(old, &waits).unwrap().len(), 0);
        assert_eq!(timers.current_signals(key), Ok(DwSignals(0)));

        let (new, count) = deadlines.expire(200);
        assert_eq!(count, 1);
        assert_eq!(timers.expire(new[0].unwrap(), &waits).unwrap().len(), 0);
        assert_eq!(timers.current_signals(key), Ok(DW_SIGNAL_SIGNALED));

        // A future arm clears SIGNALED. If its token is already dequeued,
        // cancel still invalidates it before late callback delivery.
        assert!(
            timers
                .set(key, DwDeadline(300), &mut deadlines, &waits)
                .unwrap()
                .len()
                == 0
        );
        assert_eq!(timers.current_signals(key), Ok(DwSignals(0)));
        let (cancelled, count) = deadlines.expire(300);
        assert_eq!(count, 1);
        timers.cancel(key, &mut deadlines).unwrap();
        assert_eq!(
            timers.expire(cancelled[0].unwrap(), &waits).unwrap().len(),
            0
        );
        assert_eq!(timers.current_signals(key), Ok(DwSignals(0)));

        let final_release = registry.release_handle(handle).unwrap().unwrap();
        let finalization = timers
            .take_finalization(final_release, &mut deadlines)
            .unwrap();
        complete_timer_finalization(&mut registry, finalization);
    }

    #[test]
    fn capacity_failure_and_repeated_cancelled_expiry_leave_timer_state_exact() {
        let mut registry = ObjectRegistry::<4>::new();
        let timers = TimerAuthority::<2>::new();
        let waits = WaitRegistry::<2>::new();
        let mut deadlines = HostDeadlines::<1>::new(10);
        let (first_key, first_handle) = timers.create_timer(&mut registry).unwrap();
        let (second_key, second_handle) = timers.create_timer(&mut registry).unwrap();

        let first_wakes = timers
            .set(first_key, DwDeadline(100), &mut deadlines, &waits)
            .unwrap();
        assert_eq!(first_wakes.len(), 0);
        let (wake_intents, pins) = first_wakes.into_parts();
        assert!(wake_intents.into_iter().flatten().next().is_none());
        assert!(pins.into_iter().flatten().next().is_none());
        assert!(matches!(
            timers.set(second_key, DwDeadline(200), &mut deadlines, &waits),
            Err(TimerError::Deadline(TimerDeadlineError::Capacity))
        ));
        assert_eq!(timers.current_signals(second_key), Ok(DwSignals(0)));
        assert_eq!(deadlines.queue.earliest(), Some(100));

        timers.cancel(first_key, &mut deadlines).unwrap();
        for iteration in 0..64_u64 {
            let deadline = 300 + iteration;
            let wakes = timers
                .set(second_key, DwDeadline(deadline), &mut deadlines, &waits)
                .unwrap();
            assert_eq!(wakes.len(), 0);
            let (wake_intents, pins) = wakes.into_parts();
            assert!(wake_intents.into_iter().flatten().next().is_none());
            assert!(pins.into_iter().flatten().next().is_none());
            let (expired, count) = deadlines.expire(deadline);
            assert_eq!(count, 1);
            let token = expired[0].expect("one Timer token dequeued");
            timers.cancel(second_key, &mut deadlines).unwrap();
            assert_eq!(timers.expire(token, &waits).unwrap().len(), 0);
            assert_eq!(timers.current_signals(second_key), Ok(DwSignals(0)));
        }

        let wakes = timers
            .set(second_key, DwDeadline(500), &mut deadlines, &waits)
            .unwrap();
        let (wake_intents, pins) = wakes.into_parts();
        assert!(wake_intents.into_iter().flatten().next().is_none());
        assert!(pins.into_iter().flatten().next().is_none());
        let (expired, count) = deadlines.expire(500);
        assert_eq!(count, 1);
        let token = expired[0].unwrap();
        assert_eq!(timers.expire(token, &waits).unwrap().len(), 0);
        assert_eq!(timers.current_signals(second_key), Ok(DW_SIGNAL_SIGNALED));
        assert_eq!(timers.expire(token, &waits).unwrap().len(), 0);
        assert_eq!(timers.current_signals(second_key), Ok(DW_SIGNAL_SIGNALED));

        for handle in [first_handle, second_handle] {
            let release = registry.release_handle(handle).unwrap().unwrap();
            let finalization = timers.take_finalization(release, &mut deadlines).unwrap();
            complete_timer_finalization(&mut registry, finalization);
        }
    }

    #[test]
    fn immediate_deadline_signals_and_future_set_resets_level_state() {
        let mut registry = ObjectRegistry::<2>::new();
        let timers = TimerAuthority::<1>::new();
        let waits = WaitRegistry::<2>::new();
        let mut deadlines = HostDeadlines::<2>::new(50);
        let (key, handle) = timers.create_timer(&mut registry).unwrap();

        assert_eq!(timers.current_signals(key), Ok(DwSignals(0)));
        assert_eq!(
            timers
                .set(key, DwDeadline(50), &mut deadlines, &waits)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(timers.current_signals(key), Ok(DW_SIGNAL_SIGNALED));
        assert_eq!(deadlines.queue.earliest(), None);

        assert_eq!(
            timers
                .set(key, DwDeadline(75), &mut deadlines, &waits)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(timers.current_signals(key), Ok(DwSignals(0)));
        assert_eq!(deadlines.queue.earliest(), Some(75));
        timers.cancel(key, &mut deadlines).unwrap();
        assert_eq!(timers.current_signals(key), Ok(DwSignals(0)));
        assert_eq!(deadlines.queue.earliest(), None);
        assert!(matches!(
            timers.set(key, DW_DEADLINE_INFINITE, &mut deadlines, &waits),
            Err(TimerError::InvalidDeadline)
        ));

        let final_release = registry.release_handle(handle).unwrap().unwrap();
        let finalization = timers
            .take_finalization(final_release, &mut deadlines)
            .unwrap();
        complete_timer_finalization(&mut registry, finalization);
    }

    #[test]
    fn expiry_returns_irq_safe_wake_intent_without_consuming_wait_pin() {
        let mut registry = ObjectRegistry::<4>::new();
        let timers = TimerAuthority::<1>::new();
        let waits = WaitRegistry::<2>::new();
        let mut deadlines = HostDeadlines::<2>::new(10);
        let (key, handle) = timers.create_timer(&mut registry).unwrap();
        let wait_pin = registry.retain_internal_from_handle(&handle).unwrap();
        let (thread, wake) = block_wake();
        let _registration = waits
            .register(wait_pin, DW_SIGNAL_SIGNALED, 3, thread, wake)
            .unwrap();
        assert_eq!(waits.len(), 1);

        assert_eq!(
            timers
                .set(key, DwDeadline(20), &mut deadlines, &waits)
                .unwrap()
                .len(),
            0
        );
        let (expired, count) = deadlines.expire(20);
        assert_eq!(count, 1);
        let batch = timers.expire(expired[0].unwrap(), &waits).unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch.pin_len(), 0);
        let (wakes, pins) = batch.into_parts();
        let intent = wakes[0].expect("one Timer waiter wake intent");
        assert_eq!(intent.wake_key(), wake);
        assert_eq!(intent.item_index(), 3);
        assert_eq!(intent.observed(), DW_SIGNAL_SIGNALED);
        assert!(pins.into_iter().flatten().next().is_none());
        assert_eq!(waits.len(), 1, "IRQ readiness scan retains registrations");

        let cancelled = waits.cancel_generation(wake);
        let (_, pins) = cancelled.into_parts();
        for pin in pins.into_iter().flatten() {
            assert!(registry.release_internal(pin).unwrap().is_none());
        }
        let final_release = registry.release_handle(handle).unwrap().unwrap();
        let finalization = timers
            .take_finalization(final_release, &mut deadlines)
            .unwrap();
        complete_timer_finalization(&mut registry, finalization);
    }

    #[test]
    fn ready_timer_wait_uses_level_signal_and_armed_finalization_cancels_deadline() {
        let mut registry = ObjectRegistry::<4>::new();
        let timers = TimerAuthority::<1>::new();
        let waits = WaitRegistry::<2>::new();
        let mut deadlines = HostDeadlines::<2>::new(100);
        let (key, handle) = timers.create_timer(&mut registry).unwrap();
        assert_eq!(
            timers
                .set(key, DwDeadline(100), &mut deadlines, &waits)
                .unwrap()
                .len(),
            0
        );

        let owner = registry.retain_internal_from_handle(&handle).unwrap();
        let target = crate::handle::resolve_test_internal_owner(
            &mut registry,
            &owner,
            dw_object_compatible_rights(DW_OBJECT_TYPE_TIMER),
        );
        let (thread, wake) = block_wake();
        match timers
            .register_wait(&waits, target, DW_SIGNAL_SIGNALED, 0, thread, wake)
            .unwrap()
        {
            TimerWaitOutcome::Ready { observed, pin } => {
                assert_eq!(observed, DW_SIGNAL_SIGNALED);
                assert!(registry.release_internal(pin).unwrap().is_none());
            }
            TimerWaitOutcome::Registered(_) => panic!("signaled Timer wait must be ready"),
        }
        assert!(registry.release_internal(owner).unwrap().is_none());

        // Re-arm and close the only public handle. Finalization owns exact
        // deadline cancellation before releasing the typed Timer slot.
        assert_eq!(
            timers
                .set(key, DwDeadline(200), &mut deadlines, &waits)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(deadlines.queue.earliest(), Some(200));
        let final_release = registry.release_handle(handle).unwrap().unwrap();
        let finalization = timers
            .take_finalization(final_release, &mut deadlines)
            .unwrap();
        assert_eq!(deadlines.queue.earliest(), None);
        complete_timer_finalization(&mut registry, finalization);

        let (_replacement, replacement_handle) = timers.create_timer(&mut registry).unwrap();
        let final_release = registry
            .release_handle(replacement_handle)
            .unwrap()
            .unwrap();
        let finalization = timers
            .take_finalization(final_release, &mut deadlines)
            .unwrap();
        complete_timer_finalization(&mut registry, finalization);
    }

    #[test]
    fn expiry_captures_readiness_before_rearm_can_publish_a_new_waiter() {
        let mut registry = ObjectRegistry::<8>::new();
        let timers = TimerAuthority::<1>::new();
        let waits = WaitRegistry::<4>::new();
        let deadlines = Mutex::new(HostDeadlines::<4>::new(10));
        let (key, handle) = timers.create_timer(&mut registry).unwrap();
        let old_pin = registry.retain_internal_from_handle(&handle).unwrap();
        let new_pin = registry.retain_internal_from_handle(&handle).unwrap();
        let (old_thread, old_wake) = block_wake();
        let (new_thread, new_wake) = block_wake();
        let _old_registration = waits
            .register(old_pin, DW_SIGNAL_SIGNALED, 0, old_thread, old_wake)
            .unwrap();
        assert_eq!(
            timers
                .set(
                    key,
                    DwDeadline(100),
                    &mut LockedHostDeadlines(&deadlines),
                    &waits,
                )
                .unwrap()
                .len(),
            0
        );
        let (expired, count) = deadlines.lock().unwrap().expire(100);
        assert_eq!(count, 1);
        let token = expired[0].unwrap();

        let batch = std::thread::scope(|scope| {
            let (committed_tx, committed_rx) = mpsc::channel();
            let (continue_tx, continue_rx) = mpsc::channel();
            let timers_ref = &timers;
            let waits_ref = &waits;
            let expiry = scope.spawn(move || {
                timers_ref.expire_with_readiness_hook(token, waits_ref, || {
                    committed_tx.send(()).unwrap();
                    continue_rx.recv().unwrap();
                })
            });
            committed_rx.recv().unwrap();

            let (attempting_tx, attempting_rx) = mpsc::channel();
            let (finished_tx, finished_rx) = mpsc::channel();
            let timers_ref = &timers;
            let waits_ref = &waits;
            let deadlines_ref = &deadlines;
            let rearm = scope.spawn(move || {
                attempting_tx.send(()).unwrap();
                let wakes = timers_ref
                    .set(
                        key,
                        DwDeadline(200),
                        &mut LockedHostDeadlines(deadlines_ref),
                        waits_ref,
                    )
                    .unwrap();
                assert_eq!(wakes.len(), 0);
                let _new_registration = waits_ref
                    .register(new_pin, DW_SIGNAL_SIGNALED, 1, new_thread, new_wake)
                    .unwrap();
                finished_tx.send(()).unwrap();
            });
            attempting_rx.recv().unwrap();
            assert_eq!(
                finished_rx.recv_timeout(Duration::from_millis(50)),
                Err(mpsc::RecvTimeoutError::Timeout),
                "rearm must remain behind the Timer readiness linearization point"
            );
            continue_tx.send(()).unwrap();
            let batch = expiry.join().unwrap().unwrap();
            rearm.join().unwrap();
            finished_rx.recv().unwrap();
            batch
        });

        let (wake_intents, pins) = batch.into_parts();
        assert!(pins.into_iter().flatten().next().is_none());
        let intents: std::vec::Vec<_> = wake_intents.into_iter().flatten().collect();
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].wake_key(), old_wake);
        assert_ne!(intents[0].wake_key(), new_wake);
        assert_eq!(waits.len(), 2);

        for wake in [old_wake, new_wake] {
            let (_, pins) = waits.cancel_generation(wake).into_parts();
            for pin in pins.into_iter().flatten() {
                assert!(registry.release_internal(pin).unwrap().is_none());
            }
        }
        let final_release = registry.release_handle(handle).unwrap().unwrap();
        let finalization = timers
            .take_finalization(final_release, &mut LockedHostDeadlines(&deadlines))
            .unwrap();
        complete_timer_finalization(&mut registry, finalization);
    }

    #[test]
    fn immediate_set_captures_readiness_before_rearm_can_publish_a_new_waiter() {
        let mut registry = ObjectRegistry::<8>::new();
        let timers = TimerAuthority::<1>::new();
        let waits = WaitRegistry::<4>::new();
        let deadlines = Mutex::new(HostDeadlines::<4>::new(50));
        let (key, handle) = timers.create_timer(&mut registry).unwrap();
        let old_pin = registry.retain_internal_from_handle(&handle).unwrap();
        let new_pin = registry.retain_internal_from_handle(&handle).unwrap();
        let (old_thread, old_wake) = block_wake();
        let (new_thread, new_wake) = block_wake();
        let _old_registration = waits
            .register(old_pin, DW_SIGNAL_SIGNALED, 0, old_thread, old_wake)
            .unwrap();

        let batch = std::thread::scope(|scope| {
            let (committed_tx, committed_rx) = mpsc::channel();
            let (continue_tx, continue_rx) = mpsc::channel();
            let timers_ref = &timers;
            let waits_ref = &waits;
            let deadlines_ref = &deadlines;
            let immediate = scope.spawn(move || {
                timers_ref.set_with_readiness_hook(
                    key,
                    DwDeadline(50),
                    &mut LockedHostDeadlines(deadlines_ref),
                    waits_ref,
                    || {
                        committed_tx.send(()).unwrap();
                        continue_rx.recv().unwrap();
                    },
                )
            });
            committed_rx.recv().unwrap();

            let (attempting_tx, attempting_rx) = mpsc::channel();
            let (finished_tx, finished_rx) = mpsc::channel();
            let timers_ref = &timers;
            let waits_ref = &waits;
            let deadlines_ref = &deadlines;
            let rearm = scope.spawn(move || {
                attempting_tx.send(()).unwrap();
                let wakes = timers_ref
                    .set(
                        key,
                        DwDeadline(75),
                        &mut LockedHostDeadlines(deadlines_ref),
                        waits_ref,
                    )
                    .unwrap();
                assert_eq!(wakes.len(), 0);
                let _new_registration = waits_ref
                    .register(new_pin, DW_SIGNAL_SIGNALED, 1, new_thread, new_wake)
                    .unwrap();
                finished_tx.send(()).unwrap();
            });
            attempting_rx.recv().unwrap();
            assert_eq!(
                finished_rx.recv_timeout(Duration::from_millis(50)),
                Err(mpsc::RecvTimeoutError::Timeout),
                "rearm must remain behind the immediate-set readiness point"
            );
            continue_tx.send(()).unwrap();
            let batch = immediate.join().unwrap().unwrap();
            rearm.join().unwrap();
            finished_rx.recv().unwrap();
            batch
        });

        let (wake_intents, pins) = batch.into_parts();
        let intents: std::vec::Vec<_> = wake_intents.into_iter().flatten().collect();
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].wake_key(), old_wake);
        assert_ne!(intents[0].wake_key(), new_wake);
        let released: std::vec::Vec<_> = pins.into_iter().flatten().collect();
        assert_eq!(released.len(), 1);
        assert!(
            registry
                .release_internal(released.into_iter().next().unwrap())
                .unwrap()
                .is_none()
        );
        assert_eq!(waits.len(), 1);

        let (_, pins) = waits.cancel_generation(new_wake).into_parts();
        for pin in pins.into_iter().flatten() {
            assert!(registry.release_internal(pin).unwrap().is_none());
        }
        let final_release = registry.release_handle(handle).unwrap().unwrap();
        let finalization = timers
            .take_finalization(final_release, &mut LockedHostDeadlines(&deadlines))
            .unwrap();
        complete_timer_finalization(&mut registry, finalization);
    }

    #[test]
    fn cancel_rearm_and_timeout_keep_one_exact_wait_winner() {
        let mut registry = ObjectRegistry::<8>::new();
        let timers = TimerAuthority::<1>::new();
        let waits = WaitRegistry::<2>::new();
        let mut deadlines = HostDeadlines::<2>::new(10);
        let (key, handle) = timers.create_timer(&mut registry).unwrap();
        let pin = registry.retain_internal_from_handle(&handle).unwrap();
        let (thread, wake) = block_wake();
        let _registration = waits
            .register(pin, DW_SIGNAL_SIGNALED, 0, thread, wake)
            .unwrap();

        let process_creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
        let process = ProcessKey::from_object_id(process_creation.id());
        registry.cancel_creation(process_creation).unwrap();
        let ledger = BlockedOperationRegistry::<1>::new();
        let blocked = BlockedOperation::publish(&ledger, process, thread, wake, ()).unwrap();

        assert_eq!(
            timers
                .set(key, DwDeadline(100), &mut deadlines, &waits)
                .unwrap()
                .len(),
            0
        );
        let (old, count) = deadlines.expire(100);
        assert_eq!(count, 1);
        timers.cancel(key, &mut deadlines).unwrap();
        assert_eq!(
            timers
                .set(key, DwDeadline(200), &mut deadlines, &waits)
                .unwrap()
                .len(),
            0
        );
        assert!(
            ledger
                .try_claim_winner(wake, BlockedOperationWinner::Timeout)
                .unwrap()
        );
        assert_eq!(timers.expire(old[0].unwrap(), &waits).unwrap().len(), 0);

        let (current, count) = deadlines.expire(200);
        assert_eq!(count, 1);
        let wakes = timers.expire(current[0].unwrap(), &waits).unwrap();
        let (wake_intents, pins) = wakes.into_parts();
        assert!(pins.into_iter().flatten().next().is_none());
        let intent = wake_intents.into_iter().flatten().next().unwrap();
        let signal = BlockedOperationWinner::Signal {
            item_index: intent.item_index(),
            observed: intent.observed(),
        };
        assert!(!ledger.try_claim_winner(intent.wake_key(), signal).unwrap());
        assert_eq!(
            ledger.winner(wake).unwrap(),
            Some(BlockedOperationWinner::Timeout)
        );

        let (_, pins) = waits.cancel_generation(wake).into_parts();
        for pin in pins.into_iter().flatten() {
            assert!(registry.release_internal(pin).unwrap().is_none());
        }
        blocked
            .complete_with(&ledger, BlockedOperationWinner::Timeout, |()| ())
            .unwrap();
        let final_release = registry.release_handle(handle).unwrap().unwrap();
        let finalization = timers
            .take_finalization(final_release, &mut deadlines)
            .unwrap();
        complete_timer_finalization(&mut registry, finalization);
    }
}
