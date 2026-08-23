//! Bounded cross-CPU stop and wake mailbox model for DW0-H2.
//!
//! The live APIC transport is deliberately outside this module.  This model
//! owns the protocol that transport must preserve: at most one generation-
//! bound stop request is outstanding for a target CPU, a coalesced wake never
//! replaces that request, and deferred resources remain linear until the exact
//! target execution publishes an exact-safe acknowledgement.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use crate::sync::IrqSpinMutex;
use crate::task::ThreadKey;

pub(crate) const RENDEZVOUS_CPU_CAPACITY: usize = 4;

const MAILBOX_IDLE: u8 = 0;
const MAILBOX_TRANSITION: u8 = 1;
const MAILBOX_STOP_REQUESTED: u8 = 2;
const MAILBOX_STOP_SAFE: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StopIdentityError {
    InvalidCpu,
    ZeroOnlineGeneration,
    ZeroExecutionGeneration,
    ZeroRootBindingGeneration,
}

/// Exact execution identity that a remote CPU must stop.
///
/// `execution_generation` is the generation from the scheduler's running
/// claim.  The root integration seam converts `SchedulerExecutionClaim` into
/// this type once that claim is exported to the architecture layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StopIdentity {
    target_cpu: u8,
    cpu_online_generation: u64,
    thread: ThreadKey,
    execution_generation: u64,
    root_binding_generation: u64,
}

impl StopIdentity {
    pub(crate) const fn new(
        target_cpu: usize,
        cpu_online_generation: u64,
        thread: ThreadKey,
        execution_generation: u64,
        root_binding_generation: u64,
    ) -> Result<Self, StopIdentityError> {
        if target_cpu >= RENDEZVOUS_CPU_CAPACITY {
            return Err(StopIdentityError::InvalidCpu);
        }
        if cpu_online_generation == 0 {
            return Err(StopIdentityError::ZeroOnlineGeneration);
        }
        if execution_generation == 0 {
            return Err(StopIdentityError::ZeroExecutionGeneration);
        }
        if root_binding_generation == 0 {
            return Err(StopIdentityError::ZeroRootBindingGeneration);
        }
        Ok(Self {
            target_cpu: target_cpu as u8,
            cpu_online_generation,
            thread,
            execution_generation,
            root_binding_generation,
        })
    }

    pub(crate) const fn target_cpu(self) -> usize {
        self.target_cpu as usize
    }

    pub(crate) const fn cpu_online_generation(self) -> u64 {
        self.cpu_online_generation
    }

    pub(crate) const fn thread(self) -> ThreadKey {
        self.thread
    }

    pub(crate) const fn execution_generation(self) -> u64 {
        self.execution_generation
    }

    pub(crate) const fn root_binding_generation(self) -> u64 {
        self.root_binding_generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StopRequest {
    mailbox_generation: u64,
    identity: StopIdentity,
}

impl StopRequest {
    pub(crate) const fn mailbox_generation(self) -> u64 {
        self.mailbox_generation
    }

    pub(crate) const fn identity(self) -> StopIdentity {
        self.identity
    }
}

/// Observable conditions required before a remote CPU may acknowledge Safe.
///
/// The live rendezvous handler must establish every condition while parked on
/// its CPU-private entry stack.  Keeping these facts explicit prevents an IPI
/// receipt alone from being confused with permission to reclaim execution
/// resources.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SafePointConditions {
    pub(crate) parked_on_cpu_private_stack: bool,
    pub(crate) scheduler_ownership_released: bool,
    pub(crate) user_access_disabled: bool,
    pub(crate) deferred_cleanup_quiescent: bool,
}

impl SafePointConditions {
    pub(crate) const EXACT_SAFE: Self = Self {
        parked_on_cpu_private_stack: true,
        scheduler_ownership_released: true,
        user_access_disabled: true,
        deferred_cleanup_quiescent: true,
    };

    const fn is_exact_safe(self) -> bool {
        self.parked_on_cpu_private_stack
            && self.scheduler_ownership_released
            && self.user_access_disabled
            && self.deferred_cleanup_quiescent
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StopObservation {
    pub(crate) identity: StopIdentity,
    pub(crate) conditions: SafePointConditions,
}

/// Move-only proof that the currently published request was observed at Safe.
#[must_use = "an exact-safe proof must be acknowledged or discarded without changing mailbox state"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ExactSafeProof {
    request: StopRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MailboxNotification {
    None,
    Wake,
    Stop(StopRequest),
    HoldSafe(StopRequest),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StopPublishError {
    WrongTargetCpu,
    Busy,
    GenerationExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SafeProofError {
    NoStopRequested,
    AlreadyAcknowledged,
    WrongIdentity,
    NotSafe,
    StaleRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReclaimError {
    WrongMailbox,
    AwaitingAcknowledgement,
    StaleRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeferredFailure {
    Transport,
    Timeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RetainedFailure {
    pub(crate) request: StopRequest,
    pub(crate) failure: DeferredFailure,
}

#[must_use = "failed publication returns ownership of the unreclaimed resource"]
#[derive(Debug)]
pub(crate) struct StopPublishFailure<R> {
    error: StopPublishError,
    resource: R,
}

impl<R> StopPublishFailure<R> {
    pub(crate) const fn error(&self) -> StopPublishError {
        self.error
    }

    pub(crate) fn into_resource(self) -> R {
        self.resource
    }
}

/// Linear ownership retained while a remote execution may still reference it.
#[must_use = "remote execution resources must remain deferred until exact-safe acknowledgement"]
#[derive(Debug)]
pub(crate) struct DeferredReclaim<R> {
    request: StopRequest,
    resource: Option<R>,
}

impl<R> DeferredReclaim<R> {
    pub(crate) const fn request(&self) -> StopRequest {
        self.request
    }
}

impl<R> Drop for DeferredReclaim<R> {
    fn drop(&mut self) {
        assert!(
            self.resource.is_none(),
            "remote execution resources dropped before exact-safe acknowledgement"
        );
    }
}

#[must_use = "failed reclaim returns the still-linear deferred ownership"]
#[derive(Debug)]
pub(crate) struct ReclaimFailure<R> {
    error: ReclaimError,
    deferred: DeferredReclaim<R>,
}

impl<R> ReclaimFailure<R> {
    pub(crate) const fn error(&self) -> ReclaimError {
        self.error
    }

    pub(crate) fn into_deferred(self) -> DeferredReclaim<R> {
        self.deferred
    }
}

/// One bounded mailbox owned by one logical target CPU.
pub(crate) struct RendezvousMailbox {
    target_cpu: u8,
    state: AtomicU8,
    next_generation: AtomicU64,
    wake_pending: AtomicBool,
    request: IrqSpinMutex<Option<StopRequest>>,
}

impl RendezvousMailbox {
    pub(crate) const fn new(target_cpu: usize) -> Option<Self> {
        if target_cpu >= RENDEZVOUS_CPU_CAPACITY {
            return None;
        }
        Some(Self {
            target_cpu: target_cpu as u8,
            state: AtomicU8::new(MAILBOX_IDLE),
            next_generation: AtomicU64::new(1),
            wake_pending: AtomicBool::new(false),
            request: IrqSpinMutex::new(None),
        })
    }

    #[cfg(test)]
    const fn with_next_generation_for_test(target_cpu: usize, next_generation: u64) -> Self {
        Self {
            target_cpu: target_cpu as u8,
            state: AtomicU8::new(MAILBOX_IDLE),
            next_generation: AtomicU64::new(next_generation),
            wake_pending: AtomicBool::new(false),
            request: IrqSpinMutex::new(None),
        }
    }

    fn mint_generation(&self) -> Option<u64> {
        let mut current = self.next_generation.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                return None;
            }
            let next = current.checked_add(1).unwrap_or(0);
            match self.next_generation.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(current),
                Err(observed) => current = observed,
            }
        }
    }

    pub(crate) fn publish_stop<R>(
        &self,
        identity: StopIdentity,
        resource: R,
    ) -> Result<DeferredReclaim<R>, StopPublishFailure<R>> {
        if identity.target_cpu != self.target_cpu {
            return Err(StopPublishFailure {
                error: StopPublishError::WrongTargetCpu,
                resource,
            });
        }
        if self
            .state
            .compare_exchange(
                MAILBOX_IDLE,
                MAILBOX_TRANSITION,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return Err(StopPublishFailure {
                error: StopPublishError::Busy,
                resource,
            });
        }
        let Some(mailbox_generation) = self.mint_generation() else {
            self.state.store(MAILBOX_IDLE, Ordering::Release);
            return Err(StopPublishFailure {
                error: StopPublishError::GenerationExhausted,
                resource,
            });
        };
        let request = StopRequest {
            mailbox_generation,
            identity,
        };
        let replaced = self.request.lock().replace(request);
        debug_assert!(replaced.is_none());
        self.state.store(MAILBOX_STOP_REQUESTED, Ordering::Release);
        Ok(DeferredReclaim {
            request,
            resource: Some(resource),
        })
    }

    /// Coalesces a wake without modifying the stop state or request payload.
    pub(crate) fn publish_wake(&self) {
        self.wake_pending.store(true, Ordering::Release);
    }

    /// Acquires the published request before returning it to the target CPU.
    pub(crate) fn take_notification(&self) -> MailboxNotification {
        match self.state.load(Ordering::Acquire) {
            MAILBOX_STOP_REQUESTED => MailboxNotification::Stop(self.current_request()),
            MAILBOX_STOP_SAFE => MailboxNotification::HoldSafe(self.current_request()),
            MAILBOX_IDLE => {
                if !self.wake_pending.swap(false, Ordering::AcqRel) {
                    return MailboxNotification::None;
                }
                match self.state.load(Ordering::Acquire) {
                    MAILBOX_STOP_REQUESTED => MailboxNotification::Stop(self.current_request()),
                    MAILBOX_STOP_SAFE => MailboxNotification::HoldSafe(self.current_request()),
                    MAILBOX_IDLE => MailboxNotification::Wake,
                    _ => {
                        self.wake_pending.store(true, Ordering::Release);
                        MailboxNotification::None
                    }
                }
            }
            _ => MailboxNotification::None,
        }
    }

    fn current_request(&self) -> StopRequest {
        self.request
            .lock()
            .expect("published rendezvous state has a request")
    }

    /// Validates the exact target tuple and every safe-point condition.
    pub(crate) fn prove_exact_safe(
        &self,
        observation: StopObservation,
    ) -> Result<ExactSafeProof, SafeProofError> {
        match self.state.load(Ordering::Acquire) {
            MAILBOX_STOP_SAFE => return Err(SafeProofError::AlreadyAcknowledged),
            MAILBOX_STOP_REQUESTED => {}
            _ => return Err(SafeProofError::NoStopRequested),
        }
        let request = self.current_request();
        if request.identity != observation.identity {
            return Err(SafeProofError::WrongIdentity);
        }
        if !observation.conditions.is_exact_safe() {
            return Err(SafeProofError::NotSafe);
        }
        Ok(ExactSafeProof { request })
    }

    /// Release-publishes Safe only for the still-current exact request.
    pub(crate) fn acknowledge_exact_safe(
        &self,
        proof: ExactSafeProof,
    ) -> Result<(), SafeProofError> {
        match self.state.load(Ordering::Acquire) {
            MAILBOX_STOP_SAFE => return Err(SafeProofError::AlreadyAcknowledged),
            MAILBOX_STOP_REQUESTED => {}
            _ => return Err(SafeProofError::StaleRequest),
        }
        if self.current_request() != proof.request {
            return Err(SafeProofError::StaleRequest);
        }
        self.state
            .compare_exchange(
                MAILBOX_STOP_REQUESTED,
                MAILBOX_STOP_SAFE,
                Ordering::Release,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|state| {
                if state == MAILBOX_STOP_SAFE {
                    SafeProofError::AlreadyAcknowledged
                } else {
                    SafeProofError::StaleRequest
                }
            })
    }

    /// Records a timeout or transport failure without consuming ownership.
    pub(crate) fn retain_after_failure<R>(
        &self,
        deferred: &DeferredReclaim<R>,
        failure: DeferredFailure,
    ) -> Result<RetainedFailure, ReclaimError> {
        if deferred.request.identity.target_cpu != self.target_cpu {
            return Err(ReclaimError::WrongMailbox);
        }
        let state = self.state.load(Ordering::Acquire);
        if !matches!(state, MAILBOX_STOP_REQUESTED | MAILBOX_STOP_SAFE)
            || self.current_request() != deferred.request
        {
            return Err(ReclaimError::StaleRequest);
        }
        Ok(RetainedFailure {
            request: deferred.request,
            failure,
        })
    }

    /// Acquires Safe and returns the resource only for the exact request.
    pub(crate) fn complete_reclaim<R>(
        &self,
        mut deferred: DeferredReclaim<R>,
    ) -> Result<R, ReclaimFailure<R>> {
        if deferred.request.identity.target_cpu != self.target_cpu {
            return Err(ReclaimFailure {
                error: ReclaimError::WrongMailbox,
                deferred,
            });
        }
        if self.state.load(Ordering::Acquire) != MAILBOX_STOP_SAFE {
            return Err(ReclaimFailure {
                error: ReclaimError::AwaitingAcknowledgement,
                deferred,
            });
        }
        let mut published = self.request.lock();
        if *published != Some(deferred.request) {
            return Err(ReclaimFailure {
                error: ReclaimError::StaleRequest,
                deferred,
            });
        }
        if self
            .state
            .compare_exchange(
                MAILBOX_STOP_SAFE,
                MAILBOX_TRANSITION,
                Ordering::Acquire,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(ReclaimFailure {
                error: ReclaimError::StaleRequest,
                deferred,
            });
        }
        let removed = published.take();
        debug_assert_eq!(removed, Some(deferred.request));
        drop(published);
        self.state.store(MAILBOX_IDLE, Ordering::Release);
        Ok(deferred
            .resource
            .take()
            .expect("live deferred reclaim owns its resource"))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::sync::{Arc, Barrier};
    use std::thread;

    use deepwyrm_abi::DW_OBJECT_TYPE_THREAD;

    use super::*;
    use crate::object::ObjectRegistry;

    fn thread_key(objects: &mut ObjectRegistry<8>) -> ThreadKey {
        let creation = objects.create(DW_OBJECT_TYPE_THREAD).unwrap();
        let key = ThreadKey::from_object_id(creation.id());
        objects.cancel_creation(creation).unwrap();
        key
    }

    fn identity(thread: ThreadKey) -> StopIdentity {
        StopIdentity::new(2, 7, thread, 11, 13).unwrap()
    }

    fn acknowledge(mailbox: &RendezvousMailbox, identity: StopIdentity) {
        let proof = mailbox
            .prove_exact_safe(StopObservation {
                identity,
                conditions: SafePointConditions::EXACT_SAFE,
            })
            .unwrap();
        mailbox.acknowledge_exact_safe(proof).unwrap();
    }

    #[test]
    fn stop_request_has_priority_over_wake_and_requires_exact_safe_tuple() {
        let mut objects = ObjectRegistry::<8>::new();
        let thread = thread_key(&mut objects);
        let other_thread = thread_key(&mut objects);
        let mailbox = RendezvousMailbox::new(2).unwrap();
        let deferred = mailbox.publish_stop(identity(thread), 41_u64).unwrap();
        mailbox.publish_wake();
        assert_eq!(
            mailbox.take_notification(),
            MailboxNotification::Stop(deferred.request())
        );

        let mut wrong = identity(thread);
        wrong.cpu_online_generation += 1;
        assert_eq!(
            mailbox.prove_exact_safe(StopObservation {
                identity: wrong,
                conditions: SafePointConditions::EXACT_SAFE,
            }),
            Err(SafeProofError::WrongIdentity)
        );
        wrong = identity(other_thread);
        assert_eq!(
            mailbox.prove_exact_safe(StopObservation {
                identity: wrong,
                conditions: SafePointConditions::EXACT_SAFE,
            }),
            Err(SafeProofError::WrongIdentity)
        );
        let mut unsafe_conditions = SafePointConditions::EXACT_SAFE;
        unsafe_conditions.deferred_cleanup_quiescent = false;
        assert_eq!(
            mailbox.prove_exact_safe(StopObservation {
                identity: identity(thread),
                conditions: unsafe_conditions,
            }),
            Err(SafeProofError::NotSafe)
        );

        acknowledge(&mailbox, identity(thread));
        assert_eq!(
            mailbox.take_notification(),
            MailboxNotification::HoldSafe(deferred.request())
        );
        assert_eq!(mailbox.complete_reclaim(deferred).unwrap(), 41);
    }

    #[test]
    fn busy_stale_duplicate_timeout_and_transport_paths_retain_ownership() {
        let mut objects = ObjectRegistry::<8>::new();
        let thread = thread_key(&mut objects);
        let mailbox = RendezvousMailbox::new(2).unwrap();
        let wrong_mailbox = RendezvousMailbox::new(1).unwrap();
        let mut deferred = mailbox.publish_stop(identity(thread), 77_u64).unwrap();

        let busy = mailbox.publish_stop(identity(thread), 88_u64).unwrap_err();
        assert_eq!(busy.error(), StopPublishError::Busy);
        assert_eq!(busy.into_resource(), 88);
        assert_eq!(
            mailbox
                .retain_after_failure(&deferred, DeferredFailure::Transport)
                .unwrap()
                .failure,
            DeferredFailure::Transport
        );
        assert_eq!(
            mailbox
                .retain_after_failure(&deferred, DeferredFailure::Timeout)
                .unwrap()
                .request,
            deferred.request()
        );

        let failure = wrong_mailbox.complete_reclaim(deferred).unwrap_err();
        assert_eq!(failure.error(), ReclaimError::WrongMailbox);
        deferred = failure.into_deferred();
        let failure = mailbox.complete_reclaim(deferred).unwrap_err();
        assert_eq!(failure.error(), ReclaimError::AwaitingAcknowledgement);
        deferred = failure.into_deferred();

        let proof = mailbox
            .prove_exact_safe(StopObservation {
                identity: identity(thread),
                conditions: SafePointConditions::EXACT_SAFE,
            })
            .unwrap();
        mailbox.acknowledge_exact_safe(proof).unwrap();
        assert_eq!(
            mailbox.prove_exact_safe(StopObservation {
                identity: identity(thread),
                conditions: SafePointConditions::EXACT_SAFE,
            }),
            Err(SafeProofError::AlreadyAcknowledged)
        );
        assert_eq!(mailbox.complete_reclaim(deferred).unwrap(), 77);
    }

    #[test]
    fn request_ack_release_acquire_handoff_is_cross_thread_safe() {
        let mut objects = ObjectRegistry::<8>::new();
        let stop_identity = identity(thread_key(&mut objects));
        let mailbox = Arc::new(RendezvousMailbox::new(2).unwrap());
        let start = Arc::new(Barrier::new(2));
        let target_mailbox = Arc::clone(&mailbox);
        let target_start = Arc::clone(&start);
        let target = thread::spawn(move || {
            target_start.wait();
            for _ in 0..10_000 {
                if let MailboxNotification::Stop(request) = target_mailbox.take_notification() {
                    assert_eq!(request.identity(), stop_identity);
                    acknowledge(&target_mailbox, stop_identity);
                    return;
                }
                thread::yield_now();
            }
            panic!("target did not acquire the published stop request");
        });

        let deferred = mailbox.publish_stop(stop_identity, 99_u64).unwrap();
        start.wait();
        target.join().unwrap();
        assert_eq!(mailbox.complete_reclaim(deferred).unwrap(), 99);
    }

    #[test]
    fn generation_exhaustion_fails_closed_after_last_nonzero_request() {
        let mut objects = ObjectRegistry::<8>::new();
        let stop_identity = identity(thread_key(&mut objects));
        let mailbox = RendezvousMailbox::with_next_generation_for_test(2, u64::MAX);
        let deferred = mailbox.publish_stop(stop_identity, 5_u64).unwrap();
        assert_eq!(deferred.request().mailbox_generation(), u64::MAX);
        acknowledge(&mailbox, stop_identity);
        assert_eq!(mailbox.complete_reclaim(deferred).unwrap(), 5);

        let exhausted = mailbox.publish_stop(stop_identity, 6_u64).unwrap_err();
        assert_eq!(exhausted.error(), StopPublishError::GenerationExhausted);
        assert_eq!(exhausted.into_resource(), 6);
        assert_eq!(mailbox.take_notification(), MailboxNotification::None);
    }

    #[test]
    fn identity_rejects_zero_generations_and_out_of_range_cpu() {
        let mut objects = ObjectRegistry::<8>::new();
        let thread = thread_key(&mut objects);
        assert_eq!(
            StopIdentity::new(RENDEZVOUS_CPU_CAPACITY, 1, thread, 1, 1),
            Err(StopIdentityError::InvalidCpu)
        );
        assert_eq!(
            StopIdentity::new(0, 0, thread, 1, 1),
            Err(StopIdentityError::ZeroOnlineGeneration)
        );
        assert_eq!(
            StopIdentity::new(0, 1, thread, 0, 1),
            Err(StopIdentityError::ZeroExecutionGeneration)
        );
        assert_eq!(
            StopIdentity::new(0, 1, thread, 1, 0),
            Err(StopIdentityError::ZeroRootBindingGeneration)
        );
    }
}
