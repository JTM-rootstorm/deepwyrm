//! Bounded cross-CPU stop and wake mailbox model for DW0-H2.
//!
//! The live APIC transport is deliberately outside this module.  This model
//! owns the protocol that transport must preserve: at most one generation-
//! bound stop request is outstanding for a target CPU, a coalesced wake never
//! replaces that request, and deferred resources remain linear until the exact
//! target execution publishes an exact-safe acknowledgement.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use crate::cpu::{CPU_CAPACITY, CpuIndex};
use crate::sync::IrqSpinMutex;
use crate::task::{SchedulerExecutionClaim, ThreadKey};

pub(crate) const RENDEZVOUS_CPU_CAPACITY: usize = CPU_CAPACITY;

const MAILBOX_IDLE: u8 = 0;
const MAILBOX_TRANSITION: u8 = 1;
const MAILBOX_STOP_REQUESTED: u8 = 2;
const MAILBOX_STOP_SAFE: u8 = 3;

/// IRQ-side handoff for fixed e1 delivery.
///
/// The interrupt callback is intentionally unable to inspect a mailbox or
/// scheduler state.  It records only that its CPU must revisit its mailbox at
/// a carrier-owned safe point after EOI.  Coalescing is sufficient: a stop
/// request remains generation-bound in the mailbox until exact acknowledgement
/// and a wake merely requires one scheduler rescan.
pub(crate) struct RendezvousIpiLatches {
    pending: [AtomicBool; RENDEZVOUS_CPU_CAPACITY],
}

impl RendezvousIpiLatches {
    pub(crate) const fn new() -> Self {
        Self {
            pending: [const { AtomicBool::new(false) }; RENDEZVOUS_CPU_CAPACITY],
        }
    }

    /// Release-publishes one bounded post-EOI rescan/stop check.
    pub(crate) fn latch(&self, cpu: CpuIndex) {
        self.pending[cpu.index()].store(true, Ordering::Release);
    }

    /// Acquires and clears the current CPU's coalesced handoff bit.
    pub(crate) fn take(&self, cpu: CpuIndex) -> bool {
        self.pending[cpu.index()].swap(false, Ordering::AcqRel)
    }

    /// Acquires whether a carrier-safe rescan is already required without
    /// consuming it. Idle uses this immediately before publishing `Halted` so
    /// an EOI-completed interrupt cannot be slept through.
    pub(crate) fn is_pending(&self, cpu: CpuIndex) -> bool {
        self.pending[cpu.index()].load(Ordering::Acquire)
    }
}

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
    target_cpu: CpuIndex,
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
        let target_cpu = match CpuIndex::new(target_cpu) {
            Some(cpu) => cpu,
            None => return Err(StopIdentityError::InvalidCpu),
        };
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
            target_cpu,
            cpu_online_generation,
            thread,
            execution_generation,
            root_binding_generation,
        })
    }

    pub(crate) const fn target_cpu(self) -> usize {
        self.target_cpu.index()
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

    pub(crate) const fn from_scheduler_claim(
        cpu_online_generation: u64,
        claim: SchedulerExecutionClaim,
        root_binding_generation: u64,
    ) -> Result<Self, StopIdentityError> {
        Self::new(
            claim.cpu().index(),
            cpu_online_generation,
            claim.thread(),
            claim.generation(),
            root_binding_generation,
        )
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

/// H0 facts observed by the architecture/carrier before it commits a stop.
///
/// This is deliberately not the acknowledgement proof. It is an input to the
/// private verifier below, which binds all observations to one exact request
/// and returns a move-only witness. A carrier must obtain these facts on its
/// CPU-private safe/reaper stack, after disabling user access and preventing
/// any return to the stopped continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SafePointPrecommitObservation {
    pub(crate) identity: StopIdentity,
    pub(crate) cpu_private_safe_stack: bool,
    pub(crate) user_access_disabled: bool,
    pub(crate) user_return_prevented: bool,
}

/// Move-only authorization to enter the irreversible stop commit phase.
///
/// Only `ExactSafePrecommit::verify` can mint this type. It is consumed by
/// the final Release acknowledgement, so a carrier cannot accidentally reuse
/// observations from another CPU, generation, or mailbox request.
#[must_use = "an exact-safe precommit witness must be committed or fail-stop"]
#[derive(Debug)]
pub(crate) struct ExactSafeWitness {
    request: StopRequest,
}

/// Move-only evidence that the native e1 path has diverged onto the current
/// CPU's terminal reaper stack after native dispatch released its usercopy
/// window.  It is deliberately minted only by the target architecture seam;
/// host models continue to exercise `SafePointPrecommitObservation` directly.
#[must_use = "a native rendezvous reaper arrival must be consumed by the stop safe point"]
pub(crate) struct NativeRendezvousReaperEntry {
    _private: (),
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn verify_native_rendezvous_reaper_entry() -> Option<NativeRendezvousReaperEntry> {
    (crate::arch::x86_64::syscall::current_cpu_is_on_terminal_reaper_stack()
        && crate::arch::x86_64::syscall::current_native_usercopy_is_quiescent())
    .then_some(NativeRendezvousReaperEntry { _private: () })
}

/// Private request-bound verifier supplied to a carrier precommit.
#[derive(Debug)]
pub(crate) struct ExactSafePrecommit {
    request: StopRequest,
}

impl ExactSafePrecommit {
    pub(crate) fn verify(
        self,
        observation: SafePointPrecommitObservation,
    ) -> Result<ExactSafeWitness, RemoteStopError> {
        if observation.identity != self.request.identity {
            return Err(RemoteStopError::WrongIdentity);
        }
        if !observation.cpu_private_safe_stack
            || !observation.user_access_disabled
            || !observation.user_return_prevented
        {
            return Err(RemoteStopError::UnsafePrecommit);
        }
        Ok(ExactSafeWitness {
            request: self.request,
        })
    }
}

/// CPU-owned, non-IRQ stop transition.
///
/// The implementation is reached only after the target CPU consumed a latched
/// `StopRequest` at a carrier safe point. `precommit_exact_stop` is the entire
/// recoverable phase: it must verify CPU/current Thread/execution/root
/// generations, move to a CPU-private safe/reaper stack, disable user access,
/// and prevent user return before minting `ExactSafeWitness`. Every later
/// method is an infallible-by-construction commit step and must fail-stop on
/// local architecture drift rather than publish a partial acknowledgement.
pub(crate) trait RemoteStopSafePoint {
    /// Verifies and establishes the complete precommit safe point for
    /// `identity`, then mints the request-bound witness through `precommit`.
    /// No recoverable work may remain after this returns `Ok`.
    fn precommit_exact_stop(
        &mut self,
        identity: StopIdentity,
        precommit: ExactSafePrecommit,
    ) -> Result<ExactSafeWitness, RemoteStopError>;

    /// Leaves the exact active root after its required local serialization.
    fn release_root_residency(&mut self);

    /// Removes the exact Running claim from the target CPU's scheduler slot.
    /// This follows the Process-to-kernel-root switch, so no scheduler-visible
    /// stopped execution retains user-root residency.
    fn release_running_ownership(&mut self);

    /// Confirms that no deferred cleanup still references the stopped carrier.
    fn deferred_cleanup_is_quiescent(&self) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoteStopError {
    StaleRequest,
    WrongIdentity,
    UnsafePrecommit,
    AlreadyAcknowledged,
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
    target_cpu: CpuIndex,
    state: AtomicU8,
    next_generation: AtomicU64,
    wake_pending: AtomicBool,
    request: IrqSpinMutex<Option<StopRequest>>,
}

impl RendezvousMailbox {
    pub(super) const fn for_cpu(target_cpu: CpuIndex) -> Self {
        Self {
            target_cpu,
            state: AtomicU8::new(MAILBOX_IDLE),
            next_generation: AtomicU64::new(1),
            wake_pending: AtomicBool::new(false),
            request: IrqSpinMutex::new(None),
        }
    }

    pub(crate) const fn new(target_cpu: usize) -> Option<Self> {
        let target_cpu = match CpuIndex::new(target_cpu) {
            Some(cpu) => cpu,
            None => return None,
        };
        Some(Self::for_cpu(target_cpu))
    }

    #[cfg(test)]
    const fn with_next_generation_for_test(target_cpu: usize, next_generation: u64) -> Self {
        Self {
            target_cpu: match CpuIndex::new(target_cpu) {
                Some(cpu) => cpu,
                None => panic!("test rendezvous CPU must be in range"),
            },
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

    /// Commits a remote stop on the target CPU's safe/reaper context.
    ///
    /// No interrupt handler may call this. The exact identity, safe stack,
    /// disabled user access, and prevented return are precommitted before the
    /// irreversible order `switch to kernel root and leave Process residency -> remove Running ->
    /// acknowledge`. The final acknowledgement is the
    /// existing Release publication consumed by `complete_reclaim` with
    /// Acquire, so a deferred Thread/root/stack resource cannot be reclaimed
    /// before the target has completed all four conditions.
    pub(crate) fn complete_stop_at_safe_point<T: RemoteStopSafePoint>(
        &self,
        request: StopRequest,
        target: &mut T,
    ) -> Result<(), RemoteStopError> {
        match self.state.load(Ordering::Acquire) {
            MAILBOX_STOP_SAFE => return Err(RemoteStopError::AlreadyAcknowledged),
            MAILBOX_STOP_REQUESTED => {}
            _ => return Err(RemoteStopError::StaleRequest),
        }
        if self.current_request() != request {
            return Err(RemoteStopError::StaleRequest);
        }
        let witness =
            target.precommit_exact_stop(request.identity, ExactSafePrecommit { request })?;
        target.release_root_residency();
        target.release_running_ownership();
        assert!(
            target.deferred_cleanup_is_quiescent(),
            "remote stop released execution ownership before deferred cleanup quiesced"
        );

        self.acknowledge_committed_exact_safe(witness);
        Ok(())
    }

    /// Consumes a precommit witness after the irreversible carrier release.
    ///
    /// A return from this function means the exact Safe state was
    /// Release-published. Any drift is a kernel invariant violation: returning
    /// an ordinary error here would permit a partially released carrier to
    /// resume with deferred resources still retained.
    fn acknowledge_committed_exact_safe(&self, witness: ExactSafeWitness) {
        let state = self.state.load(Ordering::Acquire);
        assert_eq!(
            state, MAILBOX_STOP_REQUESTED,
            "committed remote stop mailbox state drifted before acknowledgement"
        );
        assert_eq!(
            self.current_request(),
            witness.request,
            "committed remote stop request drifted before acknowledgement"
        );
        self.state
            .compare_exchange(
                MAILBOX_STOP_REQUESTED,
                MAILBOX_STOP_SAFE,
                Ordering::Release,
                Ordering::Acquire,
            )
            .unwrap_or_else(|state| {
                panic!("committed remote stop acknowledgement state drifted: {state}")
            });
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
        let request = match mailbox.take_notification() {
            MailboxNotification::Stop(request) => request,
            notification => panic!("expected stop request, got {notification:?}"),
        };
        let mut target = SafePointModel::new(identity);
        mailbox
            .complete_stop_at_safe_point(request, &mut target)
            .unwrap();
    }

    struct SafePointModel {
        identity: StopIdentity,
        cpu_private_safe_stack: bool,
        user_access_disabled: bool,
        user_return_prevented: bool,
        running_released: bool,
        residency_released: bool,
        cleanup_quiescent: bool,
    }

    impl SafePointModel {
        fn new(identity: StopIdentity) -> Self {
            Self {
                identity,
                cpu_private_safe_stack: true,
                user_access_disabled: true,
                user_return_prevented: false,
                running_released: false,
                residency_released: false,
                cleanup_quiescent: true,
            }
        }
    }

    impl RemoteStopSafePoint for SafePointModel {
        fn precommit_exact_stop(
            &mut self,
            identity: StopIdentity,
            precommit: ExactSafePrecommit,
        ) -> Result<ExactSafeWitness, RemoteStopError> {
            if self.identity != identity
                || self.user_return_prevented
                || self.running_released
                || self.residency_released
            {
                return Err(RemoteStopError::WrongIdentity);
            }
            if !self.cpu_private_safe_stack || !self.user_access_disabled {
                return Err(RemoteStopError::UnsafePrecommit);
            }
            assert!(!self.user_return_prevented);
            self.user_return_prevented = true;
            precommit.verify(SafePointPrecommitObservation {
                identity: self.identity,
                cpu_private_safe_stack: self.cpu_private_safe_stack,
                user_access_disabled: self.user_access_disabled,
                user_return_prevented: self.user_return_prevented,
            })
        }

        fn release_running_ownership(&mut self) {
            assert!(self.user_return_prevented);
            assert!(self.residency_released);
            assert!(!self.running_released);
            self.running_released = true;
        }

        fn release_root_residency(&mut self) {
            assert!(self.user_return_prevented);
            assert!(!self.residency_released);
            self.residency_released = true;
        }

        fn deferred_cleanup_is_quiescent(&self) -> bool {
            self.residency_released && self.cleanup_quiescent
        }
    }

    #[test]
    fn safe_point_stop_orders_return_root_running_before_release_ack() {
        let mut objects = ObjectRegistry::<8>::new();
        let stop_identity = identity(thread_key(&mut objects));
        let mailbox = RendezvousMailbox::new(stop_identity.target_cpu()).unwrap();
        let deferred = mailbox.publish_stop(stop_identity, 0x55_u64).unwrap();
        let request = match mailbox.take_notification() {
            MailboxNotification::Stop(request) => request,
            notification => panic!("expected stop request, got {notification:?}"),
        };
        let mut target = SafePointModel::new(stop_identity);
        mailbox
            .complete_stop_at_safe_point(request, &mut target)
            .unwrap();
        assert!(target.user_return_prevented);
        assert!(target.running_released);
        assert!(target.residency_released);
        assert_eq!(mailbox.complete_reclaim(deferred).unwrap(), 0x55);
    }

    #[test]
    fn safe_point_stop_requires_private_stack_and_disabled_user_access() {
        let mut objects = ObjectRegistry::<8>::new();
        let stop_identity = identity(thread_key(&mut objects));

        for missing_stack in [true, false] {
            let mailbox = RendezvousMailbox::new(stop_identity.target_cpu()).unwrap();
            let deferred = mailbox.publish_stop(stop_identity, 0x73_u64).unwrap();
            let request = match mailbox.take_notification() {
                MailboxNotification::Stop(request) => request,
                notification => panic!("expected stop request, got {notification:?}"),
            };
            let mut target = SafePointModel::new(stop_identity);
            if missing_stack {
                target.cpu_private_safe_stack = false;
            } else {
                target.user_access_disabled = false;
            }
            assert_eq!(
                mailbox.complete_stop_at_safe_point(request, &mut target),
                Err(RemoteStopError::UnsafePrecommit)
            );
            assert!(!target.running_released);
            assert!(!target.residency_released);
            let failure = mailbox.complete_reclaim(deferred).unwrap_err();
            assert_eq!(failure.error(), ReclaimError::AwaitingAcknowledgement);
            let deferred = failure.into_deferred();
            core::mem::forget(deferred);
        }
    }

    #[test]
    fn postcommit_acknowledgement_drift_fails_stop() {
        let mut objects = ObjectRegistry::<8>::new();
        let stop_identity = identity(thread_key(&mut objects));
        let mailbox = RendezvousMailbox::new(stop_identity.target_cpu()).unwrap();
        let deferred = mailbox.publish_stop(stop_identity, 0x74_u64).unwrap();
        let mismatched = StopRequest {
            mailbox_generation: deferred.request().mailbox_generation() + 1,
            identity: stop_identity,
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            mailbox.acknowledge_committed_exact_safe(ExactSafeWitness {
                request: mismatched,
            });
        }));
        assert!(result.is_err());
        let failure = mailbox.complete_reclaim(deferred).unwrap_err();
        assert_eq!(failure.error(), ReclaimError::AwaitingAcknowledgement);
        let deferred = failure.into_deferred();
        core::mem::forget(deferred);
    }

    #[test]
    fn safe_point_stop_rejects_wrong_duplicate_and_already_terminal_target() {
        let mut objects = ObjectRegistry::<8>::new();
        let stop_identity = identity(thread_key(&mut objects));
        let mailbox = RendezvousMailbox::new(stop_identity.target_cpu()).unwrap();
        let deferred = mailbox.publish_stop(stop_identity, 0x66_u64).unwrap();
        let request = match mailbox.take_notification() {
            MailboxNotification::Stop(request) => request,
            notification => panic!("expected stop request, got {notification:?}"),
        };
        let wrong_identity = StopIdentity::new(
            stop_identity.target_cpu(),
            stop_identity.cpu_online_generation(),
            thread_key(&mut objects),
            stop_identity.execution_generation(),
            stop_identity.root_binding_generation(),
        )
        .unwrap();
        let mut wrong = SafePointModel::new(wrong_identity);
        assert_eq!(
            mailbox.complete_stop_at_safe_point(request, &mut wrong),
            Err(RemoteStopError::WrongIdentity)
        );
        let mut target = SafePointModel::new(stop_identity);
        mailbox
            .complete_stop_at_safe_point(request, &mut target)
            .unwrap();
        assert_eq!(
            mailbox.complete_stop_at_safe_point(request, &mut target),
            Err(RemoteStopError::AlreadyAcknowledged)
        );
        assert_eq!(mailbox.complete_reclaim(deferred).unwrap(), 0x66);
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

        let wrong = identity(other_thread);
        let request = match mailbox.take_notification() {
            MailboxNotification::Stop(request) => request,
            notification => panic!("expected stop request, got {notification:?}"),
        };
        let mut wrong_target = SafePointModel::new(wrong);
        assert_eq!(
            mailbox.complete_stop_at_safe_point(request, &mut wrong_target),
            Err(RemoteStopError::WrongIdentity)
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

        acknowledge(&mailbox, identity(thread));
        assert!(matches!(
            mailbox.take_notification(),
            MailboxNotification::HoldSafe(_)
        ));
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

    #[test]
    fn e1_latch_is_cpu_local_and_coalesces_before_the_safe_point() {
        let latches = RendezvousIpiLatches::new();
        let cpu0 = CpuIndex::new(0).unwrap();
        let cpu1 = CpuIndex::new(1).unwrap();
        latches.latch(cpu1);
        latches.latch(cpu1);
        assert!(!latches.take(cpu0));
        assert!(latches.take(cpu1));
        assert!(!latches.take(cpu1));
    }
}
