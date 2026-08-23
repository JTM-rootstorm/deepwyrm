use core::sync::atomic::{AtomicU64, Ordering};

use crate::sync::SpinMutex;

use super::scheduler::{SchedulerCpuId, SchedulerExecutionClaim};
use super::{
    BlockReservation, BlockReservationFailure, BlockToken, BlockWakeKey, BlockedOperationRegistry,
    BlockedOperationsDrained, CooperativeScheduler, ExitPins, KernelStackId,
    ProcessQuiescenceProof, SchedulerError, TaskAuthority, ThreadContextId,
    ThreadExecutionResources, ThreadKey, ThreadStartState,
};

pub(crate) const E3_INITIAL_USER_RFLAGS: u64 = 0x202;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use crate::memory::kernel_stack::E3_THREAD_STACK_COUNT;
use crate::memory::kernel_stack::{KernelStackBounds, KernelStackLayoutError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExecutionResourceError {
    Capacity,
    InvalidLayout,
    Overlap,
    InvalidId,
    StaleId,
    AlreadyAllocated,
    ContinuationUnavailable,
    ContinuationAlreadyInitialized,
    ContinuationOutsideStack,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct GeneralPurposeRegisters {
    pub(crate) rax: u64,
    pub(crate) rbx: u64,
    pub(crate) rcx: u64,
    pub(crate) rdx: u64,
    pub(crate) rsi: u64,
    pub(crate) rdi: u64,
    pub(crate) rbp: u64,
    pub(crate) r8: u64,
    pub(crate) r9: u64,
    pub(crate) r10: u64,
    pub(crate) r11: u64,
    pub(crate) r12: u64,
    pub(crate) r13: u64,
    pub(crate) r14: u64,
    pub(crate) r15: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UserTlsPolicy {
    DisabledKernelGsOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FpSimdPolicy {
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SavedThreadContext {
    pub(crate) gprs: GeneralPurposeRegisters,
    pub(crate) user_rip: u64,
    pub(crate) user_rsp: u64,
    pub(crate) user_rflags: u64,
    pub(crate) startup_arguments: [u64; 2],
    pub(crate) tls_policy: UserTlsPolicy,
    pub(crate) fp_simd_policy: FpSimdPolicy,
}

impl SavedThreadContext {
    pub(crate) const fn initial(start: ThreadStartState) -> Self {
        Self {
            gprs: GeneralPurposeRegisters {
                rax: 0,
                rbx: 0,
                rcx: 0,
                rdx: 0,
                rsi: 0,
                rdi: 0,
                rbp: 0,
                r8: 0,
                r9: 0,
                r10: 0,
                r11: 0,
                r12: 0,
                r13: 0,
                r14: 0,
                r15: 0,
            },
            user_rip: start.entry(),
            user_rsp: start.stack_pointer(),
            user_rflags: E3_INITIAL_USER_RFLAGS,
            startup_arguments: [start.argument0(), start.argument1()],
            tls_policy: UserTlsPolicy::DisabledKernelGsOnly,
            fp_simd_policy: FpSimdPolicy::Unavailable,
        }
    }
}

#[derive(Clone, Copy)]
struct ResourceSlot<T: Copy> {
    generation: u32,
    value: Option<T>,
}

const fn empty_resource_slot<T: Copy>() -> ResourceSlot<T> {
    ResourceSlot {
        generation: 0,
        value: None,
    }
}

fn next_generation(generation: u32) -> Option<u32> {
    generation.checked_add(1).filter(|next| *next != 0)
}

fn encode_resource_id(slot: usize, generation: u32) -> Option<u64> {
    let slot = u32::try_from(slot.checked_add(1)?).ok()?;
    (generation != 0).then_some((u64::from(generation) << 32) | u64::from(slot))
}

fn decode_resource_id(raw: u64) -> Option<(usize, u32)> {
    let generation = (raw >> 32) as u32;
    let slot = u32::try_from(raw & u64::from(u32::MAX))
        .ok()?
        .checked_sub(1)?;
    (generation != 0).then_some((slot as usize, generation))
}

struct KernelStackPoolState<const CAPACITY: usize> {
    slots: [ResourceSlot<()>; CAPACITY],
}

pub(crate) struct KernelStackPool<const CAPACITY: usize> {
    bounds: [KernelStackBounds; CAPACITY],
    state: SpinMutex<KernelStackPoolState<CAPACITY>>,
}

impl<const CAPACITY: usize> KernelStackPool<CAPACITY> {
    pub(crate) fn new(
        bounds: [KernelStackBounds; CAPACITY],
    ) -> Result<Self, ExecutionResourceError> {
        for (index, candidate) in bounds.iter().copied().enumerate() {
            KernelStackBounds::new(candidate.guard_page, candidate.bottom, candidate.top).map_err(
                |KernelStackLayoutError::InvalidLayout| ExecutionResourceError::InvalidLayout,
            )?;
            if bounds[..index]
                .iter()
                .copied()
                .any(|prior| candidate.guard_page < prior.top && prior.guard_page < candidate.top)
            {
                return Err(ExecutionResourceError::Overlap);
            }
        }
        Ok(Self {
            bounds,
            state: SpinMutex::new(KernelStackPoolState {
                slots: [empty_resource_slot(); CAPACITY],
            }),
        })
    }

    pub(crate) fn allocate(&self) -> Result<KernelStackId, ExecutionResourceError> {
        let mut state = self.state.lock();
        for slot in 0..CAPACITY {
            if state.slots[slot].value.is_some() {
                continue;
            }
            let Some(generation) = next_generation(state.slots[slot].generation) else {
                continue;
            };
            let Some(raw) = encode_resource_id(slot, generation) else {
                continue;
            };
            state.slots[slot] = ResourceSlot {
                generation,
                value: Some(()),
            };
            return KernelStackId::from_raw(raw).ok_or(ExecutionResourceError::InvalidId);
        }
        Err(ExecutionResourceError::Capacity)
    }

    pub(crate) fn bounds(
        &self,
        id: KernelStackId,
    ) -> Result<KernelStackBounds, ExecutionResourceError> {
        let state = self.state.lock();
        let (slot, generation) =
            decode_resource_id(id.raw()).ok_or(ExecutionResourceError::InvalidId)?;
        let entry = state
            .slots
            .get(slot)
            .ok_or(ExecutionResourceError::InvalidId)?;
        if entry.generation != generation || entry.value.is_none() {
            return Err(ExecutionResourceError::StaleId);
        }
        Ok(self.bounds[slot])
    }

    pub(crate) fn reclaim(
        &self,
        id: KernelStackId,
    ) -> Result<KernelStackBounds, ExecutionResourceError> {
        let mut state = self.state.lock();
        let (slot, generation) =
            decode_resource_id(id.raw()).ok_or(ExecutionResourceError::InvalidId)?;
        let entry = state
            .slots
            .get_mut(slot)
            .ok_or(ExecutionResourceError::InvalidId)?;
        if entry.generation != generation || entry.value.is_none() {
            return Err(ExecutionResourceError::StaleId);
        }
        entry.value = None;
        Ok(self.bounds[slot])
    }
}

struct ThreadContextPoolState<const CAPACITY: usize> {
    slots: [ResourceSlot<SavedThreadContext>; CAPACITY],
}

pub(crate) struct ThreadContextPool<const CAPACITY: usize> {
    state: SpinMutex<ThreadContextPoolState<CAPACITY>>,
}

impl<const CAPACITY: usize> ThreadContextPool<CAPACITY> {
    pub(crate) const fn new() -> Self {
        Self {
            state: SpinMutex::new(ThreadContextPoolState {
                slots: [empty_resource_slot(); CAPACITY],
            }),
        }
    }

    pub(crate) fn allocate(
        &self,
        context: SavedThreadContext,
    ) -> Result<ThreadContextId, ExecutionResourceError> {
        let mut state = self.state.lock();
        for slot in 0..CAPACITY {
            if state.slots[slot].value.is_some() {
                continue;
            }
            let Some(generation) = next_generation(state.slots[slot].generation) else {
                continue;
            };
            let Some(raw) = encode_resource_id(slot, generation) else {
                continue;
            };
            state.slots[slot] = ResourceSlot {
                generation,
                value: Some(context),
            };
            return ThreadContextId::from_raw(raw).ok_or(ExecutionResourceError::InvalidId);
        }
        Err(ExecutionResourceError::Capacity)
    }

    pub(crate) fn load(
        &self,
        id: ThreadContextId,
    ) -> Result<SavedThreadContext, ExecutionResourceError> {
        let state = self.state.lock();
        let (slot, generation) =
            decode_resource_id(id.raw()).ok_or(ExecutionResourceError::InvalidId)?;
        let entry = state
            .slots
            .get(slot)
            .ok_or(ExecutionResourceError::InvalidId)?;
        if entry.generation != generation {
            return Err(ExecutionResourceError::StaleId);
        }
        entry.value.ok_or(ExecutionResourceError::StaleId)
    }

    pub(crate) fn store(
        &self,
        id: ThreadContextId,
        context: SavedThreadContext,
    ) -> Result<(), ExecutionResourceError> {
        let mut state = self.state.lock();
        let (slot, generation) =
            decode_resource_id(id.raw()).ok_or(ExecutionResourceError::InvalidId)?;
        let entry = state
            .slots
            .get_mut(slot)
            .ok_or(ExecutionResourceError::InvalidId)?;
        if entry.generation != generation || entry.value.is_none() {
            return Err(ExecutionResourceError::StaleId);
        }
        entry.value = Some(context);
        Ok(())
    }

    pub(crate) fn reclaim(
        &self,
        id: ThreadContextId,
    ) -> Result<SavedThreadContext, ExecutionResourceError> {
        let mut state = self.state.lock();
        let (slot, generation) =
            decode_resource_id(id.raw()).ok_or(ExecutionResourceError::InvalidId)?;
        let entry = state
            .slots
            .get_mut(slot)
            .ok_or(ExecutionResourceError::InvalidId)?;
        if entry.generation != generation {
            return Err(ExecutionResourceError::StaleId);
        }
        entry.value.take().ok_or(ExecutionResourceError::StaleId)
    }
}

struct KernelContinuationSlot(AtomicU64);

impl KernelContinuationSlot {
    fn new() -> Self {
        Self(AtomicU64::new(0))
    }
}

struct KernelContinuationPool<const CAPACITY: usize> {
    slots: [KernelContinuationSlot; CAPACITY],
}

impl<const CAPACITY: usize> KernelContinuationPool<CAPACITY> {
    fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| KernelContinuationSlot::new()),
        }
    }

    fn slot(
        &self,
        context: ThreadContextId,
    ) -> Result<&KernelContinuationSlot, ExecutionResourceError> {
        let (slot, _) =
            decode_resource_id(context.raw()).ok_or(ExecutionResourceError::InvalidId)?;
        self.slots
            .get(slot)
            .ok_or(ExecutionResourceError::InvalidId)
    }

    fn load(&self, context: ThreadContextId) -> Result<u64, ExecutionResourceError> {
        let slot = self.slot(context)?;
        Ok(slot.0.load(Ordering::Acquire))
    }

    fn reset(&self, context: ThreadContextId) -> Result<(), ExecutionResourceError> {
        let slot = self.slot(context)?;
        slot.0.store(0, Ordering::Release);
        Ok(())
    }

    fn seed(&self, context: ThreadContextId, rsp: u64) -> Result<(), ExecutionResourceError> {
        let slot = self.slot(context)?;
        slot.0
            .compare_exchange(0, rsp, Ordering::Release, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| ExecutionResourceError::ContinuationAlreadyInitialized)
    }

    /// Returns the aligned storage written by the context-switch assembly.
    ///
    /// That non-atomic write is exclusive while the scheduler records the
    /// outgoing continuation as CPU-owned.  After assembly has saved RSP, the
    /// new carrier must call `complete_switch_on`; the scheduler lock's
    /// Release/Acquire handoff makes the write happen-before a different CPU
    /// can claim the Thread and Acquire-load this atomic slot.
    fn save_ptr(&self, context: ThreadContextId) -> Result<*mut u64, ExecutionResourceError> {
        Ok(self.slot(context)?.0.as_ptr())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartThreadError {
    Scheduler(SchedulerError),
    Resource(ExecutionResourceError),
    Task(super::TaskError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExecutionSwitchError {
    MissingPrevious,
    MissingNext,
    WrongSchedulerState,
    Task(super::TaskError),
    Resource(ExecutionResourceError),
    Context(crate::arch::x86_64::context::KernelContextPlanError),
    InitialContext(crate::arch::x86_64::context::InitialKernelContinuationError),
}

#[must_use = "retired task pins must be released through ObjectRegistry after E3 resources are reclaimed"]
pub(crate) struct RetiredExitPins<const THREADS: usize> {
    process: Option<crate::object::InternalRef>,
    threads: [Option<crate::object::InternalRef>; THREADS],
}

/// Linear ownership of the execution resources belonging to the Thread whose
/// terminal syscall is still running on its kernel stack.
///
/// Scheduler and task ownership have already been retired.  The stack and
/// saved context deliberately remain allocated until architecture code has
/// diverged onto a separately owned terminal stack and consumes this token.
#[must_use = "current execution resources must be reclaimed after switching to a terminal stack"]
pub(crate) struct DeferredCurrentExecutionResources {
    thread: ThreadKey,
    resources: Option<ThreadExecutionResources>,
    process_pin: Option<crate::object::InternalRef>,
    thread_pin: Option<crate::object::InternalRef>,
}

impl DeferredCurrentExecutionResources {
    pub(crate) const fn thread(&self) -> ThreadKey {
        self.thread
    }
}

impl Drop for DeferredCurrentExecutionResources {
    fn drop(&mut self) {
        assert!(
            self.resources.is_none() && self.process_pin.is_none() && self.thread_pin.is_none(),
            "deferred current execution bundle leaked without ordered terminal-stack reclaim"
        );
    }
}

impl<const THREADS: usize> RetiredExitPins<THREADS> {
    pub(crate) fn into_parts(
        self,
    ) -> (
        Option<crate::object::InternalRef>,
        [Option<crate::object::InternalRef>; THREADS],
    ) {
        (self.process, self.threads)
    }
}

#[must_use = "exception termination must reclaim current execution ownership after a divergent handoff"]
pub(crate) struct RetiredProcessException<const HANDLES: usize, const THREADS: usize> {
    pub(crate) drained: super::DrainResult<HANDLES>,
    pub(crate) pins: RetiredExitPins<THREADS>,
    pub(crate) deferred_current: DeferredCurrentExecutionResources,
}

/// E3 owner for the run queue and exact per-thread execution resources.
///
/// Its three internal locks are never nested. Task state remains a caller-owned
/// `&mut TaskAuthority`, so no scheduler/resource lock spans a task mutation.
pub(crate) struct ExecutionDomain<const CAPACITY: usize> {
    scheduler: CooperativeScheduler<CAPACITY>,
    stacks: KernelStackPool<CAPACITY>,
    contexts: ThreadContextPool<CAPACITY>,
    continuations: KernelContinuationPool<CAPACITY>,
    blocked_operations: BlockedOperationRegistry<CAPACITY>,
}

/// Fully allocated initial execution state that is not yet runnable.
#[must_use = "prepared Thread starts must be committed or cancelled exactly once"]
pub(crate) struct PreparedThreadStart<'a, const CAPACITY: usize> {
    execution: &'a ExecutionDomain<CAPACITY>,
    thread: ThreadKey,
    reservation: Option<super::SchedulerReservation>,
    completed: bool,
}

impl<const CAPACITY: usize> Drop for PreparedThreadStart<'_, CAPACITY> {
    fn drop(&mut self) {
        assert!(
            self.completed,
            "prepared Thread start dropped without commit or cancellation"
        );
    }
}

impl<const CAPACITY: usize> ExecutionDomain<CAPACITY> {
    pub(crate) fn new(
        stack_bounds: [KernelStackBounds; CAPACITY],
    ) -> Result<Self, ExecutionResourceError> {
        Ok(Self {
            scheduler: CooperativeScheduler::new(),
            stacks: KernelStackPool::new(stack_bounds)?,
            contexts: ThreadContextPool::new(),
            continuations: KernelContinuationPool::new(),
            blocked_operations: BlockedOperationRegistry::new(),
        })
    }

    pub(crate) fn prepare_thread_start<
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &self,
        tasks: &mut super::TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        thread: ThreadKey,
        start: ThreadStartState,
    ) -> Result<PreparedThreadStart<'_, CAPACITY>, StartThreadError> {
        let reservation = self
            .scheduler
            .reserve(thread)
            .map_err(StartThreadError::Scheduler)?;
        let stack = match self.stacks.allocate() {
            Ok(stack) => stack,
            Err(error) => {
                self.scheduler
                    .cancel(reservation)
                    .unwrap_or_else(|failure| {
                        panic!(
                            "scheduler reservation rollback failed: {:?}",
                            failure.error()
                        )
                    });
                return Err(StartThreadError::Resource(error));
            }
        };
        let context = match self.contexts.allocate(SavedThreadContext::initial(start)) {
            Ok(context) => context,
            Err(error) => {
                self.stacks.reclaim(stack).unwrap_or_else(|rollback| {
                    panic!("kernel stack rollback failed after context allocation: {rollback:?}")
                });
                self.scheduler
                    .cancel(reservation)
                    .unwrap_or_else(|failure| {
                        panic!(
                            "scheduler reservation rollback failed: {:?}",
                            failure.error()
                        )
                    });
                return Err(StartThreadError::Resource(error));
            }
        };
        self.continuations.reset(context).unwrap_or_else(|error| {
            panic!("fresh Thread continuation slot reset failed: {error:?}")
        });
        let resources = ThreadExecutionResources {
            kernel_stack: stack,
            context,
        };

        if let Err(error) = tasks.prepare_thread_execution(thread, start, resources) {
            self.contexts.reclaim(context).unwrap_or_else(|rollback| {
                panic!("thread context rollback failed after task preparation: {rollback:?}")
            });
            self.stacks.reclaim(stack).unwrap_or_else(|rollback| {
                panic!("kernel stack rollback failed after task preparation: {rollback:?}")
            });
            self.scheduler
                .cancel(reservation)
                .unwrap_or_else(|failure| {
                    panic!(
                        "scheduler reservation rollback failed: {:?}",
                        failure.error()
                    )
                });
            return Err(StartThreadError::Task(error));
        }
        Ok(PreparedThreadStart {
            execution: self,
            thread,
            reservation: Some(reservation),
            completed: false,
        })
    }

    pub(crate) fn start_thread<
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &self,
        tasks: &mut super::TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        thread: ThreadKey,
        start: ThreadStartState,
    ) -> Result<(), StartThreadError> {
        self.prepare_thread_start(tasks, thread, start)?
            .commit(tasks);
        Ok(())
    }

    pub(crate) fn schedule_next(&self) -> Result<super::ScheduleDecision, SchedulerError> {
        self.scheduler.schedule_next()
    }

    pub(crate) fn schedule_next_on(
        &self,
        cpu: SchedulerCpuId,
    ) -> Result<super::ScheduleDecision, SchedulerError> {
        self.scheduler.schedule_next_on(cpu)
    }

    pub(crate) fn yield_current(
        &self,
        thread: ThreadKey,
    ) -> Result<super::ScheduleDecision, SchedulerError> {
        let decision = self.scheduler.yield_current(thread)?;
        if decision.current != decision.previous {
            super::notify_runnable_work();
        }
        Ok(decision)
    }

    pub(crate) fn yield_current_on(
        &self,
        cpu: SchedulerCpuId,
        thread: ThreadKey,
    ) -> Result<super::ScheduleDecision, SchedulerError> {
        let decision = self.scheduler.yield_current_on(cpu, thread)?;
        if decision.current != decision.previous {
            super::notify_runnable_work();
        }
        Ok(decision)
    }

    pub(crate) fn schedule_from_idle(
        &self,
        suspended: ThreadKey,
    ) -> Result<super::IdleScheduleDecision, SchedulerError> {
        self.scheduler.schedule_from_idle(suspended)
    }

    pub(crate) fn schedule_from_idle_on(
        &self,
        cpu: SchedulerCpuId,
        suspended: ThreadKey,
    ) -> Result<super::IdleScheduleDecision, SchedulerError> {
        self.scheduler.schedule_from_idle_on(cpu, suspended)
    }

    pub(crate) fn prepare_block_current(
        &self,
        thread: ThreadKey,
    ) -> Result<BlockReservation, SchedulerError> {
        self.scheduler.prepare_block_current(thread)
    }

    pub(crate) fn prepare_block_current_on(
        &self,
        cpu: SchedulerCpuId,
        thread: ThreadKey,
    ) -> Result<BlockReservation, SchedulerError> {
        self.scheduler.prepare_block_current_on(cpu, thread)
    }

    pub(crate) fn cancel_block(
        &self,
        reservation: BlockReservation,
    ) -> Result<(), BlockReservationFailure> {
        self.scheduler.cancel_block(reservation)
    }

    pub(crate) fn cancel_block_on(
        &self,
        cpu: SchedulerCpuId,
        reservation: BlockReservation,
    ) -> Result<(), BlockReservationFailure> {
        self.scheduler.cancel_block_on(cpu, reservation)
    }

    pub(crate) fn commit_block(
        &self,
        reservation: BlockReservation,
    ) -> Result<super::ScheduleDecision, BlockReservationFailure> {
        self.scheduler.commit_block(reservation)
    }

    pub(crate) fn commit_block_on(
        &self,
        cpu: SchedulerCpuId,
        reservation: BlockReservation,
    ) -> Result<super::ScheduleDecision, BlockReservationFailure> {
        self.scheduler.commit_block_on(cpu, reservation)
    }

    pub(crate) fn block_current(
        &self,
        thread: ThreadKey,
    ) -> Result<(BlockToken, super::ScheduleDecision), SchedulerError> {
        self.scheduler.block_current(thread)
    }

    pub(crate) fn block_current_on(
        &self,
        cpu: SchedulerCpuId,
        thread: ThreadKey,
    ) -> Result<(BlockToken, super::ScheduleDecision), SchedulerError> {
        self.scheduler.block_current_on(cpu, thread)
    }

    pub(crate) fn complete_switch_on(
        &self,
        claim: SchedulerExecutionClaim,
    ) -> Result<(), SchedulerError> {
        self.scheduler.complete_switch_on(claim)?;
        super::notify_runnable_work();
        Ok(())
    }

    pub(crate) fn running_claim_on(&self, cpu: SchedulerCpuId) -> Option<SchedulerExecutionClaim> {
        self.scheduler.running_claim_on(cpu)
    }

    pub(crate) fn suspended_claim_on(
        &self,
        cpu: SchedulerCpuId,
    ) -> Option<SchedulerExecutionClaim> {
        self.scheduler.suspended_claim_on(cpu)
    }

    pub(crate) fn wake(&self, key: BlockWakeKey) -> Result<(), SchedulerError> {
        self.scheduler.wake(key)?;
        super::notify_runnable_work();
        Ok(())
    }

    pub(crate) fn validate_issued_wake_key(&self, key: BlockWakeKey) -> Result<(), SchedulerError> {
        self.scheduler.validate_issued_wake_key(key)
    }

    pub(crate) fn blocked_operations(&self) -> &BlockedOperationRegistry<CAPACITY> {
        &self.blocked_operations
    }

    pub(crate) fn blocked_operations_drained<
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &self,
        tasks: &TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        proof: &ProcessQuiescenceProof,
    ) -> Result<BlockedOperationsDrained, super::BlockedOperationError> {
        self.blocked_operations.drained_after_quiesce(tasks, proof)
    }

    pub(crate) fn retire_exit_pins<const THREADS: usize>(
        &self,
        pins: ExitPins<THREADS>,
    ) -> RetiredExitPins<THREADS> {
        assert!(
            !pins
                .thread_keys()
                .into_iter()
                .flatten()
                .any(|thread| self.scheduler.running_cpu(thread).is_some()),
            "immediate terminal retirement contained a physical current Thread"
        );
        self.retire_exit_pins_inner(pins, None, SchedulerCpuId::BOOTSTRAP)
            .0
    }

    pub(crate) fn retire_exit_pins_on<const THREADS: usize>(
        &self,
        cpu: SchedulerCpuId,
        pins: ExitPins<THREADS>,
    ) -> RetiredExitPins<THREADS> {
        assert!(
            !pins
                .thread_keys()
                .into_iter()
                .flatten()
                .any(|thread| self.scheduler.running_cpu(thread).is_some()),
            "immediate terminal retirement contained a physical current Thread"
        );
        self.retire_exit_pins_inner(pins, None, cpu).0
    }

    /// Retires one terminal batch while preserving the named current Thread's
    /// stack and context until a divergent architecture handoff consumes the
    /// returned linear token.
    pub(crate) fn retire_exit_pins_defer_current<const THREADS: usize>(
        &self,
        pins: ExitPins<THREADS>,
        current: ThreadKey,
    ) -> (RetiredExitPins<THREADS>, DeferredCurrentExecutionResources) {
        let retired =
            self.retire_exit_pins_defer_current_on(SchedulerCpuId::BOOTSTRAP, pins, current);
        let claim = self
            .scheduler
            .suspended_claim_on(SchedulerCpuId::BOOTSTRAP)
            .expect("BSP terminal model handoff retains its execution claim");
        assert_eq!(claim.thread(), current);
        self.scheduler
            .complete_switch_on(claim)
            .expect("BSP terminal model handoff follows current retirement");
        retired
    }

    pub(crate) fn retire_exit_pins_defer_current_on<const THREADS: usize>(
        &self,
        cpu: SchedulerCpuId,
        pins: ExitPins<THREADS>,
        current: ThreadKey,
    ) -> (RetiredExitPins<THREADS>, DeferredCurrentExecutionResources) {
        assert_eq!(
            self.scheduler.current_on(cpu),
            Some(current),
            "deferred terminal retirement did not name the physical current Thread"
        );
        assert!(
            pins.thread_keys()
                .into_iter()
                .flatten()
                .any(|thread| thread == current),
            "deferred terminal retirement batch did not contain the physical current Thread"
        );
        let (pins, deferred) = self.retire_exit_pins_inner(pins, Some(current), cpu);
        (
            pins,
            deferred.expect("terminal batch did not contain the running current Thread"),
        )
    }

    fn retire_exit_pins_inner<const THREADS: usize>(
        &self,
        pins: ExitPins<THREADS>,
        defer_current: Option<ThreadKey>,
        cpu: SchedulerCpuId,
    ) -> (
        RetiredExitPins<THREADS>,
        Option<DeferredCurrentExecutionResources>,
    ) {
        let (mut process, mut thread_pins, mut resources) = pins.into_parts();
        let mut retired_threads = core::array::from_fn(|_| None);
        let mut deferred = None;
        // Retire every non-current member first. Otherwise retiring `current`
        // can select a terminal sibling as its replacement and manufacture a
        // transient Running owner that the same batch must immediately undo.
        for deferred_pass in [false, true] {
            for index in 0..THREADS {
                let Some(pin) = thread_pins[index].as_ref() else {
                    assert!(
                        resources[index].is_none(),
                        "resource exists without a terminal thread pin"
                    );
                    continue;
                };
                let thread = ThreadKey::from_object_id(pin.id());
                if (defer_current == Some(thread)) != deferred_pass {
                    continue;
                }
                let pin = thread_pins[index]
                    .take()
                    .expect("selected terminal thread retains its pin");
                let resources = resources[index].take();
                assert!(
                    !self.blocked_operations.has_thread(thread),
                    "terminal Thread still owns a blocked operation at execution-resource reclaim",
                );
                let scheduled = self.scheduler.state(thread).is_some();
                assert_eq!(
                    scheduled,
                    resources.is_some(),
                    "scheduler/resource ownership diverged at terminal retirement"
                );
                if scheduled {
                    self.scheduler
                        .retire_on(cpu, thread)
                        .unwrap_or_else(|error| {
                            panic!("terminal thread was not removable from scheduler: {error:?}")
                        });
                }
                if let Some(resources) = resources {
                    if defer_current == Some(thread) {
                        assert!(
                            deferred.is_none(),
                            "terminal batch contained duplicate current execution resources"
                        );
                        deferred = Some(DeferredCurrentExecutionResources {
                            thread,
                            resources: Some(resources),
                            process_pin: None,
                            thread_pin: Some(pin),
                        });
                    } else {
                        self.reclaim_resources(resources);
                        retired_threads[index] = Some(pin);
                    }
                } else {
                    retired_threads[index] = Some(pin);
                }
            }
        }
        if let Some(deferred) = deferred.as_mut() {
            deferred.process_pin = process.take();
        }
        (
            RetiredExitPins {
                process,
                threads: retired_threads,
            },
            deferred,
        )
    }

    /// Consumes execution-resource ownership after the caller has irreversibly
    /// left the deferred Thread's kernel stack.
    pub(crate) fn reclaim_deferred_current(
        &self,
        mut deferred: DeferredCurrentExecutionResources,
    ) -> RetiredExitPins<1> {
        assert_eq!(
            self.scheduler.state(deferred.thread),
            None,
            "deferred current Thread became schedulable before resource reclaim"
        );
        assert_eq!(
            self.scheduler.suspended_cpu(deferred.thread),
            None,
            "deferred current Thread continuation was reclaimed before CPU handoff acknowledgement"
        );
        let resources = deferred
            .resources
            .take()
            .expect("deferred current execution resources were already consumed");
        self.reclaim_resources(resources);
        let thread = deferred
            .thread_pin
            .take()
            .expect("deferred current Thread lost its execution pin");
        RetiredExitPins {
            process: deferred.process_pin.take(),
            threads: [Some(thread)],
        }
    }

    pub(crate) fn terminate_process_exception<
        const OBJECTS: usize,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &self,
        tasks: &mut super::TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        registry: &mut crate::object::ObjectRegistry<OBJECTS>,
        process: super::ProcessKey,
        faulting_thread: ThreadKey,
        exception: super::TaskExceptionRecord,
    ) -> Result<RetiredProcessException<HANDLES, THREADS>, super::TaskError> {
        let effects = tasks.terminate_process_exception(
            registry,
            process,
            faulting_thread,
            exception.exception_type,
            exception.detail,
            exception.fault_address,
        )?;
        let (pins, deferred_current) =
            self.retire_exit_pins_defer_current(effects.pins, faulting_thread);
        Ok(RetiredProcessException {
            drained: effects.drained,
            pins,
            deferred_current,
        })
    }

    fn reclaim_resources(&self, resources: ThreadExecutionResources) {
        let context = resources.context();
        let stack = resources.kernel_stack();
        self.contexts.load(context).unwrap_or_else(|error| {
            panic!("terminal Thread lost its saved context before reclaim: {error:?}")
        });
        self.stacks.bounds(stack).unwrap_or_else(|error| {
            panic!("terminal Thread lost its kernel stack before reclaim: {error:?}")
        });
        self.continuations.reset(context).unwrap_or_else(|error| {
            panic!("terminal Thread continuation reset violated F2 ownership: {error:?}")
        });
        self.contexts.reclaim(context).unwrap_or_else(|error| {
            panic!("terminal Thread context reclaim violated E3 ownership: {error:?}")
        });
        self.stacks.reclaim(stack).unwrap_or_else(|error| {
            panic!("terminal Thread stack reclaim violated E3 ownership: {error:?}")
        });
    }

    #[cfg(test)]
    pub(crate) fn seed_test_kernel_continuation(
        &self,
        stack: KernelStackId,
        context: ThreadContextId,
        rsp: u64,
    ) -> Result<(), ExecutionResourceError> {
        self.contexts.load(context)?;
        let bounds = self.stacks.bounds(stack)?;
        if !crate::arch::x86_64::context::saved_rsp_is_within_stack(bounds, rsp) {
            return Err(ExecutionResourceError::ContinuationOutsideStack);
        }
        self.continuations.seed(context, rsp)
    }

    pub(crate) fn kernel_continuation_rsp(
        &self,
        context: ThreadContextId,
    ) -> Result<u64, ExecutionResourceError> {
        self.contexts.load(context)?;
        self.continuations.load(context)
    }

    /// Builds one exact kernel-context switch plan from scheduler-owned Thread state.
    ///
    /// # Safety
    ///
    /// `decision.previous` must name the kernel stack currently executing this
    /// function. The returned plan borrows `self`, preventing safe move or
    /// replacement of its continuation storage until the plan is consumed.
    #[allow(
        unsafe_code,
        reason = "the lifetime brand makes execution-owner stationarity mechanical while the caller supplies the active continuation identity"
    )]
    pub(crate) unsafe fn prepare_kernel_switch<
        'owner,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &'owner self,
        tasks: &super::TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        decision: super::ScheduleDecision,
    ) -> Result<crate::arch::x86_64::context::KernelSwitchPlan<'owner>, ExecutionSwitchError> {
        unsafe { self.prepare_kernel_switch_inner(tasks, None, decision, false, None) }
    }

    /// CPU-owned counterpart of [`Self::prepare_kernel_switch`].
    ///
    /// The scheduler must still record `decision.previous` as the suspended
    /// continuation on `cpu`; this closes cross-CPU decision substitution.
    #[allow(
        unsafe_code,
        reason = "the caller proves the active CPU and continuation identity while the scheduler validates their exact ownership"
    )]
    pub(crate) unsafe fn prepare_kernel_switch_on<
        'owner,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &'owner self,
        tasks: &super::TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        cpu: SchedulerCpuId,
        decision: super::ScheduleDecision,
    ) -> Result<crate::arch::x86_64::context::KernelSwitchPlan<'owner>, ExecutionSwitchError> {
        unsafe { self.prepare_kernel_switch_inner(tasks, Some(cpu), decision, false, None) }
    }

    /// Builds a blocking switch plan whose destination may be either a genuine
    /// suspended kernel continuation or a never-run Thread. A fresh destination
    /// receives the audited synthetic first-run frame at the instant it is
    /// selected, while its continuation slot remains zero until it later blocks
    /// and the switch assembly saves a real kernel continuation there.
    ///
    /// # Safety
    ///
    /// `decision.previous` must name the kernel stack currently executing this
    /// function. `trusted_first_run_entry` must be the fixed executable kernel
    /// entry for a scheduler-selected fresh Thread. The returned plan borrows
    /// `self` until immediate switch consumption.
    #[allow(
        unsafe_code,
        reason = "F7 may select a never-run Runnable Thread and must construct its audited first-run frame on the exclusively owned destination kernel stack"
    )]
    pub(crate) unsafe fn prepare_blocking_kernel_switch<
        'owner,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &'owner self,
        tasks: &super::TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        decision: super::ScheduleDecision,
        trusted_first_run_entry: u64,
    ) -> Result<crate::arch::x86_64::context::KernelSwitchPlan<'owner>, ExecutionSwitchError> {
        unsafe {
            self.prepare_kernel_switch_inner(
                tasks,
                None,
                decision,
                false,
                Some(trusted_first_run_entry),
            )
        }
    }

    #[allow(
        unsafe_code,
        reason = "the caller proves the active CPU, continuation identity, and trusted first-run entry while the scheduler validates ownership"
    )]
    pub(crate) unsafe fn prepare_blocking_kernel_switch_on<
        'owner,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &'owner self,
        tasks: &super::TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        cpu: SchedulerCpuId,
        decision: super::ScheduleDecision,
        trusted_first_run_entry: u64,
    ) -> Result<crate::arch::x86_64::context::KernelSwitchPlan<'owner>, ExecutionSwitchError> {
        unsafe {
            self.prepare_kernel_switch_inner(
                tasks,
                Some(cpu),
                decision,
                false,
                Some(trusted_first_run_entry),
            )
        }
    }

    /// Builds a kernel switch plan while the CPU is physically executing an
    /// idle suspended syscall continuation. Unlike the ordinary blocked switch,
    /// the previous Thread may already be Runnable if its wake raced another
    /// FIFO winner after the CPU entered idle.
    ///
    /// # Safety
    ///
    /// The caller must prove `decision.previous` is the kernel stack currently
    /// executing this function. The returned plan mechanically borrows the
    /// execution owner until immediate switch consumption.
    #[allow(
        unsafe_code,
        reason = "F7 idle suspension can logically wake the physically-active continuation before FIFO selects another destination Thread"
    )]
    pub(crate) unsafe fn prepare_idle_kernel_switch<
        'owner,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &'owner self,
        tasks: &super::TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        decision: super::ScheduleDecision,
    ) -> Result<crate::arch::x86_64::context::KernelSwitchPlan<'owner>, ExecutionSwitchError> {
        unsafe { self.prepare_kernel_switch_inner(tasks, None, decision, true, None) }
    }

    #[allow(
        unsafe_code,
        reason = "the idle caller proves the active CPU and suspended continuation while the scheduler validates the exact carrier"
    )]
    pub(crate) unsafe fn prepare_idle_kernel_switch_on<
        'owner,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &'owner self,
        tasks: &super::TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        cpu: SchedulerCpuId,
        decision: super::ScheduleDecision,
    ) -> Result<crate::arch::x86_64::context::KernelSwitchPlan<'owner>, ExecutionSwitchError> {
        unsafe { self.prepare_kernel_switch_inner(tasks, Some(cpu), decision, true, None) }
    }

    /// Idle-suspend counterpart of [`Self::prepare_blocking_kernel_switch`].
    /// The physically active waiter may already be Runnable when FIFO selects a
    /// different destination, and that destination may itself be never-run.
    ///
    /// # Safety
    ///
    /// `decision.previous` must name the kernel stack physically executing the
    /// idle continuation. The trusted entry obeys the ordinary blocking
    /// fresh-thread contract; the returned plan brands the execution owner.
    #[allow(
        unsafe_code,
        reason = "F7 idle suspension may switch from a physically active waiter to a fresh scheduler-selected Runnable Thread"
    )]
    pub(crate) unsafe fn prepare_idle_blocking_kernel_switch<
        'owner,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &'owner self,
        tasks: &super::TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        decision: super::ScheduleDecision,
        trusted_first_run_entry: u64,
    ) -> Result<crate::arch::x86_64::context::KernelSwitchPlan<'owner>, ExecutionSwitchError> {
        unsafe {
            self.prepare_kernel_switch_inner(
                tasks,
                None,
                decision,
                true,
                Some(trusted_first_run_entry),
            )
        }
    }

    #[allow(
        unsafe_code,
        reason = "the idle caller proves CPU, continuation, and first-run entry ownership while the scheduler validates the exact carrier"
    )]
    pub(crate) unsafe fn prepare_idle_blocking_kernel_switch_on<
        'owner,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &'owner self,
        tasks: &super::TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        cpu: SchedulerCpuId,
        decision: super::ScheduleDecision,
        trusted_first_run_entry: u64,
    ) -> Result<crate::arch::x86_64::context::KernelSwitchPlan<'owner>, ExecutionSwitchError> {
        unsafe {
            self.prepare_kernel_switch_inner(
                tasks,
                Some(cpu),
                decision,
                true,
                Some(trusted_first_run_entry),
            )
        }
    }

    #[allow(
        unsafe_code,
        reason = "shared switch-plan constructor is called only by audited ordinary-block and idle-block wrappers that prove the active continuation identity"
    )]
    unsafe fn prepare_kernel_switch_inner<
        'owner,
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        &'owner self,
        tasks: &super::TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
        cpu: Option<SchedulerCpuId>,
        decision: super::ScheduleDecision,
        allow_runnable_previous: bool,
        trusted_first_run_entry: Option<u64>,
    ) -> Result<crate::arch::x86_64::context::KernelSwitchPlan<'owner>, ExecutionSwitchError> {
        let previous = decision
            .previous
            .ok_or(ExecutionSwitchError::MissingPrevious)?;
        let next = decision.current.ok_or(ExecutionSwitchError::MissingNext)?;
        if cpu.is_some_and(|cpu| self.scheduler.validate_switch_on(cpu, decision).is_err()) {
            return Err(ExecutionSwitchError::WrongSchedulerState);
        }
        let previous_state = self.scheduler.state(previous);
        let previous_valid = previous_state == Some(super::SchedulerThreadState::Blocked)
            || (allow_runnable_previous
                && previous_state == Some(super::SchedulerThreadState::Runnable));
        if !previous_valid
            || self.scheduler.state(next) != Some(super::SchedulerThreadState::Running)
        {
            return Err(ExecutionSwitchError::WrongSchedulerState);
        }
        let (_, previous_context) = tasks
            .thread_execution_resources(previous)
            .map_err(ExecutionSwitchError::Task)?
            .ok_or(ExecutionSwitchError::Resource(
                ExecutionResourceError::StaleId,
            ))?;
        let (next_stack_id, next_context) = tasks
            .thread_execution_resources(next)
            .map_err(ExecutionSwitchError::Task)?
            .ok_or(ExecutionSwitchError::Resource(
                ExecutionResourceError::StaleId,
            ))?;
        self.contexts
            .load(previous_context)
            .map_err(ExecutionSwitchError::Resource)?;
        self.contexts
            .load(next_context)
            .map_err(ExecutionSwitchError::Resource)?;
        let current_rsp_out = self
            .continuations
            .save_ptr(previous_context)
            .map_err(ExecutionSwitchError::Resource)?;
        let next_rsp = self
            .continuations
            .load(next_context)
            .map_err(ExecutionSwitchError::Resource)?;
        let next_stack = self
            .stacks
            .bounds(next_stack_id)
            .map_err(ExecutionSwitchError::Resource)?;
        if next_rsp != 0 {
            return unsafe {
                crate::arch::x86_64::context::KernelSwitchPlan::new(
                    self,
                    current_rsp_out,
                    next_rsp,
                    next_stack,
                )
            }
            .map_err(ExecutionSwitchError::Context);
        }
        let trusted_first_run_entry = trusted_first_run_entry.ok_or(
            ExecutionSwitchError::Resource(ExecutionResourceError::ContinuationUnavailable),
        )?;
        let initial = unsafe {
            crate::arch::x86_64::context::prepare_initial_kernel_continuation(
                next_stack,
                trusted_first_run_entry,
            )
        }
        .map_err(ExecutionSwitchError::InitialContext)?;
        unsafe {
            crate::arch::x86_64::context::KernelSwitchPlan::new_initial(
                self,
                current_rsp_out,
                initial,
            )
        }
        .map_err(ExecutionSwitchError::Context)
    }

    pub(crate) fn stack_bounds(
        &self,
        id: KernelStackId,
    ) -> Result<KernelStackBounds, ExecutionResourceError> {
        self.stacks.bounds(id)
    }

    pub(crate) fn load_context(
        &self,
        id: ThreadContextId,
    ) -> Result<SavedThreadContext, ExecutionResourceError> {
        self.contexts.load(id)
    }

    pub(crate) fn store_context(
        &self,
        id: ThreadContextId,
        context: SavedThreadContext,
    ) -> Result<(), ExecutionResourceError> {
        self.contexts.store(id, context)
    }

    pub(crate) fn scheduler_state(&self, thread: ThreadKey) -> Option<super::SchedulerThreadState> {
        self.scheduler.state(thread)
    }
}

impl<const CAPACITY: usize> PreparedThreadStart<'_, CAPACITY> {
    /// Publishes task state and then consumes the same-domain scheduler
    /// reservation. All recoverable resource work completed during prepare.
    pub(crate) fn commit<
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        mut self,
        tasks: &mut super::TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    ) {
        tasks
            .start_thread(self.thread)
            .unwrap_or_else(|error| panic!("prepared Thread task publication diverged: {error:?}"));
        self.execution
            .scheduler
            .commit(
                self.reservation
                    .take()
                    .expect("prepared Thread start retains its reservation"),
            )
            .unwrap_or_else(|failure| {
                panic!(
                    "prepared Thread scheduler publication diverged: {:?}",
                    failure.error()
                )
            });
        super::notify_runnable_work();
        self.completed = true;
    }

    /// Returns the Thread to an execution-resource-free CREATED state.
    pub(crate) fn cancel<
        const GROUPS: usize,
        const PROCESSES: usize,
        const THREADS: usize,
        const HANDLES: usize,
    >(
        mut self,
        tasks: &mut super::TaskAuthority<GROUPS, PROCESSES, THREADS, HANDLES>,
    ) {
        let resources = tasks
            .rollback_thread_execution(self.thread)
            .unwrap_or_else(|error| {
                panic!("prepared Thread execution cancellation diverged: {error:?}")
            });
        self.execution.reclaim_resources(resources);
        self.execution
            .scheduler
            .cancel(
                self.reservation
                    .take()
                    .expect("prepared Thread start retains its reservation"),
            )
            .unwrap_or_else(|failure| {
                panic!(
                    "prepared Thread scheduler cancellation diverged: {:?}",
                    failure.error()
                )
            });
        self.completed = true;
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl ExecutionDomain<E3_THREAD_STACK_COUNT> {
    /// Binds the E3 allocator to the linker-owned supervisor stack carriers.
    pub(crate) fn from_linked_x86_64_stacks() -> Result<Self, ExecutionResourceError> {
        let bounds = crate::arch::x86_64::linked_thread_kernel_stack_layout()
            .map_err(|_| ExecutionResourceError::InvalidLayout)?;
        Self::new(bounds)
    }
}

#[cfg(test)]
#[path = "execution/tests.rs"]
mod tests;
