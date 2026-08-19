use crate::sync::SpinMutex;

use super::{
    BlockToken, BlockWakeKey, CooperativeScheduler, ExitPins, KernelStackId, SchedulerError,
    ThreadContextId, ThreadExecutionResources, ThreadKey, ThreadStartState,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartThreadError {
    Scheduler(SchedulerError),
    Resource(ExecutionResourceError),
    Task(super::TaskError),
}

#[must_use = "retired task pins must be released through ObjectRegistry after E3 resources are reclaimed"]
pub(crate) struct RetiredExitPins<const THREADS: usize> {
    process: Option<crate::object::InternalRef>,
    threads: [Option<crate::object::InternalRef>; THREADS],
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

#[must_use = "exception termination drains handles and returns generic pins for typed finalization"]
pub(crate) struct RetiredProcessException<const HANDLES: usize, const THREADS: usize> {
    pub(crate) drained: super::DrainResult<HANDLES>,
    pub(crate) pins: RetiredExitPins<THREADS>,
}

/// E3 owner for the run queue and exact per-thread execution resources.
///
/// Its three internal locks are never nested. Task state remains a caller-owned
/// `&mut TaskAuthority`, so no scheduler/resource lock spans a task mutation.
pub(crate) struct ExecutionDomain<const CAPACITY: usize> {
    scheduler: CooperativeScheduler<CAPACITY>,
    stacks: KernelStackPool<CAPACITY>,
    contexts: ThreadContextPool<CAPACITY>,
}

impl<const CAPACITY: usize> ExecutionDomain<CAPACITY> {
    pub(crate) fn new(
        stack_bounds: [KernelStackBounds; CAPACITY],
    ) -> Result<Self, ExecutionResourceError> {
        Ok(Self {
            scheduler: CooperativeScheduler::new(),
            stacks: KernelStackPool::new(stack_bounds)?,
            contexts: ThreadContextPool::new(),
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
        if let Err(error) = tasks.start_thread(thread) {
            let resources = tasks
                .rollback_thread_execution(thread)
                .unwrap_or_else(|rollback| {
                    panic!("prepared thread could not roll back after start failure: {rollback:?}")
                });
            self.reclaim_resources(resources);
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
        self.scheduler
            .commit(reservation)
            .unwrap_or_else(|failure| {
                panic!(
                    "same-domain scheduler reservation failed after task start: {:?}",
                    failure.error()
                )
            });
        Ok(())
    }

    pub(crate) fn schedule_next(&self) -> Result<super::ScheduleDecision, SchedulerError> {
        self.scheduler.schedule_next()
    }

    pub(crate) fn yield_current(
        &self,
        thread: ThreadKey,
    ) -> Result<super::ScheduleDecision, SchedulerError> {
        self.scheduler.yield_current(thread)
    }

    pub(crate) fn block_current(
        &self,
        thread: ThreadKey,
    ) -> Result<(BlockToken, super::ScheduleDecision), SchedulerError> {
        self.scheduler.block_current(thread)
    }

    pub(crate) fn wake(&self, key: BlockWakeKey) -> Result<(), SchedulerError> {
        self.scheduler.wake(key)
    }

    pub(crate) fn retire_exit_pins<const THREADS: usize>(
        &self,
        pins: ExitPins<THREADS>,
    ) -> RetiredExitPins<THREADS> {
        let (process, thread_pins, resources) = pins.into_parts();
        let mut retired_threads = core::array::from_fn(|_| None);
        for (index, (pin, resources)) in thread_pins.into_iter().zip(resources).enumerate() {
            let Some(pin) = pin else {
                assert!(
                    resources.is_none(),
                    "resource exists without a terminal thread pin"
                );
                continue;
            };
            let thread = ThreadKey::from_object_id(pin.id());
            let scheduled = self.scheduler.state(thread).is_some();
            assert_eq!(
                scheduled,
                resources.is_some(),
                "scheduler/resource ownership diverged at terminal retirement"
            );
            if scheduled {
                self.scheduler.retire(thread).unwrap_or_else(|error| {
                    panic!("terminal thread was not removable from scheduler: {error:?}")
                });
            }
            if let Some(resources) = resources {
                self.reclaim_resources(resources);
            }
            retired_threads[index] = Some(pin);
        }
        RetiredExitPins {
            process,
            threads: retired_threads,
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
        let pins = self.retire_exit_pins(effects.pins);
        Ok(RetiredProcessException {
            drained: effects.drained,
            pins,
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
        self.contexts.reclaim(context).unwrap_or_else(|error| {
            panic!("terminal Thread context reclaim violated E3 ownership: {error:?}")
        });
        self.stacks.reclaim(stack).unwrap_or_else(|error| {
            panic!("terminal Thread stack reclaim violated E3 ownership: {error:?}")
        });
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
