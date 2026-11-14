//! Calls parked between steps when their Thread yields the CPU (DW2 §10.8).
//!
//! A call in steps (map, unmap, protect, commit, the fill-in, and
//! `MemoryObjectCreate`'s zeroing) that finds its quantum expired at a safe
//! point moves its step state here, under the runtime lock T, and its Thread
//! is switched out at the syscall trampoline. When the Thread runs again it
//! takes its record back, under T, and continues the call. The record moves
//! only under T, the lock termination holds, so a record is either with its
//! running call or here, never both, and is settled exactly once.
//!
//! A parked record holds no pin, phase, usercopy root, CPU or shootdown:
//! each of those ends within a step. Its only owned resource may be a
//! create's backing allocation; the create's quota reservation stays in the
//! registry, keyed by the Thread. A Thread that ends while parked never
//! takes its record back: the runtime settles such records after each
//! termination, in its finalizer drain (`take_ended`).

use crate::task::ThreadKey;

/// One parked call per Thread that can run. Only a started Thread with a
/// kernel stack can make a syscall, so the thread-stack count bounds them.
pub(crate) const PARKED_CALL_THREADS: usize = crate::memory::kernel_stack::E3_THREAD_STACK_COUNT;

/// The per-Thread table of parked calls, each a `C`.
pub(crate) struct ParkedCalls<C, const THREADS: usize> {
    slots: [Option<(ThreadKey, C)>; THREADS],
    parked: usize,
}

impl<C, const THREADS: usize> ParkedCalls<C, THREADS> {
    pub(crate) fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| None),
            parked: 0,
        }
    }

    /// Parks `thread`'s call. A Thread parks at most one call, and the table
    /// holds one per Thread that can run, so neither failure can happen.
    pub(crate) fn park(&mut self, thread: ThreadKey, call: C) {
        assert!(
            !self
                .slots
                .iter()
                .flatten()
                .any(|(owner, _)| *owner == thread),
            "a Thread parked a second call"
        );
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_none())
            .unwrap_or_else(|| panic!("more parked calls than Threads that can run"));
        *slot = Some((thread, call));
        self.parked += 1;
    }

    /// Takes back `thread`'s parked call, if it has one.
    pub(crate) fn take(&mut self, thread: ThreadKey) -> Option<C> {
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.as_ref().is_some_and(|(owner, _)| *owner == thread))?;
        let (_, call) = slot.take().expect("the slot was just matched");
        self.parked -= 1;
        Some(call)
    }

    /// Takes one parked call whose Thread `has_ended`, for the caller to
    /// settle. `None` once none is left.
    pub(crate) fn take_ended(
        &mut self,
        mut has_ended: impl FnMut(ThreadKey) -> bool,
    ) -> Option<(ThreadKey, C)> {
        if self.parked == 0 {
            return None;
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.as_ref().is_some_and(|(owner, _)| has_ended(*owner)))?;
        self.parked -= 1;
        slot.take()
    }

    pub(crate) const fn parked(&self) -> usize {
        self.parked
    }
}

#[cfg(test)]
#[path = "parked_calls/tests.rs"]
mod tests;
