//! The primordial runtime's coarse authority lock and its per-CPU handles.
//!
//! `RuntimeAuthorityLock` is the ticket lock around the whole
//! `PrimordialRuntimeCarrier` that DW1-C0 §6 accepts as a temporary bridge
//! (S2K design §2.1). Nothing locks it directly: `handles` mints exactly one
//! `RuntimeAuthorityHandle` per CPU, once, and a handle locks through
//! `&mut self`. A CPU's guard therefore borrows that CPU's handle for its
//! whole lifetime, which is what lets the guard-free token (S2K-3) be a
//! borrow-checker fact.
//!
//! Split out of the target-only `primordial.rs` (S2K-3) because it uses only
//! atomics and an `UnsafeCell`, so the host build compiles it, host Clippy
//! sees its `unsafe`, and host tests exercise it.

#![allow(
    unsafe_code,
    reason = "the ticket lock hands out the carrier through an UnsafeCell serialized by its ticket pair"
)]

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The ticket pair, `repr(C)` so `serving` sits exactly one word after
/// `next_ticket`.
///
/// `publish_runtime_authority` hands a debugger the address of this pair and
/// root `tools/gdb/r1-liveness.gdb` reads two words from it. `repr(Rust)`
/// reordered the lock's fields (reset card R1's run 10 read carrier bytes as
/// a ticket pair), so the order is fixed here rather than assumed.
#[repr(C)]
struct TicketPair {
    next_ticket: AtomicU64,
    serving: AtomicU64,
}

const _: () = assert!(
    core::mem::offset_of!(TicketPair, next_ticket) == 0
        && core::mem::offset_of!(TicketPair, serving) == 8,
    "the runtime authority's ticket pair is no longer two adjacent words, so the address \
     published for GDB no longer locates it"
);

/// Coarse DW0-H transaction boundary for the still-monolithic live authority
/// set. Per-CPU carrier state remains outside this lock; shared mutations are
/// serialized until the individual authorities grow narrower SMP adapters.
pub(super) struct RuntimeAuthorityLock<T> {
    tickets: TicketPair,
    handles_taken: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: `value` is initialized before any AP carrier is released, never
// moved afterward, and every access is serialized by the ticket pair. This is the
// explicit DW0-H bridge for authorities whose types intentionally do not claim
// `Send`/`Sync` independently.
unsafe impl<T> Sync for RuntimeAuthorityLock<T> {}

impl<T> RuntimeAuthorityLock<T> {
    pub(super) const fn new(value: T) -> Self {
        Self {
            tickets: TicketPair {
                next_ticket: AtomicU64::new(0),
                serving: AtomicU64::new(0),
            },
            handles_taken: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// The address a debugger reads the ticket pair from.
    pub(super) fn ticket_pair_address(&self) -> *const () {
        core::ptr::from_ref(&self.tickets).cast::<()>()
    }

    /// Mints the one handle per CPU slot. A second call panics: two handles
    /// on one CPU would let one hold a guard while the other certifies the
    /// CPU guard-free.
    pub(super) fn handles<const CPUS: usize>(&self) -> [RuntimeAuthorityHandle<'_, T>; CPUS] {
        if self.handles_taken.swap(true, Ordering::AcqRel) {
            panic!("runtime authority handles were minted twice");
        }
        core::array::from_fn(|_| RuntimeAuthorityHandle { lock: self })
    }

    fn lock(&self) -> RuntimeAuthorityGuard<'_, T> {
        let mut observed = self.tickets.next_ticket.load(Ordering::Relaxed);
        let ticket = loop {
            if observed == u64::MAX {
                panic!("runtime authority ticket space exhausted");
            }
            match self.tickets.next_ticket.compare_exchange_weak(
                observed,
                observed + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(ticket) => break ticket,
                Err(current) => observed = current,
            }
        };
        while self.tickets.serving.load(Ordering::Acquire) != ticket {
            core::hint::spin_loop();
        }
        RuntimeAuthorityGuard {
            lock: self,
            ticket,
            owns_lock: true,
            _handle: PhantomData,
        }
    }
}

/// One CPU's only way to acquire the runtime authority. Neither `Clone` nor
/// `Copy`: `RuntimeAuthorityLock::handles` mints one per CPU.
pub(super) struct RuntimeAuthorityHandle<'a, T> {
    lock: &'a RuntimeAuthorityLock<T>,
}

impl<T> RuntimeAuthorityHandle<'_, T> {
    /// Acquires the runtime authority. The guard mutably borrows this
    /// handle until it drops.
    pub(super) fn lock(&mut self) -> RuntimeAuthorityGuard<'_, T> {
        self.lock.lock()
    }
}

pub(super) struct RuntimeAuthorityGuard<'a, T> {
    lock: &'a RuntimeAuthorityLock<T>,
    ticket: u64,
    owns_lock: bool,
    _handle: PhantomData<&'a mut ()>,
}

impl<T> Deref for RuntimeAuthorityGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: `lock` is the only constructor of a guard and sets `owns_lock`, so a guard exists
        // only while it holds the ticket; `drop` releases it with a Release store that the next
        // `lock` spins on with Acquire.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for RuntimeAuthorityGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: as in `deref`, the guard holds the ticket, and `&mut self` on the guard makes
        // this the only reference to the value for its lifetime.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for RuntimeAuthorityGuard<'_, T> {
    fn drop(&mut self) {
        if self.owns_lock {
            self.lock
                .tickets
                .serving
                .store(self.ticket + 1, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn a_handle_serializes_the_value_and_releases_on_drop() {
        let lock = RuntimeAuthorityLock::new(1_u32);
        let [mut first, mut second] = lock.handles::<2>();
        {
            let mut guard = first.lock();
            *guard += 1;
        }
        {
            let mut guard = second.lock();
            *guard += 1;
        }
        assert_eq!(*first.lock(), 3);
        assert_eq!(lock.tickets.next_ticket.load(Ordering::Relaxed), 3);
        assert_eq!(lock.tickets.serving.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn handles_are_minted_once() {
        let lock = RuntimeAuthorityLock::new(());
        let _handles = lock.handles::<4>();
        let again = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = lock.handles::<4>();
        }));
        assert!(again.is_err());
    }

    #[test]
    fn the_published_address_is_the_adjacent_ticket_pair() {
        let lock = RuntimeAuthorityLock::new([0_u8; 64]);
        let [mut handle] = lock.handles::<1>();
        drop(handle.lock());
        let pair = lock.ticket_pair_address().cast::<u64>();
        // SAFETY: `pair` is the address of the live `repr(C)` ticket pair, two aligned
        // `AtomicU64`s, read here while no guard exists.
        let (next, serving) = unsafe { (pair.read(), pair.add(1).read()) };
        assert_eq!((next, serving), (1, 1));
    }
}
