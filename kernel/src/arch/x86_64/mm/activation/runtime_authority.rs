//! The primordial runtime's coarse authority lock and its per-CPU handles.
//!
//! `RuntimeAuthorityLock` is the ticket lock around the whole
//! `PrimordialRuntimeCarrier` that DW1-C0 §6 accepts as a temporary bridge
//! (S2K design §2.1). Nothing locks it directly: `handles` mints exactly one
//! `RuntimeAuthorityHandle` per CPU, once, and a handle locks through
//! `&mut self`. A CPU's guard therefore borrows that CPU's handle for its
//! whole lifetime, which is what lets the guard-free token (S2K-3) be a
//! borrow-checker fact. Nothing in interrupt context locks it (D1 commit 2,
//! design §11.2.4): the handle is a CPU's only way in. `PagingLock` is the
//! paging authority's lock beneath it (D1 commit 3), reachable only through a
//! held guard.
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

use super::GuardFree;
use crate::one_shot::init_fields;

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

    /// Builds the lock directly at `slot`, with its value built in place by
    /// `value`, so no whole-lock temporary exists (S2K stage 4).
    ///
    /// # Safety
    ///
    /// `slot` is valid for writes of `Self` and not otherwise referenced, and
    /// `value` fully initializes the `T` behind its pointer before it returns,
    /// reading nothing through it. Afterwards `*slot` is fully initialized.
    pub(super) unsafe fn init_in_place(slot: *mut Self, value: impl FnOnce(*mut T)) {
        // SAFETY: `slot` is valid for writes of `Self` (this function's contract); `init_fields!`
        // writes every field of the lock but `value` from its exhaustive field list, and `value`
        // builds that one in place through its `UnsafeCell`'s raw pointer.
        unsafe {
            value(UnsafeCell::raw_get(core::ptr::addr_of_mut!((*slot).value)));
            init_fields!(
                slot,
                RuntimeAuthorityLock {
                    tickets: (TicketPair {
                        next_ticket: AtomicU64::new(0),
                        serving: AtomicU64::new(0),
                    }),
                    handles_taken: (AtomicBool::new(false)),
                    value: in_place,
                }
            );
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

/// One CPU's way to acquire the runtime authority and certify it guard-free.
/// Neither `Clone` nor `Copy`: `RuntimeAuthorityLock::handles` mints one per
/// CPU, and it is that CPU's only way to acquire the lock.
pub(super) struct RuntimeAuthorityHandle<'a, T> {
    lock: &'a RuntimeAuthorityLock<T>,
}

impl<T> RuntimeAuthorityHandle<'_, T> {
    /// Acquires the runtime authority. The guard mutably borrows this
    /// handle until it drops.
    pub(super) fn lock(&mut self) -> RuntimeAuthorityGuard<'_, T> {
        self.lock.lock()
    }

    /// Certifies that this CPU holds no runtime-authority guard. Refused by
    /// the borrow checker while a guard from this handle is alive.
    pub(super) fn guard_free(&mut self) -> GuardFree<'_> {
        // SAFETY: a guard mutably borrows its handle for its whole life, so `&mut self` proves no
        // guard of this handle is alive, and the token's borrow keeps one from being acquired
        // before it is consumed. `lock(&self)` is private to this module, so this handle is the
        // CPU's only way to acquire the lock.
        unsafe { GuardFree::assume() }
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

/// The paging authority's lock, P (D1 commit 3, design §11.2.4).
///
/// P is a component lock beneath the runtime authority, T, in the order
/// DW0-H §12.5 permits: always T, then P, and never P before T. The order
/// is a type fact. The only way to reach P is a [`PagingAccess`], which only
/// [`RuntimeAuthorityGuard::with_paging`] mints, and which mutably borrows
/// that T guard for its whole life. So:
/// - a P guard cannot outlive the T guard beneath which it was taken;
/// - no code holds P without holding T, so none can take T after P;
/// - the CPU's handle stays borrowed by its T guard, so T cannot be taken
///   twice either.
///
/// It lives outside T's value, so a later D1 step can give usercopy its own
/// way in without reaching into T's cell.
pub(super) struct PagingLock<P> {
    locked: AtomicBool,
    value: UnsafeCell<P>,
}

// SAFETY: `value` is written once before any AP carrier is released, never moved afterward, and
// every access goes through a `PagingGuard`, which holds `locked` (acquired with Acquire, released
// with Release). This is the same explicit DW0-H bridge as `RuntimeAuthorityLock`'s, for a paging
// authority whose type deliberately does not claim `Send`/`Sync` on its own.
unsafe impl<P> Sync for PagingLock<P> {}

impl<P> PagingLock<P> {
    pub(super) const fn new(value: P) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    fn acquire(&self) -> PagingGuard<'_, P> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        PagingGuard { lock: self }
    }
}

impl<'g, T> RuntimeAuthorityGuard<'g, T> {
    /// Splits this T guard into its value and access to `paging` beneath it.
    /// The access mutably borrows the guard, so P is reached only while T is
    /// held, and only after it.
    pub(super) fn with_paging<'a, P>(
        &'a mut self,
        paging: &'a PagingLock<P>,
    ) -> (&'a mut T, PagingAccess<'a, P>) {
        let access = PagingAccess {
            lock: paging,
            _beneath_runtime_guard: PhantomData,
        };
        (&mut **self, access)
    }
}

/// The right to take P during one T hold. Neither `Clone` nor `Copy`, and
/// constructible only by [`RuntimeAuthorityGuard::with_paging`].
pub(super) struct PagingAccess<'a, P> {
    lock: &'a PagingLock<P>,
    _beneath_runtime_guard: PhantomData<&'a mut ()>,
}

impl<P> PagingAccess<'_, P> {
    /// Takes P. The guard mutably borrows this access until it drops, so P
    /// is never taken twice on one CPU.
    pub(super) fn lock(&mut self) -> PagingGuard<'_, P> {
        self.lock.acquire()
    }
}

pub(super) struct PagingGuard<'a, P> {
    lock: &'a PagingLock<P>,
}

impl<P> Deref for PagingGuard<'_, P> {
    type Target = P;

    fn deref(&self) -> &Self::Target {
        // SAFETY: `acquire` is the only constructor of a guard and returns only after it owns
        // `locked`; `drop` releases it with a Release store that the next `acquire` reads with
        // Acquire.
        unsafe { &*self.lock.value.get() }
    }
}

impl<P> DerefMut for PagingGuard<'_, P> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: as in `deref`, the guard owns `locked`, and `&mut self` on the guard makes this
        // the only reference to the value for its lifetime.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<P> Drop for PagingGuard<'_, P> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
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

    /// A lock built in place serves exactly like one built by value.
    #[test]
    fn a_lock_built_in_place_serves_its_value() {
        let mut storage = core::mem::MaybeUninit::<RuntimeAuthorityLock<[u32; 2]>>::uninit();
        // SAFETY: the storage is a fresh local, valid for writes and unreferenced, and the closure
        // writes the whole `[u32; 2]`.
        let lock = unsafe {
            RuntimeAuthorityLock::init_in_place(storage.as_mut_ptr(), |value| value.write([3, 4]));
            storage.assume_init_ref()
        };
        let [mut handle] = lock.handles::<1>();
        assert_eq!(*handle.lock(), [3, 4]);
        assert_eq!(lock.tickets.next_ticket.load(Ordering::Relaxed), 1);
        handle.lock()[0] = 5;
        assert_eq!(*handle.lock(), [5, 4]);
    }

    /// P is reached beneath a T guard, serializes its value, and is
    /// released when its guard drops, while T stays held.
    #[test]
    fn paging_is_taken_beneath_the_runtime_guard_and_released() {
        let lock = RuntimeAuthorityLock::new(1_u32);
        let paging = PagingLock::new(10_u32);
        let [mut handle] = lock.handles::<1>();
        let mut guard = handle.lock();
        let (value, mut access) = guard.with_paging(&paging);
        *value += 1;
        *access.lock() += 5;
        assert!(!paging.locked.load(Ordering::Relaxed));
        {
            let held = access.lock();
            assert_eq!(*held, 15);
            assert!(paging.locked.load(Ordering::Relaxed));
        }
        assert!(!paging.locked.load(Ordering::Relaxed));
        drop(guard);
        assert_eq!(*handle.lock(), 2);
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
