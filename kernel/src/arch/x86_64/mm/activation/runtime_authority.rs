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
    /// Called on every iteration of the ticket spin (D1 commit 4): see
    /// [`SpinService`].
    spin_service: SpinService,
    value: UnsafeCell<T>,
}

/// What a CPU does while it spins on a runtime lock with interrupts clear
/// (D1 commit 4, design §11.2.2). A CPU spinning with IF clear cannot take
/// the TLB-shootdown IPI, so if the lock's holder is waiting for that CPU's
/// acknowledgement, neither progresses. The live kernel passes
/// `user_access::service_local_tlb_shootdown`, which acknowledges a pending
/// shootdown from inside the spin. The service must take no lock this CPU
/// could already hold, and must be safe to call at any point where the
/// interrupt it stands in for could have been taken.
pub(super) type SpinService = fn();

// SAFETY: `value` is initialized before any AP carrier is released, never
// moved afterward, and every access is serialized by the ticket pair. This is the
// explicit DW0-H bridge for authorities whose types intentionally do not claim
// `Send`/`Sync` independently.
unsafe impl<T> Sync for RuntimeAuthorityLock<T> {}

impl<T> RuntimeAuthorityLock<T> {
    pub(super) const fn new(value: T, spin_service: SpinService) -> Self {
        Self {
            tickets: TicketPair {
                next_ticket: AtomicU64::new(0),
                serving: AtomicU64::new(0),
            },
            handles_taken: AtomicBool::new(false),
            spin_service,
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
    pub(super) unsafe fn init_in_place(
        slot: *mut Self,
        spin_service: SpinService,
        value: impl FnOnce(*mut T),
    ) {
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
                    spin_service: spin_service,
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
            (self.spin_service)();
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
/// is a type fact. The only way to reach P is a [`PagingAccess`]. Two
/// functions mint one, and each keeps the CPU's handle mutably borrowed for
/// the access's whole life:
/// - [`RuntimeAuthorityGuard::with_paging`] borrows a T guard, so a P guard
///   cannot outlive the T guard beneath which it was taken;
/// - [`PagingLock::guard_free_access`] consumes a `GuardFree` (D1 commit 5),
///   so no T guard exists, and none can be taken, while that access lives.
///
/// So no code takes T after P.
///
/// It lives outside T's value, so a later D1 step can give usercopy its own
/// way in without reaching into T's cell.
pub(super) struct PagingLock<P> {
    locked: AtomicBool,
    /// Called on every iteration of the spin, as for the runtime authority.
    spin_service: SpinService,
    value: UnsafeCell<P>,
}

// SAFETY: `value` is written once before any AP carrier is released, never moved afterward, and
// every access goes through a `PagingGuard`, which holds `locked` (acquired with Acquire, released
// with Release). This is the same explicit DW0-H bridge as `RuntimeAuthorityLock`'s, for a paging
// authority whose type deliberately does not claim `Send`/`Sync` on its own.
unsafe impl<P> Sync for PagingLock<P> {}

impl<P> PagingLock<P> {
    pub(super) const fn new(value: P, spin_service: SpinService) -> Self {
        Self {
            locked: AtomicBool::new(false),
            spin_service,
            value: UnsafeCell::new(value),
        }
    }

    fn acquire(&self) -> PagingGuard<'_, P> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            (self.spin_service)();
            core::hint::spin_loop();
        }
        PagingGuard { lock: self }
    }
}

impl<P> PagingLock<P> {
    /// Access to P with no T guard beneath it, for a usercopy (D1 commit 5,
    /// design §11.2.3 family A). The `GuardFree` token mutably borrows the
    /// CPU's handle for `'a`, and so does the access. So no T guard is alive
    /// while the access is, and none can be taken while it lives: P is never
    /// held before T.
    pub(super) fn guard_free_access<'a>(
        &'a self,
        _guard_free: GuardFree<'a>,
    ) -> PagingAccess<'a, P> {
        PagingAccess {
            lock: self,
            _beneath_runtime_guard: PhantomData,
        }
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

/// The right to take P during one T hold, or during one guard-free usercopy.
/// Neither `Clone` nor `Copy`, and constructible only by
/// [`RuntimeAuthorityGuard::with_paging`] and [`PagingLock::guard_free_access`].
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

/// A witness that this CPU holds P: a [`PagingGuard`], or a session built
/// from one and borrowing it. S is acquired only beneath such a witness.
pub(super) trait PagingHeld {}

impl<P> PagingHeld for PagingGuard<'_, P> {}

/// Proof that the one shootdown an S guard covered is settled: its reclaim
/// permit, or proof that its publisher published nothing. An S guard is
/// released only by consuming one ([`ShootdownInitiatorGuard::release`]).
pub(super) trait ShootdownSettled {}

/// The shootdown-initiator lock, S (D1 option B, design §11.2.9): one TLB
/// shootdown in flight system-wide, so each target CPU's one-slot mailbox
/// never meets a second request, and a second mutation of an address space
/// waits its turn rather than meeting `MutationInFlight`.
///
/// The order is T, then P, then S. S is acquired only beneath a held P
/// ([`ShootdownInitiatorLock::acquire_beneath`]), and so, by P's own order,
/// beneath T. Unlike P, its guard borrows only the lock, not the P guard, so
/// it can outlive the T and P guards it was taken beneath: it is released by
/// consuming the settlement of the shootdown it covered, not by scope.
/// While holding only S a CPU acquires nothing; it waits only for
/// acknowledgements, which targets give from e2 or from inside any IF-clear
/// spin. S's own spin calls the [`SpinService`] like T's and P's, and only a
/// CPU holding T spins on it, so at most one CPU spins on S at a time.
pub(super) struct ShootdownInitiatorLock {
    locked: AtomicBool,
    /// Called on every iteration of the spin, as for the runtime authority.
    spin_service: SpinService,
}

impl ShootdownInitiatorLock {
    pub(super) const fn new(spin_service: SpinService) -> Self {
        Self {
            locked: AtomicBool::new(false),
            spin_service,
        }
    }

    /// Takes S beneath `_paging`, a witness that this CPU holds P.
    pub(super) fn acquire_beneath(&self, _paging: &impl PagingHeld) -> ShootdownInitiatorGuard<'_> {
        self.acquire()
    }

    fn acquire(&self) -> ShootdownInitiatorGuard<'_> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            (self.spin_service)();
            core::hint::spin_loop();
        }
        ShootdownInitiatorGuard { lock: self }
    }
}

/// A held S. Neither `Clone` nor `Copy`. Dropping it unreleased is a kernel
/// bug and panics.
#[must_use = "S is released only by consuming the settlement of the shootdown it covered"]
pub(super) struct ShootdownInitiatorGuard<'s> {
    lock: &'s ShootdownInitiatorLock,
}

impl ShootdownInitiatorGuard<'_> {
    /// Releases S on the settlement of the shootdown it covered, and hands the
    /// settlement back for the reclamation it gates.
    pub(super) fn release<R: ShootdownSettled>(self, settled: R) -> R {
        self.unlock();
        settled
    }

    /// Releases an S whose transaction failed before it built a coherent
    /// publisher, so it covered no shootdown. Every S whose transaction
    /// reached a publisher is released through [`Self::release`], on that
    /// publisher's settlement.
    pub(super) fn release_unused(self) {
        self.unlock();
    }

    fn unlock(self) {
        let lock = self.lock;
        core::mem::forget(self);
        lock.locked.store(false, Ordering::Release);
    }
}

impl Drop for ShootdownInitiatorGuard<'_> {
    fn drop(&mut self) {
        panic!("the shootdown-initiator lock was dropped without its settlement");
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn no_service() {}

    /// A host model of addendum §11.2.2's deadlock (D1 commit 4). An
    /// initiator holds a lock and waits, for a bounded number of steps, for
    /// the acknowledgement of a request it published to a target. The target
    /// is spinning on that same lock. In the kernel the target spins with IF
    /// clear, so it can acknowledge only from inside the spin, through the
    /// lock's `SpinService`.
    struct ModelMailbox {
        request: AtomicBool,
        acknowledged: AtomicBool,
    }

    impl ModelMailbox {
        const fn new() -> Self {
            Self {
                request: AtomicBool::new(false),
                acknowledged: AtomicBool::new(false),
            }
        }

        fn service(&self) {
            if self.request.swap(false, Ordering::AcqRel) {
                self.acknowledged.store(true, Ordering::Release);
            }
        }

        /// Publishes the request, then waits for its acknowledgement.
        fn publish_and_wait(&self) -> bool {
            self.request.store(true, Ordering::Release);
            for _ in 0..100_000 {
                if self.acknowledged.load(Ordering::Acquire) {
                    return true;
                }
                std::thread::yield_now();
            }
            false
        }
    }

    static RUNTIME_SERVICED: ModelMailbox = ModelMailbox::new();
    static RUNTIME_UNSERVICED: ModelMailbox = ModelMailbox::new();
    static PAGING_SERVICED: ModelMailbox = ModelMailbox::new();
    static PAGING_UNSERVICED: ModelMailbox = ModelMailbox::new();

    /// The initiator holds the runtime authority while the target spins on it.
    fn runtime_initiator_is_acknowledged(
        mailbox: &'static ModelMailbox,
        spin_service: SpinService,
    ) -> bool {
        let lock = RuntimeAuthorityLock::new(0_u32, spin_service);
        let [mut initiator, mut target] = lock.handles::<2>();
        std::thread::scope(|scope| {
            let guard = initiator.lock();
            let spinner = scope.spawn(move || *target.lock() += 1);
            while lock.tickets.next_ticket.load(Ordering::Acquire) != 2 {
                std::thread::yield_now();
            }
            let acknowledged = mailbox.publish_and_wait();
            drop(guard);
            spinner.join().expect("target thread");
            acknowledged
        })
    }

    /// The initiator holds the paging lock while the target spins on it.
    fn paging_initiator_is_acknowledged(
        mailbox: &'static ModelMailbox,
        spin_service: SpinService,
    ) -> bool {
        let paging = PagingLock::new(0_u32, spin_service);
        let spinning = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let held = paging.acquire();
            let spinner = scope.spawn(|| {
                spinning.store(true, Ordering::Release);
                *paging.acquire() += 1;
            });
            while !spinning.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            let acknowledged = mailbox.publish_and_wait();
            drop(held);
            spinner.join().expect("target thread");
            acknowledged
        })
    }

    #[test]
    fn a_runtime_lock_spinner_acknowledges_only_when_its_spin_services_the_mailbox() {
        assert!(!runtime_initiator_is_acknowledged(
            &RUNTIME_UNSERVICED,
            no_service
        ));
        assert!(runtime_initiator_is_acknowledged(&RUNTIME_SERVICED, || {
            RUNTIME_SERVICED.service()
        }));
    }

    #[test]
    fn a_paging_lock_spinner_acknowledges_only_when_its_spin_services_the_mailbox() {
        assert!(!paging_initiator_is_acknowledged(
            &PAGING_UNSERVICED,
            no_service
        ));
        assert!(paging_initiator_is_acknowledged(&PAGING_SERVICED, || {
            PAGING_SERVICED.service()
        }));
    }

    #[test]
    fn a_handle_serializes_the_value_and_releases_on_drop() {
        let lock = RuntimeAuthorityLock::new(1_u32, no_service);
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
            RuntimeAuthorityLock::init_in_place(storage.as_mut_ptr(), no_service, |value| {
                value.write([3, 4])
            });
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
        let lock = RuntimeAuthorityLock::new(1_u32, no_service);
        let paging = PagingLock::new(10_u32, no_service);
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
        let lock = RuntimeAuthorityLock::new((), no_service);
        let _handles = lock.handles::<4>();
        let again = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = lock.handles::<4>();
        }));
        assert!(again.is_err());
    }

    #[test]
    fn the_published_address_is_the_adjacent_ticket_pair() {
        let lock = RuntimeAuthorityLock::new([0_u8; 64], no_service);
        let [mut handle] = lock.handles::<1>();
        drop(handle.lock());
        let pair = lock.ticket_pair_address().cast::<u64>();
        // SAFETY: `pair` is the address of the live `repr(C)` ticket pair, two aligned
        // `AtomicU64`s, read here while no guard exists.
        let (next, serving) = unsafe { (pair.read(), pair.add(1).read()) };
        assert_eq!((next, serving), (1, 1));
    }

    struct Settled;
    impl ShootdownSettled for Settled {}

    /// D1 option B1: S is taken beneath a held P, survives the T and P
    /// guards it was taken beneath, excludes a second initiator until it is
    /// released on a settlement, and is free again afterwards.
    #[test]
    fn s_outlives_t_and_p_and_is_released_only_on_a_settlement() {
        let lock = RuntimeAuthorityLock::new((), no_service);
        let paging = PagingLock::new((), no_service);
        let initiator_lock = ShootdownInitiatorLock::new(no_service);
        let [mut handle] = lock.handles::<1>();
        let initiator = {
            let mut guard = handle.lock();
            let (_, mut access) = guard.with_paging(&paging);
            let held = access.lock();
            initiator_lock.acquire_beneath(&held)
        };
        assert!(!paging.locked.load(Ordering::Relaxed));
        assert!(initiator_lock.locked.load(Ordering::Relaxed));
        drop(handle.guard_free());
        let Settled = initiator.release(Settled);
        assert!(!initiator_lock.locked.load(Ordering::Relaxed));
        initiator_lock.acquire().release_unused();
        assert!(!initiator_lock.locked.load(Ordering::Relaxed));
    }

    #[test]
    fn dropping_an_unreleased_s_panics() {
        let initiator_lock = ShootdownInitiatorLock::new(no_service);
        let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(initiator_lock.acquire());
        }));
        let message = dropped.expect_err("an unreleased S must panic");
        assert_eq!(
            message.downcast_ref::<&str>().copied(),
            Some("the shootdown-initiator lock was dropped without its settlement")
        );
    }

    static S_SERVICED: ModelMailbox = ModelMailbox::new();
    static S_UNSERVICED: ModelMailbox = ModelMailbox::new();

    /// The initiator holds S alone while the target spins on S, as a CPU
    /// holding T spins for it (design §11.2.9, item 2).
    fn s_initiator_is_acknowledged(
        mailbox: &'static ModelMailbox,
        spin_service: SpinService,
    ) -> bool {
        let initiator_lock = ShootdownInitiatorLock::new(spin_service);
        let spinning = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let held = initiator_lock.acquire();
            let spinner = scope.spawn(|| {
                spinning.store(true, Ordering::Release);
                initiator_lock.acquire().release_unused();
            });
            while !spinning.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            let acknowledged = mailbox.publish_and_wait();
            held.release_unused();
            spinner.join().expect("target thread");
            acknowledged
        })
    }

    #[test]
    fn an_s_spinner_acknowledges_only_when_its_spin_services_the_mailbox() {
        assert!(!s_initiator_is_acknowledged(&S_UNSERVICED, no_service));
        assert!(s_initiator_is_acknowledged(&S_SERVICED, || {
            S_SERVICED.service()
        }));
    }
}
