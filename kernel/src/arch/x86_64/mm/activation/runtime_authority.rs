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

/// What the runtime guard checks of the value it guards as it releases T
/// (DW2 §10.15 revision 2 item 1): the backstop that makes a hold that ends
/// without draining or staging its releases fail at that hold, not at a
/// later remote Stop's commit. It runs before the release, so no other CPU
/// sees the state that broke the rule.
pub(super) trait HoldEndCheck {
    /// `taken` is where the hold's guard was acquired, for the panic.
    fn check_hold_end(&self, taken: &'static core::panic::Location<'static>);

    /// Runs on this CPU once the hold has released T, for work the hold
    /// left that must not be done under it (DW2 §10.19 revision 3: the
    /// BSP's wake for owed work). It sees no guarded state.
    fn after_release() {}

    /// The step report's counter, read for T's timing (DW2 §13.5): when an
    /// acquisition's first check of its ticket fails and it must spin, and
    /// just before the release store. The default, for every guarded value
    /// but the live runtime's, reads none, so the lock's host tests see the
    /// lock alone.
    #[inline(always)]
    fn timing_now() -> Option<u64> {
        None
    }

    /// CPU slot `cpu` was served T, having begun to spin at `ticketed`
    /// (`None`: served at its first check, or no counter).
    #[inline(always)]
    fn hold_served(_cpu: u32, _ticketed: Option<u64>) {}

    /// CPU slot `cpu` released T at `released`, read just before the
    /// release store.
    #[inline(always)]
    fn hold_released(_cpu: u32, _released: Option<u64>) {}
}

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
        // The handle at index `cpu` is CPU slot `cpu`'s: the live kernel
        // hands handle `n` to the carrier facade of `CpuIndex` `n`, the index
        // the step report keys its per-CPU records by.
        core::array::from_fn(|cpu| RuntimeAuthorityHandle {
            lock: self,
            cpu: u32::try_from(cpu).unwrap_or(u32::MAX),
        })
    }

    #[track_caller]
    fn lock(&self, cpu: u32) -> RuntimeAuthorityGuard<'_, T>
    where
        T: HoldEndCheck,
    {
        let taken = core::panic::Location::caller();
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
        // Stamped only once the first check fails: an acquisition served at
        // once reads no counter here, and its wait is zero.
        let mut ticketed = None;
        while self.tickets.serving.load(Ordering::Acquire) != ticket {
            if ticketed.is_none() {
                ticketed = T::timing_now();
            }
            (self.spin_service)();
            core::hint::spin_loop();
        }
        T::hold_served(cpu, ticketed);
        RuntimeAuthorityGuard {
            lock: self,
            ticket,
            owns_lock: true,
            cpu,
            taken,
            _handle: PhantomData,
        }
    }
}

/// One CPU's way to acquire the runtime authority and certify it guard-free.
/// Neither `Clone` nor `Copy`: `RuntimeAuthorityLock::handles` mints one per
/// CPU, and it is that CPU's only way to acquire the lock.
pub(super) struct RuntimeAuthorityHandle<'a, T> {
    lock: &'a RuntimeAuthorityLock<T>,
    /// The CPU slot this handle was minted for, for the step report's T
    /// timing (DW2 §13.5).
    cpu: u32,
}

impl<T> RuntimeAuthorityHandle<'_, T> {
    /// Acquires the runtime authority. The guard mutably borrows this
    /// handle until it drops.
    #[track_caller]
    pub(super) fn lock(&mut self) -> RuntimeAuthorityGuard<'_, T>
    where
        T: HoldEndCheck,
    {
        self.lock.lock(self.cpu)
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

pub(super) struct RuntimeAuthorityGuard<'a, T: HoldEndCheck> {
    lock: &'a RuntimeAuthorityLock<T>,
    ticket: u64,
    owns_lock: bool,
    /// The CPU slot of the handle that took this hold.
    cpu: u32,
    /// Where this hold began, named if it ends breaking the hold-end rule.
    taken: &'static core::panic::Location<'static>,
    _handle: PhantomData<&'a mut ()>,
}

impl<T: HoldEndCheck> Deref for RuntimeAuthorityGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: `lock` is the only constructor of a guard and sets `owns_lock`, so a guard exists
        // only while it holds the ticket; `drop` releases it with a Release store that the next
        // `lock` spins on with Acquire.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T: HoldEndCheck> DerefMut for RuntimeAuthorityGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: as in `deref`, the guard holds the ticket, and `&mut self` on the guard makes
        // this the only reference to the value for its lifetime.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T: HoldEndCheck> Drop for RuntimeAuthorityGuard<'_, T> {
    fn drop(&mut self) {
        if self.owns_lock {
            // SAFETY: as in `deref`; the ticket is still held here.
            unsafe { &*self.lock.value.get() }.check_hold_end(self.taken);
            let released = T::timing_now();
            self.lock
                .tickets
                .serving
                .store(self.ticket + 1, Ordering::Release);
            T::hold_released(self.cpu, released);
            T::after_release();
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
///
/// P is a reader-writer lock (DW2 §15.2, M8b step 1). Every access above
/// takes it exclusively, as before. A third way in,
/// [`PagingLock::guard_free_shared_fault_access`], takes it shared, for the
/// fast serve of a page already committed: its guard gives `&P` only, and
/// nothing reachable from it writes what P guards.
///
/// `state` is one word: bit 0 ([`WRITER`]) is set while an exclusive guard
/// exists; bit 1 ([`WRITER_WAITING`]) is set by every exclusive acquirer
/// while it waits and cleared by the one that takes; bits 2 and up
/// ([`READER`] each) count the shared guards. A shared acquirer waits while
/// either low bit is set, so a waiting writer stops new readers; an
/// exclusive acquirer takes only when no writer holds and no reader is
/// counted. Several writers may wait at once: each re-sets the waiting bit
/// on every spin in which it finds it clear, and the one that takes clears
/// it, so a clear bit can let a reader in only until the next waiter's next
/// spin, never for more than that one reader's hold.
pub(super) struct PagingLock<P> {
    state: AtomicU64,
    /// Called on every iteration of the spin, as for the runtime authority.
    spin_service: SpinService,
    /// P's timing (DW2 §13.16 part e3), taken as T's is.
    timing: PagingTiming,
    value: UnsafeCell<P>,
}

/// [`PagingLock`]'s writer bit: an exclusive guard exists.
const WRITER: u64 = 1;
/// [`PagingLock`]'s writer-waiting bit: an exclusive acquirer is waiting.
const WRITER_WAITING: u64 = 1 << 1;
/// One shared guard in [`PagingLock`]'s reader count (bits 2 and up).
const READER: u64 = 1 << 2;
/// The reader count's bits.
const READERS: u64 = !(WRITER | WRITER_WAITING);

/// Who took P, for its timing (DW2 §13.16 part e3, the `p-lock` line):
/// every P beneath a T guard is `Runtime`; with no T guard, a fast serve is
/// `Fault` and every other holder `Usercopy`; a fast serve that takes P
/// shared is `FaultShared` (DW2 §15.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PagingSource {
    Fault = 0,
    Usercopy = 1,
    Runtime = 2,
    FaultShared = 3,
}

/// P's timing hooks. `now` reads the counter (`None`: no timing); a
/// release calls `released` with the source, the wait (`None` when taken
/// at its first try) and the hold, in counter ticks.
#[derive(Clone, Copy)]
pub(super) struct PagingTiming {
    pub(super) now: fn() -> Option<u64>,
    pub(super) released: fn(PagingSource, Option<u64>, u64),
}

impl PagingTiming {
    /// No timing: the lock alone, as host tests see it.
    pub(super) const NONE: Self = Self {
        now: untimed_now,
        released: untimed_release,
    };
}

fn untimed_now() -> Option<u64> {
    None
}

fn untimed_release(_: PagingSource, _: Option<u64>, _: u64) {}

// SAFETY: `value` is written once before any AP carrier is released, never moved afterward, and
// every access goes through a guard: a `PagingGuard`, which holds the writer bit alone (taken with
// Acquire when no reader is counted, released with Release), or a `SharedPagingGuard`, which holds
// one count of the readers (taken with Acquire while no writer holds, released with Release) and
// gives `&P` only. This is the same explicit DW0-H bridge as `RuntimeAuthorityLock`'s, for a
// paging authority whose type deliberately does not claim `Send`/`Sync` on its own; what shared
// guards on several CPUs may do through their `&P` at once is bounded where the shared guard's
// reference is formed (`SharedPagingGuard::deref`).
unsafe impl<P> Sync for PagingLock<P> {}

impl<P> PagingLock<P> {
    pub(super) const fn new(value: P, spin_service: SpinService) -> Self {
        Self::new_timed(value, spin_service, PagingTiming::NONE)
    }

    /// As [`Self::new`], with P's timing hooks.
    pub(super) const fn new_timed(
        value: P,
        spin_service: SpinService,
        timing: PagingTiming,
    ) -> Self {
        Self {
            state: AtomicU64::new(0),
            spin_service,
            timing,
            value: UnsafeCell::new(value),
        }
    }

    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "the lock's host tests take it directly")
    )]
    fn acquire(&self) -> PagingGuard<'_, P> {
        self.acquire_in(PagingSource::Runtime)
    }

    /// Takes P exclusively: sets the writer-waiting bit, waits until no
    /// writer holds and no reader is counted, then takes the writer bit and
    /// clears the waiting bit in one exchange.
    fn acquire_in<M>(&self, source: PagingSource) -> PagingGuard<'_, P, M> {
        // Stamped only once the first try fails, as for T.
        let mut ticketed = None;
        loop {
            let state = self.state.load(Ordering::Relaxed);
            if state & (WRITER | READERS) == 0
                && self
                    .state
                    .compare_exchange_weak(state, WRITER, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                break;
            }
            // Re-set on every spin that finds it clear: another writer's
            // taking clears it, and this one still waits.
            if state & WRITER_WAITING == 0 {
                self.state.fetch_or(WRITER_WAITING, Ordering::Relaxed);
            }
            if ticketed.is_none() {
                ticketed = (self.timing.now)();
            }
            (self.spin_service)();
            core::hint::spin_loop();
        }
        let served = (self.timing.now)();
        PagingGuard {
            lock: self,
            source,
            served,
            waited: waited(ticketed, served),
            _mode: PhantomData,
        }
    }

    /// Takes P shared: waits while a writer holds or waits, then counts one
    /// reader in one exchange.
    fn acquire_shared(&self) -> SharedPagingGuard<'_, P> {
        let mut ticketed = None;
        loop {
            let state = self.state.load(Ordering::Relaxed);
            if state & (WRITER | WRITER_WAITING) == 0 {
                let Some(next) = state.checked_add(READER) else {
                    panic!("the paging lock's reader count overflowed");
                };
                if self
                    .state
                    .compare_exchange_weak(state, next, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
            if ticketed.is_none() {
                ticketed = (self.timing.now)();
            }
            (self.spin_service)();
            core::hint::spin_loop();
        }
        let served = (self.timing.now)();
        SharedPagingGuard {
            lock: self,
            served,
            waited: waited(ticketed, served),
        }
    }

    /// Reads P's timing just before a release, as T's is, and reports it.
    fn time_release(&self, source: PagingSource, served: Option<u64>, waited: Option<u64>) {
        if let (Some(served), Some(released)) = (served, (self.timing.now)()) {
            (self.timing.released)(source, waited, released.saturating_sub(served));
        }
    }
}

/// The wait of an acquisition that began to spin at `ticketed` and was
/// served at `served`; `None` when it was served at its first try.
fn waited(ticketed: Option<u64>, served: Option<u64>) -> Option<u64> {
    ticketed
        .zip(served)
        .map(|(ticketed, served)| served.saturating_sub(ticketed))
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
    ) -> PagingAccess<'a, P, GuardFreeOnly> {
        PagingAccess {
            lock: self,
            source: PagingSource::Usercopy,
            _beneath_runtime_guard: PhantomData,
            _mode: PhantomData,
        }
    }

    /// As [`Self::guard_free_access`], for the fast serve of a page fault
    /// (DW2 §13.16 part e3): the same guard-free mode, timed as `Fault`.
    #[cfg_attr(
        not(all(target_os = "none", target_arch = "x86_64")),
        allow(dead_code, reason = "only the live fast serve takes it")
    )]
    pub(super) fn guard_free_fault_access<'a>(
        &'a self,
        _guard_free: GuardFree<'a>,
    ) -> PagingAccess<'a, P, GuardFreeOnly> {
        PagingAccess {
            lock: self,
            source: PagingSource::Fault,
            _beneath_runtime_guard: PhantomData,
            _mode: PhantomData,
        }
    }

    /// Shared access to P with no T guard beneath it, for the fast serve of
    /// a page already committed (DW2 §15.2): the only way P is taken
    /// shared. As [`Self::guard_free_access`], the `GuardFree` token and the
    /// access mutably borrow the CPU's handle for `'a`, so P is never held
    /// before T; timed as `FaultShared`.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "the lock's host tests take it; the shared fast serve is built on it in its own commit"
        )
    )]
    pub(super) fn guard_free_shared_fault_access<'a>(
        &'a self,
        _guard_free: GuardFree<'a>,
    ) -> SharedPagingAccess<'a, P> {
        SharedPagingAccess {
            lock: self,
            _beneath_runtime_guard: PhantomData,
        }
    }
}

impl<'g, T: HoldEndCheck> RuntimeAuthorityGuard<'g, T> {
    /// Splits this T guard into its value and access to `paging` beneath it.
    /// The access mutably borrows the guard, so P is reached only while T is
    /// held, and only after it.
    pub(super) fn with_paging<'a, P>(
        &'a mut self,
        paging: &'a PagingLock<P>,
    ) -> (&'a mut T, PagingAccess<'a, P>) {
        let access = PagingAccess {
            lock: paging,
            source: PagingSource::Runtime,
            _beneath_runtime_guard: PhantomData,
            _mode: PhantomData,
        };
        (&mut **self, access)
    }
}

/// P's mode when it is taken beneath a held T guard (D1 commit 9).
pub(super) struct BeneathRuntime;

/// P's mode when it is taken with no T guard on this CPU, through a
/// `GuardFree` token (D1 commit 9). Only a guard in this mode mints the
/// [`GuardFreeValue`] that the usercopy session's constructor consumes, so
/// "no usercopy under T" (H0 §12.8) is a type fact.
pub(super) struct GuardFreeOnly;

/// The right to take P during one T hold, or during one guard-free usercopy.
/// Neither `Clone` nor `Copy`, and constructible only by
/// [`RuntimeAuthorityGuard::with_paging`] (mode [`BeneathRuntime`]) and
/// [`PagingLock::guard_free_access`] (mode [`GuardFreeOnly`]).
pub(super) struct PagingAccess<'a, P, M = BeneathRuntime> {
    lock: &'a PagingLock<P>,
    source: PagingSource,
    _beneath_runtime_guard: PhantomData<&'a mut ()>,
    _mode: PhantomData<M>,
}

impl<P, M> PagingAccess<'_, P, M> {
    /// Takes P. The guard mutably borrows this access until it drops, so P
    /// is never taken twice on one CPU. It keeps the access's mode.
    pub(super) fn lock(&mut self) -> PagingGuard<'_, P, M> {
        self.lock.acquire_in(self.source)
    }
}

pub(super) struct PagingGuard<'a, P, M = BeneathRuntime> {
    lock: &'a PagingLock<P>,
    source: PagingSource,
    /// When P was taken, and how long it spun, in the timing's ticks.
    served: Option<u64>,
    waited: Option<u64>,
    _mode: PhantomData<M>,
}

/// P's value, reached through a guard taken with no T guard on this CPU (D1
/// commit 9). Only [`PagingGuard::guard_free_value`] on a [`GuardFreeOnly`]
/// guard mints one; the usercopy session's constructor consumes it.
pub(super) struct GuardFreeValue<'v, P> {
    value: &'v mut P,
}

impl<'v, P> GuardFreeValue<'v, P> {
    pub(super) fn into_inner(self) -> &'v mut P {
        self.value
    }

    /// The value, to read, before it is consumed (the fast serve reads its
    /// fault window before it builds its session, DW2 §13.16 part e3).
    #[cfg_attr(
        not(all(target_os = "none", target_arch = "x86_64")),
        allow(dead_code, reason = "only the live fast serve reads it")
    )]
    pub(super) fn value(&self) -> &P {
        self.value
    }
}

impl<P> PagingGuard<'_, P, GuardFreeOnly> {
    /// The value, for the work only a guard-free P holder may do: usercopy.
    pub(super) fn guard_free_value(&mut self) -> GuardFreeValue<'_, P> {
        GuardFreeValue { value: &mut **self }
    }
}

impl<P, M> Deref for PagingGuard<'_, P, M> {
    type Target = P;

    fn deref(&self) -> &Self::Target {
        // SAFETY: `acquire_in` is the only constructor of a guard and returns only after its
        // exchange set the writer bit from a word with no reader counted; while the bit is set no
        // other writer takes and no reader is counted. `drop` clears it with a Release that the
        // next acquisition's Acquire exchange reads.
        unsafe { &*self.lock.value.get() }
    }
}

impl<P, M> DerefMut for PagingGuard<'_, P, M> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: as in `deref`, the guard holds the writer bit alone, and `&mut self` on the
        // guard makes this the only reference to the value for its lifetime.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<P, M> Drop for PagingGuard<'_, P, M> {
    fn drop(&mut self) {
        // Read just before the release store, as T's is.
        self.lock
            .time_release(self.source, self.served, self.waited);
        // Only the writer bit: a waiting writer's bit stays set, so the next
        // writer takes before any new reader.
        self.lock.state.fetch_and(!WRITER, Ordering::Release);
    }
}

/// The right to take P shared during one guard-free fast serve (DW2
/// §15.2). Neither `Clone` nor `Copy`, and constructible only by
/// [`PagingLock::guard_free_shared_fault_access`].
pub(super) struct SharedPagingAccess<'a, P> {
    lock: &'a PagingLock<P>,
    _beneath_runtime_guard: PhantomData<&'a mut ()>,
}

impl<P> SharedPagingAccess<'_, P> {
    /// Takes P shared. The guard mutably borrows this access until it
    /// drops, so P is never taken twice on one CPU.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "the lock's host tests take it; the shared fast serve is built on it in its own commit"
        )
    )]
    pub(super) fn lock_shared(&mut self) -> SharedPagingGuard<'_, P> {
        self.lock.acquire_shared()
    }
}

/// A shared hold of P (DW2 §15.2): it gives `&P` and nothing else. It has
/// no `DerefMut` and mints no [`GuardFreeValue`], and neither it nor
/// anything built from it is [`PagingHeld`], so S is never taken beneath
/// it.
pub(super) struct SharedPagingGuard<'a, P> {
    lock: &'a PagingLock<P>,
    /// When P was taken, and how long it spun, in the timing's ticks.
    served: Option<u64>,
    waited: Option<u64>,
}

impl<P> Deref for SharedPagingGuard<'_, P> {
    type Target = P;

    fn deref(&self) -> &Self::Target {
        // SAFETY: `acquire_shared` is the only constructor of this guard and returns only after
        // its exchange counted one reader while the writer bit was clear (Acquire); the count
        // stays nonzero until `drop` (Release). An exclusive guard is formed only by the exchange
        // that sets the writer bit from a word with no reader counted, so no `PagingGuard`, and
        // so no `&mut P`, exists while this reference does. Other shared guards on other CPUs may
        // hold `&P` at the same time; each reaches P's value only through `&P`, and what may be
        // done through it is bounded by the shared fault session (DW2 §15.2,
        // `SharedFaultSession`): every path from it reads, or writes through a structure's own
        // lock (the pin tracker, the residency state, the scheduler) or an atomic (a page-table
        // leaf, this CPU's scratch leaf, the step report), and none writes a field of P's value
        // through a shared reference.
        unsafe { &*self.lock.value.get() }
    }
}

impl<P> Drop for SharedPagingGuard<'_, P> {
    fn drop(&mut self) {
        self.lock
            .time_release(PagingSource::FaultShared, self.served, self.waited);
        self.lock.state.fetch_sub(READER, Ordering::Release);
    }
}

/// A witness that this CPU holds P: a [`PagingGuard`], or a session built
/// from one and borrowing it. S is acquired only beneath such a witness.
pub(super) trait PagingHeld {}

/// S is taken beneath P beneath T: a guard-free P does not witness it.
impl<P> PagingHeld for PagingGuard<'_, P, BeneathRuntime> {}

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

    /// Releases an S whose transaction published no shootdown and so holds
    /// no settlement: a family-G transaction that failed before it built a
    /// coherent publisher, or a root teardown that failed before its
    /// publication. Every S whose transaction reached a publisher, or
    /// published a teardown, is released through [`Self::release`], on its
    /// settlement.
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

    impl HoldEndCheck for () {
        fn check_hold_end(&self, _taken: &'static core::panic::Location<'static>) {}
    }
    impl HoldEndCheck for u32 {
        fn check_hold_end(&self, _taken: &'static core::panic::Location<'static>) {}
    }
    impl<const N: usize> HoldEndCheck for [u8; N] {
        fn check_hold_end(&self, _taken: &'static core::panic::Location<'static>) {}
    }
    impl<const N: usize> HoldEndCheck for [u32; N] {
        fn check_hold_end(&self, _taken: &'static core::panic::Location<'static>) {}
    }

    /// A guarded value with the live runtime's two queues, checked as the
    /// live one is.
    struct Queues {
        shared: crate::syscall::CleanupQueue<4>,
        services: crate::syscall::CleanupQueue<4>,
    }

    impl HoldEndCheck for Queues {
        fn check_hold_end(&self, taken: &'static core::panic::Location<'static>) {
            if !(self.shared.is_empty() && self.services.is_empty()) {
                panic!("hold taken at {}:{}", taken.file(), taken.line());
            }
        }
    }

    /// DW2 §10.15 revision 2 item 1: the guard's backstop fires on a hold
    /// that ends with a release in a queue, and only then.
    #[test]
    fn the_guard_backstop_fires_on_an_undrained_hold() {
        let lock = RuntimeAuthorityLock::new(
            Queues {
                shared: crate::syscall::CleanupQueue::new(),
                services: crate::syscall::CleanupQueue::new(),
            },
            no_service,
        );
        let [mut handle] = lock.handles::<1>();
        let mut registry = crate::object::ObjectRegistry::<4>::new();
        let creation = registry.create(deepwyrm_abi::DW_OBJECT_TYPE_EVENT).unwrap();
        let reference = registry.creation_into_handle(creation).unwrap();
        let release = registry.release_handle(reference).unwrap().unwrap();
        // A drained hold ends quietly.
        {
            let mut guard = handle.lock();
            guard.services.push(release);
            let release = guard.services.pop().unwrap();
            registry.complete_finalization(release).unwrap();
        }
        let creation = registry.create(deepwyrm_abi::DW_OBJECT_TYPE_EVENT).unwrap();
        let reference = registry.creation_into_handle(creation).unwrap();
        let release = registry.release_handle(reference).unwrap().unwrap();
        let mut taken_line = 0;
        let undrained = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            taken_line = line!() + 1;
            let mut guard = handle.lock();
            guard.shared.push(release);
        }));
        let message = undrained.expect_err("an undrained hold must fail at its end");
        // The backstop names the hold by where its guard was taken.
        assert_eq!(
            message
                .downcast_ref::<std::string::String>()
                .map(std::string::String::as_str),
            Some(std::format!("hold taken at {}:{taken_line}", file!()).as_str())
        );
    }

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
        assert!(!writer_held(&paging));
        {
            let held = access.lock();
            assert_eq!(*held, 15);
            assert!(writer_held(&paging));
        }
        assert!(!writer_held(&paging));
        drop(guard);
        assert_eq!(*handle.lock(), 2);
    }

    /// A counter for P's timing test: each read is one tick later.
    static P_CLOCK: AtomicU64 = AtomicU64::new(100);
    static P_RELEASES: std::sync::Mutex<std::vec::Vec<(PagingSource, Option<u64>, u64)>> =
        std::sync::Mutex::new(std::vec::Vec::new());

    fn p_clock() -> Option<u64> {
        Some(P_CLOCK.fetch_add(1, Ordering::Relaxed))
    }

    fn p_released(source: PagingSource, waited: Option<u64>, held: u64) {
        P_RELEASES.lock().unwrap().push((source, waited, held));
    }

    /// DW2 §13.16 part e3: P is timed as T is, by who took it: beneath a T
    /// guard is `Runtime`, guard-free is `Usercopy`, and the fast serve's
    /// guard-free access is `Fault`. A taking served at its first try has no
    /// wait; one that spun has one; the hold is read just before release.
    #[test]
    fn paging_is_timed_by_its_source_with_its_wait_and_hold() {
        let lock = RuntimeAuthorityLock::new(1_u32, no_service);
        let paging = PagingLock::new_timed(
            10_u32,
            no_service,
            PagingTiming {
                now: p_clock,
                released: p_released,
            },
        );
        let [mut handle] = lock.handles::<1>();
        {
            let mut guard = handle.lock();
            let (_, mut access) = guard.with_paging(&paging);
            *access.lock() += 1;
        }
        {
            let mut access = paging.guard_free_access(handle.guard_free());
            *access.lock() += 1;
        }
        {
            let mut access = paging.guard_free_fault_access(handle.guard_free());
            *access.lock() += 1;
        }
        // Served at once: one read when served, one at release.
        assert_eq!(
            *P_RELEASES.lock().unwrap(),
            [
                (PagingSource::Runtime, None, 1),
                (PagingSource::Usercopy, None, 1),
                (PagingSource::Fault, None, 1),
            ]
        );
        // A taking that spins has a wait.
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
            // Six reads so far and one when `held` was served: the next is
            // the spinner's, made only when its first try fails.
            while P_CLOCK.load(Ordering::Relaxed) < 108 {
                std::thread::yield_now();
            }
            drop(held);
            spinner.join().expect("spinning thread");
        });
        {
            let releases = P_RELEASES.lock().unwrap();
            assert_eq!(releases.len(), 5);
            assert_eq!(releases[3].1, None);
            assert!(releases[4].1.is_some_and(|waited| waited >= 1));
        }
        assert_eq!(*paging.acquire(), 14);
    }

    /// Whether an exclusive guard of `paging` exists.
    fn writer_held<P>(paging: &PagingLock<P>) -> bool {
        paging.state.load(Ordering::Relaxed) & WRITER != 0
    }

    /// Whether an exclusive acquirer of `paging` is waiting.
    fn writer_waiting<P>(paging: &PagingLock<P>) -> bool {
        paging.state.load(Ordering::Relaxed) & WRITER_WAITING != 0
    }

    /// The shared guards of `paging` now.
    fn readers<P>(paging: &PagingLock<P>) -> u64 {
        (paging.state.load(Ordering::Relaxed) & READERS) / READER
    }

    /// Yields until `done` holds, at most a bounded number of times;
    /// whether it held.
    fn eventually(done: impl Fn() -> bool) -> bool {
        for _ in 0..200_000 {
            if done() {
                return true;
            }
            std::thread::yield_now();
        }
        done()
    }

    /// Yields a while and answers whether `done` held at any point: for
    /// what must not happen while something else is held.
    fn ever_within_a_while(done: impl Fn() -> bool) -> bool {
        for _ in 0..20_000 {
            if done() {
                return true;
            }
            std::thread::yield_now();
        }
        done()
    }

    /// DW2 §15.2: two shared holders of P overlap, each on its own thread,
    /// and each reads the value; P is free once both have left.
    #[test]
    fn two_shared_holders_overlap() {
        let paging = PagingLock::new(7_u32, no_service);
        let inside = AtomicU64::new(0);
        let leave = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let holders = [(); 2].map(|()| {
                scope.spawn(|| {
                    let held = paging.acquire_shared();
                    inside.fetch_add(1, Ordering::AcqRel);
                    // Each stays until both are inside at once.
                    assert!(eventually(|| leave.load(Ordering::Acquire)));
                    *held
                })
            });
            assert!(
                eventually(|| inside.load(Ordering::Acquire) == 2),
                "a second shared holder did not get in beside the first"
            );
            assert_eq!(readers(&paging), 2);
            assert!(!writer_held(&paging));
            leave.store(true, Ordering::Release);
            for holder in holders {
                assert_eq!(holder.join().expect("shared holder"), 7);
            }
        });
        assert_eq!(paging.state.load(Ordering::Relaxed), 0);
    }

    /// An exclusive holder of P excludes a shared and an exclusive acquirer
    /// until it releases; each then gets P.
    #[test]
    fn an_exclusive_holder_excludes_shared_and_exclusive_acquirers() {
        let paging = PagingLock::new(0_u32, no_service);
        let shared_in = AtomicBool::new(false);
        let exclusive_in = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let mut held = paging.acquire();
            let shared = scope.spawn(|| {
                let value = *paging.acquire_shared();
                shared_in.store(true, Ordering::Release);
                value
            });
            let exclusive = scope.spawn(|| {
                let mut guard = paging.acquire();
                exclusive_in.store(true, Ordering::Release);
                *guard += 10;
            });
            assert!(eventually(|| writer_waiting(&paging)));
            assert!(!ever_within_a_while(
                || shared_in.load(Ordering::Acquire) || exclusive_in.load(Ordering::Acquire)
            ));
            assert_eq!(readers(&paging), 0);
            *held = 1;
            drop(held);
            exclusive.join().expect("exclusive acquirer");
            let seen = shared.join().expect("shared acquirer");
            // The reader saw the value either before or after the other
            // writer, never a torn one.
            assert!(seen == 1 || seen == 11, "{seen}");
        });
        assert!(shared_in.load(Ordering::Relaxed) && exclusive_in.load(Ordering::Relaxed));
        assert_eq!(*paging.acquire(), 11);
        assert_eq!(paging.state.load(Ordering::Relaxed), 0);
    }

    /// DW2 §15.2: a writer waiting for the readers stops new readers, and
    /// gets P as soon as the readers it waited for have left, before the
    /// new reader.
    #[test]
    fn a_waiting_writer_stops_new_readers_and_takes_when_the_readers_leave() {
        let paging = PagingLock::new(0_u32, no_service);
        let order = std::sync::Mutex::new(std::vec::Vec::new());
        let writer_in = AtomicBool::new(false);
        let writer_leave = AtomicBool::new(false);
        let reader_in = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let first = paging.acquire_shared();
            let writer = scope.spawn(|| {
                let mut guard = paging.acquire();
                order.lock().unwrap().push("writer");
                writer_in.store(true, Ordering::Release);
                assert!(eventually(|| writer_leave.load(Ordering::Acquire)));
                *guard += 1;
            });
            assert!(eventually(|| writer_waiting(&paging)));
            let reader = scope.spawn(|| {
                let value = *paging.acquire_shared();
                order.lock().unwrap().push("reader");
                reader_in.store(true, Ordering::Release);
                value
            });
            // The new reader waits behind the waiting writer, though only a
            // reader holds P.
            assert!(!ever_within_a_while(|| reader_in.load(Ordering::Acquire)));
            assert!(!writer_in.load(Ordering::Acquire));
            assert_eq!(readers(&paging), 1);
            drop(first);
            // The writer takes once the first reader leaves.
            assert!(eventually(|| writer_in.load(Ordering::Acquire)));
            assert!(!ever_within_a_while(|| reader_in.load(Ordering::Acquire)));
            writer_leave.store(true, Ordering::Release);
            writer.join().expect("writer");
            assert_eq!(reader.join().expect("reader"), 1);
        });
        assert_eq!(*order.lock().unwrap(), ["writer", "reader"]);
        assert_eq!(paging.state.load(Ordering::Relaxed), 0);
    }

    /// Two writers wait behind a reader: whichever takes first clears the
    /// waiting bit and the other sets it again, so a new reader still
    /// waits for both.
    #[test]
    fn two_waiting_writers_both_take_before_a_new_reader() {
        let paging = PagingLock::new(0_u32, no_service);
        let writers_done = AtomicU64::new(0);
        let reader_saw = AtomicU64::new(u64::MAX);
        let release = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let first = paging.acquire_shared();
            let writers = [(); 2].map(|()| {
                scope.spawn(|| {
                    let mut guard = paging.acquire();
                    // Each holds until the test lets them go, so the other
                    // waits behind it with the bit set.
                    assert!(eventually(|| release.load(Ordering::Acquire)));
                    *guard += 1;
                    writers_done.fetch_add(1, Ordering::AcqRel);
                })
            });
            assert!(eventually(|| writer_waiting(&paging)));
            let reader = scope.spawn(|| {
                let value = *paging.acquire_shared();
                reader_saw.store(u64::from(value), Ordering::Release);
            });
            drop(first);
            // One writer holds; the other waits with the bit set again.
            assert!(eventually(
                || writer_held(&paging) && writer_waiting(&paging)
            ));
            release.store(true, Ordering::Release);
            for writer in writers {
                writer.join().expect("writer");
            }
            reader.join().expect("reader");
        });
        assert_eq!(writers_done.load(Ordering::Relaxed), 2);
        assert_eq!(reader_saw.load(Ordering::Relaxed), 2);
        assert_eq!(paging.state.load(Ordering::Relaxed), 0);
    }

    static SHARED_WAITER_SPINS: AtomicU64 = AtomicU64::new(0);
    static EXCLUSIVE_WAITER_SPINS: AtomicU64 = AtomicU64::new(0);

    fn count_shared_waiter_spin() {
        SHARED_WAITER_SPINS.fetch_add(1, Ordering::Relaxed);
    }

    fn count_exclusive_waiter_spin() {
        EXCLUSIVE_WAITER_SPINS.fetch_add(1, Ordering::Relaxed);
    }

    /// Both kinds of acquirer call the spin service on every turn of their
    /// wait: a shared one behind a writer, an exclusive one behind a reader.
    #[test]
    fn both_kinds_of_waiter_call_the_spin_service() {
        let paging = PagingLock::new(0_u32, count_shared_waiter_spin);
        std::thread::scope(|scope| {
            let held = paging.acquire();
            let waiter = scope.spawn(|| *paging.acquire_shared());
            assert!(eventually(
                || SHARED_WAITER_SPINS.load(Ordering::Relaxed) >= 3
            ));
            drop(held);
            waiter.join().expect("shared waiter");
        });
        let paging = PagingLock::new(0_u32, count_exclusive_waiter_spin);
        std::thread::scope(|scope| {
            let held = paging.acquire_shared();
            let waiter = scope.spawn(|| *paging.acquire() += 1);
            assert!(eventually(|| EXCLUSIVE_WAITER_SPINS
                .load(Ordering::Relaxed)
                >= 3));
            drop(held);
            waiter.join().expect("exclusive waiter");
        });
        // Taken at the first try, neither calls it.
        let spins = SHARED_WAITER_SPINS.load(Ordering::Relaxed);
        drop(PagingLock::new(0_u32, count_shared_waiter_spin).acquire_shared());
        assert_eq!(SHARED_WAITER_SPINS.load(Ordering::Relaxed), spins);
    }

    static SHARED_CLOCK: AtomicU64 = AtomicU64::new(100);
    static SHARED_RELEASES: std::sync::Mutex<std::vec::Vec<(PagingSource, Option<u64>, u64)>> =
        std::sync::Mutex::new(std::vec::Vec::new());

    fn shared_clock() -> Option<u64> {
        Some(SHARED_CLOCK.fetch_add(1, Ordering::Relaxed))
    }

    fn shared_released(source: PagingSource, waited: Option<u64>, held: u64) {
        SHARED_RELEASES.lock().unwrap().push((source, waited, held));
    }

    /// DW2 §15.2: the shared fault access is the only shared way in; it
    /// reads the value, is timed as `FaultShared` with its wait and hold as
    /// the others are, and leaves P free.
    #[test]
    fn the_shared_fault_access_is_timed_as_fault_shared() {
        let lock = RuntimeAuthorityLock::new(1_u32, no_service);
        let paging = PagingLock::new_timed(
            10_u32,
            no_service,
            PagingTiming {
                now: shared_clock,
                released: shared_released,
            },
        );
        let [mut handle] = lock.handles::<1>();
        {
            let mut access = paging.guard_free_shared_fault_access(handle.guard_free());
            let held = access.lock_shared();
            assert_eq!(*held, 10);
            assert_eq!(readers(&paging), 1);
        }
        assert_eq!(paging.state.load(Ordering::Relaxed), 0);
        assert_eq!(
            *SHARED_RELEASES.lock().unwrap(),
            [(PagingSource::FaultShared, None, 1)]
        );
        // A shared taking that spins behind a writer has a wait.
        let spinning = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let held = paging.acquire();
            let spinner = scope.spawn(|| {
                spinning.store(true, Ordering::Release);
                *paging.acquire_shared()
            });
            assert!(eventually(|| spinning.load(Ordering::Acquire)));
            // Two reads by the shared hold, one when `held` was served: the
            // next is the spinner's, made only when its first try fails.
            assert!(eventually(|| SHARED_CLOCK.load(Ordering::Relaxed) >= 104));
            drop(held);
            assert_eq!(spinner.join().expect("spinning thread"), 10);
        });
        let releases = SHARED_RELEASES.lock().unwrap();
        assert_eq!(releases.len(), 3);
        assert_eq!(releases[1].0, PagingSource::Runtime);
        assert_eq!(releases[2].0, PagingSource::FaultShared);
        assert!(releases[2].1.is_some_and(|waited| waited >= 1));
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
        assert!(!writer_held(&paging));
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
