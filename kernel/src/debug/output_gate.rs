//! The COM1 output gate: one record at a time across every CPU.
//!
//! The gate's word holds [`FREE`] or the writer's identity, the CPU's initial
//! APIC ID plus one. A writer finding it held by another CPU waits for it, up
//! to a bound the caller supplies; a writer finding it held by itself is a
//! record inside a record (a fault interrupting one) and is refused at once.
//! Every refusal adds one to the gate's dropped-records count. The panic path
//! does not refuse: after the bound, or at once on its own CPU, it takes the
//! gate by force, because a CPU stopped in the middle of a record must not
//! silence a panic.
//!
//! The gate is a plain value so host tests can build one per test and model
//! two CPUs with two identities and a scripted wait; the kernel's emitters use
//! one global instance.

use core::num::NonZeroU32;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// The holder word's value when no record is being written.
const FREE: u32 = 0;

/// One writer's identity in the holder word: its CPU's initial APIC ID plus
/// one, so no writer is [`FREE`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WriterId(NonZeroU32);

impl WriterId {
    pub(super) fn from_initial_apic_id(apic_id: u8) -> Self {
        // An 8-bit ID plus one is at least 1 and cannot saturate 32 bits.
        Self(NonZeroU32::MIN.saturating_add(u32::from(apic_id)))
    }

    const fn word(self) -> u32 {
        self.0.get()
    }
}

/// What an acquire does each time it finds the gate held by another CPU.
pub(super) trait ContendedWait {
    /// Waits a little and returns `true` to retry, or returns `false` once
    /// the bound has passed.
    fn wait(&mut self) -> bool;
}

impl<F: FnMut() -> bool> ContendedWait for F {
    fn wait(&mut self) -> bool {
        self()
    }
}

/// A wait bounded by elapsed clock ticks, with an iteration count as a
/// backstop for a clock that does not advance. Each retry spins with `pause`.
pub(super) struct BoundedWait<C: FnMut() -> u64> {
    clock: C,
    started: Option<u64>,
    ticks: u64,
    spins: u64,
    spin_cap: u64,
}

impl<C: FnMut() -> u64> BoundedWait<C> {
    pub(super) const fn new(clock: C, ticks: u64, spin_cap: u64) -> Self {
        Self {
            clock,
            started: None,
            ticks,
            spins: 0,
            spin_cap,
        }
    }
}

impl<C: FnMut() -> u64> ContendedWait for BoundedWait<C> {
    fn wait(&mut self) -> bool {
        let now = (self.clock)();
        let started = *self.started.get_or_insert(now);
        if now.wrapping_sub(started) >= self.ticks || self.spins >= self.spin_cap {
            return false;
        }
        self.spins += 1;
        core::hint::spin_loop();
        true
    }
}

/// The gate: who is writing a record now, and how many records were refused.
pub(super) struct OutputGate {
    holder: AtomicU32,
    dropped: AtomicU64,
}

impl OutputGate {
    pub(super) const fn new() -> Self {
        Self {
            holder: AtomicU32::new(FREE),
            dropped: AtomicU64::new(0),
        }
    }

    /// Takes the gate for one ordinary record, waiting while another CPU
    /// holds it. Returns `None`, and counts one dropped record, when this
    /// writer already holds it or the wait's bound passes first.
    pub(super) fn acquire(
        &self,
        writer: WriterId,
        wait: &mut impl ContendedWait,
    ) -> Option<OutputHold<'_>> {
        match self.take_or_wait(writer, wait) {
            Taken::Free => Some(OutputHold { gate: self, writer }),
            Taken::OwnRecord | Taken::BoundPassed => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Takes the gate for a panic record. Waits like [`Self::acquire`]; then,
    /// when the wait's bound passes or this writer already holds the gate, it
    /// takes the gate by force. Never refuses and never counts a drop.
    pub(super) fn acquire_for_panic(
        &self,
        writer: WriterId,
        wait: &mut impl ContendedWait,
    ) -> OutputHold<'_> {
        if let Taken::OwnRecord | Taken::BoundPassed = self.take_or_wait(writer, wait) {
            self.holder.swap(writer.word(), Ordering::AcqRel);
        }
        OutputHold { gate: self, writer }
    }

    /// Records refused since boot.
    pub(super) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    fn take_or_wait(&self, writer: WriterId, wait: &mut impl ContendedWait) -> Taken {
        loop {
            match self.holder.compare_exchange(
                FREE,
                writer.word(),
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Taken::Free,
                Err(holder) if holder == writer.word() => return Taken::OwnRecord,
                Err(_) => {
                    if !wait.wait() {
                        return Taken::BoundPassed;
                    }
                }
            }
        }
    }
}

enum Taken {
    /// The gate was free and is now this writer's.
    Free,
    /// This writer already holds the gate: a record inside a record.
    OwnRecord,
    /// Another CPU held the gate for the whole bound.
    BoundPassed,
}

/// One writer's hold of the gate, released when dropped.
///
/// The release frees the gate only if the word still names this writer. A
/// panic that took the gate by force from a stalled CPU therefore frees it
/// when its record is written, and the stalled CPU's own hold, if it ever
/// resumes, does not free a gate someone else has taken since. A panic that
/// forced its own CPU's hold (a panic inside a record) also frees the gate:
/// the panic path ends in a halt, so the interrupted record never resumes,
/// and leaving the word set would make every other CPU wait out the bound
/// and drop each of its records.
pub(super) struct OutputHold<'a> {
    gate: &'a OutputGate,
    writer: WriterId,
}

impl Drop for OutputHold<'_> {
    fn drop(&mut self) {
        let _ = self.gate.holder.compare_exchange(
            self.writer.word(),
            FREE,
            Ordering::Release,
            Ordering::Relaxed,
        );
    }
}
