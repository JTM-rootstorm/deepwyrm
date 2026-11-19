//! What calls in steps did during a boot, logged at power-off (DW2 M5
//! §10.5 probes 14 and 15).
//!
//! For each call in steps (map, unmap, protect, the fill-in, commit and a
//! create's zeroing) the kernel keeps:
//! - the longest time one step held its CPU, from the safe point that began
//!   it to the next (interrupts are off for a whole syscall, so this is time
//!   nothing else ran there);
//! - how many Stops a safe point took after the call had made a step since
//!   it started or resumed, which is a Stop that landed between steps rather
//!   than before the first;
//! - how many parked calls were settled because their Thread ended while
//!   parked (§10.8 item 5);
//! - per call, its longest step, its steps and their total time, which
//!   give the cost per step and so per page (§10.6 step 6, probe 14);
//! - the longest time queued teardown, and queued finalization, stayed owed
//!   without the queue emptying (§10.10 item 8, §10.12): an upper bound on
//!   how long one dead job's memory waits to be freed;
//! - for queued finalization (§10.19 revision 2): one object's longest wait
//!   from being queued to its completion, with the frames it freed; the
//!   longest gap between finalize steps while some is owed; and every
//!   finalize step, nested in a timed step or not, by what drained.
//!
//! Every count is a relaxed atomic. Nothing here decides anything; it only
//! reports. The finalization records are written only under the runtime
//! authority T (queueing and stepping both run in its holds), so each has
//! one writer at a time; they are read at power-off.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// A call in steps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StepCall {
    Map = 0,
    Unmap = 1,
    Protect = 2,
    FillIn = 3,
    Commit = 4,
    Create = 5,
    /// A step of an exited Process's queued teardown (DW2 §10.10).
    Teardown = 6,
    /// A step of releasing a handle-less object's unmapped pages (§10.9).
    Release = 7,
    /// A step of the queued finalization of on-demand objects (§10.12).
    Finalize = 8,
}

const CALLS: usize = 9;
const NAMES: [&str; CALLS] = [
    "map", "unmap", "protect", "fill", "commit", "create", "teardown", "release", "finalize",
];
/// The low bits of the packed longest step hold the call.
const CALL_BITS: u32 = 4;
const _: () = assert!(CALLS <= 1 << CALL_BITS);

/// Queued work whose time owed is reported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Owed {
    Teardown = 0,
    Finalize = 1,
}

/// What drained when a finalize step ran (DW2 §10.19 revision 2 item 3):
/// the kind of entry this CPU last made, kept per CPU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DrainSource {
    /// The timer gate of a user-mode interrupt (only the BSP's drains).
    Gate = 0,
    /// A syscall, from its entry to its return.
    Syscall = 1,
    /// A user page fault.
    Fault = 2,
    /// An idle loop, or the poll of a CPU idling on a blocked Thread's root.
    Idle = 3,
    /// Anything else: the reapers, a fresh Thread's entry.
    Other = 4,
}

const SOURCES: usize = 5;
const SOURCE_NAMES: [&str; SOURCES] = ["gate", "syscall", "fault", "idle", "other"];

/// A point of one pass of the inner fault serve, stamped on its CPU (DW2
/// §13.5 line 1). A pass begins at [`StepTally::fault_pass_began`]; these
/// are the points after it, in order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FaultStamp {
    /// Just before the admission.
    AdmitBegan = 0,
    /// The admission returned.
    AdmitEnded = 1,
    /// The page's commit returned (frames and index nodes taken and zeroed),
    /// or, for a page already committed, the point it would have.
    CommitEnded = 2,
    /// The inner serve is about to return `Served`.
    ServeEnded = 3,
}

/// The pass's start and the four [`FaultStamp`]s.
const FAULT_STAMPS: usize = 5;

/// How one pass of the fault gate's serve loop ended: the wrapper's
/// outcome (DW2 §13.5 line 1, `fault-passes`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FaultPass {
    Served = 0,
    AlreadyPresent = 1,
    Released = 2,
    Retry = 3,
    Unserved = 4,
    Exhausted = 5,
}

const FAULT_PASSES: usize = 6;

/// A call that met a refusal owed work could admit and took the owed step
/// instead of returning it (DW2 §13.12 part b), for the `admission-waits`
/// line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionWait {
    /// `memory_object_create`'s first hold, or its final hold restarting it.
    Create = 0,
    /// A step of `memory_object_commit`, of a fill-in or of `dma_map`'s
    /// commit.
    Commit = 1,
    /// A user page fault.
    Fault = 2,
}

const ADMISSION_WAITS: usize = 3;

/// The parts of a served fault's time, in the `faults` line's order: sync
/// (the gate's entry to the inner serve's start: the stop poll, taking T
/// and the safe point's checks), lookup, admit, commit, tables (to
/// [`FaultStamp::ServeEnded`]), and return, from the end of tables to the
/// gate's `fault_returned`: the drain rule, the frame's authorisation, the
/// reschedule read and T's release, all in the serve's one hold since DW2
/// §13.13 part c.
const FAULT_PARTS: usize = 6;

/// A T acquisition's figures, per CPU and drain source: count, how many
/// spun, wait sum, wait longest, held sum, held longest.
const T_LOCK_FIGURES: usize = 6;

/// The points of a fast serve (DW2 §13.16 part e3), stamped on its CPU
/// after the gate's entry: the end of its checks (before the leaf's walk),
/// of its commit, and of its leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FastFaultStamp {
    Checked = 0,
    Committed = 1,
    Written = 2,
}

const FAST_STAMPS: usize = 3;

/// The parts of a fast-served fault's time, in the `faults-fast` line's
/// order: check (the gate's entry, taking P included, to before the leaf's
/// walk), commit, tables (the leaf), and return (to `fault_returned`).
const FAST_PARTS: usize = 4;

/// Why the fast serve declined (DW2 §13.16 part e3), in the
/// `fault-declines` line's order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowDecline {
    Identity = 0,
    Mapping = 1,
    Tables = 2,
    Credit = 3,
    Memory = 4,
    Leaf = 5,
    Return = 6,
    /// A shared serve's page had no frame (DW2 §15.2): written in its own
    /// `fault-declines-shared` line.
    NotCommitted = 7,
}

const WINDOW_DECLINES: usize = 8;

/// The parts of a shared-served fault's time, in the `faults-shared`
/// line's order (DW2 §15.2): check (the gate's entry, taking P shared
/// included, to before the leaf's walk), tables (the walk, the resolve
/// and the leaf: a shared serve commits nothing), and return.
const SHARED_PARTS: usize = 3;

/// Who took P (DW2 §13.16 part e3), in the `p-lock` line's names.
pub(crate) const P_LOCK_SOURCES: usize = 4;
const P_LOCK_SOURCE_NAMES: [&str; P_LOCK_SOURCES] =
    ["fault", "usercopy", "runtime", "fault-shared"];

/// A P acquisition's figures, per CPU and source: count, how many spun,
/// wait sum, held sum.
const P_LOCK_FIGURES: usize = 4;

/// `ticks` of the TSC at `hz`, in whole microseconds; zero when no rate
/// was measured. 128-bit, so no product overflows; clamped to `u64::MAX`.
fn ticks_to_us(ticks: u64, hz: u64) -> u64 {
    if hz == 0 {
        return 0;
    }
    u64::try_from(u128::from(ticks) * 1_000_000 / u128::from(hz)).unwrap_or(u64::MAX)
}

impl DrainSource {
    fn from_index(index: u8) -> Self {
        match index {
            0 => Self::Gate,
            1 => Self::Syscall,
            2 => Self::Fault,
            3 => Self::Idle,
            _ => Self::Other,
        }
    }
}

/// When each owed finalization was queued and the frames its steps have
/// freed, by its owed slot (DW2 §10.19 revision 2 item 1). Bounded as the
/// owed queue is, one entry per slot.
pub(crate) struct OwedWaits<const SLOTS: usize> {
    /// When the slot's object was queued, in nanoseconds plus one; zero
    /// when nothing queued there is recorded.
    queued: [AtomicU64; SLOTS],
    freed: [AtomicU64; SLOTS],
}

impl<const SLOTS: usize> OwedWaits<SLOTS> {
    pub(crate) const fn new() -> Self {
        Self {
            queued: [const { AtomicU64::new(0) }; SLOTS],
            freed: [const { AtomicU64::new(0) }; SLOTS],
        }
    }

    /// An object was queued in `slot` at `now`.
    pub(crate) fn queued(&self, slot: usize, now: u64) {
        if let (Some(queued), Some(freed)) = (self.queued.get(slot), self.freed.get(slot)) {
            queued.store(now.saturating_add(1), Ordering::Relaxed);
            freed.store(0, Ordering::Relaxed);
        }
    }

    /// A step freed `frames` of `slot`'s object.
    pub(crate) fn freed(&self, slot: usize, frames: u64) {
        if let Some(freed) = self.freed.get(slot) {
            freed.fetch_add(frames, Ordering::Relaxed);
        }
    }

    /// `slot`'s object completed: when it was queued and the frames freed,
    /// if its queueing was recorded. The slot's record is cleared.
    pub(crate) fn completed(&self, slot: usize) -> Option<(u64, u64)> {
        let queued = self.queued.get(slot)?.swap(0, Ordering::Relaxed);
        let freed = self.freed.get(slot)?.swap(0, Ordering::Relaxed);
        (queued != 0).then(|| (queued - 1, freed))
    }
}

/// The report's state, for `CPUS` CPUs.
pub(crate) struct StepTally<const CPUS: usize> {
    /// When each CPU's current step began, in nanoseconds plus one; zero
    /// when none is being timed.
    started: [AtomicU64; CPUS],
    /// The longest step in nanoseconds, shifted left by [`CALL_BITS`], with
    /// its call in the low bits, so one `fetch_max` keeps both.
    longest: AtomicU64,
    stops: [AtomicU64; CALLS],
    ended: [AtomicU64; CALLS],
    /// Per call: its longest step, its steps and their total, in ns.
    call_longest: [AtomicU64; CALLS],
    call_steps: [AtomicU64; CALLS],
    call_total: [AtomicU64; CALLS],
    /// Per kind of owed work: since when it has been owed, plus one (zero
    /// when nothing is), and the longest stretch owed, in ns.
    owed_since: [AtomicU64; 2],
    owed_longest: [AtomicU64; 2],
    /// One object's longest wait from queued to completed, in ns, and the
    /// frames that object freed.
    finalize_wait_longest: AtomicU64,
    finalize_wait_pages: AtomicU64,
    /// Since when no finalize step has run while some is owed: the end of
    /// the last step, or a queueing into an empty queue, in ns plus one;
    /// zero while nothing is owed. And the longest such gap, in ns.
    finalize_gap_since: AtomicU64,
    finalize_gap_longest: AtomicU64,
    /// The longest finalize step, nested in a timed step or not, in ns.
    finalize_step_longest: AtomicU64,
    /// Finalize steps by what drained, counted whether or not they were
    /// nested in a timed step.
    finalize_steps: [AtomicU64; SOURCES],
    /// The most finalize steps one hold of the runtime lock ran (DW2
    /// §12.11 part 2 item 11).
    finalize_hold_longest: AtomicU64,
    /// Wakes of the BSP for owed work (DW2 §10.19 revision 3), sent and
    /// not sent.
    owed_wakes: AtomicU64,
    owed_wakes_unsent: AtomicU64,
    /// Wakes by cause: a queue newly owed, the bootstrap's root retired
    /// with teardown owed (one wake can have both).
    owed_wakes_queue: AtomicU64,
    owed_wakes_retirement: AtomicU64,
    /// The eager backing with the most runs made since boot (DW2 §12.10):
    /// its runs in the high half, its pages in the low half, each clamped
    /// to `u32::MAX`, so a reader never pairs one backing's runs with
    /// another's pages. Zero while none was made.
    backing_runs: AtomicU64,
    /// The longest single `allocate_backing` call a create made since boot
    /// (DW2 §12.11), with the runs and pages of the allocation it returned,
    /// packed so a reader never pairs one call's duration with another's
    /// runs or pages: microseconds in the top [`ALLOC_US_BITS`], runs in
    /// the next [`ALLOC_RUNS_BITS`], pages in the low [`ALLOC_PAGES_BITS`],
    /// each clamped to its field's maximum. Zero while none was recorded.
    backing_alloc: AtomicU64,
    /// The measurement's stamps (DW2 §13.5) are raw TSC reads, compared
    /// only with other reads on the same CPU, and its times are kept in TSC
    /// ticks, converted with the boot's measured rate only when written.
    ///
    /// Per CPU, when the fault gate entered for the fault it is serving, in
    /// ticks plus one; zero when that CPU's gate is not timing one.
    fault_entry: [AtomicU64; CPUS],
    /// Per CPU, the current serve pass's start and its [`FaultStamp`]s, in
    /// ticks plus one; zero where not stamped.
    fault_stamps: [[AtomicU64; FAULT_STAMPS]; CPUS],
    /// Served faults sampled, their total time and longest total, and the
    /// sums of their parts, in ticks.
    faults_served: AtomicU64,
    fault_total: AtomicU64,
    fault_longest: AtomicU64,
    fault_parts: [AtomicU64; FAULT_PARTS],
    /// The gate's serve passes by outcome, and the fill-in's serves.
    fault_passes: [AtomicU64; FAULT_PASSES],
    fill_in_serves: AtomicU64,
    /// Per CPU, the current T hold's served time in ticks plus one (zero
    /// when not timed) and its wait in ticks plus one (zero when it was
    /// served at once): one hold per CPU at a time.
    t_lock_served: [AtomicU64; CPUS],
    t_lock_wait: [AtomicU64; CPUS],
    /// Per CPU and drain source, [`T_LOCK_FIGURES`], times in ticks.
    t_lock: [[[AtomicU64; T_LOCK_FIGURES]; SOURCES]; CPUS],
    /// Commit steps timed, and the sums of their admission, frame take and
    /// zeroing, and the rest, in ticks.
    commit_steps: AtomicU64,
    commit_admit: AtomicU64,
    commit_take: AtomicU64,
    commit_rest: AtomicU64,
    /// The power-off hold's check of kept usage against the scan (DW2
    /// §13.12 part a): see [`StepTally::usage_checked`]. Zero until it is
    /// recorded.
    usage_check: AtomicU64,
    /// Passes that met an owed refusal and took the owed step, by
    /// [`AdmissionWait`].
    admission_waits: [AtomicU64; ADMISSION_WAITS],
    /// Per CPU, the current fast serve's [`FastFaultStamp`]s, in ticks plus
    /// one; zero where not stamped (DW2 §13.16 part e3).
    fast_stamps: [[AtomicU64; FAST_STAMPS]; CPUS],
    /// Fast-served faults sampled, their total and longest, and the sums of
    /// their [`FAST_PARTS`], in ticks.
    faults_fast: AtomicU64,
    fault_fast_total: AtomicU64,
    fault_fast_longest: AtomicU64,
    fault_fast_parts: [AtomicU64; FAST_PARTS],
    /// The gate's passes the fast serve answered.
    fault_passes_fast: AtomicU64,
    /// Per CPU, whether the fast serve that answered its current fault was
    /// the shared one (DW2 §15.2): its sample goes to `faults-shared`.
    fast_shared: [AtomicBool; CPUS],
    /// Shared-served faults sampled, their total and longest, and the sums
    /// of their [`SHARED_PARTS`], in ticks.
    faults_shared: AtomicU64,
    fault_shared_total: AtomicU64,
    fault_shared_longest: AtomicU64,
    fault_shared_parts: [AtomicU64; SHARED_PARTS],
    /// Fault windows opened (an admission that stored or topped one up),
    /// closed, and the fast serve's declines by [`WindowDecline`].
    windows_opened: AtomicU64,
    windows_closed: AtomicU64,
    window_declines: [AtomicU64; WINDOW_DECLINES],
    /// Serves under T that committed ahead of a stream, the frames they
    /// took, and the commit ahead's time in ticks (DW2 §15.6).
    ahead_commits: AtomicU64,
    ahead_frames: AtomicU64,
    ahead_ticks: AtomicU64,
    /// Streams started and ended (DW2 §15.6).
    streams_started: AtomicU64,
    streams_ended: AtomicU64,
    /// Per CPU and source, [`P_LOCK_FIGURES`], times in ticks.
    p_lock: [[[AtomicU64; P_LOCK_FIGURES]; P_LOCK_SOURCES]; CPUS],
}

/// The fields of [`StepTally::backing_allocated`]'s packed record. 24 bits
/// of microseconds hold 16.7 s (under `--icount`, 16.7 billion guest
/// instructions); 20 bits of runs or pages hold 1,048,575 (4 GiB of pages).
/// A value past its field is clamped to the field's maximum: a clamped
/// duration still ranks above every shorter one, and on a tie between two
/// clamped durations the first is kept.
const ALLOC_US_BITS: u32 = 24;
const ALLOC_RUNS_BITS: u32 = 20;
const ALLOC_PAGES_BITS: u32 = 20;
const ALLOC_RUNS_SHIFT: u32 = ALLOC_PAGES_BITS;
const ALLOC_US_SHIFT: u32 = ALLOC_RUNS_BITS + ALLOC_PAGES_BITS;
const _: () = assert!(ALLOC_US_BITS + ALLOC_RUNS_BITS + ALLOC_PAGES_BITS == u64::BITS);

/// [`StepTally::usage_checked`]'s packed record: a flag bit, then two
/// 31-bit counts.
const USAGE_RECORDED: u64 = 1 << 63;
const USAGE_FIELD: u64 = field_max(31);

/// The largest value a field of `bits` bits holds.
const fn field_max(bits: u32) -> u64 {
    (1 << bits) - 1
}

impl<const CPUS: usize> StepTally<CPUS> {
    pub(crate) const fn new() -> Self {
        Self {
            started: [const { AtomicU64::new(0) }; CPUS],
            longest: AtomicU64::new(0),
            stops: [const { AtomicU64::new(0) }; CALLS],
            ended: [const { AtomicU64::new(0) }; CALLS],
            call_longest: [const { AtomicU64::new(0) }; CALLS],
            call_steps: [const { AtomicU64::new(0) }; CALLS],
            call_total: [const { AtomicU64::new(0) }; CALLS],
            owed_since: [const { AtomicU64::new(0) }; 2],
            owed_longest: [const { AtomicU64::new(0) }; 2],
            finalize_wait_longest: AtomicU64::new(0),
            finalize_wait_pages: AtomicU64::new(0),
            finalize_gap_since: AtomicU64::new(0),
            finalize_gap_longest: AtomicU64::new(0),
            finalize_step_longest: AtomicU64::new(0),
            finalize_steps: [const { AtomicU64::new(0) }; SOURCES],
            finalize_hold_longest: AtomicU64::new(0),
            owed_wakes: AtomicU64::new(0),
            owed_wakes_unsent: AtomicU64::new(0),
            owed_wakes_queue: AtomicU64::new(0),
            owed_wakes_retirement: AtomicU64::new(0),
            backing_runs: AtomicU64::new(0),
            backing_alloc: AtomicU64::new(0),
            fault_entry: [const { AtomicU64::new(0) }; CPUS],
            fault_stamps: [const { [const { AtomicU64::new(0) }; FAULT_STAMPS] }; CPUS],
            faults_served: AtomicU64::new(0),
            fault_total: AtomicU64::new(0),
            fault_longest: AtomicU64::new(0),
            fault_parts: [const { AtomicU64::new(0) }; FAULT_PARTS],
            fault_passes: [const { AtomicU64::new(0) }; FAULT_PASSES],
            fill_in_serves: AtomicU64::new(0),
            t_lock_served: [const { AtomicU64::new(0) }; CPUS],
            t_lock_wait: [const { AtomicU64::new(0) }; CPUS],
            t_lock: [const { [const { [const { AtomicU64::new(0) }; T_LOCK_FIGURES] }; SOURCES] };
                CPUS],
            commit_steps: AtomicU64::new(0),
            commit_admit: AtomicU64::new(0),
            commit_take: AtomicU64::new(0),
            commit_rest: AtomicU64::new(0),
            usage_check: AtomicU64::new(0),
            admission_waits: [const { AtomicU64::new(0) }; ADMISSION_WAITS],
            fast_stamps: [const { [const { AtomicU64::new(0) }; FAST_STAMPS] }; CPUS],
            faults_fast: AtomicU64::new(0),
            fault_fast_total: AtomicU64::new(0),
            fault_fast_longest: AtomicU64::new(0),
            fault_fast_parts: [const { AtomicU64::new(0) }; FAST_PARTS],
            fault_passes_fast: AtomicU64::new(0),
            fast_shared: [const { AtomicBool::new(false) }; CPUS],
            faults_shared: AtomicU64::new(0),
            fault_shared_total: AtomicU64::new(0),
            fault_shared_longest: AtomicU64::new(0),
            fault_shared_parts: [const { AtomicU64::new(0) }; SHARED_PARTS],
            windows_opened: AtomicU64::new(0),
            windows_closed: AtomicU64::new(0),
            window_declines: [const { AtomicU64::new(0) }; WINDOW_DECLINES],
            ahead_commits: AtomicU64::new(0),
            ahead_frames: AtomicU64::new(0),
            ahead_ticks: AtomicU64::new(0),
            streams_started: AtomicU64::new(0),
            streams_ended: AtomicU64::new(0),
            p_lock: [const { [const { [const { AtomicU64::new(0) }; P_LOCK_FIGURES] }; P_LOCK_SOURCES] };
                CPUS],
        }
    }

    /// The fault gate entered on `cpu` at `now` (ticks). Clears any record a
    /// gate left that did not end (a Stop polled in its loop).
    pub(crate) fn fault_entered(&self, cpu: usize, now: u64) {
        if let Some(entry) = self.fault_entry.get(cpu) {
            entry.store(now.saturating_add(1), Ordering::Relaxed);
        }
        if let Some(shared) = self.fast_shared.get(cpu) {
            shared.store(false, Ordering::Relaxed);
        }
    }

    /// Whether `cpu`'s fault gate is timing a fault: the inner serve stamps
    /// only then, so a fill-in's serves read no counter.
    pub(crate) fn fault_timing(&self, cpu: usize) -> bool {
        self.fault_entry
            .get(cpu)
            .is_some_and(|entry| entry.load(Ordering::Relaxed) != 0)
    }

    /// `cpu`'s fault gate is not timing a fault from here (an exit that does
    /// not return, or a syscall's fill-in).
    pub(crate) fn fault_untimed(&self, cpu: usize) {
        if let Some(entry) = self.fault_entry.get(cpu) {
            entry.store(0, Ordering::Relaxed);
        }
    }

    /// A pass of the inner serve began on `cpu` at `now`: the stamps of any
    /// earlier pass are cleared, so a pass's sample never mixes two passes.
    pub(crate) fn fault_pass_began(&self, cpu: usize, now: u64) {
        if let Some(stamps) = self.fault_stamps.get(cpu) {
            let [began, rest @ ..] = stamps;
            began.store(now.saturating_add(1), Ordering::Relaxed);
            for stamp in rest {
                stamp.store(0, Ordering::Relaxed);
            }
        }
    }

    /// `cpu`'s current pass reached `stamp` at `now`.
    pub(crate) fn fault_stamped(&self, cpu: usize, stamp: FaultStamp, now: u64) {
        if let Some(slot) = self
            .fault_stamps
            .get(cpu)
            .and_then(|stamps| stamps.get(stamp as usize + 1))
        {
            slot.store(now.saturating_add(1), Ordering::Relaxed);
        }
    }

    /// One pass of the gate's serve loop ended as `pass`.
    pub(crate) fn fault_pass(&self, pass: FaultPass) {
        self.fault_passes[pass as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// A syscall's fill-in called the inner serve once.
    pub(crate) fn fill_in_served(&self) {
        self.fill_in_serves.fetch_add(1, Ordering::Relaxed);
    }

    /// `cpu`'s gate had its last pass back, its return authorised in that
    /// pass's hold, at `now` (`None` when it read no counter: a fault not
    /// timed or not served), after a fault whose final pass was `served`: a
    /// served fault with the gate's entry and every stamp of its last pass
    /// is one sample. The CPU's record is cleared either way.
    pub(crate) fn fault_returned(&self, cpu: usize, served: bool, now: Option<u64>) {
        let (Some(entry), Some(stamps)) = (self.fault_entry.get(cpu), self.fault_stamps.get(cpu))
        else {
            return;
        };
        if let Some(fast) = self.fast_stamps.get(cpu) {
            for stamp in fast {
                stamp.store(0, Ordering::Relaxed);
            }
        }
        if let Some(shared) = self.fast_shared.get(cpu) {
            shared.store(false, Ordering::Relaxed);
        }
        let entry = entry.swap(0, Ordering::Relaxed);
        let stamps = stamps
            .each_ref()
            .map(|stamp| stamp.swap(0, Ordering::Relaxed));
        let (true, Some(now)) = (served, now) else {
            return;
        };
        if entry == 0 || stamps.contains(&0) {
            return;
        }
        let [began, admit_began, admit_ended, commit_ended, serve_ended] =
            stamps.map(|stamp| stamp - 1);
        let points = [
            entry - 1,
            began,
            admit_began,
            admit_ended,
            commit_ended,
            serve_ended,
            now,
        ];
        let total = now.saturating_sub(entry - 1);
        self.faults_served.fetch_add(1, Ordering::Relaxed);
        self.fault_total.fetch_add(total, Ordering::Relaxed);
        self.fault_longest.fetch_max(total, Ordering::Relaxed);
        for (part, pair) in self.fault_parts.iter().zip(points.windows(2)) {
            part.fetch_add(pair[1].saturating_sub(pair[0]), Ordering::Relaxed);
        }
    }

    /// `cpu`'s fast serve reached `stamp` at `now` (DW2 §13.16 part e3).
    pub(crate) fn fast_stamped(&self, cpu: usize, stamp: FastFaultStamp, now: u64) {
        if let Some(slot) = self
            .fast_stamps
            .get(cpu)
            .and_then(|stamps| stamps.get(stamp as usize))
        {
            slot.store(now.saturating_add(1), Ordering::Relaxed);
        }
    }

    /// One pass of the gate's serve loop was answered by the fast serve
    /// (it is counted by its outcome too).
    pub(crate) fn fault_pass_fast(&self) {
        self.fault_passes_fast.fetch_add(1, Ordering::Relaxed);
    }

    /// The fast serve that answered `cpu`'s current fault was the shared
    /// one (DW2 §15.2): [`Self::fault_returned_fast`] samples it as
    /// `faults-shared`. Cleared at the gate's entry and at every return.
    pub(crate) fn fast_served_shared(&self, cpu: usize) {
        if let Some(shared) = self.fast_shared.get(cpu) {
            shared.store(true, Ordering::Relaxed);
        }
    }

    /// As [`Self::fault_returned`], after a fault whose last pass the fast
    /// serve answered: a served one with the gate's entry and every fast
    /// stamp is one `faults-fast` sample. The CPU's record, the slow serve's
    /// stamps included, is cleared either way.
    pub(crate) fn fault_returned_fast(&self, cpu: usize, served: bool, now: Option<u64>) {
        let (Some(entry), Some(stamps), Some(slow)) = (
            self.fault_entry.get(cpu),
            self.fast_stamps.get(cpu),
            self.fault_stamps.get(cpu),
        ) else {
            return;
        };
        for stamp in slow {
            stamp.store(0, Ordering::Relaxed);
        }
        let shared = self
            .fast_shared
            .get(cpu)
            .is_some_and(|shared| shared.swap(false, Ordering::Relaxed));
        let entry = entry.swap(0, Ordering::Relaxed);
        let stamps = stamps
            .each_ref()
            .map(|stamp| stamp.swap(0, Ordering::Relaxed));
        let (true, Some(now)) = (served, now) else {
            return;
        };
        if entry == 0 || stamps.contains(&0) {
            return;
        }
        let [checked, committed, written] = stamps.map(|stamp| stamp - 1);
        if shared {
            let points = [entry - 1, checked, written, now];
            let total = now.saturating_sub(entry - 1);
            self.faults_shared.fetch_add(1, Ordering::Relaxed);
            self.fault_shared_total.fetch_add(total, Ordering::Relaxed);
            self.fault_shared_longest
                .fetch_max(total, Ordering::Relaxed);
            for (part, pair) in self.fault_shared_parts.iter().zip(points.windows(2)) {
                part.fetch_add(pair[1].saturating_sub(pair[0]), Ordering::Relaxed);
            }
            return;
        }
        let points = [entry - 1, checked, committed, written, now];
        let total = now.saturating_sub(entry - 1);
        self.faults_fast.fetch_add(1, Ordering::Relaxed);
        self.fault_fast_total.fetch_add(total, Ordering::Relaxed);
        self.fault_fast_longest.fetch_max(total, Ordering::Relaxed);
        for (part, pair) in self.fault_fast_parts.iter().zip(points.windows(2)) {
            part.fetch_add(pair[1].saturating_sub(pair[0]), Ordering::Relaxed);
        }
    }

    /// `opened` fault windows were opened or topped up and `closed` closed.
    pub(crate) fn windows_changed(&self, opened: u64, closed: u64) {
        self.windows_opened.fetch_add(opened, Ordering::Relaxed);
        self.windows_closed.fetch_add(closed, Ordering::Relaxed);
    }

    /// A serve under T committed ahead of a stream (DW2 §15.6), taking
    /// `frames`, in `ticks` (zero when the fault was not timed).
    pub(crate) fn fault_ahead(&self, frames: u64, ticks: u64) {
        self.ahead_commits.fetch_add(1, Ordering::Relaxed);
        self.ahead_frames.fetch_add(frames, Ordering::Relaxed);
        self.ahead_ticks.fetch_add(ticks, Ordering::Relaxed);
    }

    /// `started` streams started and `ended` ended (DW2 §15.6).
    pub(crate) fn streams_changed(&self, started: u64, ended: u64) {
        self.streams_started.fetch_add(started, Ordering::Relaxed);
        self.streams_ended.fetch_add(ended, Ordering::Relaxed);
    }

    /// The fast serve declined for `decline`.
    pub(crate) fn window_declined(&self, decline: WindowDecline) {
        self.window_declines[decline as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// `cpu` released P taken by `source` (an index of
    /// [`P_LOCK_SOURCE_NAMES`]) after holding it `held` ticks; `waited` is
    /// its spin, `None` when it was taken at its first try.
    pub(crate) fn p_lock_released(
        &self,
        cpu: usize,
        source: usize,
        waited: Option<u64>,
        held: u64,
    ) {
        let Some([count, spun, wait_sum, held_sum]) =
            self.p_lock.get(cpu).and_then(|sources| sources.get(source))
        else {
            return;
        };
        count.fetch_add(1, Ordering::Relaxed);
        if let Some(waited) = waited {
            spun.fetch_add(1, Ordering::Relaxed);
            wait_sum.fetch_add(waited, Ordering::Relaxed);
        }
        held_sum.fetch_add(held, Ordering::Relaxed);
    }

    /// `cpu` was served T at `served` (ticks). `ticketed` is when it began
    /// to spin, read only when its first check of the ticket failed; `None`
    /// when it was served at once, with no wait.
    pub(crate) fn t_lock_served(&self, cpu: usize, ticketed: Option<u64>, served: u64) {
        let (Some(slot), Some(wait)) = (self.t_lock_served.get(cpu), self.t_lock_wait.get(cpu))
        else {
            return;
        };
        let spun = ticketed.map_or(0, |ticketed| {
            served.saturating_sub(ticketed).saturating_add(1)
        });
        wait.store(spun, Ordering::Relaxed);
        slot.store(served.saturating_add(1), Ordering::Relaxed);
    }

    /// `cpu` released T at `released` (ticks), draining as `source`: the
    /// hold, if its service was stamped, is one acquisition of the CPU and
    /// source.
    pub(crate) fn t_lock_released(&self, cpu: usize, source: DrainSource, released: u64) {
        let (Some(slot), Some(wait), Some(figures)) = (
            self.t_lock_served.get(cpu),
            self.t_lock_wait.get(cpu),
            self.t_lock.get(cpu),
        ) else {
            return;
        };
        let served = slot.swap(0, Ordering::Relaxed);
        if served == 0 {
            return;
        }
        let spun = wait.swap(0, Ordering::Relaxed);
        let held = released.saturating_sub(served - 1);
        let [
            count,
            waited,
            wait_sum,
            wait_longest,
            held_sum,
            held_longest,
        ] = &figures[source as usize];
        count.fetch_add(1, Ordering::Relaxed);
        if spun != 0 {
            waited.fetch_add(1, Ordering::Relaxed);
            wait_sum.fetch_add(spun - 1, Ordering::Relaxed);
            wait_longest.fetch_max(spun - 1, Ordering::Relaxed);
        }
        held_sum.fetch_add(held, Ordering::Relaxed);
        held_longest.fetch_max(held, Ordering::Relaxed);
    }

    /// A commit step began at `began`, admitted from `admit_began` to
    /// `admit_ended`, took and zeroed its frames until `taken`, and ended at
    /// `ended` (ticks): its admission, its take, and the rest (before the
    /// admission and after the take).
    pub(crate) fn commit_step(
        &self,
        began: u64,
        admit_began: u64,
        admit_ended: u64,
        taken: u64,
        ended: u64,
    ) {
        self.commit_steps.fetch_add(1, Ordering::Relaxed);
        self.commit_admit
            .fetch_add(admit_ended.saturating_sub(admit_began), Ordering::Relaxed);
        self.commit_take
            .fetch_add(taken.saturating_sub(admit_ended), Ordering::Relaxed);
        self.commit_rest.fetch_add(
            admit_began
                .saturating_sub(began)
                .saturating_add(ended.saturating_sub(taken)),
            Ordering::Relaxed,
        );
    }

    /// Writes the first-touch measurement's lines (DW2 §13.5): served
    /// faults, the gate's passes, T per CPU and source (a line only for a
    /// nonzero count), and commit steps. Times are converted from
    /// ticks with `tsc_hz`, the boot's measured TSC rate; with none (0) they
    /// print as zero and the counts still print.
    pub(crate) fn write_measure_lines(
        &self,
        tsc_hz: u64,
        mut line: impl FnMut(core::fmt::Arguments<'_>),
    ) {
        let us = |value: &AtomicU64| ticks_to_us(value.load(Ordering::Relaxed), tsc_hz);
        let [sync, lookup, admit, commit, tables, ret] = self.fault_parts.each_ref().map(us);
        line(format_args!(
            "faults served={} total-us={} longest-us={} sync-us={sync} lookup-us={lookup} admit-us={admit} commit-us={commit} tables-us={tables} return-us={ret}",
            self.faults_served.load(Ordering::Relaxed),
            us(&self.fault_total),
            us(&self.fault_longest),
        ));
        let [check, commit, tables, ret] = self.fault_fast_parts.each_ref().map(us);
        line(format_args!(
            "faults-fast served={} total-us={} longest-us={} check-us={check} commit-us={commit} tables-us={tables} return-us={ret}",
            self.faults_fast.load(Ordering::Relaxed),
            us(&self.fault_fast_total),
            us(&self.fault_fast_longest),
        ));
        let [check, tables, ret] = self.fault_shared_parts.each_ref().map(us);
        line(format_args!(
            "faults-shared served={} total-us={} longest-us={} check-us={check} tables-us={tables} return-us={ret}",
            self.faults_shared.load(Ordering::Relaxed),
            us(&self.fault_shared_total),
            us(&self.fault_shared_longest),
        ));
        let [served, present, released, retry, unserved, exhausted] = self
            .fault_passes
            .each_ref()
            .map(|count| count.load(Ordering::Relaxed));
        line(format_args!(
            "fault-passes served={served} already-present={present} released={released} retry={retry} unserved={unserved} exhausted={exhausted} fill-in-serves={} fast={}",
            self.fill_in_serves.load(Ordering::Relaxed),
            self.fault_passes_fast.load(Ordering::Relaxed),
        ));
        let [
            identity,
            mapping,
            tables,
            credit,
            memory,
            leaf,
            declined_return,
            not_committed,
        ] = self
            .window_declines
            .each_ref()
            .map(|count| count.load(Ordering::Relaxed));
        // Two lines, so neither can pass a record's 192 bytes.
        line(format_args!(
            "fault-windows opened={} closed={}",
            self.windows_opened.load(Ordering::Relaxed),
            self.windows_closed.load(Ordering::Relaxed),
        ));
        line(format_args!(
            "fault-ahead commits={} frames={} us={}",
            self.ahead_commits.load(Ordering::Relaxed),
            self.ahead_frames.load(Ordering::Relaxed),
            us(&self.ahead_ticks),
        ));
        line(format_args!(
            "streams started={} ended={}",
            self.streams_started.load(Ordering::Relaxed),
            self.streams_ended.load(Ordering::Relaxed),
        ));
        line(format_args!(
            "fault-declines identity={identity} mapping={mapping} tables={tables} credit={credit} memory={memory} leaf={leaf} return={declined_return}"
        ));
        line(format_args!(
            "fault-declines-shared not-committed={not_committed}"
        ));
        for (cpu, sources) in self.t_lock.iter().enumerate() {
            for (name, figures) in SOURCE_NAMES.iter().zip(sources) {
                let count = figures[0].load(Ordering::Relaxed);
                if count == 0 {
                    continue;
                }
                let waited = figures[1].load(Ordering::Relaxed);
                let [_, _, wait, wait_longest, held, held_longest] = figures.each_ref().map(us);
                line(format_args!(
                    "t-lock cpu={cpu} source={name} count={count} waited={waited} wait-us={wait} wait-longest-us={wait_longest} held-us={held} held-longest-us={held_longest}"
                ));
            }
        }
        for (cpu, sources) in self.p_lock.iter().enumerate() {
            for (name, figures) in P_LOCK_SOURCE_NAMES.iter().zip(sources) {
                let count = figures[0].load(Ordering::Relaxed);
                if count == 0 {
                    continue;
                }
                let waited = figures[1].load(Ordering::Relaxed);
                let [_, _, wait, held] = figures.each_ref().map(us);
                line(format_args!(
                    "p-lock cpu={cpu} source={name} count={count} waited={waited} wait-us={wait} held-us={held}"
                ));
            }
        }
        line(format_args!(
            "commit-steps count={} admit-us={} take-us={} rest-us={}",
            self.commit_steps.load(Ordering::Relaxed),
            us(&self.commit_admit),
            us(&self.commit_take),
            us(&self.commit_rest),
        ));
    }

    /// The power-off hold compared `groups` live TaskGroups' kept usage
    /// with the scan and found `mismatches` figures that differ (DW2
    /// §13.12 part a). Each count is clamped to 31 bits; the top bit marks
    /// the record as made, so a report that reached no power-off hold has
    /// no `usage-check` line rather than one of zeros.
    pub(crate) fn usage_checked(&self, groups: usize, mismatches: usize) {
        let clamp =
            |value: usize| u64::try_from(value).map_or(USAGE_FIELD, |value| value.min(USAGE_FIELD));
        self.usage_check.store(
            USAGE_RECORDED | (clamp(groups) << 31) | clamp(mismatches),
            Ordering::Relaxed,
        );
    }

    /// A pass of `wait`'s kind met an owed refusal and took the owed step.
    pub(crate) fn admission_waited(&self, wait: AdmissionWait) {
        self.admission_waits[wait as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// The `admission-waits` line: always written.
    fn write_admission_line(&self, mut line: impl FnMut(core::fmt::Arguments<'_>)) {
        let [create, commit, fault] = self
            .admission_waits
            .each_ref()
            .map(|count| count.load(Ordering::Relaxed));
        line(format_args!(
            "admission-waits create={create} commit={commit} fault={fault}"
        ));
    }

    /// The `usage-check` line, only once [`Self::usage_checked`] recorded.
    fn write_usage_line(&self, mut line: impl FnMut(core::fmt::Arguments<'_>)) {
        let packed = self.usage_check.load(Ordering::Relaxed);
        if packed & USAGE_RECORDED == 0 {
            return;
        }
        line(format_args!(
            "usage-check groups={} mismatches={}",
            (packed >> 31) & USAGE_FIELD,
            packed & USAGE_FIELD
        ));
    }

    /// Writes the whole report's line bodies in order: the step lines, the
    /// finalization lines, the measurement's lines, the admission waits,
    /// the usage check if it was recorded, then the closing lines, whose values `closing` reads
    /// only once every line before them is written (see
    /// [`write_closing_lines`]).
    pub(crate) fn write_report(
        &self,
        now: Option<u64>,
        tsc_hz: u64,
        closing: impl FnOnce() -> ((u64, u64), u64),
        mut line: impl FnMut(core::fmt::Arguments<'_>),
    ) {
        self.write_lines(&mut line);
        self.write_finalize_lines(now, &mut line);
        self.write_measure_lines(tsc_hz, &mut line);
        self.write_admission_line(&mut line);
        self.write_usage_line(&mut line);
        let (timer_arm, records_dropped) = closing();
        write_closing_lines(timer_arm, records_dropped, line);
    }

    /// An eager backing of `runs` runs and `pages` pages was made: it is
    /// kept if it has more runs than the one kept, the first kept on a tie.
    pub(crate) fn backing_made(&self, runs: u64, pages: u64) {
        let runs = runs.min(u64::from(u32::MAX));
        let packed = (runs << 32) | pages.min(u64::from(u32::MAX));
        let _ = self
            .backing_runs
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |kept| {
                (runs > kept >> 32).then_some(packed)
            });
    }

    /// A create's `allocate_backing` call ran from `began` to `ended` (ns)
    /// and returned an allocation of `runs` runs and `pages` pages: it is
    /// kept if it took more whole microseconds than the one kept, the first
    /// kept on a tie. The three are one atomic word, replaced whole by one
    /// `fetch_update`, so the kept duration always comes with its own
    /// call's runs and pages, whoever calls and whoever reads.
    pub(crate) fn backing_allocated(&self, began: u64, ended: u64, runs: u64, pages: u64) {
        let us = (ended.saturating_sub(began) / 1000).min(field_max(ALLOC_US_BITS));
        let packed = (us << ALLOC_US_SHIFT)
            | (runs.min(field_max(ALLOC_RUNS_BITS)) << ALLOC_RUNS_SHIFT)
            | pages.min(field_max(ALLOC_PAGES_BITS));
        let _ = self
            .backing_alloc
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |kept| {
                (us > kept >> ALLOC_US_SHIFT).then_some(packed)
            });
    }

    /// A hold woke the BSP for owed work (`sent`), or could not, for a
    /// queue newly owed, the bootstrap's retirement, or both.
    pub(crate) fn owed_wake(&self, queue: bool, retirement: bool, sent: bool) {
        let count = if sent {
            &self.owed_wakes
        } else {
            &self.owed_wakes_unsent
        };
        count.fetch_add(1, Ordering::Relaxed);
        if queue {
            self.owed_wakes_queue.fetch_add(1, Ordering::Relaxed);
        }
        if retirement {
            self.owed_wakes_retirement.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// An object's finalization was queued at `now`, into a queue that was
    /// empty if `into_empty`: a gap begins there.
    pub(crate) fn finalize_queued(&self, into_empty: bool, now: u64) {
        if into_empty {
            let _ = self.finalize_gap_since.compare_exchange(
                0,
                now.saturating_add(1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
    }

    /// A finalize step drained by `source` ran from `began` to `ended`; it
    /// ends the gap before it, and if finalization is still `owed` after
    /// it, the next gap begins at its end.
    pub(crate) fn finalize_stepped(&self, source: DrainSource, began: u64, ended: u64, owed: bool) {
        self.finalize_steps[source as usize].fetch_add(1, Ordering::Relaxed);
        self.finalize_step_longest
            .fetch_max(ended.saturating_sub(began), Ordering::Relaxed);
        let next = if owed { ended.saturating_add(1) } else { 0 };
        let since = self.finalize_gap_since.swap(next, Ordering::Relaxed);
        if since != 0 {
            self.finalize_gap_longest
                .fetch_max(began.saturating_sub(since - 1), Ordering::Relaxed);
        }
    }

    /// A hold of the runtime lock ended having run `steps` finalize steps;
    /// a hold that ran none records nothing.
    pub(crate) fn finalize_hold_ended(&self, steps: u32) {
        if steps != 0 {
            self.finalize_hold_longest
                .fetch_max(u64::from(steps), Ordering::Relaxed);
        }
    }

    /// An object completed after waiting `wait` ns since it was queued,
    /// having freed `pages` frames. One writer at a time (T), so the pair
    /// is kept together.
    pub(crate) fn finalize_waited(&self, wait: u64, pages: u64) {
        if wait > self.finalize_wait_longest.load(Ordering::Relaxed) {
            self.finalize_wait_longest.store(wait, Ordering::Relaxed);
            self.finalize_wait_pages.store(pages, Ordering::Relaxed);
        }
    }

    /// Writes the finalization lines' bodies (§10.19 revision 2); a gap
    /// still open at `now` counts.
    pub(crate) fn write_finalize_lines(
        &self,
        now: Option<u64>,
        mut line: impl FnMut(core::fmt::Arguments<'_>),
    ) {
        line(format_args!(
            "finalize-wait-longest-us={} pages={}",
            self.finalize_wait_longest.load(Ordering::Relaxed) / 1000,
            self.finalize_wait_pages.load(Ordering::Relaxed)
        ));
        let since = self.finalize_gap_since.load(Ordering::Relaxed);
        let open = match now {
            Some(now) if since != 0 => now.saturating_sub(since - 1),
            _ => 0,
        };
        let gap = self.finalize_gap_longest.load(Ordering::Relaxed).max(open);
        line(format_args!("finalize-gap-longest-us={}", gap / 1000));
        line(format_args!(
            "finalize-step-longest-us={}",
            self.finalize_step_longest.load(Ordering::Relaxed) / 1000
        ));
        let [gate, syscall, fault, idle, other] = [0, 1, 2, 3, 4]
            .map(|source: usize| self.finalize_steps[source].load(Ordering::Relaxed));
        line(format_args!(
            "finalize-steps gate={gate} syscall={syscall} fault={fault} idle={idle} other={other}"
        ));
        line(format_args!(
            "finalize-steps-in-one-hold longest={}",
            self.finalize_hold_longest.load(Ordering::Relaxed)
        ));
        line(format_args!(
            "owed-wakes={} unsent={} queue={} retirement={}",
            self.owed_wakes.load(Ordering::Relaxed),
            self.owed_wakes_unsent.load(Ordering::Relaxed),
            self.owed_wakes_queue.load(Ordering::Relaxed),
            self.owed_wakes_retirement.load(Ordering::Relaxed)
        ));
    }

    /// Whether `cpu` is timing a step now.
    pub(crate) fn timing(&self, cpu: usize) -> bool {
        self.started
            .get(cpu)
            .is_some_and(|slot| slot.load(Ordering::Relaxed) != 0)
    }

    /// Whether `kind` of work is `owed` at `now`: a stretch begins when it
    /// becomes owed and is recorded when it no longer is.
    pub(crate) fn owed_at(&self, kind: Owed, owed: bool, now: u64) {
        let since = &self.owed_since[kind as usize];
        if owed {
            let _ = since.compare_exchange(
                0,
                now.saturating_add(1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        } else {
            let began = since.swap(0, Ordering::Relaxed);
            if began != 0 {
                self.owed_longest[kind as usize]
                    .fetch_max(now.saturating_sub(began - 1), Ordering::Relaxed);
            }
        }
    }

    /// A step of a call begins on `cpu` at `now`.
    pub(crate) fn step_began(&self, cpu: usize, now: u64) {
        if let Some(slot) = self.started.get(cpu) {
            slot.store(now.saturating_add(1), Ordering::Relaxed);
        }
    }

    /// The step `cpu` was timing ends at `now`, at a safe point of `call`.
    /// Nothing is recorded if no step was being timed there.
    /// A call in steps ended on `cpu` at `now` (every exit of its loop):
    /// the step being timed there, if any, is recorded as `last`'s last
    /// step when `last` names one, and the CPU times nothing afterwards
    /// either way, so no slot stays open past the call (§10.19 revision 2).
    pub(crate) fn call_ended(&self, cpu: usize, last: Option<StepCall>, now: u64) {
        match last {
            Some(call) => self.step_ended(cpu, call, now),
            None => {
                if let Some(slot) = self.started.get(cpu) {
                    slot.store(0, Ordering::Relaxed);
                }
            }
        }
    }

    /// Runs `step` as one step of `call` on `cpu`, timed with `now`, unless
    /// a step is being timed there already: then it is part of that step's
    /// hold and is counted in it (step-6 review D4).
    pub(crate) fn timed_nested<T>(
        &self,
        cpu: usize,
        call: StepCall,
        mut now: impl FnMut() -> Option<u64>,
        step: impl FnOnce() -> T,
    ) -> T {
        if self.timing(cpu) {
            return step();
        }
        if let Some(began) = now() {
            self.step_began(cpu, began);
        }
        let result = step();
        if let Some(ended) = now() {
            self.step_ended(cpu, call, ended);
        }
        result
    }

    /// Times `step` on `cpu` as one step of `call`, with `now`. A step being
    /// timed there already, of a call in whose hold this one runs, keeps
    /// its start: both are recorded, the outer one including this one's
    /// time (DW2 §10.19 revision 3 item 3).
    pub(crate) fn timed<T>(
        &self,
        cpu: usize,
        call: StepCall,
        mut now: impl FnMut() -> Option<u64>,
        step: impl FnOnce() -> T,
    ) -> T {
        let outer = self
            .started
            .get(cpu)
            .map_or(0, |slot| slot.swap(0, Ordering::Relaxed));
        if let Some(began) = now() {
            self.step_began(cpu, began);
        }
        let result = step();
        if let Some(ended) = now() {
            self.step_ended(cpu, call, ended);
        }
        if let Some(slot) = self.started.get(cpu) {
            slot.store(outer, Ordering::Relaxed);
        }
        result
    }

    pub(crate) fn step_ended(&self, cpu: usize, call: StepCall, now: u64) {
        let Some(slot) = self.started.get(cpu) else {
            return;
        };
        let started = slot.swap(0, Ordering::Relaxed);
        if started == 0 {
            return;
        }
        let held = now.saturating_sub(started - 1).min(u64::MAX >> CALL_BITS);
        self.longest
            .fetch_max((held << CALL_BITS) | call as u64, Ordering::Relaxed);
        let call = call as usize;
        self.call_longest[call].fetch_max(held, Ordering::Relaxed);
        self.call_steps[call].fetch_add(1, Ordering::Relaxed);
        self.call_total[call].fetch_add(held, Ordering::Relaxed);
    }

    /// A Stop ended `call` at a safe point after it had made a step.
    pub(crate) fn stopped_between_steps(&self, call: StepCall) {
        self.stops[call as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// A parked `call` was settled because its Thread had ended.
    pub(crate) fn parked_call_ended(&self, call: StepCall) {
        self.ended[call as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// The longest step, in nanoseconds, and its call; `None` before any.
    pub(crate) fn longest(&self) -> Option<(u64, &'static str)> {
        let packed = self.longest.load(Ordering::Relaxed);
        (packed != 0).then(|| {
            let call = (packed & ((1 << CALL_BITS) - 1)) as usize;
            (packed >> CALL_BITS, NAMES.get(call).copied().unwrap_or("?"))
        })
    }

    /// Writes the report lines' bodies, one call each.
    pub(crate) fn write_lines(&self, mut line: impl FnMut(core::fmt::Arguments<'_>)) {
        match self.longest() {
            Some((held, call)) => line(format_args!("longest-step-us={} call={call}", held / 1000)),
            None => line(format_args!("longest-step-us=0 call=none")),
        }
        let counts = |counts: &[AtomicU64; CALLS]| {
            let mut values = [0u64; CALLS];
            for (value, count) in values.iter_mut().zip(counts) {
                *value = count.load(Ordering::Relaxed);
            }
            values
        };
        let [map, unmap, protect, fill, commit, create, ..] = counts(&self.stops);
        line(format_args!(
            "stops-between-steps map={map} unmap={unmap} protect={protect} fill={fill} commit={commit} create={create}"
        ));
        let [map, unmap, protect, fill, commit, create, ..] = counts(&self.ended);
        line(format_args!(
            "parked-ended map={map} unmap={unmap} protect={protect} fill={fill} commit={commit} create={create}"
        ));
        let per_call = |line: &mut dyn FnMut(core::fmt::Arguments<'_>),
                        name: &str,
                        values: [u64; CALLS],
                        scale: u64| {
            let [
                map,
                unmap,
                protect,
                fill,
                commit,
                create,
                teardown,
                release,
                finalize,
            ] = values.map(|value| value / scale);
            line(format_args!(
                "{name} map={map} unmap={unmap} protect={protect} fill={fill} commit={commit} create={create} teardown={teardown} release={release} finalize={finalize}"
            ));
        };
        per_call(
            &mut line,
            "call-longest-us",
            counts(&self.call_longest),
            1000,
        );
        per_call(&mut line, "call-steps", counts(&self.call_steps), 1);
        per_call(&mut line, "call-total-us", counts(&self.call_total), 1000);
        let [teardown, finalize] =
            [0, 1].map(|kind| self.owed_longest[kind].load(Ordering::Relaxed) / 1000);
        line(format_args!(
            "owed-longest-us teardown={teardown} finalize={finalize}"
        ));
        let kept = self.backing_runs.load(Ordering::Relaxed);
        line(format_args!(
            "backing-runs longest={} pages={}",
            kept >> 32,
            kept & u64::from(u32::MAX)
        ));
        let kept = self.backing_alloc.load(Ordering::Relaxed);
        line(format_args!(
            "backing-alloc-longest-us={} runs={} pages={}",
            kept >> ALLOC_US_SHIFT,
            (kept >> ALLOC_RUNS_SHIFT) & field_max(ALLOC_RUNS_BITS),
            kept & field_max(ALLOC_PAGES_BITS)
        ));
    }
}

/// The report's last lines, after the tally's: the timer's arm counts, then
/// the records the COM1 output gate has dropped, which is the report's last
/// line. `records_dropped` is read before any of these lines is written, so a
/// drop of one of them is not in it (a check that requires the line sees that
/// drop as the line missing).
fn write_closing_lines(
    (retries, deferred): (u64, u64),
    records_dropped: u64,
    mut line: impl FnMut(core::fmt::Arguments<'_>),
) {
    line(format_args!(
        "timer-arm retries={retries} deferred={deferred}"
    ));
    line(format_args!("records-dropped={records_dropped}"));
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod live {
    use super::{DrainSource, StepCall, StepTally};
    use crate::cpu::CPU_CAPACITY;

    static TALLY: StepTally<CPU_CAPACITY> = StepTally::new();
    /// Per CPU, whether a queued teardown step may still run since the
    /// CPU last entered from user mode (DW2 §10.10 item 7): one step per
    /// syscall, timer interrupt, page fault or idle poll.
    static TEARDOWN_ALLOWED: [core::sync::atomic::AtomicBool; CPU_CAPACITY] =
        [const { core::sync::atomic::AtomicBool::new(false) }; CPU_CAPACITY];

    /// An entry from user mode (or an idle poll) on `cpu`: one teardown
    /// step may run before the next.
    pub(crate) fn allow_teardown_step(cpu: usize) {
        if let Some(slot) = TEARDOWN_ALLOWED.get(cpu) {
            slot.store(true, core::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Takes `cpu`'s one teardown step, if it has not been taken.
    pub(crate) fn take_teardown_step(cpu: usize) -> bool {
        TEARDOWN_ALLOWED
            .get(cpu)
            .is_some_and(|slot| slot.swap(false, core::sync::atomic::Ordering::Relaxed))
    }

    /// Per CPU, the kind of entry it last made (DW2 §10.19 revision 2 item
    /// 3), as a [`DrainSource`]. Written and read only on its own CPU.
    static DRAIN_SOURCE: [core::sync::atomic::AtomicU8; CPU_CAPACITY] =
        [const { core::sync::atomic::AtomicU8::new(DrainSource::Other as u8) }; CPU_CAPACITY];

    /// `cpu` is now draining as `source`.
    pub(crate) fn set_drain_source(cpu: usize, source: DrainSource) {
        if let Some(slot) = DRAIN_SOURCE.get(cpu) {
            slot.store(source as u8, core::sync::atomic::Ordering::Relaxed);
        }
    }

    fn drain_source(cpu: usize) -> DrainSource {
        DRAIN_SOURCE.get(cpu).map_or(DrainSource::Other, |slot| {
            DrainSource::from_index(slot.load(core::sync::atomic::Ordering::Relaxed))
        })
    }

    /// The report's clock: the kernel's monotonic nanoseconds.
    pub(crate) fn now() -> Option<u64> {
        crate::time::monotonic_now().ok()
    }

    /// An owed finalization was queued at `now` (see
    /// [`StepTally::finalize_queued`]).
    pub(crate) fn finalize_queued(into_empty: bool, now: u64) {
        TALLY.finalize_queued(into_empty, now);
    }

    /// A finalize step ran on `cpu` (see [`StepTally::finalize_stepped`]).
    pub(crate) fn finalize_stepped(cpu: usize, began: u64, ended: u64, owed: bool) {
        TALLY.finalize_stepped(drain_source(cpu), began, ended, owed);
    }

    /// A hold of the runtime lock ended having run `steps` finalize steps
    /// (see [`StepTally::finalize_hold_ended`]).
    pub(crate) fn finalize_hold_ended(steps: u32) {
        TALLY.finalize_hold_ended(steps);
    }

    /// An owed finalization completed (see [`StepTally::finalize_waited`]).
    pub(crate) fn finalize_waited(wait: u64, pages: u64) {
        TALLY.finalize_waited(wait, pages);
    }

    /// Times a step from here, for a loop whose first step has no safe point
    /// before it.
    pub(crate) fn step_began(cpu: usize) {
        if let Some(now) = now() {
            TALLY.step_began(cpu, now);
        }
    }

    /// At a safe point of `call` on `cpu`: ends the step being timed if the
    /// call `stepped`, and returns the time for [`after_safe_point`].
    pub(crate) fn at_safe_point(cpu: usize, call: StepCall, stepped: bool) -> Option<u64> {
        let now = now();
        if let Some(now) = now
            && stepped
        {
            TALLY.step_ended(cpu, call, now);
        }
        now
    }

    /// After that safe point: a Stop that ended a call that had stepped is
    /// counted, and a step about to run is timed.
    pub(crate) fn after_safe_point(
        cpu: usize,
        call: StepCall,
        stepped: bool,
        now: Option<u64>,
        stopped: bool,
        stepping: bool,
    ) {
        if stopped && stepped {
            TALLY.stopped_between_steps(call);
        }
        if let (Some(now), true) = (now, stepping) {
            TALLY.step_began(cpu, now);
        }
    }

    pub(crate) fn parked_call_ended(call: StepCall) {
        TALLY.parked_call_ended(call);
    }

    /// Times `step` on `cpu` as one step of `call`, unless a step is being
    /// timed there already: then it is part of that step's hold and is
    /// counted in it (step-6 review D4).
    pub(crate) fn timed_nested<T>(cpu: usize, call: StepCall, step: impl FnOnce() -> T) -> T {
        TALLY.timed_nested(cpu, call, now, step)
    }

    /// A call in steps ended on `cpu` (see [`StepTally::call_ended`]).
    pub(crate) fn call_ended(cpu: usize, last: Option<StepCall>) {
        match now() {
            Some(now) => TALLY.call_ended(cpu, last, now),
            None => TALLY.call_ended(cpu, None, 0),
        }
    }

    /// Whether `kind` of work is owed now (see [`StepTally::owed_at`]).
    pub(crate) fn owed(kind: super::Owed, owed: bool) {
        if let Some(now) = now() {
            TALLY.owed_at(kind, owed, now);
        }
    }

    /// Times `step` on `cpu` as one step of `call`.
    pub(crate) fn timed<T>(cpu: usize, call: StepCall, step: impl FnOnce() -> T) -> T {
        TALLY.timed(cpu, call, now, step)
    }

    /// An eager backing was made (see [`StepTally::backing_made`]).
    pub(crate) fn backing_made(runs: u64, pages: u64) {
        TALLY.backing_made(runs, pages);
    }

    /// A create's `allocate_backing` call, timed with [`now`] read just
    /// before and just after it, returned an allocation of `runs` runs and
    /// `pages` pages (see [`StepTally::backing_allocated`]). Not recorded
    /// when either read found no clock.
    pub(crate) fn backing_allocated(began: Option<u64>, ended: Option<u64>, runs: u64, pages: u64) {
        if let (Some(began), Some(ended)) = (began, ended) {
            TALLY.backing_allocated(began, ended, runs, pages);
        }
    }

    /// A hold woke the BSP for owed work (see [`StepTally::owed_wake`]).
    pub(crate) fn owed_wake(queue: bool, retirement: bool, sent: bool) {
        TALLY.owed_wake(queue, retirement, sent);
    }

    pub(crate) fn report() {
        fn emit(arguments: core::fmt::Arguments<'_>) {
            let mut line = Line::new();
            let _ = core::fmt::Write::write_fmt(&mut line, arguments);
            if let Ok(message) = core::str::from_utf8(line.text()) {
                let _ = crate::debug::emit_early_record(
                    crate::debug::DiagnosticLevel::Info,
                    "steps",
                    message,
                );
            }
        }
        TALLY.write_report(
            now(),
            crate::time::measured_tsc_hz(),
            || {
                (
                    crate::time::timer_arm_counts(),
                    crate::debug::records_dropped(),
                )
            },
            emit,
        );
    }

    /// The measurement's stamp (DW2 §13.5): a raw TSC read on this CPU, no
    /// lock and no per-CPU lookup. Not [`now`], whose clock lock every CPU
    /// shares.
    #[inline(always)]
    pub(crate) fn ticks() -> u64 {
        crate::time::raw_tsc()
    }

    /// The fault gate entered on `cpu`: one TSC read.
    pub(crate) fn fault_entered(cpu: usize) {
        TALLY.fault_entered(cpu, ticks());
    }

    /// `cpu`'s gate stops timing without a sample, or a fill-in begins.
    pub(crate) fn fault_untimed(cpu: usize) {
        TALLY.fault_untimed(cpu);
    }

    /// The inner serve began a pass on `cpu`: one TSC read, only while the
    /// CPU's fault gate is timing a fault.
    pub(crate) fn fault_pass_began(cpu: usize) {
        if TALLY.fault_timing(cpu) {
            TALLY.fault_pass_began(cpu, ticks());
        }
    }

    /// The inner serve reached `stamp` on `cpu`: one TSC read, only while
    /// the CPU's fault gate is timing a fault.
    pub(crate) fn fault_stamped(cpu: usize, stamp: super::FaultStamp) {
        if TALLY.fault_timing(cpu) {
            TALLY.fault_stamped(cpu, stamp, ticks());
        }
    }

    /// One pass of the gate's serve loop ended as `pass`.
    pub(crate) fn fault_pass(pass: super::FaultPass) {
        TALLY.fault_pass(pass);
    }

    /// A syscall's fill-in called the inner serve.
    pub(crate) fn fill_in_served() {
        TALLY.fill_in_served();
    }

    /// `cpu`'s gate had its last pass back with its return authorised (see
    /// [`StepTally::fault_returned`]): one TSC read for a timed fault that
    /// was served, none otherwise. `fast`: the fast serve answered that
    /// pass (see [`StepTally::fault_returned_fast`]).
    pub(crate) fn fault_returned(cpu: usize, served: bool, fast: bool) {
        let now = (served && TALLY.fault_timing(cpu)).then(ticks);
        if fast {
            TALLY.fault_returned_fast(cpu, served, now);
        } else {
            TALLY.fault_returned(cpu, served, now);
        }
    }

    /// The fast serve reached `stamp` on `cpu`: one TSC read, only while
    /// the CPU's fault gate is timing a fault.
    pub(crate) fn fast_stamped(cpu: usize, stamp: super::FastFaultStamp) {
        if TALLY.fault_timing(cpu) {
            TALLY.fast_stamped(cpu, stamp, ticks());
        }
    }

    /// One pass of the gate's loop was the fast serve's.
    pub(crate) fn fault_pass_fast() {
        TALLY.fault_pass_fast();
    }

    /// The fast serve that answered `cpu`'s fault was the shared one (see
    /// [`StepTally::fast_served_shared`]).
    pub(crate) fn fast_served_shared(cpu: usize) {
        TALLY.fast_served_shared(cpu);
    }

    /// Fault windows opened and closed (see [`StepTally::windows_changed`]).
    pub(crate) fn windows_changed(opened: u64, closed: u64) {
        TALLY.windows_changed(opened, closed);
    }

    /// The start of a commit ahead on `cpu` (DW2 §15.6): one TSC read, only
    /// while the CPU's fault gate is timing a fault.
    pub(crate) fn fault_ahead_began(cpu: usize) -> Option<u64> {
        TALLY.fault_timing(cpu).then(ticks)
    }

    /// A commit ahead begun at `began` took `frames` (see
    /// [`StepTally::fault_ahead`]): one TSC read when it was timed.
    pub(crate) fn fault_ahead(began: Option<u64>, frames: u64) {
        let elapsed = began.map_or(0, |began| ticks().saturating_sub(began));
        TALLY.fault_ahead(frames, elapsed);
    }

    /// Streams started and ended (see [`StepTally::streams_changed`]).
    pub(crate) fn streams_changed(changes: crate::memory::address_region::StreamChanges) {
        if changes.started != 0 || changes.ended != 0 {
            TALLY.streams_changed(changes.started, changes.ended);
        }
    }

    /// The fast serve declined (see [`StepTally::window_declined`]).
    pub(crate) fn window_declined(decline: super::WindowDecline) {
        TALLY.window_declined(decline);
    }

    /// P released on this CPU (see [`StepTally::p_lock_released`]).
    pub(crate) fn p_lock_released(source: usize, waited: Option<u64>, held: u64) {
        if let Some(cpu) = crate::arch::x86_64::syscall::current_cpu_index_for_diagnostics() {
            TALLY.p_lock_released(cpu, source, waited, held);
        }
    }

    /// `cpu` was served T, having begun to spin at `ticketed` (`None`:
    /// served at once): one TSC read.
    pub(crate) fn t_lock_served(cpu: usize, ticketed: Option<u64>) {
        TALLY.t_lock_served(cpu, ticketed, ticks());
    }

    /// `cpu` released T at `released`, read just before the release store.
    pub(crate) fn t_lock_released(cpu: usize, released: u64) {
        TALLY.t_lock_released(cpu, drain_source(cpu), released);
    }

    /// A pass met an owed refusal and took the owed step (see
    /// [`StepTally::admission_waited`]).
    pub(crate) fn admission_waited(wait: super::AdmissionWait) {
        TALLY.admission_waited(wait);
    }

    /// The power-off hold's usage check (see
    /// [`StepTally::usage_checked`]).
    pub(crate) fn usage_checked(groups: usize, mismatches: usize) {
        TALLY.usage_checked(groups, mismatches);
    }

    /// A commit step's five [`ticks`] stamps (see
    /// [`StepTally::commit_step`]).
    pub(crate) fn commit_step(
        began: u64,
        admit_began: u64,
        admit_ended: u64,
        taken: u64,
        ended: u64,
    ) {
        TALLY.commit_step(began, admit_began, admit_ended, taken, ended);
    }

    struct Line {
        bytes: [u8; 224],
        len: usize,
    }

    impl Line {
        const fn new() -> Self {
            Self {
                bytes: [0; 224],
                len: 0,
            }
        }

        fn text(&self) -> &[u8] {
            &self.bytes[..self.len]
        }
    }

    impl core::fmt::Write for Line {
        fn write_str(&mut self, text: &str) -> core::fmt::Result {
            let end = self.len + text.len();
            let slot = self.bytes.get_mut(self.len..end).ok_or(core::fmt::Error)?;
            slot.copy_from_slice(text.as_bytes());
            self.len = end;
            Ok(())
        }
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) use live::{
    admission_waited, after_safe_point, allow_teardown_step, at_safe_point, backing_allocated,
    backing_made, call_ended, commit_step, fast_served_shared, fast_stamped, fault_ahead,
    fault_ahead_began, fault_entered, fault_pass, fault_pass_began, fault_pass_fast,
    fault_returned, fault_stamped, fault_untimed, fill_in_served, finalize_hold_ended,
    finalize_queued, finalize_stepped, finalize_waited, now, owed, owed_wake, p_lock_released,
    parked_call_ended, report, set_drain_source, step_began, streams_changed, t_lock_released,
    t_lock_served, take_teardown_step, ticks, timed, timed_nested, usage_checked, window_declined,
    windows_changed,
};

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::string::String;
    use std::vec::Vec;

    fn lines(tally: &StepTally<2>) -> Vec<String> {
        let mut out = Vec::new();
        tally.write_lines(|arguments| out.push(std::fmt::format(arguments)));
        out
    }

    #[test]
    fn nothing_recorded_reports_zero() {
        let tally = StepTally::<2>::new();
        assert_eq!(
            lines(&tally),
            [
                "longest-step-us=0 call=none",
                "stops-between-steps map=0 unmap=0 protect=0 fill=0 commit=0 create=0",
                "parked-ended map=0 unmap=0 protect=0 fill=0 commit=0 create=0",
                "call-longest-us map=0 unmap=0 protect=0 fill=0 commit=0 create=0 teardown=0 release=0 finalize=0",
                "call-steps map=0 unmap=0 protect=0 fill=0 commit=0 create=0 teardown=0 release=0 finalize=0",
                "call-total-us map=0 unmap=0 protect=0 fill=0 commit=0 create=0 teardown=0 release=0 finalize=0",
                "owed-longest-us teardown=0 finalize=0",
                "backing-runs longest=0 pages=0",
                "backing-alloc-longest-us=0 runs=0 pages=0",
            ]
        );
    }

    #[test]
    fn the_backing_with_the_most_runs_is_kept_with_its_pages() {
        let tally = StepTally::<2>::new();
        let backing_line = |tally: &StepTally<2>| {
            lines(tally)
                .into_iter()
                .find(|line| line.starts_with("backing-runs "))
                .unwrap()
        };
        assert_eq!(backing_line(&tally), "backing-runs longest=0 pages=0");
        for (runs, pages) in [(1, 512), (7, 40), (3, 900), (1, 4096)] {
            tally.backing_made(runs, pages);
        }
        assert_eq!(backing_line(&tally), "backing-runs longest=7 pages=40");
        // An equal run count later does not replace it.
        tally.backing_made(7, 2000);
        assert_eq!(backing_line(&tally), "backing-runs longest=7 pages=40");
        tally.backing_made(8, 16);
        assert_eq!(backing_line(&tally), "backing-runs longest=8 pages=16");
    }

    fn alloc_line(tally: &StepTally<2>) -> String {
        lines(tally).last().cloned().unwrap()
    }

    #[test]
    fn the_longest_backing_allocation_is_kept_with_its_runs_and_pages() {
        let tally = StepTally::<2>::new();
        assert_eq!(
            alloc_line(&tally),
            "backing-alloc-longest-us=0 runs=0 pages=0"
        );
        tally.backing_allocated(1_000, 4_000, 2, 600);
        assert_eq!(
            alloc_line(&tally),
            "backing-alloc-longest-us=3 runs=2 pages=600"
        );
        // A longer call replaces it, with its own runs and pages.
        tally.backing_allocated(10_000, 19_500, 17, 9_000);
        assert_eq!(
            alloc_line(&tally),
            "backing-alloc-longest-us=9 runs=17 pages=9000"
        );
        // A shorter one does not, nor an equal one (in whole microseconds).
        tally.backing_allocated(0, 2_000, 400, 400);
        tally.backing_allocated(0, 9_000, 1, 1);
        tally.backing_allocated(0, 9_999, 3, 3);
        assert_eq!(
            alloc_line(&tally),
            "backing-alloc-longest-us=9 runs=17 pages=9000"
        );
        // A clock that went backwards counts as no time.
        tally.backing_allocated(50_000, 10_000, 5, 5);
        assert_eq!(
            alloc_line(&tally),
            "backing-alloc-longest-us=9 runs=17 pages=9000"
        );
    }

    #[test]
    fn backing_allocation_fields_past_their_width_are_clamped() {
        let tally = StepTally::<2>::new();
        tally.backing_allocated(0, 1_000 << 30, 1 << 40, u64::MAX);
        assert_eq!(
            alloc_line(&tally),
            "backing-alloc-longest-us=16777215 runs=1048575 pages=1048575"
        );
        // A clamped duration ties with another clamped one: the first stays.
        tally.backing_allocated(0, u64::MAX, 1, 1);
        assert_eq!(
            alloc_line(&tally),
            "backing-alloc-longest-us=16777215 runs=1048575 pages=1048575"
        );
        // Values that fit are kept exactly beside a clamped neighbour.
        let tally = StepTally::<2>::new();
        tally.backing_allocated(0, 16_777_215_000, 1_048_575, 7);
        assert_eq!(
            alloc_line(&tally),
            "backing-alloc-longest-us=16777215 runs=1048575 pages=7"
        );
    }

    #[test]
    fn each_call_keeps_its_longest_step_its_steps_and_their_total() {
        let tally = StepTally::<2>::new();
        for (cpu, call, began, ended) in [
            (0, StepCall::Finalize, 0, 2_000_000),
            (1, StepCall::Finalize, 0, 3_000_000),
            (0, StepCall::Release, 5_000_000, 5_400_000),
            (1, StepCall::Map, 0, 9_000_000),
        ] {
            tally.step_began(cpu, began);
            tally.step_ended(cpu, call, ended);
        }
        assert_eq!(tally.longest(), Some((9_000_000, "map")));
        let lines = lines(&tally);
        assert_eq!(
            lines[3],
            "call-longest-us map=9000 unmap=0 protect=0 fill=0 commit=0 create=0 teardown=0 release=400 finalize=3000"
        );
        assert_eq!(
            lines[4],
            "call-steps map=1 unmap=0 protect=0 fill=0 commit=0 create=0 teardown=0 release=1 finalize=2"
        );
        assert_eq!(
            lines[5],
            "call-total-us map=9000 unmap=0 protect=0 fill=0 commit=0 create=0 teardown=0 release=400 finalize=5000"
        );
    }

    #[test]
    fn the_longest_stretch_owed_is_kept_per_kind() {
        let tally = StepTally::<2>::new();
        // Owed from 1 ms; still owed at 2 ms; done at 4 ms.
        tally.owed_at(Owed::Teardown, true, 1_000_000);
        tally.owed_at(Owed::Teardown, true, 2_000_000);
        tally.owed_at(Owed::Teardown, false, 4_000_000);
        // A shorter stretch later keeps the longest.
        tally.owed_at(Owed::Teardown, true, 10_000_000);
        tally.owed_at(Owed::Teardown, false, 11_000_000);
        // Not owed, then owed from time zero and done.
        tally.owed_at(Owed::Finalize, false, 1);
        tally.owed_at(Owed::Finalize, true, 0);
        tally.owed_at(Owed::Finalize, false, 7_000_000);
        assert_eq!(
            lines(&tally)[6],
            "owed-longest-us teardown=3000 finalize=7000"
        );
    }

    #[test]
    fn a_cpu_is_timing_only_between_a_begin_and_its_end() {
        let tally = StepTally::<2>::new();
        assert!(!tally.timing(0));
        tally.step_began(0, 0);
        assert!(tally.timing(0) && !tally.timing(1));
        tally.step_ended(0, StepCall::Finalize, 10);
        assert!(!tally.timing(0));
        assert!(!tally.timing(9));
    }

    #[test]
    fn the_longest_step_on_any_cpu_is_kept_with_its_call() {
        let tally = StepTally::<2>::new();
        tally.step_began(0, 1_000);
        tally.step_began(1, 0);
        tally.step_ended(0, StepCall::Map, 5_001_000);
        tally.step_ended(1, StepCall::Create, 9_000_000);
        assert_eq!(tally.longest(), Some((9_000_000, "create")));
        tally.step_began(1, 0);
        tally.step_ended(1, StepCall::Teardown, 9_500_000);
        assert_eq!(tally.longest(), Some((9_500_000, "teardown")));
        // A shorter step later changes nothing.
        tally.step_began(0, 10_000_000);
        tally.step_ended(0, StepCall::Commit, 10_000_500);
        assert_eq!(tally.longest(), Some((9_500_000, "teardown")));
        assert_eq!(lines(&tally)[0], "longest-step-us=9500 call=teardown");
    }

    #[test]
    fn an_end_with_no_timed_step_records_nothing() {
        let tally = StepTally::<2>::new();
        tally.step_ended(0, StepCall::Map, 1_000_000);
        assert_eq!(tally.longest(), None);
        // A step began at time zero is still timed.
        tally.step_began(0, 0);
        tally.step_ended(0, StepCall::Unmap, 7_000);
        assert_eq!(tally.longest(), Some((7_000, "unmap")));
        // Each begin is ended once.
        tally.step_ended(0, StepCall::Map, 99_000_000);
        assert_eq!(tally.longest(), Some((7_000, "unmap")));
        // A CPU past the table is ignored.
        tally.step_began(5, 0);
        tally.step_ended(5, StepCall::Map, 99_000_000);
        assert_eq!(tally.longest(), Some((7_000, "unmap")));
    }

    fn finalize_lines(tally: &StepTally<2>, now: Option<u64>) -> Vec<String> {
        let mut out = Vec::new();
        tally.write_finalize_lines(now, |arguments| out.push(std::fmt::format(arguments)));
        out
    }

    /// The events the runtime reports for owed finalization, scripted: the
    /// tally and the per-slot record together, as `finalize_owed_step` and
    /// the cleanup drain use them.
    struct Script {
        tally: StepTally<2>,
        waits: OwedWaits<4>,
        queued: usize,
    }

    impl Script {
        fn new() -> Self {
            Self {
                tally: StepTally::new(),
                waits: OwedWaits::new(),
                queued: 0,
            }
        }

        fn queue(&mut self, slot: usize, now_us: u64) {
            let now = now_us * 1000;
            self.waits.queued(slot, now);
            self.tally.finalize_queued(self.queued == 0, now);
            self.queued += 1;
        }

        /// A step from `began_us` to `ended_us` that freed `freed` frames
        /// of each `(slot, frames, completed)`.
        fn step(
            &mut self,
            source: DrainSource,
            began_us: u64,
            ended_us: u64,
            freed: &[(usize, u64, bool)],
        ) {
            let ended = ended_us * 1000;
            let mut oldest: Option<(u64, u64)> = None;
            for &(slot, frames, completed) in freed {
                self.waits.freed(slot, frames);
                if completed {
                    self.queued -= 1;
                    if let Some((queued, pages)) = self.waits.completed(slot)
                        && oldest.is_none_or(|(first, _)| queued < first)
                    {
                        oldest = Some((queued, pages));
                    }
                }
            }
            if let Some((queued, pages)) = oldest {
                self.tally.finalize_waited(ended - queued, pages);
            }
            self.tally
                .finalize_stepped(source, began_us * 1000, ended, self.queued != 0);
        }
    }

    #[test]
    fn nothing_queued_reports_zero_finalization() {
        let tally = StepTally::<2>::new();
        assert_eq!(
            finalize_lines(&tally, Some(9_000_000)),
            [
                "finalize-wait-longest-us=0 pages=0",
                "finalize-gap-longest-us=0",
                "finalize-step-longest-us=0",
                "finalize-steps gate=0 syscall=0 fault=0 idle=0 other=0",
                "finalize-steps-in-one-hold longest=0",
                "owed-wakes=0 unsent=0 queue=0 retirement=0",
            ]
        );
    }

    #[test]
    fn an_object_queued_into_an_empty_queue_waits_for_its_first_step() {
        let mut script = Script::new();
        // Queued at 1 ms; nothing steps until 4 ms; done by 6 ms.
        script.queue(2, 1_000);
        script.step(DrainSource::Gate, 4_000, 4_500, &[(2, 512, false)]);
        script.step(DrainSource::Gate, 5_000, 6_000, &[(2, 100, true)]);
        assert_eq!(
            finalize_lines(&script.tally, Some(50_000_000)),
            [
                "finalize-wait-longest-us=5000 pages=612",
                // 3 ms before the first step; 0.5 ms between the steps.
                "finalize-gap-longest-us=3000",
                "finalize-step-longest-us=1000",
                "finalize-steps gate=2 syscall=0 fault=0 idle=0 other=0",
                "finalize-steps-in-one-hold longest=0",
                "owed-wakes=0 unsent=0 queue=0 retirement=0",
            ]
        );
    }

    #[test]
    fn the_time_nothing_is_owed_is_no_gap() {
        let mut script = Script::new();
        script.queue(0, 0);
        script.step(DrainSource::Syscall, 1_000, 1_100, &[(0, 7, true)]);
        // Empty for 100 ms, then queued again and stepped 2 ms later.
        script.queue(0, 101_100);
        script.step(DrainSource::Idle, 103_100, 103_200, &[(0, 9, true)]);
        assert_eq!(
            finalize_lines(&script.tally, Some(200_000_000)),
            [
                "finalize-wait-longest-us=2100 pages=9",
                "finalize-gap-longest-us=2000",
                "finalize-step-longest-us=100",
                "finalize-steps gate=0 syscall=1 fault=0 idle=1 other=0",
                "finalize-steps-in-one-hold longest=0",
                "owed-wakes=0 unsent=0 queue=0 retirement=0",
            ]
        );
    }

    #[test]
    fn two_overlapping_objects_keep_the_longest_wait_with_its_pages() {
        let mut script = Script::new();
        script.queue(1, 0);
        script.queue(3, 2_000);
        // Queued into a non-empty queue: no gap begins at 2 ms.
        script.step(DrainSource::Fault, 3_000, 3_200, &[(1, 512, false)]);
        script.step(
            DrainSource::Gate,
            4_000,
            4_300,
            &[(1, 40, true), (3, 300, false)],
        );
        script.step(DrainSource::Gate, 4_500, 30_000, &[(3, 200, true)]);
        assert_eq!(
            finalize_lines(&script.tally, Some(90_000_000)),
            [
                // Slot 1 waited 4.3 ms for 552 frames; slot 3, 28 ms for 500.
                "finalize-wait-longest-us=28000 pages=500",
                "finalize-gap-longest-us=3000",
                "finalize-step-longest-us=25500",
                "finalize-steps gate=2 syscall=0 fault=1 idle=0 other=0",
                "finalize-steps-in-one-hold longest=0",
                "owed-wakes=0 unsent=0 queue=0 retirement=0",
            ]
        );
    }

    #[test]
    fn a_gap_still_open_at_the_report_counts() {
        let mut script = Script::new();
        script.queue(0, 0);
        script.step(DrainSource::Other, 1_000, 2_000, &[(0, 512, false)]);
        // Still owed at 900 ms: the gap since 2 ms counts, the wait does not.
        assert_eq!(
            finalize_lines(&script.tally, Some(900_000_000)),
            [
                "finalize-wait-longest-us=0 pages=0",
                "finalize-gap-longest-us=898000",
                "finalize-step-longest-us=1000",
                "finalize-steps gate=0 syscall=0 fault=0 idle=0 other=1",
                "finalize-steps-in-one-hold longest=0",
                "owed-wakes=0 unsent=0 queue=0 retirement=0",
            ]
        );
        // Without a clock at the report, only closed gaps.
        assert_eq!(
            finalize_lines(&script.tally, None)[1],
            "finalize-gap-longest-us=1000"
        );
    }

    #[test]
    fn a_completion_without_its_queueing_is_not_a_wait() {
        let waits = OwedWaits::<2>::new();
        waits.freed(1, 5);
        assert_eq!(waits.completed(1), None);
        // The record is cleared by the completion, and a slot past the
        // record is ignored.
        waits.queued(1, 10);
        waits.freed(1, 3);
        assert_eq!(waits.completed(1), Some((10, 3)));
        assert_eq!(waits.completed(1), None);
        waits.queued(7, 10);
        waits.freed(7, 3);
        assert_eq!(waits.completed(7), None);
    }

    /// A clock for `timed_nested` that reads `times` in turn, in ms.
    fn clock(times: &[u64]) -> impl FnMut() -> Option<u64> + '_ {
        let mut times = times.iter();
        move || times.next().map(|ms| ms * 1_000_000)
    }

    #[test]
    fn a_call_that_ended_no_longer_swallows_a_later_finalize_step() {
        let tally = StepTally::<2>::new();
        // A map's last step began at a safe point at 0 and the call
        // returned at 3 ms.
        tally.step_began(0, 0);
        tally.call_ended(0, Some(StepCall::Map), 3_000_000);
        assert!(!tally.timing(0));
        // A finalize step on that CPU later, from 4 to 6 ms, is its own.
        let ran = tally.timed_nested(0, StepCall::Finalize, clock(&[4, 6]), || true);
        assert!(ran);
        let lines = lines(&tally);
        assert_eq!(
            lines[3],
            "call-longest-us map=3000 unmap=0 protect=0 fill=0 commit=0 create=0 teardown=0 release=0 finalize=2000"
        );
        assert_eq!(
            lines[4],
            "call-steps map=1 unmap=0 protect=0 fill=0 commit=0 create=0 teardown=0 release=0 finalize=1"
        );
    }

    #[test]
    fn a_finalize_step_inside_a_timed_step_is_part_of_it() {
        let tally = StepTally::<2>::new();
        tally.step_began(0, 0);
        let ran = tally.timed_nested(0, StepCall::Finalize, clock(&[1, 2]), || 7);
        assert_eq!(ran, 7);
        tally.step_ended(0, StepCall::Commit, 5_000_000);
        assert_eq!(
            lines(&tally)[4],
            "call-steps map=0 unmap=0 protect=0 fill=0 commit=1 create=0 teardown=0 release=0 finalize=0"
        );
    }

    #[test]
    fn the_last_step_of_a_call_is_counted_and_timed() {
        let tally = StepTally::<2>::new();
        // Safe points at 0 and 2 ms each begin a step; the call returns
        // after the second at 7 ms.
        tally.step_began(1, 0);
        tally.step_ended(1, StepCall::Unmap, 2_000_000);
        tally.step_began(1, 2_000_000);
        tally.call_ended(1, Some(StepCall::Unmap), 7_000_000);
        assert!(!tally.timing(1));
        let lines = lines(&tally);
        assert_eq!(lines[0], "longest-step-us=5000 call=unmap");
        assert_eq!(
            lines[4],
            "call-steps map=0 unmap=2 protect=0 fill=0 commit=0 create=0 teardown=0 release=0 finalize=0"
        );
        assert_eq!(
            lines[5],
            "call-total-us map=0 unmap=7000 protect=0 fill=0 commit=0 create=0 teardown=0 release=0 finalize=0"
        );
    }

    #[test]
    fn a_parked_call_resumed_on_another_cpu_counts_each_step_once() {
        let tally = StepTally::<2>::new();
        // On CPU 0: a step from 0 to 3 ms, then the quantum expires at that
        // safe point, which ends the step and begins none; the call parks.
        tally.step_began(0, 0);
        tally.step_ended(0, StepCall::Map, 3_000_000);
        tally.call_ended(0, None, 3_000_000);
        // Resumed on CPU 1: its first safe point ends nothing and begins a
        // step at 10 ms; the call returns after it at 12 ms.
        tally.step_began(1, 10_000_000);
        tally.call_ended(1, Some(StepCall::Map), 12_000_000);
        assert!(!tally.timing(0) && !tally.timing(1));
        let lines = lines(&tally);
        assert_eq!(
            lines[4],
            "call-steps map=2 unmap=0 protect=0 fill=0 commit=0 create=0 teardown=0 release=0 finalize=0"
        );
        assert_eq!(
            lines[5],
            "call-total-us map=5000 unmap=0 protect=0 fill=0 commit=0 create=0 teardown=0 release=0 finalize=0"
        );
    }

    #[test]
    fn a_call_ended_before_any_step_records_nothing() {
        let tally = StepTally::<2>::new();
        tally.step_began(0, 0);
        tally.call_ended(0, None, 9_000_000);
        assert!(!tally.timing(0));
        assert_eq!(tally.longest(), None);
        // Ending a call on a CPU past the table changes nothing.
        tally.call_ended(7, Some(StepCall::Map), 1);
        assert_eq!(tally.longest(), None);
    }

    #[test]
    fn a_teardown_step_inside_another_call_s_step_records_both() {
        let tally = StepTally::<2>::new();
        // A commit's step began at a safe point at 0; inside its hold a
        // teardown step runs from 2 to 5 ms; the commit's next safe point
        // is at 9 ms.
        tally.step_began(0, 0);
        let ran = tally.timed(0, StepCall::Teardown, clock(&[2, 5]), || 3);
        assert_eq!(ran, 3);
        assert!(tally.timing(0), "the commit's step is still being timed");
        tally.step_ended(0, StepCall::Commit, 9_000_000);
        let lines = lines(&tally);
        assert_eq!(
            lines[3],
            "call-longest-us map=0 unmap=0 protect=0 fill=0 commit=9000 create=0 teardown=3000 release=0 finalize=0"
        );
        assert_eq!(
            lines[4],
            "call-steps map=0 unmap=0 protect=0 fill=0 commit=1 create=0 teardown=1 release=0 finalize=0"
        );
        // With nothing being timed, a teardown step leaves nothing open.
        tally.timed(1, StepCall::Teardown, clock(&[10, 11]), || ());
        assert!(!tally.timing(1));
    }

    #[test]
    fn wakes_for_owed_work_are_counted_sent_unsent_and_by_cause() {
        let tally = StepTally::<2>::new();
        tally.owed_wake(true, false, true);
        tally.owed_wake(false, true, true);
        tally.owed_wake(true, true, false);
        assert_eq!(
            finalize_lines(&tally, None)[5],
            "owed-wakes=2 unsent=1 queue=2 retirement=2"
        );
    }

    /// DW2 §12.11 part 2 item 11: the line keeps the most finalize steps
    /// any one hold ran, a later hold with fewer or none not lowering it.
    #[test]
    fn the_most_finalize_steps_in_one_hold_is_kept() {
        let tally = StepTally::<2>::new();
        let held = |tally: &StepTally<2>| finalize_lines(tally, None)[4].clone();
        assert_eq!(held(&tally), "finalize-steps-in-one-hold longest=0");
        tally.finalize_hold_ended(0);
        assert_eq!(held(&tally), "finalize-steps-in-one-hold longest=0");
        tally.finalize_hold_ended(1);
        assert_eq!(held(&tally), "finalize-steps-in-one-hold longest=1");
        tally.finalize_hold_ended(3);
        tally.finalize_hold_ended(1);
        tally.finalize_hold_ended(0);
        assert_eq!(held(&tally), "finalize-steps-in-one-hold longest=3");
    }

    #[test]
    fn stops_and_ended_parked_calls_are_counted_by_call() {
        let tally = StepTally::<2>::new();
        tally.stopped_between_steps(StepCall::Map);
        tally.stopped_between_steps(StepCall::Map);
        tally.stopped_between_steps(StepCall::Create);
        tally.parked_call_ended(StepCall::Commit);
        tally.parked_call_ended(StepCall::FillIn);
        let lines = lines(&tally);
        assert_eq!(
            lines[1],
            "stops-between-steps map=2 unmap=0 protect=0 fill=0 commit=0 create=1"
        );
        assert_eq!(
            lines[2],
            "parked-ended map=0 unmap=0 protect=0 fill=1 commit=1 create=0"
        );
    }

    /// A TSC rate of 1 GHz: one tick is one nanosecond.
    const GHZ: u64 = 1_000_000_000;

    fn measure_lines_at(tally: &StepTally<2>, tsc_hz: u64) -> Vec<String> {
        let mut out = Vec::new();
        tally.write_measure_lines(tsc_hz, |arguments| {
            out.push(std::fmt::format(arguments));
        });
        out
    }

    fn measure_lines(tally: &StepTally<2>) -> Vec<String> {
        measure_lines_at(tally, GHZ)
    }

    /// `us` microseconds in ticks at [`GHZ`].
    fn us(us: u64) -> u64 {
        us * 1000
    }

    /// One gate pass on `cpu` that runs the inner serve to `Served`, with
    /// its stamps in µs: entry, pass start, admit start and end, commit end,
    /// serve end, and the return's authorisation.
    fn served_fault(tally: &StepTally<2>, cpu: usize, stamps: [u64; 7]) {
        let [
            entry,
            began,
            admit_began,
            admit_ended,
            commit_ended,
            serve_ended,
            returned,
        ] = stamps.map(us);
        tally.fault_entered(cpu, entry);
        assert!(tally.fault_timing(cpu));
        tally.fault_pass_began(cpu, began);
        tally.fault_stamped(cpu, FaultStamp::AdmitBegan, admit_began);
        tally.fault_stamped(cpu, FaultStamp::AdmitEnded, admit_ended);
        tally.fault_stamped(cpu, FaultStamp::CommitEnded, commit_ended);
        tally.fault_stamped(cpu, FaultStamp::ServeEnded, serve_ended);
        tally.fault_pass(FaultPass::Served);
        tally.fault_returned(cpu, true, Some(returned));
        assert!(!tally.fault_timing(cpu));
    }

    #[test]
    fn nothing_measured_reports_zero_and_no_t_lock_line() {
        let tally = StepTally::<2>::new();
        assert_eq!(
            measure_lines(&tally),
            [
                "faults served=0 total-us=0 longest-us=0 sync-us=0 lookup-us=0 admit-us=0 commit-us=0 tables-us=0 return-us=0",
                "faults-fast served=0 total-us=0 longest-us=0 check-us=0 commit-us=0 tables-us=0 return-us=0",
                "faults-shared served=0 total-us=0 longest-us=0 check-us=0 tables-us=0 return-us=0",
                "fault-passes served=0 already-present=0 released=0 retry=0 unserved=0 exhausted=0 fill-in-serves=0 fast=0",
                "fault-windows opened=0 closed=0",
                "fault-ahead commits=0 frames=0 us=0",
                "streams started=0 ended=0",
                "fault-declines identity=0 mapping=0 tables=0 credit=0 memory=0 leaf=0 return=0",
                "fault-declines-shared not-committed=0",
                "commit-steps count=0 admit-us=0 take-us=0 rest-us=0",
            ]
        );
    }

    #[test]
    fn served_faults_sum_their_parts_and_keep_the_longest_total() {
        let tally = StepTally::<2>::new();
        // Total 100 µs: sync 10, lookup 5, admit 20, commit 40, tables 15,
        // return 10.
        served_fault(&tally, 0, [0, 10, 15, 35, 75, 90, 100]);
        // On the other CPU, total 30 µs: 1, 2, 3, 4, 5, 15.
        served_fault(&tally, 1, [1_000, 1_001, 1_003, 1_006, 1_010, 1_015, 1_030]);
        let lines = measure_lines(&tally);
        assert_eq!(
            lines[0],
            "faults served=2 total-us=130 longest-us=100 sync-us=11 lookup-us=7 admit-us=23 commit-us=44 tables-us=20 return-us=25"
        );
        assert_eq!(
            lines[3],
            "fault-passes served=2 already-present=0 released=0 retry=0 unserved=0 exhausted=0 fill-in-serves=0 fast=0"
        );
        // A shorter fault later keeps the longest.
        served_fault(&tally, 0, [2_000, 2_001, 2_002, 2_003, 2_004, 2_005, 2_006]);
        assert_eq!(
            measure_lines(&tally)[0],
            "faults served=3 total-us=136 longest-us=100 sync-us=12 lookup-us=8 admit-us=24 commit-us=45 tables-us=21 return-us=26"
        );
    }

    #[test]
    fn only_the_final_serving_pass_is_a_sample() {
        let tally = StepTally::<2>::new();
        tally.fault_entered(0, us(0));
        // A first pass stamps up to its admission and is refused: Retry.
        tally.fault_pass_began(0, us(5));
        tally.fault_stamped(0, FaultStamp::AdmitBegan, us(6));
        tally.fault_stamped(0, FaultStamp::AdmitEnded, us(7));
        tally.fault_pass(FaultPass::Retry);
        // A pass that never reached the inner serve: Retry again.
        tally.fault_pass(FaultPass::Retry);
        // The final pass serves.
        tally.fault_pass_began(0, us(50));
        tally.fault_stamped(0, FaultStamp::AdmitBegan, us(52));
        tally.fault_stamped(0, FaultStamp::AdmitEnded, us(55));
        tally.fault_stamped(0, FaultStamp::CommitEnded, us(60));
        tally.fault_stamped(0, FaultStamp::ServeEnded, us(70));
        tally.fault_pass(FaultPass::Served);
        tally.fault_returned(0, true, Some(us(80)));
        assert_eq!(
            measure_lines(&tally)[..4],
            [
                // The earlier passes are in the final pass's sync.
                "faults served=1 total-us=80 longest-us=80 sync-us=50 lookup-us=2 admit-us=3 commit-us=5 tables-us=10 return-us=10",
                "faults-fast served=0 total-us=0 longest-us=0 check-us=0 commit-us=0 tables-us=0 return-us=0",
                "faults-shared served=0 total-us=0 longest-us=0 check-us=0 tables-us=0 return-us=0",
                "fault-passes served=1 already-present=0 released=0 retry=2 unserved=0 exhausted=0 fill-in-serves=0 fast=0",
            ]
        );
    }

    #[test]
    fn a_pass_that_is_not_served_changes_only_the_pass_counts() {
        let tally = StepTally::<2>::new();
        // Each pass, and whether the gate returns after it (the others end
        // the process).
        for (pass, returns) in [
            (FaultPass::AlreadyPresent, true),
            (FaultPass::Released, true),
            (FaultPass::Unserved, false),
            (FaultPass::Exhausted, false),
        ] {
            tally.fault_entered(1, us(0));
            tally.fault_pass_began(1, us(1));
            tally.fault_stamped(1, FaultStamp::AdmitBegan, us(2));
            tally.fault_stamped(1, FaultStamp::AdmitEnded, us(3));
            tally.fault_stamped(1, FaultStamp::CommitEnded, us(4));
            tally.fault_pass(pass);
            if returns {
                tally.fault_returned(1, false, None);
            } else {
                tally.fault_untimed(1);
            }
            assert!(!tally.fault_timing(1));
        }
        tally.fill_in_served();
        tally.fill_in_served();
        let lines = measure_lines(&tally);
        assert_eq!(
            lines[0],
            "faults served=0 total-us=0 longest-us=0 sync-us=0 lookup-us=0 admit-us=0 commit-us=0 tables-us=0 return-us=0"
        );
        assert_eq!(
            lines[3],
            "fault-passes served=0 already-present=1 released=1 retry=0 unserved=1 exhausted=1 fill-in-serves=2 fast=0"
        );
    }

    #[test]
    fn a_served_fault_missing_a_stamp_is_no_sample() {
        let tally = StepTally::<2>::new();
        // A served pass with no gate entry (a fill-in's, say) is no sample.
        tally.fault_pass_began(0, us(1));
        tally.fault_pass(FaultPass::Served);
        tally.fault_returned(0, true, Some(us(9)));
        // A stamp the serving pass did not reach.
        tally.fault_entered(0, us(0));
        tally.fault_pass_began(0, us(1));
        tally.fault_stamped(0, FaultStamp::AdmitBegan, us(2));
        tally.fault_stamped(0, FaultStamp::CommitEnded, us(4));
        tally.fault_stamped(0, FaultStamp::ServeEnded, us(5));
        tally.fault_pass(FaultPass::Served);
        tally.fault_returned(0, true, Some(us(9)));
        // A stamp left by an earlier pass is cleared by the next pass.
        tally.fault_entered(0, us(0));
        tally.fault_pass_began(0, us(1));
        tally.fault_stamped(0, FaultStamp::AdmitBegan, us(2));
        tally.fault_stamped(0, FaultStamp::AdmitEnded, us(3));
        tally.fault_stamped(0, FaultStamp::CommitEnded, us(4));
        tally.fault_stamped(0, FaultStamp::ServeEnded, us(5));
        tally.fault_pass(FaultPass::Retry);
        tally.fault_pass_began(0, us(6));
        tally.fault_pass(FaultPass::Served);
        tally.fault_returned(0, true, Some(us(9)));
        // Only a whole pass is a sample.
        served_fault(&tally, 1, [0, 1, 2, 3, 4, 5, 6]);
        let lines = measure_lines(&tally);
        assert_eq!(
            lines[0],
            "faults served=1 total-us=6 longest-us=6 sync-us=1 lookup-us=1 admit-us=1 commit-us=1 tables-us=1 return-us=1"
        );
        // No stamp at the return.
        tally.fault_entered(1, us(0));
        tally.fault_pass_began(1, us(1));
        tally.fault_returned(1, true, None);
        assert_eq!(measure_lines(&tally)[0], lines[0]);
        // A CPU past the table is ignored.
        tally.fault_entered(5, us(0));
        assert!(!tally.fault_timing(5));
        tally.fault_returned(5, true, Some(us(1)));
        assert_eq!(measure_lines(&tally)[0], lines[0]);
    }

    #[test]
    fn t_lock_holds_are_kept_by_cpu_and_source_with_longest_values() {
        let tally = StepTally::<2>::new();
        // CPU 0 in a syscall: spun 3 µs, held 10; then spun 7, held 4.
        tally.t_lock_served(0, Some(us(0)), us(3));
        tally.t_lock_released(0, DrainSource::Syscall, us(13));
        tally.t_lock_served(0, Some(us(20)), us(27));
        tally.t_lock_released(0, DrainSource::Syscall, us(31));
        // Then served at once: counted, not waited, held 5.
        tally.t_lock_served(0, None, us(40));
        tally.t_lock_released(0, DrainSource::Syscall, us(45));
        // CPU 1 in a fault: spun for no measurable time, held 2.
        tally.t_lock_served(1, Some(us(5)), us(5));
        tally.t_lock_released(1, DrainSource::Fault, us(7));
        // CPU 0 idle, served at once: held 1.
        tally.t_lock_served(0, None, us(50));
        tally.t_lock_released(0, DrainSource::Idle, us(51));
        // A release with no hold stamped, and a CPU past the table.
        tally.t_lock_released(1, DrainSource::Gate, us(70));
        tally.t_lock_served(4, Some(us(0)), us(1));
        tally.t_lock_released(4, DrainSource::Gate, us(2));
        let lines = measure_lines(&tally);
        assert_eq!(
            lines[9..12],
            [
                "t-lock cpu=0 source=syscall count=3 waited=2 wait-us=10 wait-longest-us=7 held-us=19 held-longest-us=10",
                "t-lock cpu=0 source=idle count=1 waited=0 wait-us=0 wait-longest-us=0 held-us=1 held-longest-us=1",
                "t-lock cpu=1 source=fault count=1 waited=1 wait-us=0 wait-longest-us=0 held-us=2 held-longest-us=2",
            ]
        );
        assert!(lines[12].starts_with("commit-steps "));
    }

    #[test]
    fn ticks_are_converted_with_the_measured_rate_only_when_written() {
        let tally = StepTally::<2>::new();
        // At 3 GHz: a fault of 3,000,000 ticks is 1,000 µs.
        tally.fault_entered(0, 0);
        tally.fault_pass_began(0, 300_000);
        tally.fault_stamped(0, FaultStamp::AdmitBegan, 600_000);
        tally.fault_stamped(0, FaultStamp::AdmitEnded, 900_000);
        tally.fault_stamped(0, FaultStamp::CommitEnded, 1_500_000);
        tally.fault_stamped(0, FaultStamp::ServeEnded, 2_400_000);
        tally.fault_returned(0, true, Some(3_000_000));
        tally.t_lock_served(1, Some(0), 2_999);
        tally.t_lock_released(1, DrainSource::Gate, 2_999 + 6_000);
        tally.commit_step(0, 3_000, 6_000, 9_000, 12_000);
        assert_eq!(
            measure_lines_at(&tally, 3_000_000_000),
            [
                "faults served=1 total-us=1000 longest-us=1000 sync-us=100 lookup-us=100 admit-us=100 commit-us=200 tables-us=300 return-us=200",
                "faults-fast served=0 total-us=0 longest-us=0 check-us=0 commit-us=0 tables-us=0 return-us=0",
                "faults-shared served=0 total-us=0 longest-us=0 check-us=0 tables-us=0 return-us=0",
                "fault-passes served=0 already-present=0 released=0 retry=0 unserved=0 exhausted=0 fill-in-serves=0 fast=0",
                "fault-windows opened=0 closed=0",
                "fault-ahead commits=0 frames=0 us=0",
                "streams started=0 ended=0",
                "fault-declines identity=0 mapping=0 tables=0 credit=0 memory=0 leaf=0 return=0",
                "fault-declines-shared not-committed=0",
                // 2,999 ticks is under one microsecond: whole µs, rounded down.
                "t-lock cpu=1 source=gate count=1 waited=1 wait-us=0 wait-longest-us=0 held-us=2 held-longest-us=2",
                "commit-steps count=1 admit-us=1 take-us=1 rest-us=2",
            ]
        );
        // With no rate measured the times are zero and the counts remain.
        assert_eq!(
            measure_lines_at(&tally, 0),
            [
                "faults served=1 total-us=0 longest-us=0 sync-us=0 lookup-us=0 admit-us=0 commit-us=0 tables-us=0 return-us=0",
                "faults-fast served=0 total-us=0 longest-us=0 check-us=0 commit-us=0 tables-us=0 return-us=0",
                "faults-shared served=0 total-us=0 longest-us=0 check-us=0 tables-us=0 return-us=0",
                "fault-passes served=0 already-present=0 released=0 retry=0 unserved=0 exhausted=0 fill-in-serves=0 fast=0",
                "fault-windows opened=0 closed=0",
                "fault-ahead commits=0 frames=0 us=0",
                "streams started=0 ended=0",
                "fault-declines identity=0 mapping=0 tables=0 credit=0 memory=0 leaf=0 return=0",
                "fault-declines-shared not-committed=0",
                "t-lock cpu=1 source=gate count=1 waited=1 wait-us=0 wait-longest-us=0 held-us=0 held-longest-us=0",
                "commit-steps count=1 admit-us=0 take-us=0 rest-us=0",
            ]
        );
    }

    #[test]
    fn a_tick_count_past_a_naive_product_converts_exactly() {
        // `u64::MAX * 1_000_000` overflows 64 bits; 128-bit does not.
        assert_eq!(ticks_to_us(u64::MAX, 1_000_000), u64::MAX);
        assert_eq!(ticks_to_us(u64::MAX, 2_000_000), u64::MAX / 2);
        // 2^60 ticks at 3 GHz: 384,307,168,202,282 µs (truncated).
        assert_eq!(ticks_to_us(1 << 60, 3_000_000_000), 384_307_168_202_282);
        // A rate below 1 MHz yields more µs than ticks; past u64 it clamps.
        assert_eq!(ticks_to_us(u64::MAX, 1), u64::MAX);
        assert_eq!(ticks_to_us(5, 0), 0);
        let tally = StepTally::<2>::new();
        tally.fault_total.store(u64::MAX, Ordering::Relaxed);
        assert!(measure_lines_at(&tally, 4_000_000_000)[0].contains(" total-us=4611686018427387 "));
    }

    #[test]
    fn commit_steps_split_into_admission_take_and_rest() {
        let tally = StepTally::<2>::new();
        // Began at 0, admitted 10 to 30, took until 530, ended at 540 (µs).
        tally.commit_step(0, us(10), us(30), us(530), us(540));
        tally.commit_step(us(1_000), us(1_001), us(1_002), us(1_102), us(1_105));
        assert_eq!(
            measure_lines(&tally)[9],
            "commit-steps count=2 admit-us=21 take-us=600 rest-us=24"
        );
    }

    #[test]
    fn measure_lines_stay_under_a_records_message_limit() {
        let tally = StepTally::<2>::new();
        let big = 9_999_999_999_000; // ten digits of microseconds at 1 GHz
        let many = 9_999_999_999;
        for slot in [
            &tally.faults_served,
            &tally.fill_in_serves,
            &tally.commit_steps,
        ]
        .into_iter()
        .chain(&tally.fault_passes)
        {
            slot.store(many, Ordering::Relaxed);
        }
        for slot in [&tally.fault_total, &tally.fault_longest]
            .into_iter()
            .chain(&tally.fault_parts)
            .chain([&tally.commit_admit, &tally.commit_take, &tally.commit_rest])
        {
            slot.store(big, Ordering::Relaxed);
        }
        let [count, waited, times @ ..] = &tally.t_lock[1][DrainSource::Syscall as usize];
        count.store(many, Ordering::Relaxed);
        waited.store(many, Ordering::Relaxed);
        for slot in times {
            slot.store(big, Ordering::Relaxed);
        }
        let lines = measure_lines(&tally);
        assert_eq!(lines.len(), 11);
        for line in &lines {
            assert!(line.len() < 190, "{} bytes: {line}", line.len());
        }
    }

    /// The whole report written by `tally`, and how many lines were written
    /// when the closing lines' values were read.
    fn report(tally: &StepTally<2>) -> (Vec<String>, usize) {
        let mut out: Vec<String> = Vec::new();
        let written = core::cell::Cell::new(0);
        let mut before_closing = 0;
        tally.write_report(
            None,
            GHZ,
            || {
                before_closing = written.get();
                ((2, 3), 0)
            },
            |arguments| {
                written.set(written.get() + 1);
                out.push(std::fmt::format(arguments));
            },
        );
        (out, before_closing)
    }

    /// The whole report, in order: the measurement's lines come after the
    /// finalization lines and the closing lines are still last, with their
    /// values read after every line before them. With no usage check
    /// recorded there is no `usage-check` line at all.
    #[test]
    fn the_report_ends_with_the_closing_lines_after_the_measurement() {
        let tally = StepTally::<2>::new();
        tally.t_lock_served(1, Some(0), 1_000);
        tally.t_lock_released(1, DrainSource::Gate, 3_000);
        let (out, before_closing) = report(&tally);
        // Every line before the closing lines is written by then.
        assert_eq!(before_closing, 9 + 6 + 11 + 1);
        assert_eq!(out.len(), 9 + 6 + 11 + 1 + 2);
        assert_eq!(out[8], "backing-alloc-longest-us=0 runs=0 pages=0");
        assert_eq!(out[14], "owed-wakes=0 unsent=0 queue=0 retirement=0");
        assert!(out[15].starts_with("faults served="));
        assert!(out[16].starts_with("faults-fast served="));
        assert!(out[17].starts_with("faults-shared served="));
        assert!(out[18].starts_with("fault-passes "));
        assert!(out[19].starts_with("fault-windows "));
        assert!(out[20].starts_with("fault-ahead "));
        assert!(out[21].starts_with("streams "));
        assert!(out[22].starts_with("fault-declines "));
        assert!(out[23].starts_with("fault-declines-shared "));
        assert_eq!(
            out[24],
            "t-lock cpu=1 source=gate count=1 waited=1 wait-us=1 wait-longest-us=1 held-us=2 held-longest-us=2"
        );
        assert!(out[25].starts_with("commit-steps "));
        assert_eq!(out[26], "admission-waits create=0 commit=0 fault=0");
        assert_eq!(
            out[27..],
            ["timer-arm retries=2 deferred=3", "records-dropped=0"]
        );
        assert!(!out.iter().any(|line| line.starts_with("usage-check")));
    }

    /// DW2 §13.12 part b: the admission waits are counted by kind and
    /// written after the measurement's lines, before the usage check.
    #[test]
    fn admission_waits_are_counted_by_kind_before_the_usage_check() {
        let tally = StepTally::<2>::new();
        tally.admission_waited(AdmissionWait::Create);
        for _ in 0..3 {
            tally.admission_waited(AdmissionWait::Commit);
        }
        for _ in 0..2 {
            tally.admission_waited(AdmissionWait::Fault);
        }
        tally.usage_checked(1, 0);
        let (out, _) = report(&tally);
        assert!(out[24].starts_with("commit-steps "));
        assert_eq!(out[25], "admission-waits create=1 commit=3 fault=2");
        assert_eq!(out[26], "usage-check groups=1 mismatches=0");
        assert_eq!(
            out[27..],
            ["timer-arm retries=2 deferred=3", "records-dropped=0"]
        );
    }

    /// DW2 §13.12 part a: the power-off hold's usage check is printed after
    /// the measurement and before the closing lines, last record kept, its
    /// counts clamped to their fields; zeros recorded still print.
    #[test]
    fn a_recorded_usage_check_is_written_before_the_closing_lines() {
        let tally = StepTally::<2>::new();
        tally.usage_checked(0, 0);
        let (out, before_closing) = report(&tally);
        assert_eq!(before_closing, 9 + 6 + 10 + 1 + 1);
        assert_eq!(
            out[24],
            "commit-steps count=0 admit-us=0 take-us=0 rest-us=0"
        );
        assert_eq!(out[25], "admission-waits create=0 commit=0 fault=0");
        assert_eq!(out[26], "usage-check groups=0 mismatches=0");
        assert_eq!(
            out[27..],
            ["timer-arm retries=2 deferred=3", "records-dropped=0"]
        );

        tally.usage_checked(12, 3);
        assert_eq!(report(&tally).0[26], "usage-check groups=12 mismatches=3");
        tally.usage_checked(usize::MAX, usize::MAX);
        assert_eq!(
            report(&tally).0[26],
            "usage-check groups=2147483647 mismatches=2147483647"
        );
    }

    /// DW2 §13.4 item 1: the report ends with the dropped-records count, after
    /// the timer's arm counts, so a check can require `records-dropped=0`.
    #[test]
    fn the_report_ends_with_the_dropped_records_count() {
        let closing = |records_dropped| {
            let mut out = Vec::new();
            write_closing_lines((4, 1), records_dropped, |arguments| {
                out.push(std::fmt::format(arguments));
            });
            out
        };
        assert_eq!(
            closing(0),
            ["timer-arm retries=4 deferred=1", "records-dropped=0"]
        );
        assert_eq!(closing(17).last().unwrap(), "records-dropped=17");
    }

    /// The count the live report prints is the output gate's own: a record
    /// the gate refuses raises it.
    #[test]
    fn the_report_prints_the_output_gates_count() {
        let _output = crate::debug::lock_output_for_test();
        let before = crate::debug::records_dropped();
        crate::debug::drop_one_record_for_test();
        let mut last = String::new();
        write_closing_lines((0, 0), crate::debug::records_dropped(), |arguments| {
            last = std::fmt::format(arguments);
        });
        assert_eq!(last, std::format!("records-dropped={}", before + 1));
    }

    /// DW2 §13.16 part e3: a fault whose last pass the fast serve answered
    /// is a `faults-fast` sample (check from the gate's entry, commit,
    /// tables, return), not a `faults` one; the pass is counted by its
    /// outcome and as `fast`.
    #[test]
    fn a_fast_served_fault_is_a_faults_fast_sample() {
        let tally = StepTally::<2>::new();
        tally.fault_entered(0, us(0));
        tally.fast_stamped(0, FastFaultStamp::Checked, us(4));
        tally.fast_stamped(0, FastFaultStamp::Committed, us(6));
        tally.fast_stamped(0, FastFaultStamp::Written, us(9));
        tally.fault_pass(FaultPass::Served);
        tally.fault_pass_fast();
        tally.fault_returned_fast(0, true, Some(us(10)));
        // A slow pass's stamps left before it are no sample of either.
        tally.fault_entered(1, us(100));
        tally.fault_pass_began(1, us(101));
        tally.fast_stamped(1, FastFaultStamp::Checked, us(102));
        tally.fault_pass(FaultPass::AlreadyPresent);
        tally.fault_pass_fast();
        tally.fault_returned_fast(1, false, None);
        // A second fast sample, shorter: the longest is kept.
        tally.fault_entered(1, us(200));
        tally.fast_stamped(1, FastFaultStamp::Checked, us(201));
        tally.fast_stamped(1, FastFaultStamp::Committed, us(202));
        tally.fast_stamped(1, FastFaultStamp::Written, us(203));
        tally.fault_pass(FaultPass::Served);
        tally.fault_pass_fast();
        tally.fault_returned_fast(1, true, Some(us(204)));
        let lines = measure_lines(&tally);
        assert!(lines[0].starts_with("faults served=0 "));
        assert_eq!(
            lines[1],
            "faults-fast served=2 total-us=14 longest-us=10 check-us=5 commit-us=3 tables-us=4 return-us=2"
        );
        assert_eq!(
            lines[3],
            "fault-passes served=2 already-present=1 released=0 retry=0 unserved=0 exhausted=0 fill-in-serves=0 fast=3"
        );
        // A fast serve missing a stamp, or after the slow serve answered, is
        // no fast sample; the slow serve's return clears fast stamps.
        tally.fault_entered(0, us(300));
        tally.fast_stamped(0, FastFaultStamp::Checked, us(301));
        tally.fault_returned_fast(0, true, Some(us(302)));
        tally.fault_entered(0, us(400));
        tally.fast_stamped(0, FastFaultStamp::Checked, us(401));
        tally.fast_stamped(0, FastFaultStamp::Committed, us(402));
        tally.fast_stamped(0, FastFaultStamp::Written, us(403));
        tally.fault_returned(0, false, None);
        tally.fault_entered(0, us(500));
        tally.fault_returned_fast(0, true, Some(us(501)));
        assert_eq!(measure_lines(&tally)[1], lines[1]);
    }

    /// DW2 §13.16 part e3: windows opened and closed, and each decline by
    /// its step.
    #[test]
    fn fault_windows_count_opens_closes_and_declines_by_step() {
        let tally = StepTally::<2>::new();
        tally.windows_changed(3, 1);
        tally.windows_changed(0, 2);
        for (decline, times) in [
            (WindowDecline::Identity, 7),
            (WindowDecline::Mapping, 1),
            (WindowDecline::Tables, 2),
            (WindowDecline::Credit, 3),
            (WindowDecline::Memory, 4),
            (WindowDecline::Leaf, 5),
            (WindowDecline::Return, 6),
            (WindowDecline::NotCommitted, 8),
        ] {
            for _ in 0..times {
                tally.window_declined(decline);
            }
        }
        let lines = measure_lines(&tally);
        assert_eq!(lines[4], "fault-windows opened=3 closed=3");
        assert_eq!(
            lines[7],
            "fault-declines identity=7 mapping=1 tables=2 credit=3 memory=4 leaf=5 return=6"
        );
        assert_eq!(lines[8], "fault-declines-shared not-committed=8");
    }

    /// DW2 §15.6: commits ahead (their frames and time) and streams
    /// started and ended, each in its own line after `fault-windows`.
    #[test]
    fn commits_ahead_and_streams_are_counted_after_the_fault_windows() {
        let tally = StepTally::<2>::new();
        tally.fault_ahead(64, us(11));
        tally.fault_ahead(20, us(4));
        tally.fault_ahead(0, 0);
        tally.streams_changed(2, 0);
        tally.streams_changed(0, 1);
        let lines = measure_lines(&tally);
        assert!(lines[4].starts_with("fault-windows "));
        assert_eq!(lines[5], "fault-ahead commits=3 frames=84 us=15");
        assert_eq!(lines[6], "streams started=2 ended=1");
        assert!(lines[7].starts_with("fault-declines "));
    }

    /// DW2 §13.16 part e3: P is reported per CPU and source as T is, a line
    /// only for a nonzero count, after T's lines.
    #[test]
    fn p_lock_holds_are_kept_by_cpu_and_source() {
        let tally = StepTally::<2>::new();
        // CPU 1's fast serves: one spun 3 µs and held 2, one held 1.
        tally.p_lock_released(1, 0, Some(us(3)), us(2));
        tally.p_lock_released(1, 0, None, us(1));
        // CPU 0's runtime hold, and a usercopy on CPU 1.
        tally.p_lock_released(0, 2, None, us(5));
        tally.p_lock_released(1, 1, Some(0), us(4));
        // CPU 0's shared fast serve.
        tally.p_lock_released(0, 3, Some(us(2)), us(1));
        // A CPU past the table, and a source past the names.
        tally.p_lock_released(4, 0, None, us(1));
        tally.p_lock_released(0, 4, None, us(1));
        tally.t_lock_served(0, None, us(0));
        tally.t_lock_released(0, DrainSource::Fault, us(1));
        let lines = measure_lines(&tally);
        assert_eq!(
            lines[9..14],
            [
                "t-lock cpu=0 source=fault count=1 waited=0 wait-us=0 wait-longest-us=0 held-us=1 held-longest-us=1",
                "p-lock cpu=0 source=runtime count=1 waited=0 wait-us=0 held-us=5",
                "p-lock cpu=0 source=fault-shared count=1 waited=1 wait-us=2 held-us=1",
                "p-lock cpu=1 source=fault count=2 waited=1 wait-us=3 held-us=3",
                "p-lock cpu=1 source=usercopy count=1 waited=1 wait-us=0 held-us=4",
            ]
        );
        assert!(lines[14].starts_with("commit-steps "));
    }

    /// The fault-window lines and the shared serve's two lines (DW2
    /// §15.2), every value at 17 digits, as the report writes them, fit a
    /// diagnostic record's 192 bytes; that bound is enough because a count
    /// cannot reach 10^17 in a boot (at one a nanosecond that is about
    /// three years), and if a field is ever added it is the format that
    /// must change, not this test.
    #[test]
    fn the_fault_window_lines_fit_a_record_up_to_seventeen_digit_counts() {
        const LARGEST: u64 = 99_999_999_999_999_999;
        let tally = StepTally::<2>::new();
        for slot in [
            &tally.windows_opened,
            &tally.windows_closed,
            &tally.faults_shared,
            &tally.fault_shared_total,
            &tally.fault_shared_longest,
            &tally.ahead_commits,
            &tally.ahead_frames,
            &tally.ahead_ticks,
            &tally.streams_started,
            &tally.streams_ended,
        ]
        .into_iter()
        .chain(&tally.window_declines)
        .chain(&tally.fault_shared_parts)
        {
            slot.store(LARGEST, Ordering::Relaxed);
        }
        // At 1 MHz a tick is a microsecond, so the times print as stored.
        let lines = measure_lines_at(&tally, 1_000_000);
        let find = |prefix: &str| {
            lines
                .iter()
                .find(|line| line.starts_with(prefix))
                .unwrap()
                .clone()
        };
        let windows = find("fault-windows ");
        let declines = find("fault-declines ");
        let shared = find("faults-shared ");
        let shared_declines = find("fault-declines-shared ");
        let ahead = find("fault-ahead ");
        let streams = find("streams ");
        assert_eq!(
            ahead,
            std::format!("fault-ahead commits={LARGEST} frames={LARGEST} us={LARGEST}")
        );
        assert_eq!(
            streams,
            std::format!("streams started={LARGEST} ended={LARGEST}")
        );
        assert!(windows.ends_with(&std::format!("closed={LARGEST}")));
        assert!(declines.ends_with(&std::format!("return={LARGEST}")));
        assert_eq!(
            shared,
            std::format!(
                "faults-shared served={LARGEST} total-us={LARGEST} longest-us={LARGEST} check-us={LARGEST} tables-us={LARGEST} return-us={LARGEST}"
            )
        );
        assert_eq!(
            shared_declines,
            std::format!("fault-declines-shared not-committed={LARGEST}")
        );
        for line in [windows, declines, shared, shared_declines, ahead, streams] {
            assert!(line.len() <= 192, "{} bytes: {line}", line.len());
        }
    }

    /// DW2 §15.2: a fault whose last pass the shared serve answered is a
    /// `faults-shared` sample (check from the gate's entry; tables from the
    /// end of the checks through the walk, the resolve and the leaf; and
    /// return), not a `faults-fast` one; the pass is counted as `fast`. The
    /// mark is the fault's own: the next fault on that CPU, answered by the
    /// exclusive serve, is a `faults-fast` sample.
    #[test]
    fn a_shared_served_fault_is_a_faults_shared_sample() {
        let tally = StepTally::<2>::new();
        tally.fault_entered(1, us(0));
        tally.fast_stamped(1, FastFaultStamp::Checked, us(3));
        tally.fast_stamped(1, FastFaultStamp::Committed, us(4));
        tally.fast_stamped(1, FastFaultStamp::Written, us(7));
        tally.fast_served_shared(1);
        tally.fault_pass(FaultPass::Served);
        tally.fault_pass_fast();
        tally.fault_returned_fast(1, true, Some(us(9)));
        // A shared serve's already-present pass is no sample.
        tally.fault_entered(1, us(10));
        tally.fast_stamped(1, FastFaultStamp::Checked, us(11));
        tally.fast_stamped(1, FastFaultStamp::Committed, us(12));
        tally.fast_stamped(1, FastFaultStamp::Written, us(13));
        tally.fast_served_shared(1);
        tally.fault_pass(FaultPass::AlreadyPresent);
        tally.fault_pass_fast();
        tally.fault_returned_fast(1, false, None);
        // The next fault there is the exclusive serve's.
        tally.fault_entered(1, us(100));
        tally.fast_stamped(1, FastFaultStamp::Checked, us(101));
        tally.fast_stamped(1, FastFaultStamp::Committed, us(103));
        tally.fast_stamped(1, FastFaultStamp::Written, us(104));
        tally.fault_pass(FaultPass::Served);
        tally.fault_pass_fast();
        tally.fault_returned_fast(1, true, Some(us(105)));
        // A mark left by a fault that did not return is cleared at the
        // next entry.
        tally.fast_served_shared(0);
        tally.fault_untimed(0);
        tally.fault_entered(0, us(200));
        tally.fast_stamped(0, FastFaultStamp::Checked, us(201));
        tally.fast_stamped(0, FastFaultStamp::Committed, us(202));
        tally.fast_stamped(0, FastFaultStamp::Written, us(203));
        tally.fault_pass(FaultPass::Served);
        tally.fault_pass_fast();
        tally.fault_returned_fast(0, true, Some(us(204)));
        let lines = measure_lines(&tally);
        assert_eq!(
            lines[1],
            "faults-fast served=2 total-us=9 longest-us=5 check-us=2 commit-us=3 tables-us=2 return-us=2"
        );
        assert_eq!(
            lines[2],
            "faults-shared served=1 total-us=9 longest-us=9 check-us=3 tables-us=4 return-us=2"
        );
        assert_eq!(
            lines[3],
            "fault-passes served=3 already-present=1 released=0 retry=0 unserved=0 exhausted=0 fill-in-serves=0 fast=4"
        );
    }
}
