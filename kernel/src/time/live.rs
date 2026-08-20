//! Target-only ACPI-PM/LAPIC implementation of the F3 monotonic service.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::arch::x86_64::apic::{ApicMode, LocalApic};
use crate::arch::x86_64::apic_live::{
    LiveApicBaseMsr, LiveXApicMmio, discover_local_apic, lapic_pat_entry_is_uncacheable,
};
use crate::arch::x86_64::mm::{ActiveDeepPaging, FrameAddress, LiveActivePagingTarget};
use crate::interrupt::LocalApicVectors;
use crate::sync::IrqSpinMutex;
use crate::task::BlockWakeKey;

use super::{
    DEADLINE_QUEUE_CAPACITY, DeadlineQueue, DeadlineRegistration, MonotonicSample,
    PmTimerDescriptor, PmTimerState, apic_one_shot_for_delta,
};

const UNINITIALIZED: u8 = 0;
const INITIALIZING: u8 = 1;
const INITIALIZED: u8 = 2;
const CALIBRATION_NANOSECONDS: u64 = 10_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveTimeError {
    AlreadyInitialized,
    AcpiTimerDidNotAdvance,
    ApicDiscovery,
    ApicMode,
    ApicMapping,
    ApicAccess,
    Calibration,
    Clock,
    Deadline,
    NoWakeRuntime,
}

#[must_use = "a failed deadline registration returns the exact scheduler wake key to its owner"]
#[derive(Debug)]
pub(crate) struct DeadlineRegistrationFailure {
    error: LiveTimeError,
    wake: BlockWakeKey,
}

impl DeadlineRegistrationFailure {
    pub(crate) const fn error(&self) -> LiveTimeError {
        self.error
    }

    pub(crate) fn into_parts(self) -> (LiveTimeError, BlockWakeKey) {
        (self.error, self.wake)
    }
}

fn registration_failure(error: LiveTimeError, wake: BlockWakeKey) -> DeadlineRegistrationFailure {
    DeadlineRegistrationFailure { error, wake }
}

pub(crate) trait DeadlineWakeTarget: Sync {
    fn wake_deadline(&self, key: BlockWakeKey);
}

#[derive(Clone, Copy)]
struct WakeBinding {
    context: *const (),
    handler: unsafe fn(*const (), BlockWakeKey),
}

struct WakeStorage(UnsafeCell<MaybeUninit<WakeBinding>>);

impl WakeStorage {
    const fn new() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }
}

#[allow(
    unsafe_code,
    reason = "one-shot F3 wake-target publication stores an immutable static shared target before timer interrupts are enabled"
)]
unsafe impl Sync for WakeStorage {}

static WAKE_STATE: AtomicU8 = AtomicU8::new(UNINITIALIZED);
static WAKE_STORAGE: WakeStorage = WakeStorage::new();

#[allow(
    unsafe_code,
    reason = "the binding requires a 'static Sync target and erases it together with its monomorphized shared-reference trampoline"
)]
pub(crate) fn bind_deadline_wake_target<W: DeadlineWakeTarget + 'static>(
    target: &'static W,
) -> Result<(), LiveTimeError> {
    if WAKE_STATE
        .compare_exchange(
            UNINITIALIZED,
            INITIALIZING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return Err(LiveTimeError::AlreadyInitialized);
    }
    unsafe {
        (*WAKE_STORAGE.0.get()).write(WakeBinding {
            context: core::ptr::from_ref(target).cast::<()>(),
            handler: wake_trampoline::<W>,
        });
    }
    WAKE_STATE.store(INITIALIZED, Ordering::Release);
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "the stored context originated from the matching static typed wake-target reference"
)]
unsafe fn wake_trampoline<W: DeadlineWakeTarget>(context: *const (), key: BlockWakeKey) {
    let target = unsafe { &*context.cast::<W>() };
    target.wake_deadline(key);
}

fn wake_binding() -> Option<WakeBinding> {
    if WAKE_STATE.load(Ordering::Acquire) != INITIALIZED {
        return None;
    }
    #[allow(
        unsafe_code,
        reason = "Acquire observes the immutable wake binding published before INITIALIZED"
    )]
    Some(unsafe { (*WAKE_STORAGE.0.get()).assume_init() })
}

#[derive(Clone, Copy)]
struct InterruptOutcome {
    wakes: [Option<BlockWakeKey>; DEADLINE_QUEUE_CAPACITY],
    wake_count: usize,
}

struct LiveTimeState {
    pm: PmTimerState,
    apic: LocalApic,
    registers: LiveXApicMmio,
    apic_timer_hz: u64,
    deadlines: DeadlineQueue,
    last_sample: MonotonicSample,
}

impl LiveTimeState {
    fn sample_now(&mut self) -> Result<MonotonicSample, LiveTimeError> {
        let raw = read_pm_timer(self.pm.descriptor());
        let sample = self.pm.sample(raw).map_err(|_| LiveTimeError::Clock)?;
        self.last_sample = sample;
        Ok(sample)
    }

    fn next_deadline(&self, sample: MonotonicSample) -> u64 {
        self.deadlines
            .earliest()
            .map_or(sample.maintenance_deadline, |user| {
                user.min(sample.maintenance_deadline)
            })
    }

    fn reprogram(&mut self, sample: MonotonicSample) -> Result<(), LiveTimeError> {
        let next = self.next_deadline(sample);
        let delta = next.saturating_sub(sample.nanoseconds);
        let shot = apic_one_shot_for_delta(delta, self.apic_timer_hz)
            .map_err(|_| LiveTimeError::Deadline)?;
        self.apic
            .program_one_shot_timer(&mut self.registers, shot.initial_count)
            .map_err(|_| LiveTimeError::ApicAccess)
    }

    fn interrupt(&mut self) -> Result<InterruptOutcome, LiveTimeError> {
        let sample = self.sample_now()?;
        let mut wakes = [None; DEADLINE_QUEUE_CAPACITY];
        let wake_count = self.deadlines.expire(sample.nanoseconds, &mut wakes);
        self.reprogram(sample)?;
        self.apic
            .end_of_interrupt(&mut self.registers)
            .map_err(|_| LiveTimeError::ApicAccess)?;
        Ok(InterruptOutcome { wakes, wake_count })
    }

    fn register_deadline(
        &mut self,
        deadline_ns: u64,
        wake: BlockWakeKey,
    ) -> Result<DeadlineRegistration, DeadlineRegistrationFailure> {
        let sample = self
            .sample_now()
            .map_err(|error| registration_failure(error, wake))?;
        if deadline_ns <= sample.nanoseconds {
            return Err(registration_failure(LiveTimeError::Deadline, wake));
        }
        let registration = self
            .deadlines
            .register(deadline_ns, wake)
            .map_err(|_| registration_failure(LiveTimeError::Deadline, wake))?;
        if self.reprogram(sample).is_err() {
            let recovered = self
                .deadlines
                .cancel(registration)
                .expect("fresh deadline registration remains cancellable before publication");
            return Err(registration_failure(LiveTimeError::ApicAccess, recovered));
        }
        Ok(registration)
    }
}

struct TimeStorage(UnsafeCell<MaybeUninit<IrqSpinMutex<LiveTimeState>>>);

impl TimeStorage {
    const fn new() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }
}

#[allow(
    unsafe_code,
    reason = "the one-shot F3 initializer publishes one stationary IRQ-safe state object before interrupts can consume it"
)]
unsafe impl Sync for TimeStorage {}

static TIME_STATE: AtomicU8 = AtomicU8::new(UNINITIALIZED);
static TIME_STORAGE: TimeStorage = TimeStorage::new();

fn live_state() -> Option<&'static IrqSpinMutex<LiveTimeState>> {
    if TIME_STATE.load(Ordering::Acquire) != INITIALIZED {
        return None;
    }
    #[allow(
        unsafe_code,
        reason = "Acquire observes the fully initialized stationary F3 time service"
    )]
    Some(unsafe { &*(*TIME_STORAGE.0.get()).as_ptr() })
}

pub(crate) fn initialize<'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    active: &mut ActiveDeepPaging<LiveActivePagingTarget<'root, RANGE_CAPACITY, ROLE_CAPACITY>>,
    pm_descriptor: PmTimerDescriptor,
) -> Result<(), LiveTimeError> {
    if TIME_STATE
        .compare_exchange(
            UNINITIALIZED,
            INITIALIZING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return Err(LiveTimeError::AlreadyInitialized);
    }
    let result = initialize_inner(active, pm_descriptor);
    if result.is_err() {
        TIME_STATE.store(UNINITIALIZED, Ordering::Release);
    }
    result
}

fn publish(state: LiveTimeState) {
    #[allow(
        unsafe_code,
        reason = "the successful one-shot initializer has exclusive publication ownership"
    )]
    unsafe {
        (*TIME_STORAGE.0.get()).write(IrqSpinMutex::new(state));
    }
    TIME_STATE.store(INITIALIZED, Ordering::Release);
}

fn initialize_inner<'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    active: &mut ActiveDeepPaging<LiveActivePagingTarget<'root, RANGE_CAPACITY, ROLE_CAPACITY>>,
    pm_descriptor: PmTimerDescriptor,
) -> Result<(), LiveTimeError> {
    let discovery = discover_local_apic().map_err(|_| LiveTimeError::ApicDiscovery)?;
    if discovery.mode() == ApicMode::X2Apic {
        return Err(LiveTimeError::ApicMode);
    }
    if !lapic_pat_entry_is_uncacheable() {
        return Err(LiveTimeError::ApicMapping);
    }
    let frame = FrameAddress::new(discovery.physical_base(), active.root().physical_limit())
        .map_err(|_| LiveTimeError::ApicMapping)?;
    let virtual_base = active
        .install_kernel_mmio_page(frame)
        .map_err(|_| LiveTimeError::ApicMapping)?;
    let mut apic = LocalApic::discovered(discovery, LocalApicVectors::DW0);
    if discovery.mode() == ApicMode::Disabled {
        apic.enable_xapic(&mut LiveApicBaseMsr)
            .map_err(|_| LiveTimeError::ApicAccess)?;
    }
    let mut registers = LiveXApicMmio::new(virtual_base).map_err(|_| LiveTimeError::ApicMapping)?;
    apic.prepare(&mut registers)
        .map_err(|_| LiveTimeError::ApicAccess)?;
    apic.bring_online(&mut registers)
        .map_err(|_| LiveTimeError::ApicAccess)?;
    apic.configure_one_shot_timer(&mut registers)
        .map_err(|_| LiveTimeError::ApicAccess)?;

    let initial_raw = read_pm_timer(pm_descriptor);
    let mut pm = PmTimerState::new(pm_descriptor, initial_raw);
    let initial_sample = pm.sample(initial_raw).map_err(|_| LiveTimeError::Clock)?;
    let apic_timer_hz = calibrate_apic_timer(&mut apic, &mut registers, &mut pm)?;
    let final_sample = pm
        .sample(read_pm_timer(pm_descriptor))
        .map_err(|_| LiveTimeError::Clock)?;
    if final_sample.nanoseconds <= initial_sample.nanoseconds {
        return Err(LiveTimeError::AcpiTimerDidNotAdvance);
    }
    let mut state = LiveTimeState {
        pm,
        apic,
        registers,
        apic_timer_hz,
        deadlines: DeadlineQueue::new(),
        last_sample: final_sample,
    };
    state.reprogram(final_sample)?;
    publish(state);
    Ok(())
}

fn calibrate_apic_timer(
    apic: &mut LocalApic,
    registers: &mut LiveXApicMmio,
    pm: &mut PmTimerState,
) -> Result<u64, LiveTimeError> {
    apic.start_timer_calibration(registers, u32::MAX)
        .map_err(|_| LiveTimeError::ApicAccess)?;
    let start = pm
        .sample(read_pm_timer(pm.descriptor()))
        .map_err(|_| LiveTimeError::Clock)?;

    let mut end = None;
    for _ in 0..10_000_000_u32 {
        let sample = pm
            .sample(read_pm_timer(pm.descriptor()))
            .map_err(|_| LiveTimeError::Clock)?;
        if sample.nanoseconds.saturating_sub(start.nanoseconds) >= CALIBRATION_NANOSECONDS {
            end = Some(sample);
            break;
        }
        core::hint::spin_loop();
    }
    let end = end.ok_or(LiveTimeError::AcpiTimerDidNotAdvance)?;
    let current = apic
        .timer_current_count(registers)
        .map_err(|_| LiveTimeError::ApicAccess)?;
    apic.stop_timer(registers)
        .map_err(|_| LiveTimeError::ApicAccess)?;
    let elapsed_counts = u64::from(u32::MAX - current);
    let elapsed_ns = end.nanoseconds.saturating_sub(start.nanoseconds);
    if elapsed_counts == 0 || elapsed_ns == 0 {
        return Err(LiveTimeError::Calibration);
    }
    let frequency = u128::from(elapsed_counts)
        .checked_mul(1_000_000_000)
        .ok_or(LiveTimeError::Calibration)?
        / u128::from(elapsed_ns);
    let frequency = u64::try_from(frequency).map_err(|_| LiveTimeError::Calibration)?;
    if !(1_000..=10_000_000_000).contains(&frequency) {
        return Err(LiveTimeError::Calibration);
    }
    Ok(frequency)
}

pub(crate) fn monotonic_now() -> Result<u64, LiveTimeError> {
    let state = live_state().ok_or(LiveTimeError::Clock)?;
    let mut state = state.lock();
    Ok(state.sample_now()?.nanoseconds)
}

pub(crate) fn register_deadline(
    deadline_ns: u64,
    wake: BlockWakeKey,
) -> Result<DeadlineRegistration, DeadlineRegistrationFailure> {
    if wake_binding().is_none() {
        return Err(registration_failure(LiveTimeError::NoWakeRuntime, wake));
    }
    let Some(state) = live_state() else {
        return Err(registration_failure(LiveTimeError::Clock, wake));
    };
    state.lock().register_deadline(deadline_ns, wake)
}

#[allow(
    unsafe_code,
    reason = "the fixed assembly timer entry requires one unmangled Rust dispatch symbol"
)]
#[unsafe(no_mangle)]
pub(crate) extern "sysv64" fn dw_x86_64_timer_interrupt_dispatch() {
    let Some(state) = live_state() else {
        halt_forever();
    };
    let outcome = {
        let mut state = state.lock();
        state.interrupt().unwrap_or_else(|_| halt_forever())
    };
    if outcome.wake_count == 0 {
        return;
    }
    let Some(binding) = wake_binding() else {
        halt_forever();
    };
    for key in outcome.wakes.into_iter().take(outcome.wake_count).flatten() {
        #[allow(
            unsafe_code,
            reason = "the immutable static wake binding is invoked only after the IRQ-safe time lock has been released"
        )]
        unsafe {
            (binding.handler)(binding.context, key);
        }
    }
}

#[allow(
    unsafe_code,
    reason = "F3 reads the validated ACPI PM timer through its architectural System-I/O DWORD port"
)]
fn read_pm_timer(descriptor: PmTimerDescriptor) -> u32 {
    let value: u32;
    unsafe {
        core::arch::asm!(
            "in eax, dx",
            in("dx") descriptor.port(),
            out("eax") value,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}

#[allow(
    unsafe_code,
    reason = "an impossible F3 interrupt/runtime invariant is fail-stop with interrupts disabled"
)]
fn halt_forever() -> ! {
    loop {
        unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

#[cfg(feature = "test-support")]
pub(crate) fn calibrated_apic_timer_hz() -> Option<u64> {
    live_state().map(|state| state.lock().apic_timer_hz)
}

#[cfg(feature = "test-support")]
struct ProbeWakeTarget {
    scheduler: crate::task::CooperativeScheduler<1>,
    failed: AtomicU8,
}

#[cfg(feature = "test-support")]
impl DeadlineWakeTarget for ProbeWakeTarget {
    fn wake_deadline(&self, key: BlockWakeKey) {
        if self.scheduler.wake(key).is_err() {
            self.failed.store(1, Ordering::Release);
        }
    }
}

#[cfg(feature = "test-support")]
struct ProbeStorage(UnsafeCell<MaybeUninit<ProbeWakeTarget>>);

#[cfg(feature = "test-support")]
impl ProbeStorage {
    const fn new() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }
}

#[cfg(feature = "test-support")]
#[allow(
    unsafe_code,
    reason = "the one-shot F3 target probe publishes stationary scheduler state before IRQ delivery"
)]
unsafe impl Sync for ProbeStorage {}

#[cfg(feature = "test-support")]
static PROBE_STATE: AtomicU8 = AtomicU8::new(UNINITIALIZED);
#[cfg(feature = "test-support")]
static PROBE_STORAGE: ProbeStorage = ProbeStorage::new();

#[cfg(feature = "test-support")]
fn probe_target() -> Result<&'static ProbeWakeTarget, LiveTimeError> {
    if PROBE_STATE
        .compare_exchange(
            UNINITIALIZED,
            INITIALIZING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return Err(LiveTimeError::AlreadyInitialized);
    }
    #[allow(
        unsafe_code,
        reason = "the target probe has one-shot BSP ownership before the static scheduler becomes interrupt-visible"
    )]
    unsafe {
        (*PROBE_STORAGE.0.get()).write(ProbeWakeTarget {
            scheduler: crate::task::CooperativeScheduler::new(),
            failed: AtomicU8::new(0),
        });
    }
    PROBE_STATE.store(INITIALIZED, Ordering::Release);
    #[allow(
        unsafe_code,
        reason = "the published probe target remains stationary for the rest of the test boot"
    )]
    Ok(unsafe { &*(*PROBE_STORAGE.0.get()).as_ptr() })
}

#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct F3TargetProbe {
    pub(crate) before_ns: u64,
    pub(crate) after_ns: u64,
    pub(crate) apic_timer_hz: u64,
}

#[cfg(feature = "test-support")]
pub(crate) fn run_target_deadline_probe() -> Result<F3TargetProbe, LiveTimeError> {
    let target = probe_target()?;
    bind_deadline_wake_target(target)?;

    let mut registry = crate::object::ObjectRegistry::<2>::new();
    let creation = registry
        .create(deepwyrm_abi::DW_OBJECT_TYPE_THREAD)
        .map_err(|_| LiveTimeError::Deadline)?;
    let thread = crate::task::ThreadKey::from_object_id(creation.id());
    registry
        .cancel_creation(creation)
        .map_err(|_| LiveTimeError::Deadline)?;
    let reservation = target
        .scheduler
        .reserve(thread)
        .map_err(|_| LiveTimeError::Deadline)?;
    target
        .scheduler
        .commit(reservation)
        .map_err(|_| LiveTimeError::Deadline)?;
    if target
        .scheduler
        .schedule_next()
        .map_err(|_| LiveTimeError::Deadline)?
        .current
        != Some(thread)
    {
        return Err(LiveTimeError::Deadline);
    }
    let (blocked, decision) = target
        .scheduler
        .block_current(thread)
        .map_err(|_| LiveTimeError::Deadline)?;
    if decision.current.is_some() {
        return Err(LiveTimeError::Deadline);
    }

    let before_ns = monotonic_now()?;
    let deadline_ns = before_ns
        .checked_add(20_000_000)
        .filter(|value| *value < deepwyrm_abi::DW_DEADLINE_INFINITE.0)
        .ok_or(LiveTimeError::Deadline)?;
    let _registration = match register_deadline(deadline_ns, blocked.into_wake_key()) {
        Ok(registration) => registration,
        Err(failure) => {
            let (error, wake) = failure.into_parts();
            let _ = target.scheduler.wake(wake);
            return Err(error);
        }
    };

    for _ in 0..8 {
        if target.scheduler.state(thread) == Some(crate::task::SchedulerThreadState::Runnable) {
            break;
        }
        wait_for_interrupt();
    }
    if target.failed.load(Ordering::Acquire) != 0
        || target.scheduler.state(thread) != Some(crate::task::SchedulerThreadState::Runnable)
    {
        return Err(LiveTimeError::Deadline);
    }
    let after_ns = monotonic_now()?;
    if after_ns < deadline_ns {
        return Err(LiveTimeError::Deadline);
    }
    Ok(F3TargetProbe {
        before_ns,
        after_ns,
        apic_timer_hz: calibrated_apic_timer_hz().ok_or(LiveTimeError::Calibration)?,
    })
}

#[cfg(feature = "test-support")]
#[allow(
    unsafe_code,
    reason = "STI;HLT is the F3 target proof's race-free sleeping wait; CLI restores the caller's IF-clear test state"
)]
fn wait_for_interrupt() {
    unsafe { core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack)) };
}
