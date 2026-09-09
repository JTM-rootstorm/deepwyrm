//! Target-only ACPI-PM/LAPIC implementation of the F3 monotonic service.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use crate::arch::x86_64::apic::{
    ApicMode, IpiOperation, LocalApic, LocalApicDiscovery, XApicRegisterAccess,
};
use crate::arch::x86_64::apic_live::{
    LiveApicBaseMsr, LiveXApicMmio, discover_local_apic, lapic_pat_entry_is_uncacheable,
};
use crate::arch::x86_64::ipi::{
    LiveIpiTransport, LiveIpiVector, bind_live_ipi_transport, bind_live_rendezvous_handler,
    live_ipi_transport_is_bound, send_live_ipi,
};
use crate::arch::x86_64::mm::{ActiveDeepPaging, FrameAddress, LiveActivePagingTarget};
use crate::cpu::{CPU_CAPACITY, CpuIndex};
use crate::interrupt::{ControllerState, LocalApicVectors};
use crate::sync::IrqSpinMutex;
use crate::task::BlockWakeKey;

use super::arbiter::{
    HardwareArmIntent, HardwareStopIntent, LocalDeadlineSource, PhysicalArmSequence,
    earliest_deadline,
};
use super::service::TimerServiceSignal;
use super::{
    DEADLINE_QUEUE_CAPACITY, DeadlineQueue, DeadlineRegistration, MonotonicSample,
    PmTimerDescriptor, PmTimerState, TimeInitState, TimerDeadlineAuthority, TimerDeadlineError,
    TimerExpiryToken, apic_one_shot_for_delta,
};

#[cfg(feature = "test-support")]
mod probes;
#[cfg(feature = "test-support")]
pub(crate) use probes::{
    F3TargetProbe, F8TargetTimerProbe, calibrated_apic_timer_hz, run_target_deadline_probe,
    run_target_timer_probe,
};

const UNINITIALIZED: u8 = 0;
const INITIALIZING: u8 = 1;
const INITIALIZED: u8 = 2;
const CALIBRATION_NANOSECONDS: u64 = 10_000_000;
const LAPIC_SLOT_EMPTY: u8 = 0;
const LAPIC_SLOT_PUBLISHING: u8 = 1;
const LAPIC_SLOT_ONLINE: u8 = 2;
const AP_TIMER_UNINITIALIZED: u8 = 0;
const AP_TIMER_MASKED_READY: u8 = 1;
const AP_TIMER_FAULTED: u8 = 2;
const XAPIC_EOI_REGISTER: u32 = 0x0b0;

/// Coalesced request for logical CPU 0 to resample and reprogram its one-shot
/// timer after another CPU mutates the synchronized global deadline queues.
///
/// The Release store precedes the fixed e1 send. The BSP's Acquire swap runs
/// after EOI and before it takes the time lock, so one delivery may safely
/// cover any number of mutations already visible through that lock.
static BSP_TIMER_SERVICE: TimerServiceSignal = TimerServiceSignal::new();
#[cfg(deepwyrm_dw1e_platform)]
static Q35_BSP_RETIREMENT_REQUEST: IrqSpinMutex<crate::device::Q35BspRetirementCarrier> =
    IrqSpinMutex::new(crate::device::Q35BspRetirementCarrier::new());
static AP_SCHEDULER_TIMER_MASKED: [AtomicBool; CPU_CAPACITY] =
    [const { AtomicBool::new(false) }; CPU_CAPACITY];

struct ApSchedulerTimerState {
    cpu: CpuIndex,
    timer_hz: u64,
    scheduler_quantum: LocalDeadlineSource<crate::task::SchedulerQuantumTicket>,
    hardware_arms: PhysicalArmSequence,
}

impl ApSchedulerTimerState {
    const fn uninitialized() -> Self {
        Self {
            cpu: CpuIndex::BOOTSTRAP,
            timer_hz: 0,
            scheduler_quantum: LocalDeadlineSource::new(),
            hardware_arms: PhysicalArmSequence::initialized(),
        }
    }

    fn initialize(&mut self, cpu: CpuIndex, timer_hz: u64) -> Result<(), LiveTimeError> {
        if cpu == CpuIndex::BOOTSTRAP || timer_hz == 0 || self.timer_hz != 0 {
            return Err(LiveTimeError::AlreadyInitialized);
        }
        self.cpu = cpu;
        self.timer_hz = timer_hz;
        Ok(())
    }

    fn record_source_mutation(&mut self) -> Result<(), LiveTimeError> {
        self.hardware_arms
            .source_mutated()
            .map_err(|_| LiveTimeError::Deadline)
    }

    fn arm(&mut self, ticket: crate::task::SchedulerQuantumTicket) -> Result<(), LiveTimeError> {
        if ticket.cpu() != self.cpu
            || ticket.source_arm_generation() == 0
            || ticket.execution_generation() == 0
        {
            return Err(LiveTimeError::Deadline);
        }
        self.scheduler_quantum
            .replace(ticket.source_arm_generation(), ticket.deadline_ns(), ticket)
            .map_err(|_| LiveTimeError::Deadline)?;
        self.record_source_mutation()
    }

    fn cancel(
        &mut self,
        ticket: crate::task::SchedulerQuantumTicket,
    ) -> Result<bool, LiveTimeError> {
        if ticket.cpu() != self.cpu {
            return Ok(false);
        }
        let cancelled = self
            .scheduler_quantum
            .cancel(ticket.source_arm_generation(), ticket);
        if cancelled {
            self.record_source_mutation()?;
        }
        Ok(cancelled)
    }

    fn take_due(
        &mut self,
        now_ns: u64,
    ) -> Result<Option<crate::task::SchedulerQuantumTicket>, LiveTimeError> {
        let due = self.scheduler_quantum.take_due(now_ns);
        if due.is_some() {
            self.record_source_mutation()?;
        }
        Ok(due)
    }

    fn prepare_hardware(&mut self, now_ns: u64) -> Result<PreparedApHardwareIntent, LiveTimeError> {
        match self.scheduler_quantum.earliest() {
            Some(deadline_ns) => self
                .hardware_arms
                .prepare(deadline_ns, now_ns, self.timer_hz)
                .map(PreparedApHardwareIntent::Arm)
                .map_err(|_| LiveTimeError::Deadline),
            None => self
                .hardware_arms
                .prepare_stop()
                .map(PreparedApHardwareIntent::Stop)
                .map_err(|_| LiveTimeError::Deadline),
        }
    }

    fn hardware_intent_is_current(&self, intent: &PreparedApHardwareIntent) -> bool {
        match intent {
            PreparedApHardwareIntent::Arm(intent) => self.hardware_arms.is_current(intent),
            PreparedApHardwareIntent::Stop(intent) => self.hardware_arms.is_stop_current(intent),
        }
    }
}

enum PreparedApHardwareIntent {
    Arm(HardwareArmIntent),
    Stop(HardwareStopIntent),
}

struct ApSchedulerTimerSlot {
    lifecycle: AtomicU8,
    state: IrqSpinMutex<ApSchedulerTimerState>,
}

impl ApSchedulerTimerSlot {
    const fn uninitialized() -> Self {
        Self {
            lifecycle: AtomicU8::new(AP_TIMER_UNINITIALIZED),
            state: IrqSpinMutex::new(ApSchedulerTimerState::uninitialized()),
        }
    }

    fn initialize(&self, cpu: CpuIndex, timer_hz: u64) -> Result<(), LiveTimeError> {
        if self
            .lifecycle
            .compare_exchange(
                AP_TIMER_UNINITIALIZED,
                AP_TIMER_FAULTED,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return Err(LiveTimeError::AlreadyInitialized);
        }
        self.state.lock().initialize(cpu, timer_hz)?;
        self.lifecycle
            .store(AP_TIMER_MASKED_READY, Ordering::Release);
        Ok(())
    }

    fn is_ready(&self) -> bool {
        self.lifecycle.load(Ordering::Acquire) == AP_TIMER_MASKED_READY
    }
}

static AP_SCHEDULER_TIMERS: [ApSchedulerTimerSlot; CPU_CAPACITY] =
    [const { ApSchedulerTimerSlot::uninitialized() }; CPU_CAPACITY];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveTimeError {
    AlreadyInitialized,
    AcpiTimerDidNotAdvance,
    ApicDiscovery,
    ApicMode,
    ApicMapping,
    ApicAccess,
    CpuIdentity,
    Calibration,
    Clock,
    Deadline,
    NoWakeRuntime,
    IpiTransport,
    Faulted,
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

pub(crate) trait TimerExpiryTarget: Sync {
    fn expire_timer(&self, token: TimerExpiryToken);
}

#[derive(Clone, Copy)]
struct TimerExpiryBinding {
    context: *const (),
    handler: unsafe fn(*const (), TimerExpiryToken),
}

struct TimerExpiryStorage(UnsafeCell<MaybeUninit<TimerExpiryBinding>>);

impl TimerExpiryStorage {
    const fn new() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }
}

#[allow(
    unsafe_code,
    reason = "one-shot F8 Timer expiry publication stores an immutable static shared target before Timer deadlines are armed"
)]
unsafe impl Sync for TimerExpiryStorage {}

static TIMER_EXPIRY_STATE: AtomicU8 = AtomicU8::new(UNINITIALIZED);
static TIMER_EXPIRY_STORAGE: TimerExpiryStorage = TimerExpiryStorage::new();

pub(crate) fn bind_timer_expiry_target<T: TimerExpiryTarget + 'static>(
    target: &'static T,
) -> Result<(), LiveTimeError> {
    if TIMER_EXPIRY_STATE
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
        reason = "the static Timer expiry target is erased together with its monomorphized shared-reference trampoline"
    )]
    unsafe {
        (*TIMER_EXPIRY_STORAGE.0.get()).write(TimerExpiryBinding {
            context: core::ptr::from_ref(target).cast::<()>(),
            handler: timer_expiry_trampoline::<T>,
        });
    }
    TIMER_EXPIRY_STATE.store(INITIALIZED, Ordering::Release);
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "the stored Timer expiry context originated from the matching static typed target reference"
)]
unsafe fn timer_expiry_trampoline<T: TimerExpiryTarget>(
    context: *const (),
    token: TimerExpiryToken,
) {
    let target = unsafe { &*context.cast::<T>() };
    target.expire_timer(token);
}

fn timer_expiry_binding() -> Option<TimerExpiryBinding> {
    if TIMER_EXPIRY_STATE.load(Ordering::Acquire) != INITIALIZED {
        return None;
    }
    #[allow(
        unsafe_code,
        reason = "Acquire observes the immutable Timer expiry binding published before INITIALIZED"
    )]
    Some(unsafe { (*TIMER_EXPIRY_STORAGE.0.get()).assume_init() })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LocalApicIdentity {
    local_apic_id: u8,
    physical_base: u64,
    virtual_base: u64,
}

struct LiveLocalApicOwner {
    controller: LocalApic,
    registers: LiveXApicMmio,
}

/// One stationary local-APIC owner selected only through canonical logical CPU
/// identity. Controller state is serialized with local IF clear. Receive EOI
/// uses only the release-published immutable MMIO base and never takes this
/// lock, so an IPI cannot deadlock an interrupted sender.
struct PerCpuLocalApicSlot {
    state: AtomicU8,
    local_apic_id: AtomicU8,
    physical_base: AtomicU64,
    virtual_base: AtomicU64,
    owner: IrqSpinMutex<Option<LiveLocalApicOwner>>,
}

impl PerCpuLocalApicSlot {
    const fn empty() -> Self {
        Self {
            state: AtomicU8::new(LAPIC_SLOT_EMPTY),
            local_apic_id: AtomicU8::new(0),
            physical_base: AtomicU64::new(0),
            virtual_base: AtomicU64::new(0),
            owner: IrqSpinMutex::new(None),
        }
    }

    fn publish(&self, owner: LiveLocalApicOwner) -> Result<(), LiveTimeError> {
        if owner.controller.state() != ControllerState::Online {
            return Err(LiveTimeError::ApicAccess);
        }
        let local_apic_id = owner
            .controller
            .apic_id()
            .ok_or(LiveTimeError::ApicAccess)?;
        let physical_base = owner.controller.discovery().physical_base();
        let virtual_base = owner.registers.base();
        self.state
            .compare_exchange(
                LAPIC_SLOT_EMPTY,
                LAPIC_SLOT_PUBLISHING,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .map_err(|_| LiveTimeError::AlreadyInitialized)?;

        let mut slot = self.owner.lock();
        debug_assert!(slot.is_none());
        *slot = Some(owner);
        self.local_apic_id.store(local_apic_id, Ordering::Relaxed);
        self.physical_base.store(physical_base, Ordering::Relaxed);
        self.virtual_base.store(virtual_base, Ordering::Relaxed);
        self.state.store(LAPIC_SLOT_ONLINE, Ordering::Release);
        Ok(())
    }

    fn identity(&self) -> Option<LocalApicIdentity> {
        if self.state.load(Ordering::Acquire) != LAPIC_SLOT_ONLINE {
            return None;
        }
        Some(LocalApicIdentity {
            local_apic_id: self.local_apic_id.load(Ordering::Relaxed),
            physical_base: self.physical_base.load(Ordering::Relaxed),
            virtual_base: self.virtual_base.load(Ordering::Relaxed),
        })
    }

    fn with_owner<T>(
        &self,
        operation: impl FnOnce(&mut LocalApic, &mut LiveXApicMmio) -> Result<T, LiveTimeError>,
    ) -> Result<T, LiveTimeError> {
        if self.state.load(Ordering::Acquire) != LAPIC_SLOT_ONLINE {
            return Err(LiveTimeError::ApicAccess);
        }
        let mut owner = self.owner.lock();
        let owner = owner.as_mut().ok_or(LiveTimeError::ApicAccess)?;
        operation(&mut owner.controller, &mut owner.registers)
    }

    fn end_of_interrupt(&self) -> Result<(), LiveTimeError> {
        let identity = self.identity().ok_or(LiveTimeError::ApicAccess)?;
        let mut registers =
            LiveXApicMmio::new(identity.virtual_base).map_err(|_| LiveTimeError::ApicMapping)?;
        registers
            .write(XAPIC_EOI_REGISTER, 0)
            .map_err(|_| LiveTimeError::ApicAccess)
    }
}

static LOCAL_APIC_SLOTS: [PerCpuLocalApicSlot; CPU_CAPACITY] =
    [const { PerCpuLocalApicSlot::empty() }; CPU_CAPACITY];

fn installed_current_cpu_index() -> Result<CpuIndex, LiveTimeError> {
    crate::arch::x86_64::syscall::current_cpu_index_for_diagnostics()
        .and_then(CpuIndex::new)
        .ok_or(LiveTimeError::CpuIdentity)
}

fn current_local_apic_slot() -> Result<&'static PerCpuLocalApicSlot, LiveTimeError> {
    let cpu = installed_current_cpu_index()?;
    LOCAL_APIC_SLOTS
        .get(cpu.index())
        .ok_or(LiveTimeError::CpuIdentity)
}

fn with_bootstrap_local_apic<T>(
    operation: impl FnOnce(&mut LocalApic, &mut LiveXApicMmio) -> Result<T, LiveTimeError>,
) -> Result<T, LiveTimeError> {
    if installed_current_cpu_index()? != CpuIndex::BOOTSTRAP {
        return Err(LiveTimeError::CpuIdentity);
    }
    LOCAL_APIC_SLOTS[CpuIndex::BOOTSTRAP.index()].with_owner(operation)
}

/// Performs DW1-E2C's ordered CPU0 IRR/ISR observation for vector `0x30`.
/// Callers must already have proved the IOAPIC route masked and Delivery
/// Status idle; this helper rejects execution on every non-bootstrap CPU.
#[cfg(deepwyrm_dw1e_platform)]
pub(crate) fn q35_bsp_vector_is_clear() -> Result<bool, LiveTimeError> {
    with_bootstrap_local_apic(|controller, registers| {
        let state = controller
            .vector_state(registers, 0x30)
            .map_err(|_| LiveTimeError::ApicAccess)?;
        Ok(!state.pending && !state.in_service)
    })
}

#[cfg(deepwyrm_dw1e_platform)]
pub(crate) fn q35_current_cpu_is_bsp() -> Result<bool, LiveTimeError> {
    Ok(installed_current_cpu_index()? == CpuIndex::BOOTSTRAP)
}

/// Publishes the exact q35 retirement token without notifying CPU0. The q35
/// source remains in `Publishing` until this durable store succeeds, so a
/// concurrent CPU0 retry cannot release the generation ahead of publication.
#[cfg(deepwyrm_dw1e_platform)]
pub(crate) fn publish_q35_bsp_retirement_check(
    request: crate::device::Q35BspCheckRequest,
) -> Result<(), LiveTimeError> {
    Q35_BSP_RETIREMENT_REQUEST
        .lock()
        .publish_exact(request)
        .map_err(|_| LiveTimeError::Faulted)
}

/// Notifies CPU0 only after the q35 source and carrier both expose the same
/// Published token. A failed notification leaves that durable token pending
/// for the next ordinary CPU0 carrier safe point.
#[cfg(deepwyrm_dw1e_platform)]
pub(crate) fn notify_q35_bsp_retirement_check(
    _request: crate::device::Q35BspCheckRequest,
) -> Result<(), LiveTimeError> {
    if installed_current_cpu_index()? == CpuIndex::BOOTSTRAP {
        return Ok(());
    }
    crate::arch::x86_64::idle::publish_bsp_service_wake().map_err(|_| LiveTimeError::Faulted)?;
    let bsp = LOCAL_APIC_SLOTS[CpuIndex::BOOTSTRAP.index()]
        .identity()
        .ok_or(LiveTimeError::ApicAccess)?;
    send_live_ipi(bsp.local_apic_id, LiveIpiVector::Rendezvous)
        .map_err(|_| LiveTimeError::IpiTransport)
}

/// Terminal freeze is selector-private work, not Interrupt retirement. Its
/// exact state remains in the q35 source/evidence authorities; e1 is only a
/// remote wake and never occupies the retirement carrier.
#[cfg(deepwyrm_dw1e_platform)]
pub(crate) fn request_q35_bsp_terminal_check(
    _request: crate::device::Q35BspCheckRequest,
) -> Result<(), LiveTimeError> {
    if installed_current_cpu_index()? == CpuIndex::BOOTSTRAP {
        return Ok(());
    }
    crate::arch::x86_64::idle::publish_bsp_service_wake().map_err(|_| LiveTimeError::Faulted)?;
    let bsp = LOCAL_APIC_SLOTS[CpuIndex::BOOTSTRAP.index()]
        .identity()
        .ok_or(LiveTimeError::ApicAccess)?;
    send_live_ipi(bsp.local_apic_id, LiveIpiVector::Rendezvous)
        .map_err(|_| LiveTimeError::IpiTransport)
}

#[cfg(deepwyrm_dw1e_platform)]
pub(crate) fn pending_q35_bsp_retirement_check()
-> Result<Option<crate::device::Q35BspCheckRequest>, LiveTimeError> {
    if installed_current_cpu_index()? != CpuIndex::BOOTSTRAP {
        return Err(LiveTimeError::CpuIdentity);
    }
    Ok(Q35_BSP_RETIREMENT_REQUEST.lock().pending())
}

#[cfg(deepwyrm_dw1e_platform)]
pub(crate) fn complete_q35_bsp_retirement_check(
    request: crate::device::Q35BspCheckRequest,
) -> Result<(), LiveTimeError> {
    Q35_BSP_RETIREMENT_REQUEST
        .lock()
        .complete_exact(request)
        .map_err(|_| LiveTimeError::Faulted)
}

fn current_cpu_is_timer_service() -> Result<bool, LiveTimeError> {
    Ok(installed_current_cpu_index()? == CpuIndex::BOOTSTRAP)
}

fn request_bsp_timer_service() -> Result<(), LiveTimeError> {
    BSP_TIMER_SERVICE
        .ensure_healthy()
        .map_err(|_| LiveTimeError::Faulted)?;
    let is_timer_service = match current_cpu_is_timer_service() {
        Ok(is_timer_service) => is_timer_service,
        Err(error) => {
            BSP_TIMER_SERVICE.fail_transport();
            return Err(error);
        }
    };
    if is_timer_service {
        return service_bsp_timer_request();
    }
    let Some(bsp) = LOCAL_APIC_SLOTS[CpuIndex::BOOTSTRAP.index()].identity() else {
        BSP_TIMER_SERVICE.fail_transport();
        return Err(LiveTimeError::ApicAccess);
    };
    BSP_TIMER_SERVICE
        .publish()
        .map_err(|_| LiveTimeError::Faulted)?;
    if send_live_ipi(bsp.local_apic_id, LiveIpiVector::Rendezvous).is_err() {
        BSP_TIMER_SERVICE.fail_transport();
        return Err(LiveTimeError::IpiTransport);
    }
    Ok(())
}

fn service_bsp_timer_request() -> Result<(), LiveTimeError> {
    BSP_TIMER_SERVICE
        .ensure_healthy()
        .map_err(|_| LiveTimeError::Faulted)?;
    if !current_cpu_is_timer_service()? {
        return Err(LiveTimeError::CpuIdentity);
    }
    reconcile_bsp_hardware_arm()
}

/// Programs the one physical BSP one-shot only after dropping the arbiter
/// state guard, then verifies that no newer logical-source update won.
fn reconcile_bsp_hardware_arm() -> Result<(), LiveTimeError> {
    if installed_current_cpu_index()? != CpuIndex::BOOTSTRAP {
        return Err(LiveTimeError::CpuIdentity);
    }
    let state = live_state().ok_or(LiveTimeError::Clock)?;
    for _ in 0..8 {
        let sample = sample_clock_now()?;
        let intent = {
            let mut state = state.lock();
            state.prepare_hardware_arm(sample)?
        };
        with_bootstrap_local_apic(|controller, registers| {
            debug_assert_ne!(intent.deadline_ns, 0);
            controller
                .program_one_shot_timer(registers, intent.shot.initial_count)
                .map_err(|_| LiveTimeError::ApicAccess)
        })?;
        let committed = {
            let state = state.lock();
            state.hardware_arms.is_current(&intent)
        };
        if committed {
            return Ok(());
        }
    }
    Err(LiveTimeError::Faulted)
}

/// e1 receive seam shared with idle-wake/stop rendezvous state.
///
/// This runs after EOI with IF clear and may only publish the CPU-local latch.
/// Timer service, mailbox inspection, scheduling, and stop acknowledgement
/// happen later from the carrier-owned safe point.
fn live_rendezvous_handler() {
    crate::arch::x86_64::idle::latch_current_rendezvous_ipi();
}

/// Consumes the current carrier's post-EOI rendezvous latch. `Wake` requires
/// only the caller's ordinary scheduler rescan. `Stop` and `HoldSafe` are
/// returned without acknowledgement so the later D carrier join can establish
/// the exact safe tuple outside interrupt context.
pub(crate) fn service_current_rendezvous_latch()
-> Result<crate::arch::x86_64::rendezvous::MailboxNotification, LiveTimeError> {
    let notification = crate::arch::x86_64::idle::take_current_latched_notification();
    if installed_current_cpu_index() == Ok(CpuIndex::BOOTSTRAP) {
        match BSP_TIMER_SERVICE.take() {
            Ok(true) => {
                if service_bsp_timer_request().is_err() {
                    halt_forever();
                }
            }
            Ok(false) => {}
            Err(_) => halt_forever(),
        }
    }
    Ok(notification)
}

struct StationaryLiveIpiTransport;

static LIVE_IPI_TRANSPORT: StationaryLiveIpiTransport = StationaryLiveIpiTransport;

impl LiveIpiTransport for StationaryLiveIpiTransport {
    fn send_fixed(&self, destination_apic_id: u8, vector: LiveIpiVector) -> bool {
        current_local_apic_slot()
            .and_then(|slot| {
                slot.with_owner(|controller, registers| {
                    controller
                        .send_ipi(
                            registers,
                            destination_apic_id,
                            IpiOperation::Fixed {
                                vector: vector.vector(),
                            },
                        )
                        .map_err(|_| LiveTimeError::ApicAccess)
                })
            })
            .is_ok()
    }

    fn end_of_interrupt(&self) -> bool {
        current_local_apic_slot()
            .and_then(PerCpuLocalApicSlot::end_of_interrupt)
            .is_ok()
    }
}

struct InterruptOutcome {
    wakes: [Option<BlockWakeKey>; DEADLINE_QUEUE_CAPACITY],
    wake_count: usize,
    timer_expiries: [Option<TimerExpiryToken>; DEADLINE_QUEUE_CAPACITY],
    timer_expiry_count: usize,
    scheduler_quantum: Option<crate::task::SchedulerQuantumTicket>,
}

impl InterruptOutcome {
    const fn empty() -> Self {
        Self {
            wakes: [None; DEADLINE_QUEUE_CAPACITY],
            wake_count: 0,
            timer_expiries: [None; DEADLINE_QUEUE_CAPACITY],
            timer_expiry_count: 0,
            scheduler_quantum: None,
        }
    }

    fn assert_drained(&self) {
        debug_assert_eq!(self.wake_count, 0);
        debug_assert!(self.wakes.iter().all(Option::is_none));
        debug_assert_eq!(self.timer_expiry_count, 0);
        debug_assert!(self.timer_expiries.iter().all(Option::is_none));
        debug_assert!(self.scheduler_quantum.is_none());
    }
}

struct BspInterruptOutcomeStorage(UnsafeCell<InterruptOutcome>);

impl BspInterruptOutcomeStorage {
    const fn new() -> Self {
        Self(UnsafeCell::new(InterruptOutcome::empty()))
    }
}

#[allow(
    unsafe_code,
    reason = "the CPU0-only timer interrupt gate keeps IF clear, so its stationary outcome scratch cannot be entered concurrently or recursively"
)]
unsafe impl Sync for BspInterruptOutcomeStorage {}

static BSP_INTERRUPT_OUTCOME: BspInterruptOutcomeStorage = BspInterruptOutcomeStorage::new();

struct ApInterruptOutcomeStorage(UnsafeCell<Option<crate::task::SchedulerQuantumTicket>>);

impl ApInterruptOutcomeStorage {
    const fn empty() -> Self {
        Self(UnsafeCell::new(None))
    }
}

#[allow(
    unsafe_code,
    reason = "each AP owns one CPU-indexed timer outcome cell and its interrupt gate keeps local IF clear through consumption"
)]
unsafe impl Sync for ApInterruptOutcomeStorage {}

static AP_INTERRUPT_OUTCOMES: [ApInterruptOutcomeStorage; CPU_CAPACITY] =
    [const { ApInterruptOutcomeStorage::empty() }; CPU_CAPACITY];

struct LiveTimeState {
    apic_timer_hz: u64,
    deadlines: DeadlineQueue,
    timer_deadlines: DeadlineQueue<DEADLINE_QUEUE_CAPACITY, TimerExpiryToken>,
    scheduler_quantum: LocalDeadlineSource<crate::task::SchedulerQuantumTicket>,
    hardware_arms: PhysicalArmSequence,
}

impl LiveTimeState {
    fn record_source_mutation(&mut self) {
        self.hardware_arms
            .source_mutated()
            .unwrap_or_else(|_| panic!("DW1-B logical-source revision exhausted"));
    }

    fn next_deadline(&self, sample: MonotonicSample) -> u64 {
        earliest_deadline(
            [
                self.deadlines.earliest(),
                self.timer_deadlines.earliest(),
                self.scheduler_quantum.earliest(),
            ],
            sample.maintenance_deadline,
        )
    }

    fn prepare_hardware_arm(
        &mut self,
        sample: MonotonicSample,
    ) -> Result<HardwareArmIntent, LiveTimeError> {
        let next = self.next_deadline(sample);
        self.hardware_arms
            .prepare(next, sample.nanoseconds, self.apic_timer_hz)
            .map_err(|_| LiveTimeError::Deadline)
    }

    fn interrupt(&mut self, outcome: &mut InterruptOutcome) -> Result<(), LiveTimeError> {
        outcome.assert_drained();
        let sample = sample_clock_now()?;
        outcome.wake_count = self
            .deadlines
            .expire(sample.nanoseconds, &mut outcome.wakes);
        outcome.timer_expiry_count = self
            .timer_deadlines
            .expire(sample.nanoseconds, &mut outcome.timer_expiries);
        outcome.scheduler_quantum = self.scheduler_quantum.take_due(sample.nanoseconds);
        if outcome.wake_count != 0
            || outcome.timer_expiry_count != 0
            || outcome.scheduler_quantum.is_some()
        {
            self.record_source_mutation();
        }
        Ok(())
    }

    fn register_deadline(
        &mut self,
        deadline_ns: u64,
        wake: BlockWakeKey,
        _program_local_timer: bool,
    ) -> Result<DeadlineRegistration, DeadlineRegistrationFailure> {
        let sample = sample_clock_now().map_err(|error| registration_failure(error, wake))?;
        if deadline_ns <= sample.nanoseconds {
            return Err(registration_failure(LiveTimeError::Deadline, wake));
        }
        let registration = self
            .deadlines
            .register(deadline_ns, wake)
            .map_err(|_| registration_failure(LiveTimeError::Deadline, wake))?;
        self.record_source_mutation();
        Ok(registration)
    }

    fn cancel_deadline(
        &mut self,
        registration: DeadlineRegistration,
        program_local_timer: bool,
    ) -> Result<(), LiveTimeError> {
        let sample = sample_clock_now()?;
        let cancelled = self
            .deadlines
            .cancel_if_live(registration)
            .map_err(|_| LiveTimeError::Deadline)?;
        if cancelled.is_some() {
            self.record_source_mutation();
        }
        let _ = (sample, program_local_timer);
        Ok(())
    }

    fn replace_timer_deadline(
        &mut self,
        old: Option<&DeadlineRegistration>,
        deadline_ns: u64,
        token: TimerExpiryToken,
        program_local_timer: bool,
    ) -> Result<Option<DeadlineRegistration>, TimerDeadlineError> {
        let sample = sample_clock_now().map_err(|_| TimerDeadlineError::Fault)?;
        if deadline_ns <= sample.nanoseconds {
            if let Some(old) = old {
                let cancelled = self
                    .timer_deadlines
                    .cancel_if_live_ref(old)
                    .map_err(|_| TimerDeadlineError::Fault)?;
                if cancelled.is_some() {
                    self.record_source_mutation();
                }
            }
            let _ = program_local_timer;
            return Ok(None);
        }

        let registration = if let Some(old) = old {
            match self
                .timer_deadlines
                .replace_if_live(old, deadline_ns, token)
                .map_err(map_timer_queue_error)?
            {
                Some(registration) => registration,
                None => self
                    .timer_deadlines
                    .register(deadline_ns, token)
                    .map_err(map_timer_queue_error)?,
            }
        } else {
            self.timer_deadlines
                .register(deadline_ns, token)
                .map_err(map_timer_queue_error)?
        };
        self.record_source_mutation();
        Ok(Some(registration))
    }

    fn cancel_timer_deadline(
        &mut self,
        registration: &DeadlineRegistration,
        program_local_timer: bool,
    ) -> Result<(), TimerDeadlineError> {
        let sample = sample_clock_now().map_err(|_| TimerDeadlineError::Fault)?;
        let cancelled = self
            .timer_deadlines
            .cancel_if_live_ref(registration)
            .map_err(|_| TimerDeadlineError::Fault)?;
        if cancelled.is_some() {
            self.record_source_mutation();
        }
        let _ = (sample, program_local_timer);
        Ok(())
    }

    fn arm_scheduler_quantum(
        &mut self,
        ticket: crate::task::SchedulerQuantumTicket,
    ) -> Result<Option<crate::task::SchedulerQuantumTicket>, LiveTimeError> {
        if ticket.cpu() != CpuIndex::BOOTSTRAP
            || ticket.source_arm_generation() == 0
            || ticket.execution_generation() == 0
        {
            return Err(LiveTimeError::Deadline);
        }
        let sample = sample_clock_now()?;
        self.scheduler_quantum
            .replace(ticket.source_arm_generation(), ticket.deadline_ns(), ticket)
            .map_err(|_| LiveTimeError::Deadline)?;
        self.record_source_mutation();
        let due = self.scheduler_quantum.take_due(sample.nanoseconds);
        if due.is_some() {
            self.record_source_mutation();
        }
        Ok(due)
    }

    fn cancel_scheduler_quantum(
        &mut self,
        ticket: crate::task::SchedulerQuantumTicket,
    ) -> Result<bool, LiveTimeError> {
        let cancelled = self
            .scheduler_quantum
            .cancel(ticket.source_arm_generation(), ticket);
        if cancelled {
            self.record_source_mutation();
        }
        Ok(cancelled)
    }

    fn take_due_scheduler_quantum(
        &mut self,
    ) -> Result<Option<crate::task::SchedulerQuantumTicket>, LiveTimeError> {
        let sample = sample_clock_now()?;
        let due = self.scheduler_quantum.take_due(sample.nanoseconds);
        if due.is_some() {
            self.record_source_mutation();
        }
        Ok(due)
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

struct LiveClockState {
    pm: PmTimerState,
    last_sample: MonotonicSample,
}

impl LiveClockState {
    fn sample_now(&mut self) -> Result<MonotonicSample, LiveTimeError> {
        let raw = read_pm_timer(self.pm.descriptor());
        let sample = self.pm.sample(raw).map_err(|_| LiveTimeError::Clock)?;
        self.last_sample = sample;
        Ok(sample)
    }
}

struct ClockStorage(UnsafeCell<MaybeUninit<IrqSpinMutex<LiveClockState>>>);

impl ClockStorage {
    const fn new() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }
}

#[allow(
    unsafe_code,
    reason = "the one-shot F3 initializer publishes one stationary IRQ-safe monotonic clock before any CPU samples it"
)]
unsafe impl Sync for ClockStorage {}

static TIME_STATE: AtomicU8 = AtomicU8::new(TimeInitState::Uninitialized as u8);
static TIME_STORAGE: TimeStorage = TimeStorage::new();
static CLOCK_STORAGE: ClockStorage = ClockStorage::new();

fn live_state() -> Option<&'static IrqSpinMutex<LiveTimeState>> {
    if TIME_STATE.load(Ordering::Acquire) != TimeInitState::Initialized as u8 {
        return None;
    }
    #[allow(
        unsafe_code,
        reason = "Acquire observes the fully initialized stationary F3 time service"
    )]
    Some(unsafe { &*(*TIME_STORAGE.0.get()).as_ptr() })
}

fn live_clock() -> Option<&'static IrqSpinMutex<LiveClockState>> {
    if TIME_STATE.load(Ordering::Acquire) != TimeInitState::Initialized as u8 {
        return None;
    }
    #[allow(
        unsafe_code,
        reason = "Acquire observes the fully initialized stationary F3 monotonic clock"
    )]
    Some(unsafe { &*(*CLOCK_STORAGE.0.get()).as_ptr() })
}

fn sample_clock_now() -> Result<MonotonicSample, LiveTimeError> {
    let clock = live_clock().ok_or(LiveTimeError::Clock)?;
    clock.lock().sample_now()
}

pub(crate) fn initialize<'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    active: &mut ActiveDeepPaging<LiveActivePagingTarget<'root, RANGE_CAPACITY, ROLE_CAPACITY>>,
    pm_descriptor: PmTimerDescriptor,
) -> Result<(), LiveTimeError> {
    let observed = TIME_STATE.compare_exchange(
        TimeInitState::Uninitialized as u8,
        TimeInitState::Preparing as u8,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    if let Err(observed) = observed {
        return if TimeInitState::from_u8(observed) == Some(TimeInitState::Faulted) {
            Err(LiveTimeError::Faulted)
        } else {
            Err(LiveTimeError::AlreadyInitialized)
        };
    }

    let plan = match prepare_initialize(active) {
        Ok(plan) => plan,
        Err(error) => {
            TIME_STATE.store(TimeInitState::Uninitialized as u8, Ordering::Release);
            return Err(error);
        }
    };

    // Installing the LAPIC leaf is the first irreversible effect. Publish the
    // non-retryable state before crossing that boundary; success later replaces it.
    TIME_STATE.store(TimeInitState::Faulted as u8, Ordering::Release);
    let committed = commit_initialize(active, pm_descriptor, plan)?;
    LOCAL_APIC_SLOTS[CpuIndex::BOOTSTRAP.index()].publish(committed.local_apic)?;
    bind_live_ipi_transport(&LIVE_IPI_TRANSPORT).map_err(|_| LiveTimeError::IpiTransport)?;
    publish(committed.clock, committed.time);
    bind_live_rendezvous_handler(live_rendezvous_handler)
        .map_err(|_| LiveTimeError::IpiTransport)?;
    Ok(())
}

#[derive(Clone, Copy)]
struct TimeInitPlan {
    discovery: LocalApicDiscovery,
    frame: FrameAddress,
}

fn prepare_initialize<'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    active: &ActiveDeepPaging<LiveActivePagingTarget<'root, RANGE_CAPACITY, ROLE_CAPACITY>>,
) -> Result<TimeInitPlan, LiveTimeError> {
    let discovery = discover_local_apic().map_err(|_| LiveTimeError::ApicDiscovery)?;
    if discovery.mode() == ApicMode::X2Apic {
        return Err(LiveTimeError::ApicMode);
    }
    if !lapic_pat_entry_is_uncacheable() {
        return Err(LiveTimeError::ApicMapping);
    }
    let frame = FrameAddress::new(discovery.physical_base(), active.root().physical_limit())
        .map_err(|_| LiveTimeError::ApicMapping)?;
    Ok(TimeInitPlan { discovery, frame })
}

fn publish(clock: LiveClockState, state: LiveTimeState) {
    #[allow(
        unsafe_code,
        reason = "the successful one-shot initializer has exclusive publication ownership"
    )]
    unsafe {
        (*CLOCK_STORAGE.0.get()).write(IrqSpinMutex::new(clock));
        (*TIME_STORAGE.0.get()).write(IrqSpinMutex::new(state));
    }
    TIME_STATE.store(TimeInitState::Initialized as u8, Ordering::Release);
}

struct CommittedLiveTimeState {
    clock: LiveClockState,
    time: LiveTimeState,
    local_apic: LiveLocalApicOwner,
}

fn commit_initialize<'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    active: &mut ActiveDeepPaging<LiveActivePagingTarget<'root, RANGE_CAPACITY, ROLE_CAPACITY>>,
    pm_descriptor: PmTimerDescriptor,
    plan: TimeInitPlan,
) -> Result<CommittedLiveTimeState, LiveTimeError> {
    let discovery = plan.discovery;
    let virtual_base = active
        .install_kernel_mmio_page(plan.frame)
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
    let state = LiveTimeState {
        apic_timer_hz,
        deadlines: DeadlineQueue::new(),
        timer_deadlines: DeadlineQueue::new(),
        scheduler_quantum: LocalDeadlineSource::new(),
        hardware_arms: PhysicalArmSequence::initialized(),
    };
    let next = state.next_deadline(final_sample);
    let delta = next.saturating_sub(final_sample.nanoseconds);
    let shot =
        apic_one_shot_for_delta(delta, apic_timer_hz).map_err(|_| LiveTimeError::Deadline)?;
    apic.program_one_shot_timer(&mut registers, shot.initial_count)
        .map_err(|_| LiveTimeError::ApicAccess)?;
    Ok(CommittedLiveTimeState {
        clock: LiveClockState {
            pm,
            last_sample: final_sample,
        },
        time: state,
        local_apic: LiveLocalApicOwner {
            controller: apic,
            registers,
        },
    })
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

fn map_timer_queue_error(error: super::DeadlineQueueError) -> TimerDeadlineError {
    match error {
        super::DeadlineQueueError::Capacity | super::DeadlineQueueError::GenerationExhausted => {
            TimerDeadlineError::Capacity
        }
        _ => TimerDeadlineError::Fault,
    }
}

pub(crate) struct LiveTimerDeadlineAuthority;

impl TimerDeadlineAuthority for LiveTimerDeadlineAuthority {
    fn replace_timer_deadline(
        &mut self,
        old: Option<&DeadlineRegistration>,
        deadline_ns: u64,
        token: TimerExpiryToken,
    ) -> Result<Option<DeadlineRegistration>, TimerDeadlineError> {
        BSP_TIMER_SERVICE
            .ensure_healthy()
            .map_err(|_| TimerDeadlineError::Fault)?;
        if timer_expiry_binding().is_none() {
            return Err(TimerDeadlineError::Fault);
        }
        let program_local_timer =
            current_cpu_is_timer_service().map_err(|_| TimerDeadlineError::Fault)?;
        let state = live_state().ok_or(TimerDeadlineError::Fault)?;
        let registration =
            state
                .lock()
                .replace_timer_deadline(old, deadline_ns, token, program_local_timer)?;
        if program_local_timer {
            reconcile_bsp_hardware_arm().map_err(|_| TimerDeadlineError::Fault)?;
        } else if request_bsp_timer_service().is_err() {
            // The queue mutation is already committed and the authority trait
            // forbids returning an error that pretends `old` remained valid.
            // Losing the only timer-service notification is therefore a
            // correctness fault, not a recoverable Timer syscall failure.
            halt_forever();
        }
        Ok(registration)
    }

    fn cancel_timer_deadline(
        &mut self,
        registration: &DeadlineRegistration,
    ) -> Result<(), TimerDeadlineError> {
        BSP_TIMER_SERVICE
            .ensure_healthy()
            .map_err(|_| TimerDeadlineError::Fault)?;
        let program_local_timer =
            current_cpu_is_timer_service().map_err(|_| TimerDeadlineError::Fault)?;
        let state = live_state().ok_or(TimerDeadlineError::Fault)?;
        state
            .lock()
            .cancel_timer_deadline(registration, program_local_timer)?;
        if program_local_timer {
            reconcile_bsp_hardware_arm().map_err(|_| TimerDeadlineError::Fault)?;
        } else if request_bsp_timer_service().is_err() {
            halt_forever();
        }
        Ok(())
    }
}

pub(crate) fn monotonic_now() -> Result<u64, LiveTimeError> {
    if installed_current_cpu_index()? == CpuIndex::BOOTSTRAP {
        BSP_TIMER_SERVICE
            .ensure_healthy()
            .map_err(|_| LiveTimeError::Faulted)?;
    }
    Ok(sample_clock_now()?.nanoseconds)
}

/// Allows every native kernel re-entry to observe an ambiguous timer-service
/// transport failure even before the BSP's already-programmed maintenance
/// interrupt arrives.
pub(crate) fn timer_service_is_healthy() -> bool {
    BSP_TIMER_SERVICE.ensure_healthy().is_ok()
}

pub(crate) fn bsp_local_apic_identity() -> Result<(u8, u64), LiveTimeError> {
    let identity = LOCAL_APIC_SLOTS[CpuIndex::BOOTSTRAP.index()]
        .identity()
        .ok_or(LiveTimeError::ApicAccess)?;
    Ok((identity.local_apic_id, identity.physical_base))
}

/// Initializes the current application processor's xAPIC through the BSP's
/// already-established permanent UC mapping. The scheduler timer remains
/// masked under the H0 designated-timer-CPU policy.
pub(crate) fn initialize_ap_local_apic(
    cpu_index: usize,
    expected_apic_id: u8,
    expected_physical_base: u64,
) -> Result<(), LiveTimeError> {
    let cpu = CpuIndex::new(cpu_index).ok_or(LiveTimeError::CpuIdentity)?;
    if cpu == CpuIndex::BOOTSTRAP || installed_current_cpu_index()? != cpu {
        return Err(LiveTimeError::CpuIdentity);
    }
    let discovery = discover_local_apic().map_err(|_| LiveTimeError::ApicDiscovery)?;
    if discovery.is_bootstrap_processor()
        || discovery.mode() == ApicMode::X2Apic
        || discovery.physical_base() != expected_physical_base
    {
        return Err(LiveTimeError::ApicMode);
    }
    let bsp_identity = LOCAL_APIC_SLOTS[CpuIndex::BOOTSTRAP.index()]
        .identity()
        .ok_or(LiveTimeError::ApicAccess)?;
    if bsp_identity.physical_base != expected_physical_base {
        return Err(LiveTimeError::ApicMapping);
    }
    let virtual_base = bsp_identity.virtual_base;
    let mut apic = LocalApic::discovered(discovery, LocalApicVectors::DW0);
    if discovery.mode() == ApicMode::Disabled {
        apic.enable_xapic(&mut LiveApicBaseMsr)
            .map_err(|_| LiveTimeError::ApicAccess)?;
    }
    let mut registers = LiveXApicMmio::new(virtual_base).map_err(|_| LiveTimeError::ApicMapping)?;
    apic.prepare(&mut registers)
        .map_err(|_| LiveTimeError::ApicAccess)?;
    if apic.apic_id() != Some(expected_apic_id) {
        return Err(LiveTimeError::ApicAccess);
    }
    apic.bring_online(&mut registers)
        .map_err(|_| LiveTimeError::ApicAccess)?;
    apic.configure_one_shot_timer(&mut registers)
        .map_err(|_| LiveTimeError::ApicAccess)?;
    // The xAPIC one-shot counter rate is a package/platform property on the
    // supported q35 xAPIC profile. Copy the BSP's PM-timer-calibrated rate into
    // this CPU-private scheduler-only source; APs never acquire the BSP's
    // general Timer/wait queues or physical-arm state.
    let timer_hz = live_state()
        .ok_or(LiveTimeError::Clock)?
        .lock()
        .apic_timer_hz;
    AP_SCHEDULER_TIMERS[cpu.index()].initialize(cpu, timer_hz)?;
    AP_SCHEDULER_TIMER_MASKED[cpu.index()].store(true, Ordering::Release);
    LOCAL_APIC_SLOTS[cpu.index()].publish(LiveLocalApicOwner {
        controller: apic,
        registers,
    })?;
    current_cpu_ipi_transport_ready(cpu_index)
        .then_some(())
        .ok_or(LiveTimeError::IpiTransport)
}

pub(crate) fn ap_scheduler_timer_is_masked(cpu: CpuIndex) -> bool {
    cpu != CpuIndex::BOOTSTRAP
        && AP_SCHEDULER_TIMERS[cpu.index()].is_ready()
        && AP_SCHEDULER_TIMER_MASKED[cpu.index()].load(Ordering::Acquire)
}

/// Proves that the current CPU has its private IDT/GS identity, stationary
/// local-APIC slot, and the global send/EOI transport before it enables IF.
fn current_cpu_ipi_transport_ready(expected_cpu_index: usize) -> bool {
    let Some(expected) = CpuIndex::new(expected_cpu_index) else {
        return false;
    };
    live_ipi_transport_is_bound()
        && installed_current_cpu_index() == Ok(expected)
        && LOCAL_APIC_SLOTS[expected.index()].identity().is_some()
}

pub(crate) fn send_bsp_ipi(destination: u8, operation: IpiOperation) -> Result<(), LiveTimeError> {
    with_bootstrap_local_apic(|controller, registers| {
        controller
            .send_ipi(registers, destination, operation)
            .map_err(|_| LiveTimeError::ApicAccess)
    })
}

pub(crate) fn busy_wait_nanoseconds(delay: u64) -> Result<(), LiveTimeError> {
    BSP_TIMER_SERVICE
        .ensure_healthy()
        .map_err(|_| LiveTimeError::Faulted)?;
    let clock = live_clock().ok_or(LiveTimeError::Clock)?;
    let mut clock = clock.lock();
    let start = clock.sample_now()?.nanoseconds;
    let target = start.checked_add(delay).ok_or(LiveTimeError::Clock)?;
    for _ in 0..20_000_000_u32 {
        if clock.sample_now()?.nanoseconds >= target {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(LiveTimeError::Clock)
}

pub(crate) fn register_deadline(
    deadline_ns: u64,
    wake: BlockWakeKey,
) -> Result<DeadlineRegistration, DeadlineRegistrationFailure> {
    if BSP_TIMER_SERVICE.ensure_healthy().is_err() {
        return Err(registration_failure(LiveTimeError::Faulted, wake));
    }
    if wake_binding().is_none() {
        return Err(registration_failure(LiveTimeError::NoWakeRuntime, wake));
    }
    let Some(state) = live_state() else {
        return Err(registration_failure(LiveTimeError::Clock, wake));
    };
    let program_local_timer = match current_cpu_is_timer_service() {
        Ok(value) => value,
        Err(error) => return Err(registration_failure(error, wake)),
    };
    let registration = state
        .lock()
        .register_deadline(deadline_ns, wake, program_local_timer)?;
    if program_local_timer {
        if reconcile_bsp_hardware_arm().is_err() {
            let recovered = {
                let mut state = state.lock();
                let recovered = state
                    .deadlines
                    .cancel(registration)
                    .unwrap_or_else(|_| halt_forever());
                state.record_source_mutation();
                recovered
            };
            return Err(registration_failure(LiveTimeError::ApicAccess, recovered));
        }
    } else if request_bsp_timer_service().is_err() {
        let recovered = {
            let mut state = state.lock();
            let recovered = state
                .deadlines
                .cancel(registration)
                .unwrap_or_else(|_| halt_forever());
            state.record_source_mutation();
            recovered
        };
        return Err(registration_failure(LiveTimeError::IpiTransport, recovered));
    }
    Ok(registration)
}

pub(crate) fn cancel_deadline(registration: DeadlineRegistration) -> Result<(), LiveTimeError> {
    BSP_TIMER_SERVICE
        .ensure_healthy()
        .map_err(|_| LiveTimeError::Faulted)?;
    let Some(state) = live_state() else {
        return Err(LiveTimeError::Clock);
    };
    let program_local_timer = current_cpu_is_timer_service()?;
    state
        .lock()
        .cancel_deadline(registration, program_local_timer)?;
    if program_local_timer {
        reconcile_bsp_hardware_arm()?;
    } else {
        request_bsp_timer_service()?;
    }
    Ok(())
}

fn ap_scheduler_timer_slot(cpu: CpuIndex) -> Result<&'static ApSchedulerTimerSlot, LiveTimeError> {
    if cpu == CpuIndex::BOOTSTRAP {
        return Err(LiveTimeError::CpuIdentity);
    }
    let slot = &AP_SCHEDULER_TIMERS[cpu.index()];
    slot.is_ready()
        .then_some(slot)
        .ok_or(LiveTimeError::Faulted)
}

/// Reconciles one AP's scheduler-only logical source with that AP's physical
/// one-shot. The CPU-local source guard is dropped before Local APIC MMIO and
/// the exact physical generation is revalidated afterward.
fn reconcile_ap_scheduler_hardware(
    cpu: CpuIndex,
) -> Result<Option<crate::task::SchedulerQuantumTicket>, LiveTimeError> {
    if installed_current_cpu_index()? != cpu {
        return Err(LiveTimeError::CpuIdentity);
    }
    let slot = ap_scheduler_timer_slot(cpu)?;
    let mut pending_due = None;
    for _ in 0..8 {
        // AP scheduler deadlines share only the monotonic clock. They never
        // acquire CPU0's unified deadline state or BSP timer-service signal.
        let now_ns = sample_clock_now()?.nanoseconds;
        let intent = {
            let mut state = slot.state.lock();
            if let Some(due) = state.take_due(now_ns)? {
                if pending_due.replace(due).is_some() {
                    return Err(LiveTimeError::Faulted);
                }
            }
            state.prepare_hardware(now_ns)?
        };
        current_local_apic_slot()?.with_owner(|controller, registers| match &intent {
            PreparedApHardwareIntent::Arm(intent) => {
                controller
                    .program_one_shot_timer(registers, intent.shot.initial_count)
                    .map_err(|_| LiveTimeError::ApicAccess)?;
                AP_SCHEDULER_TIMER_MASKED[cpu.index()].store(false, Ordering::Release);
                Ok(())
            }
            PreparedApHardwareIntent::Stop(_) => {
                controller
                    .stop_timer(registers)
                    .map_err(|_| LiveTimeError::ApicAccess)?;
                AP_SCHEDULER_TIMER_MASKED[cpu.index()].store(true, Ordering::Release);
                Ok(())
            }
        })?;
        if slot.state.lock().hardware_intent_is_current(&intent) {
            return Ok(pending_due);
        }
    }
    Err(LiveTimeError::Faulted)
}

/// Replaces the current CPU's scheduler source. CPU0 retains its unified
/// Timer/wait arbiter; each AP mutates only its private quantum source and
/// physical-arm generation. Returns true when the source expired during arm
/// preparation and the caller must revisit its safe-return scheduling gate.
/// In that case an AP has no remaining physical timer to force a later entry.
pub(crate) fn arm_scheduler_quantum(
    ticket: crate::task::SchedulerQuantumTicket,
) -> Result<bool, LiveTimeError> {
    let cpu = installed_current_cpu_index()?;
    if ticket.cpu() != cpu {
        return Err(LiveTimeError::CpuIdentity);
    }
    let due = if cpu == CpuIndex::BOOTSTRAP {
        let state = live_state().ok_or(LiveTimeError::Clock)?;
        let due = state.lock().arm_scheduler_quantum(ticket)?;
        reconcile_bsp_hardware_arm()?;
        due
    } else {
        let slot = ap_scheduler_timer_slot(cpu)?;
        slot.state.lock().arm(ticket)?;
        reconcile_ap_scheduler_hardware(cpu)?
    };
    if let Some(due) = due {
        crate::arch::x86_64::syscall::publish_current_quantum_expiry(due)
            .map_err(|_| LiveTimeError::Faulted)?;
    }
    Ok(due.is_some())
}

pub(crate) fn cancel_scheduler_quantum(
    ticket: crate::task::SchedulerQuantumTicket,
) -> Result<bool, LiveTimeError> {
    let cpu = installed_current_cpu_index()?;
    if ticket.cpu() != cpu {
        return Err(LiveTimeError::CpuIdentity);
    }
    if cpu == CpuIndex::BOOTSTRAP {
        let state = live_state().ok_or(LiveTimeError::Clock)?;
        let cancelled = state.lock().cancel_scheduler_quantum(ticket)?;
        if cancelled {
            reconcile_bsp_hardware_arm()?;
        }
        return Ok(cancelled);
    }
    let slot = ap_scheduler_timer_slot(cpu)?;
    let cancelled = slot.state.lock().cancel(ticket)?;
    let due = reconcile_ap_scheduler_hardware(cpu)?;
    if let Some(due) = due {
        crate::arch::x86_64::syscall::publish_current_quantum_expiry(due)
            .map_err(|_| LiveTimeError::Faulted)?;
    }
    Ok(cancelled)
}

/// Converts an exact CPU-local quantum that became due while IF was clear in a
/// syscall into the same coalesced scheduler request the timer IRQ publishes.
/// A later delivery of the already-pending vector is only a harmless rescan.
pub(crate) fn service_current_scheduler_quantum_deadline() -> Result<bool, LiveTimeError> {
    let cpu = installed_current_cpu_index()?;
    let due = if cpu == CpuIndex::BOOTSTRAP {
        let state = live_state().ok_or(LiveTimeError::Clock)?;
        let due = state.lock().take_due_scheduler_quantum()?;
        if due.is_some() {
            reconcile_bsp_hardware_arm()?;
        }
        due
    } else {
        reconcile_ap_scheduler_hardware(cpu)?
    };
    let Some(ticket) = due else {
        return Ok(false);
    };
    crate::arch::x86_64::syscall::publish_current_quantum_expiry(ticket)
        .map_err(|_| LiveTimeError::Faulted)?;
    Ok(true)
}

#[allow(
    unsafe_code,
    reason = "the fixed assembly timer entry requires one unmangled Rust dispatch symbol"
)]
#[unsafe(no_mangle)]
pub(crate) extern "sysv64" fn dw_x86_64_timer_interrupt_dispatch() {
    if !crate::arch::x86_64::idle::live_idle_wake_is_healthy() {
        halt_forever();
    }
    let cpu = installed_current_cpu_index().unwrap_or_else(|_| halt_forever());
    if cpu != CpuIndex::BOOTSTRAP {
        let scratch = {
            #[allow(
                unsafe_code,
                reason = "the current AP exclusively owns its IF-clear timer outcome slot"
            )]
            unsafe {
                &mut *AP_INTERRUPT_OUTCOMES[cpu.index()].0.get()
            }
        };
        if scratch.is_some() {
            halt_forever();
        }
        *scratch = reconcile_ap_scheduler_hardware(cpu).unwrap_or_else(|_| halt_forever());
        current_local_apic_slot()
            .and_then(PerCpuLocalApicSlot::end_of_interrupt)
            .unwrap_or_else(|_| halt_forever());
        if let Some(ticket) = scratch.take() {
            crate::arch::x86_64::syscall::publish_current_quantum_expiry(ticket)
                .unwrap_or_else(|_| halt_forever());
        }
        return;
    }
    if BSP_TIMER_SERVICE.ensure_healthy().is_err() {
        halt_forever();
    }
    let Some(state) = live_state() else {
        halt_forever();
    };
    #[allow(
        unsafe_code,
        reason = "CPU0 alone owns this scratch and the interrupt gate keeps IF clear through all callback consumption"
    )]
    let outcome = unsafe { &mut *BSP_INTERRUPT_OUTCOME.0.get() };
    {
        let mut state = state.lock();
        state.interrupt(outcome).unwrap_or_else(|_| halt_forever());
    }
    reconcile_bsp_hardware_arm().unwrap_or_else(|_| halt_forever());
    current_local_apic_slot()
        .and_then(PerCpuLocalApicSlot::end_of_interrupt)
        .unwrap_or_else(|_| halt_forever());
    if outcome.wake_count != 0 {
        let Some(binding) = wake_binding() else {
            halt_forever();
        };
        let wake_count = core::mem::take(&mut outcome.wake_count);
        for key in outcome
            .wakes
            .iter_mut()
            .take(wake_count)
            .filter_map(Option::take)
        {
            #[allow(
                unsafe_code,
                reason = "the immutable static wake binding is invoked only after the IRQ-safe time lock has been released"
            )]
            unsafe {
                (binding.handler)(binding.context, key);
            }
        }
    }
    if outcome.timer_expiry_count != 0 {
        let Some(binding) = timer_expiry_binding() else {
            halt_forever();
        };
        let timer_expiry_count = core::mem::take(&mut outcome.timer_expiry_count);
        for token in outcome
            .timer_expiries
            .iter_mut()
            .take(timer_expiry_count)
            .filter_map(Option::take)
        {
            #[allow(
                unsafe_code,
                reason = "the immutable static Timer expiry binding is invoked only after the IRQ-safe time lock has been released"
            )]
            unsafe {
                (binding.handler)(binding.context, token);
            }
        }
    }
    if let Some(ticket) = outcome.scheduler_quantum.take() {
        crate::arch::x86_64::syscall::publish_current_quantum_expiry(ticket)
            .unwrap_or_else(|_| halt_forever());
    }
}

fn read_pm_timer(descriptor: PmTimerDescriptor) -> u32 {
    use crate::arch::x86_64::io_port::ScalarPortIo;

    let mut io = crate::arch::x86_64::io_port::X86PortIo;
    io.read_u32(descriptor.port())
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
