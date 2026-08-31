//! Generation-exact q35 IRQ3 platform owner for DW1-E2C.
//!
//! The source-slot lock precedes the E2A IOAPIC selector/window lock. Neither
//! lock is held while publishing wait/scheduler wakes, issuing LAPIC EOI, or
//! entering object finalization. The fixed route stays unmasked across all
//! ordinary userspace acknowledgement outcomes.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::x86_64::acpi::{
    IoApicRedirectionEntry, IoApicRouteLifecycle, IoApicRouteState, PlatformIrqPolarity,
    PlatformIrqRoute, PlatformIrqTrigger,
};
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use crate::arch::x86_64::ioapic_live::{LiveIoApicError, ValidatedQ35IoApic};
use crate::sync::IrqSpinMutex;

use super::interrupt::{
    InterruptAckOutcome, InterruptBinding, InterruptDelivery, InterruptPlatform,
    InterruptPlatformAck, InterruptPlatformError, InterruptSourceReservation, mint_platform_domain,
};

pub(crate) const Q35_COM2_SOURCE: u32 = 3;
pub(crate) const DELIVERY_STATUS_POLL_LIMIT: usize = 65_536;

const IOAPIC_REDIR_BASE: u32 = 0x10;
const IOAPIC_REDIR_MASK: u32 = 1 << 16;
const IOAPIC_REDIR_DELIVERY_STATUS: u32 = 1 << 12;
const IOAPIC_REDIR_REMOTE_IRR: u32 = 1 << 14;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Q35ControllerError {
    Access,
    RouteDrift,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Q35BspCheckRequest {
    source: u32,
    vector: u8,
    platform_generation: u64,
    request_generation: u64,
}

pub(crate) trait Q35InterruptController: Sync {
    fn route(&self) -> PlatformIrqRoute;
    fn program_and_verify(&self, masked: bool) -> Result<(), Q35ControllerError>;
    fn mask_and_verify(&self) -> Result<(), Q35ControllerError>;
    fn delivery_status_idle(&self) -> Result<bool, Q35ControllerError>;
    fn revalidate_masked_idle(&self) -> Result<(), Q35ControllerError>;
    fn current_cpu_is_bsp(&self) -> Result<bool, Q35ControllerError>;
    fn request_bsp_check(&self, request: Q35BspCheckRequest) -> Result<(), Q35ControllerError>;
    fn bsp_vector_clear(&self) -> Result<bool, Q35ControllerError>;
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl Q35InterruptController for ValidatedQ35IoApic {
    fn route(&self) -> PlatformIrqRoute {
        self.route()
    }

    fn program_and_verify(&self, masked: bool) -> Result<(), Q35ControllerError> {
        let (low_register, high_register) = selected_registers(self.route())?;
        let bits =
            IoApicRedirectionEntry::encode_q35_com2(masked, self.route().bsp_local_apic_id())
                .bits();
        self.with_registers(|registers| {
            // The low dword is masked before destination programming, then is
            // the final publication write. Readback serializes completion.
            registers
                .write_register(low_register, bits as u32 | IOAPIC_REDIR_MASK)
                .map_err(map_live_error)?;
            registers
                .write_register(high_register, (bits >> 32) as u32)
                .map_err(map_live_error)?;
            registers
                .write_register(low_register, bits as u32)
                .map_err(map_live_error)?;
            let observed_low = registers
                .read_register(low_register)
                .map_err(map_live_error)?;
            let observed_high = registers
                .read_register(high_register)
                .map_err(map_live_error)?;
            verify_route(bits, observed_low, observed_high, masked)
        })
    }

    fn mask_and_verify(&self) -> Result<(), Q35ControllerError> {
        let (low_register, _) = selected_registers(self.route())?;
        self.with_registers(|registers| {
            let low = registers
                .read_register(low_register)
                .map_err(map_live_error)?;
            registers
                .write_register(low_register, low | IOAPIC_REDIR_MASK)
                .map_err(map_live_error)?;
            let observed = registers
                .read_register(low_register)
                .map_err(map_live_error)?;
            (observed & IOAPIC_REDIR_MASK != 0)
                .then_some(())
                .ok_or(Q35ControllerError::RouteDrift)
        })
    }

    fn delivery_status_idle(&self) -> Result<bool, Q35ControllerError> {
        let (low_register, _) = selected_registers(self.route())?;
        self.read_register(low_register)
            .map(|low| low & IOAPIC_REDIR_DELIVERY_STATUS == 0)
            .map_err(map_live_error)
    }

    fn revalidate_masked_idle(&self) -> Result<(), Q35ControllerError> {
        let (low_register, high_register) = selected_registers(self.route())?;
        let expected =
            IoApicRedirectionEntry::encode_q35_com2(true, self.route().bsp_local_apic_id()).bits();
        self.with_registers(|registers| {
            let low = registers
                .read_register(low_register)
                .map_err(map_live_error)?;
            let high = registers
                .read_register(high_register)
                .map_err(map_live_error)?;
            verify_route(expected, low, high, true)?;
            (low & IOAPIC_REDIR_DELIVERY_STATUS == 0)
                .then_some(())
                .ok_or(Q35ControllerError::RouteDrift)
        })
    }

    fn bsp_vector_clear(&self) -> Result<bool, Q35ControllerError> {
        crate::time::q35_bsp_vector_is_clear().map_err(|_| Q35ControllerError::Access)
    }

    fn current_cpu_is_bsp(&self) -> Result<bool, Q35ControllerError> {
        crate::time::q35_current_cpu_is_bsp().map_err(|_| Q35ControllerError::Access)
    }

    fn request_bsp_check(&self, request: Q35BspCheckRequest) -> Result<(), Q35ControllerError> {
        crate::time::request_q35_bsp_retirement_check(
            request.source,
            request.vector,
            request.platform_generation,
            request.request_generation,
        )
        .map_err(|_| Q35ControllerError::Access)
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn map_live_error(_: LiveIoApicError) -> Q35ControllerError {
    Q35ControllerError::Access
}

fn selected_registers(route: PlatformIrqRoute) -> Result<(u32, u32), Q35ControllerError> {
    let index = route
        .gsi()
        .checked_sub(route.controller().gsi_base())
        .ok_or(Q35ControllerError::RouteDrift)?;
    let low = IOAPIC_REDIR_BASE
        .checked_add(index.checked_mul(2).ok_or(Q35ControllerError::RouteDrift)?)
        .ok_or(Q35ControllerError::RouteDrift)?;
    let high = low.checked_add(1).ok_or(Q35ControllerError::RouteDrift)?;
    (high <= 0xff)
        .then_some((low, high))
        .ok_or(Q35ControllerError::RouteDrift)
}

fn verify_route(
    expected: u64,
    observed_low: u32,
    observed_high: u32,
    masked: bool,
) -> Result<(), Q35ControllerError> {
    // Delivery Status and Remote IRR are read-only observations. Remote IRR
    // is not meaningful for this edge route and may not be compared as a
    // writable template bit.
    let writable_low = observed_low & !(IOAPIC_REDIR_DELIVERY_STATUS | IOAPIC_REDIR_REMOTE_IRR);
    if writable_low != expected as u32
        || observed_high != (expected >> 32) as u32
        || (observed_low & IOAPIC_REDIR_MASK != 0) != masked
    {
        return Err(Q35ControllerError::RouteDrift);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Q35DeliverySnapshot {
    Live {
        delivery: InterruptDelivery,
        generation: u64,
    },
    Retiring {
        generation: u64,
    },
    Orphan,
}

#[derive(Clone, Copy)]
struct Q35SourceState {
    lifecycle: IoApicRouteLifecycle,
    in_handler_generation: u64,
    in_handler: u32,
    next_request_generation: u64,
    outstanding_request: Option<Q35BspCheckRequest>,
}

impl Q35SourceState {
    const fn new() -> Self {
        Self {
            lifecycle: IoApicRouteLifecycle::new(),
            in_handler_generation: 0,
            in_handler: 0,
            next_request_generation: 1,
            outstanding_request: None,
        }
    }
}

pub(crate) struct Q35InterruptCounters {
    physical_entries: AtomicU64,
    exact_deliveries: AtomicU64,
    pending_deliveries: AtomicU64,
    acknowledgements: AtomicU64,
    stale_orphans: AtomicU64,
    route_masks: AtomicU64,
    route_unmasks: AtomicU64,
    final_releases: AtomicU64,
    generation_replacements: AtomicU64,
}

impl Q35InterruptCounters {
    const fn new() -> Self {
        Self {
            physical_entries: AtomicU64::new(0),
            exact_deliveries: AtomicU64::new(0),
            pending_deliveries: AtomicU64::new(0),
            acknowledgements: AtomicU64::new(0),
            stale_orphans: AtomicU64::new(0),
            route_masks: AtomicU64::new(0),
            route_unmasks: AtomicU64::new(0),
            final_releases: AtomicU64::new(0),
            generation_replacements: AtomicU64::new(0),
        }
    }

    fn increment(counter: &AtomicU64) {
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            Some(value.saturating_add(1))
        });
    }
}

/// The one real q35 source platform. Its controller is permanently mapped by
/// E2A and its domain/generation never escapes the private Interrupt binding.
pub(crate) struct Q35InterruptPlatform {
    domain: u64,
    controller: &'static dyn Q35InterruptController,
    source: IrqSpinMutex<Q35SourceState>,
    counters: Q35InterruptCounters,
}

impl Q35InterruptPlatform {
    pub(crate) fn new(
        controller: &'static dyn Q35InterruptController,
    ) -> Result<Self, Q35ControllerError> {
        // Source 3 is the native logical identity. A valid MADT ISO may map
        // ISA IRQ3 to a different edge/high GSI, so only the resolved route's
        // vector/controller invariants are fixed here.
        let route = controller.route();
        if route.vector() != 0x30
            || route.polarity() != PlatformIrqPolarity::ActiveHigh
            || route.trigger() != PlatformIrqTrigger::Edge
            || selected_registers(route).is_err()
        {
            return Err(Q35ControllerError::RouteDrift);
        }
        controller.program_and_verify(true)?;
        Ok(Self {
            domain: mint_platform_domain(),
            controller,
            source: IrqSpinMutex::new(Q35SourceState::new()),
            counters: Q35InterruptCounters::new(),
        })
    }

    pub(crate) fn snapshot_delivery(&self) -> Q35DeliverySnapshot {
        Q35InterruptCounters::increment(&self.counters.physical_entries);
        let mut source = self.source.lock();
        match source.lifecycle.state() {
            IoApicRouteState::LiveUnmasked { generation } => {
                if !begin_handler(&mut source, generation) {
                    Q35InterruptCounters::increment(&self.counters.stale_orphans);
                    drop(source);
                    self.fail_safe_mask();
                    return Q35DeliverySnapshot::Orphan;
                }
                Q35InterruptCounters::increment(&self.counters.exact_deliveries);
                Q35DeliverySnapshot::Live {
                    delivery: InterruptDelivery {
                        binding: InterruptBinding::new_private(
                            self.domain,
                            Q35_COM2_SOURCE,
                            generation,
                        ),
                    },
                    generation,
                }
            }
            IoApicRouteState::Retiring { generation }
            | IoApicRouteState::RetiringMasked { generation } => {
                if !begin_handler(&mut source, generation) {
                    Q35InterruptCounters::increment(&self.counters.stale_orphans);
                    drop(source);
                    self.fail_safe_mask();
                    return Q35DeliverySnapshot::Orphan;
                }
                Q35DeliverySnapshot::Retiring { generation }
            }
            _ => {
                Q35InterruptCounters::increment(&self.counters.stale_orphans);
                drop(source);
                self.fail_safe_mask();
                Q35DeliverySnapshot::Orphan
            }
        }
    }

    fn fail_safe_mask(&self) {
        if self.controller.mask_and_verify().is_ok() {
            Q35InterruptCounters::increment(&self.counters.route_masks);
        }
    }

    pub(crate) fn record_pending_delivery(&self) {
        Q35InterruptCounters::increment(&self.counters.pending_deliveries);
    }

    pub(crate) fn complete_handler(&self, generation: u64) {
        let mut source = self.source.lock();
        assert_eq!(source.in_handler_generation, generation);
        source.in_handler = source
            .in_handler
            .checked_sub(1)
            .expect("q35 handler completion underflow");
        if source.in_handler == 0 {
            source.in_handler_generation = 0;
        }
    }

    /// Attempts the ordered fixed-vector reuse proof. `Ok(false)` retains the
    /// unchanged generation in quarantine for a later carrier safe-point.
    pub(crate) fn try_finish_retirement(
        &self,
        binding: InterruptBinding,
    ) -> Result<bool, Q35ControllerError> {
        validate_binding(self.domain, binding)?;
        {
            let mut source = self.source.lock();
            match source.lifecycle.state() {
                IoApicRouteState::LiveUnmasked { generation }
                    if generation == binding.generation() =>
                {
                    source
                        .lifecycle
                        .begin_retire(generation)
                        .map_err(|_| Q35ControllerError::RouteDrift)?;
                }
                IoApicRouteState::Retiring { generation }
                | IoApicRouteState::RetiringMasked { generation }
                    if generation == binding.generation() => {}
                _ => return Err(Q35ControllerError::RouteDrift),
            }
        }

        if matches!(
            self.source.lock().lifecycle.state(),
            IoApicRouteState::Retiring { .. }
        ) {
            self.controller.mask_and_verify()?;
            Q35InterruptCounters::increment(&self.counters.route_masks);
            let mut source = self.source.lock();
            source
                .lifecycle
                .mask(binding.generation())
                .map_err(|_| Q35ControllerError::RouteDrift)?;
        }

        let mut idle = false;
        for _ in 0..DELIVERY_STATUS_POLL_LIMIT {
            if self.controller.delivery_status_idle()? {
                idle = true;
                break;
            }
        }
        if !idle {
            return Ok(false);
        }
        if self.source.lock().in_handler != 0 {
            return Ok(false);
        }
        self.controller.revalidate_masked_idle()?;
        let request = {
            let mut source = self.source.lock();
            let request = match source.outstanding_request {
                Some(request) => request,
                None => {
                    let request_generation = source.next_request_generation;
                    if request_generation == 0 {
                        return Ok(false);
                    }
                    source.next_request_generation = request_generation.checked_add(1).unwrap_or(0);
                    let request = Q35BspCheckRequest {
                        source: binding.source(),
                        vector: 0x30,
                        platform_generation: binding.generation(),
                        request_generation,
                    };
                    source.outstanding_request = Some(request);
                    request
                }
            };
            if request.source != Q35_COM2_SOURCE
                || request.vector != 0x30
                || request.platform_generation != binding.generation()
                || request.request_generation == 0
            {
                return Ok(false);
            }
            request
        };
        if !self.controller.current_cpu_is_bsp()? {
            self.controller.request_bsp_check(request)?;
            return Ok(false);
        }
        if !self.controller.bsp_vector_clear()? {
            return Ok(false);
        }
        self.controller.revalidate_masked_idle()?;
        let mut source = self.source.lock();
        if source.in_handler != 0 || source.outstanding_request != Some(request) {
            return Ok(false);
        }
        source.outstanding_request = None;
        source
            .lifecycle
            .release(binding.generation())
            .map_err(|_| Q35ControllerError::RouteDrift)?;
        Q35InterruptCounters::increment(&self.counters.final_releases);
        Ok(true)
    }
}

fn begin_handler(source: &mut Q35SourceState, generation: u64) -> bool {
    if source.in_handler != 0 && source.in_handler_generation != generation {
        return false;
    }
    let Some(next) = source.in_handler.checked_add(1) else {
        return false;
    };
    source.in_handler_generation = generation;
    source.in_handler = next;
    true
}

fn validate_binding(domain: u64, binding: InterruptBinding) -> Result<(), Q35ControllerError> {
    if binding.domain() != domain || binding.source() != Q35_COM2_SOURCE {
        return Err(Q35ControllerError::RouteDrift);
    }
    Ok(())
}

impl InterruptPlatform for Q35InterruptPlatform {
    fn reserve_source(
        &self,
        source: u32,
    ) -> Result<InterruptSourceReservation, InterruptPlatformError> {
        if source != Q35_COM2_SOURCE {
            return Err(InterruptPlatformError::InvalidSource);
        }
        let generation = {
            let mut state = self.source.lock();
            state.lifecycle.reserve().map_err(|error| match error {
                crate::arch::x86_64::acpi::IoApicRouteTransitionError::Busy => {
                    InterruptPlatformError::SourceInUse
                }
                crate::arch::x86_64::acpi::IoApicRouteTransitionError::GenerationExhausted => {
                    InterruptPlatformError::Capacity
                }
                _ => InterruptPlatformError::BadState,
            })?
        };
        if self.controller.program_and_verify(true).is_err() {
            self.source
                .lock()
                .lifecycle
                .release(generation)
                .expect("failed q35 reserve reprobe rolls back its exact generation");
            return Err(InterruptPlatformError::BadState);
        }
        if generation > 1 {
            Q35InterruptCounters::increment(&self.counters.generation_replacements);
        }
        let binding = InterruptBinding::new_private(self.domain, source, generation);
        #[cfg(all(deepwyrm_dw1e_evidence, target_os = "none"))]
        crate::test_support::DW1E_EVIDENCE
            .observe_reserved(binding)
            .unwrap_or_else(|error| panic!("selector-31 reserve observation failed: {error:?}"));
        Ok(InterruptSourceReservation { binding })
    }

    fn cancel_source(
        &self,
        reservation: InterruptSourceReservation,
    ) -> Result<(), InterruptPlatformError> {
        validate_binding(self.domain, reservation.binding)
            .map_err(|_| InterruptPlatformError::StaleBinding)?;
        self.controller
            .program_and_verify(true)
            .map_err(|_| InterruptPlatformError::BadState)?;
        self.source
            .lock()
            .lifecycle
            .release(reservation.binding.generation())
            .map_err(|_| InterruptPlatformError::BadState)
    }

    fn commit_source(&self, reservation: InterruptSourceReservation) -> InterruptBinding {
        validate_binding(self.domain, reservation.binding)
            .expect("committed q35 reservation retains exact domain/source");
        {
            let mut source = self.source.lock();
            source
                .lifecycle
                .commit(reservation.binding.generation())
                .expect("committed q35 reservation retains exact generation");
        }
        // The route becomes logically live before the final unmask write.
        // The controller transaction is the final physical publication and
        // runs after dropping the source guard, preserving the E0 partial
        // order. No physical edge can enter through the still-masked route
        // before this write, while every later edge snapshots LiveUnmasked.
        self.controller
            .program_and_verify(false)
            .expect("validated q35 route must commit at the no-fail publication point");
        Q35InterruptCounters::increment(&self.counters.route_unmasks);
        reservation.binding
    }

    fn mask_source(&self, binding: InterruptBinding) {
        // Rollback/finalization callers immediately follow with release. The
        // full quarantine proof is owned by `release_source`.
        validate_binding(self.domain, binding).expect("owned q35 binding remains exact");
        let state = self.source.lock().lifecycle.state();
        if matches!(state, IoApicRouteState::LiveUnmasked { .. }) {
            self.source
                .lock()
                .lifecycle
                .begin_retire(binding.generation())
                .expect("owned q35 binding begins exact retirement");
        }
        self.controller
            .mask_and_verify()
            .expect("owned q35 route mask/readback is no-fail");
        Q35InterruptCounters::increment(&self.counters.route_masks);
        if matches!(
            self.source.lock().lifecycle.state(),
            IoApicRouteState::Retiring { .. }
        ) {
            self.source
                .lock()
                .lifecycle
                .mask(binding.generation())
                .expect("masked q35 route retains exact generation");
        }
    }

    fn acknowledge_source(
        &self,
        binding: InterruptBinding,
    ) -> Result<InterruptPlatformAck, InterruptPlatformError> {
        validate_binding(self.domain, binding).map_err(|_| InterruptPlatformError::StaleBinding)?;
        match self.source.lock().lifecycle.state() {
            IoApicRouteState::LiveUnmasked { generation } if generation == binding.generation() => {
                Ok(InterruptPlatformAck { binding })
            }
            IoApicRouteState::LiveUnmasked { .. } => Err(InterruptPlatformError::StaleBinding),
            _ => Err(InterruptPlatformError::BadState),
        }
    }

    fn complete_ack(&self, ack: InterruptPlatformAck, _outcome: InterruptAckOutcome) {
        validate_binding(self.domain, ack.binding)
            .expect("prepared q35 acknowledgement retains exact domain/source");
        assert!(matches!(
            self.source.lock().lifecycle.state(),
            IoApicRouteState::LiveUnmasked { generation }
                if generation == ack.binding.generation()
        ));
        Q35InterruptCounters::increment(&self.counters.acknowledgements);
    }

    fn release_source(&self, binding: InterruptBinding) {
        if !self
            .try_finish_retirement(binding)
            .expect("owned q35 retirement proof cannot drift")
        {
            panic!("q35 retirement requires deferred-finalizer staging");
        }
    }

    fn retire_source(&self, binding: InterruptBinding) -> super::interrupt::InterruptRetirement {
        match self.try_finish_retirement(binding) {
            Ok(true) => super::interrupt::InterruptRetirement::Complete,
            Ok(false) | Err(_) => super::interrupt::InterruptRetirement::Deferred,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::interrupt::InterruptRetirement;
    use super::*;
    use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};

    struct FakeController {
        route_bits: AtomicU64,
        pending_reads: AtomicU32,
        bsp_clear: AtomicBool,
        current_bsp: AtomicBool,
        requests: AtomicU32,
    }

    impl FakeController {
        const fn new() -> Self {
            Self {
                route_bits: AtomicU64::new(0x0000_0000_0001_0030),
                pending_reads: AtomicU32::new(0),
                bsp_clear: AtomicBool::new(true),
                current_bsp: AtomicBool::new(true),
                requests: AtomicU32::new(0),
            }
        }
    }

    impl Q35InterruptController for FakeController {
        fn route(&self) -> PlatformIrqRoute {
            PlatformIrqRoute::test_q35(
                crate::arch::x86_64::acpi::IoApicDescriptor::test_descriptor(0, 0xfec0_0000, 0),
                5,
                0,
            )
        }

        fn program_and_verify(&self, masked: bool) -> Result<(), Q35ControllerError> {
            self.route_bits.store(
                IoApicRedirectionEntry::encode_q35_com2(masked, 0).bits(),
                Ordering::Release,
            );
            Ok(())
        }

        fn mask_and_verify(&self) -> Result<(), Q35ControllerError> {
            self.route_bits
                .fetch_or(u64::from(IOAPIC_REDIR_MASK), Ordering::AcqRel);
            Ok(())
        }

        fn delivery_status_idle(&self) -> Result<bool, Q35ControllerError> {
            Ok(self
                .pending_reads
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_err())
        }

        fn revalidate_masked_idle(&self) -> Result<(), Q35ControllerError> {
            (self.route_bits.load(Ordering::Acquire) & u64::from(IOAPIC_REDIR_MASK) != 0
                && self.pending_reads.load(Ordering::Acquire) == 0)
                .then_some(())
                .ok_or(Q35ControllerError::RouteDrift)
        }

        fn bsp_vector_clear(&self) -> Result<bool, Q35ControllerError> {
            Ok(self.bsp_clear.load(Ordering::Acquire))
        }

        fn current_cpu_is_bsp(&self) -> Result<bool, Q35ControllerError> {
            Ok(self.current_bsp.load(Ordering::Acquire))
        }

        fn request_bsp_check(&self, request: Q35BspCheckRequest) -> Result<(), Q35ControllerError> {
            assert_eq!(request.source, Q35_COM2_SOURCE);
            assert_eq!(request.vector, 0x30);
            assert_ne!(request.platform_generation, 0);
            assert_ne!(request.request_generation, 0);
            self.requests.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    static FAKE: FakeController = FakeController::new();

    // Full controller/finalizer fault injection is exercised through the
    // state-machine tests in the adjacent Interrupt suite. Keep this module's
    // pure helpers focused on register identity and read-only status handling.
    #[test]
    fn readback_ignores_read_only_status_bits_only() {
        let expected = IoApicRedirectionEntry::encode_q35_com2(true, 2).bits();
        assert_eq!(
            verify_route(
                expected,
                expected as u32 | IOAPIC_REDIR_DELIVERY_STATUS,
                (expected >> 32) as u32,
                true
            ),
            Ok(())
        );
        assert_eq!(
            verify_route(
                expected,
                expected as u32 | IOAPIC_REDIR_REMOTE_IRR,
                (expected >> 32) as u32,
                true
            ),
            Ok(())
        );
        assert_eq!(
            verify_route(
                expected,
                expected as u32 | (1 << 13),
                (expected >> 32) as u32,
                true
            ),
            Err(Q35ControllerError::RouteDrift)
        );
    }

    #[test]
    fn edge_route_stays_unmasked_across_ack_and_quarantines_until_exact_clear_proof() {
        let platform = Q35InterruptPlatform::new(&FAKE).unwrap();
        let reservation = platform.reserve_source(Q35_COM2_SOURCE).unwrap();
        let binding = reservation.binding;
        platform.commit_source(reservation);
        assert_eq!(
            FAKE.route_bits.load(Ordering::Acquire) & u64::from(IOAPIC_REDIR_MASK),
            0
        );

        let Q35DeliverySnapshot::Live { generation, .. } = platform.snapshot_delivery() else {
            panic!("live route did not produce an exact delivery snapshot");
        };
        let ack = platform.acknowledge_source(binding).unwrap();
        platform.complete_ack(ack, InterruptAckOutcome::PendingAfterRace);
        assert_eq!(
            FAKE.route_bits.load(Ordering::Acquire) & u64::from(IOAPIC_REDIR_MASK),
            0
        );

        // Logical retirement and physical mask precede handler/BSP proof.
        assert_eq!(
            platform.retire_source(binding),
            InterruptRetirement::Deferred
        );
        assert_ne!(
            FAKE.route_bits.load(Ordering::Acquire) & u64::from(IOAPIC_REDIR_MASK),
            0
        );
        platform.complete_handler(generation);
        FAKE.current_bsp.store(false, Ordering::Release);
        assert_eq!(
            platform.retire_source(binding),
            InterruptRetirement::Deferred
        );
        assert_eq!(FAKE.requests.load(Ordering::Acquire), 1);
        FAKE.current_bsp.store(true, Ordering::Release);
        FAKE.bsp_clear.store(false, Ordering::Release);
        assert_eq!(
            platform.retire_source(binding),
            InterruptRetirement::Deferred
        );
        FAKE.bsp_clear.store(true, Ordering::Release);
        assert_eq!(
            platform.retire_source(binding),
            InterruptRetirement::Complete
        );

        let replacement = platform.reserve_source(Q35_COM2_SOURCE).unwrap();
        assert!(replacement.binding.generation() > binding.generation());
        platform.cancel_source(replacement).unwrap();

        let timeout_reservation = platform.reserve_source(Q35_COM2_SOURCE).unwrap();
        let timeout_binding = timeout_reservation.binding;
        platform.commit_source(timeout_reservation);
        FAKE.pending_reads.store(
            u32::try_from(DELIVERY_STATUS_POLL_LIMIT).unwrap() + 1,
            Ordering::Release,
        );
        assert_eq!(
            platform.retire_source(timeout_binding),
            InterruptRetirement::Deferred
        );
        assert_eq!(FAKE.pending_reads.load(Ordering::Acquire), 1);
        assert!(matches!(
            platform.reserve_source(Q35_COM2_SOURCE),
            Err(InterruptPlatformError::SourceInUse)
        ));
        assert_eq!(
            platform.retire_source(timeout_binding),
            InterruptRetirement::Complete
        );

        assert_eq!(platform.snapshot_delivery(), Q35DeliverySnapshot::Orphan);
        platform
            .counters
            .pending_deliveries
            .store(u64::MAX, Ordering::Relaxed);
        platform.record_pending_delivery();
        assert_eq!(
            platform.counters.pending_deliveries.load(Ordering::Relaxed),
            u64::MAX
        );
    }
}
