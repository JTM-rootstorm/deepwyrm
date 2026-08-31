//! Target-only q35 IOAPIC mapping and probe boundary for DW1-E2A.
//!
//! This module owns no route lifecycle and installs no redirection entry.  It
//! first uses a bounded transient UC/NX mapping to measure every firmware
//! candidate, then retains exactly the controller selected by E1's pure route
//! resolver through one permanent UC/NX leaf.  E2C owns binding, masking,
//! programming, and delivery.

#![allow(
    dead_code,
    unused_imports,
    reason = "the reserved DW1-E product cfg reaches this target-only boundary after E2B registers it"
)]

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::arch::x86_64::acpi::{
    IoApicDescriptor, IoApicProbe, MAX_MADT_IOAPICS, PlatformIrqRoute, Q35Com2MadtSnapshot,
    Q35Com2RouteError, resolve_q35_com2_route_snapshot,
};
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use crate::arch::x86_64::mm::{ActiveDeepPaging, FrameAddress, LiveActivePagingTarget};
use crate::sync::IrqSpinMutex;

const PAGE_SIZE: u64 = 4096;
const IOREGSEL: u32 = 0x00;
const IOWIN: u32 = 0x10;
const IOAPIC_REG_ID: u32 = 0x00;
const IOAPIC_REG_VERSION: u32 = 0x01;
const SLOT_EMPTY: u8 = 0;
const SLOT_PUBLISHING: u8 = 1;
const SLOT_READY: u8 = 2;
const SLOT_FAULTED: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveIoApicError {
    Mapping,
    InvalidMmioBase,
    InvalidRegisterOffset,
    ControllerId { expected: u8, observed: u8 },
    InvalidVersion,
    InvalidCapacity,
    ProbeDrift,
    Route(Q35Com2RouteError),
    AlreadyInitialized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LiveIoApicProbe {
    id: u8,
    version: u8,
    redirection_entries: u32,
}

impl LiveIoApicProbe {
    pub(crate) const fn id(self) -> u8 {
        self.id
    }

    pub(crate) const fn version(self) -> u8 {
        self.version
    }

    pub(crate) const fn redirection_entries(self) -> u32 {
        self.redirection_entries
    }
}

/// The one permanent kernel mapping selected after candidate probing.  The
/// selector/window pair remains behind this IRQ-safe lock; no raw register
/// pointer can escape this owner.
pub(crate) struct ValidatedQ35IoApic {
    route: PlatformIrqRoute,
    probe: LiveIoApicProbe,
    registers: IrqSpinMutex<LiveIoApicMmio>,
}

impl ValidatedQ35IoApic {
    pub(crate) const fn route(&self) -> PlatformIrqRoute {
        self.route
    }

    pub(crate) const fn probe(&self) -> LiveIoApicProbe {
        self.probe
    }

    pub(crate) fn read_register(&self, register: u32) -> Result<u32, LiveIoApicError> {
        self.registers.lock().read_register(register)
    }

    /// E2C may perform one bounded controller transaction while this exact
    /// selector/window owner is held. It must release the guard before taking
    /// any wait, scheduler, process, object, or finalization lock.
    pub(crate) fn with_registers<T>(&self, operation: impl FnOnce(&mut LiveIoApicMmio) -> T) -> T {
        operation(&mut self.registers.lock())
    }
}

struct IoApicSlot {
    state: AtomicU8,
    owner: UnsafeCell<MaybeUninit<ValidatedQ35IoApic>>,
}

impl IoApicSlot {
    const fn empty() -> Self {
        Self {
            state: AtomicU8::new(SLOT_EMPTY),
            owner: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn publish(&self, owner: ValidatedQ35IoApic) -> Result<(), LiveIoApicError> {
        self.state
            .compare_exchange(
                SLOT_EMPTY,
                SLOT_PUBLISHING,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .map_err(|_| LiveIoApicError::AlreadyInitialized)?;
        #[allow(
            unsafe_code,
            reason = "the one-shot BSP E2A path owns the unpublished IOAPIC slot until its release publication"
        )]
        unsafe {
            (*self.owner.get()).write(owner);
        }
        self.state.store(SLOT_READY, Ordering::Release);
        Ok(())
    }

    fn fault(&self) {
        let _ = self.state.compare_exchange(
            SLOT_EMPTY,
            SLOT_FAULTED,
            Ordering::Release,
            Ordering::Relaxed,
        );
    }

    fn get(&self) -> Option<&'static ValidatedQ35IoApic> {
        if self.state.load(Ordering::Acquire) != SLOT_READY {
            return None;
        }
        #[allow(
            unsafe_code,
            reason = "the release-published IOAPIC owner is immutable and remains permanently retained"
        )]
        Some(unsafe { (*self.owner.get()).assume_init_ref() })
    }
}

// SAFETY: publication is one-shot BSP-only; readers obtain the immutable
// owner only after the release state transition, and volatile selector/window
// access remains serialized by `registers`.
#[allow(
    unsafe_code,
    reason = "publication is one-shot BSP-only and all shared register access remains IRQ-lock serialized"
)]
unsafe impl Sync for IoApicSlot {}

static Q35_IOAPIC: IoApicSlot = IoApicSlot::empty();

pub(crate) fn q35_ioapic() -> Option<&'static ValidatedQ35IoApic> {
    Q35_IOAPIC.get()
}

/// Maps/probes every bounded MADT candidate transiently, resolves the one
/// exact q35 route, then installs and re-probes only that selected controller
/// through a permanent UC/NX leaf.  The route remains untouched and masked.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn initialize_q35_ioapic<
    'root,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
>(
    active: &mut ActiveDeepPaging<LiveActivePagingTarget<'root, RANGE_CAPACITY, ROLE_CAPACITY>>,
    snapshot: Q35Com2MadtSnapshot,
) -> Result<(), LiveIoApicError> {
    let result = initialize_q35_ioapic_inner(active, snapshot);
    if result.is_err() {
        Q35_IOAPIC.fault();
    }
    result
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn initialize_q35_ioapic_inner<'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    active: &mut ActiveDeepPaging<LiveActivePagingTarget<'root, RANGE_CAPACITY, ROLE_CAPACITY>>,
    snapshot: Q35Com2MadtSnapshot,
) -> Result<(), LiveIoApicError> {
    let count = snapshot.controller_count();
    if count == 0 || count > MAX_MADT_IOAPICS {
        return Err(LiveIoApicError::Route(Q35Com2RouteError::MissingIoApic));
    }
    let first = snapshot
        .controller(0)
        .ok_or(LiveIoApicError::Route(Q35Com2RouteError::InvalidMadt))?;
    let first_measured = probe_candidate(active, first)?;
    let mut probes = [IoApicProbe::new(first, 1); MAX_MADT_IOAPICS];
    let mut measurements = [first_measured; MAX_MADT_IOAPICS];
    for (index, probe) in probes.iter_mut().take(count).enumerate() {
        let descriptor = snapshot
            .controller(index)
            .ok_or(LiveIoApicError::Route(Q35Com2RouteError::InvalidMadt))?;
        let measured = if index == 0 {
            first_measured
        } else {
            probe_candidate(active, descriptor)?
        };
        *probe = IoApicProbe::new(descriptor, measured.redirection_entries());
        measurements[index] = measured;
    }
    let route = resolve_q35_com2_route_snapshot(snapshot, &probes[..count])
        .map_err(LiveIoApicError::Route)?;
    let (expected, expected_measurement) = probes
        .iter()
        .take(count)
        .enumerate()
        .find_map(|(index, probe)| {
            (snapshot.controller(index) == Some(route.controller()))
                .then_some((*probe, measurements[index]))
        })
        .ok_or(LiveIoApicError::Route(
            Q35Com2RouteError::ProbeDoesNotMatchMadt,
        ))?;
    let mut controller = map_permanent(active, route.controller())?;
    let measured = controller.probe(route.controller())?;
    if measured.redirection_entries() != expected.redirection_entries()
        || measured.id() != expected.descriptor().id()
        || measured.version() != expected_measurement.version()
    {
        return Err(LiveIoApicError::ProbeDrift);
    }
    if route.gsi() < route.controller().gsi_base()
        || route.gsi() - route.controller().gsi_base() >= measured.redirection_entries()
    {
        return Err(LiveIoApicError::Route(Q35Com2RouteError::UncoveredGsi(
            route.gsi(),
        )));
    }
    Q35_IOAPIC.publish(ValidatedQ35IoApic {
        route,
        probe: measured,
        registers: IrqSpinMutex::new(controller),
    })
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn probe_candidate<'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    active: &mut ActiveDeepPaging<LiveActivePagingTarget<'root, RANGE_CAPACITY, ROLE_CAPACITY>>,
    descriptor: IoApicDescriptor,
) -> Result<LiveIoApicProbe, LiveIoApicError> {
    let frame = frame_for(active, descriptor)?;
    active
        .with_bootstrap_kernel_mmio_page(frame, |base| {
            let controller = LiveIoApicMmio::new(base)?;
            controller.probe(descriptor)
        })
        .map_err(|_| LiveIoApicError::Mapping)?
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn map_permanent<'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    active: &mut ActiveDeepPaging<LiveActivePagingTarget<'root, RANGE_CAPACITY, ROLE_CAPACITY>>,
    descriptor: IoApicDescriptor,
) -> Result<LiveIoApicMmio, LiveIoApicError> {
    let frame = frame_for(active, descriptor)?;
    let base = active
        .install_kernel_mmio_page(frame)
        .map_err(|_| LiveIoApicError::Mapping)?;
    LiveIoApicMmio::new(base)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn frame_for<'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    active: &ActiveDeepPaging<LiveActivePagingTarget<'root, RANGE_CAPACITY, ROLE_CAPACITY>>,
    descriptor: IoApicDescriptor,
) -> Result<FrameAddress, LiveIoApicError> {
    FrameAddress::new(
        descriptor.physical_address(),
        active.root().physical_limit(),
    )
    .map_err(|_| LiveIoApicError::Mapping)
}

pub(crate) struct LiveIoApicMmio {
    base: u64,
}

impl LiveIoApicMmio {
    const fn new(base: u64) -> Result<Self, LiveIoApicError> {
        if base < 0xffff_8000_0000_0000 || !base.is_multiple_of(PAGE_SIZE) {
            return Err(LiveIoApicError::InvalidMmioBase);
        }
        Ok(Self { base })
    }

    fn address(&self, offset: u32) -> Result<*mut u32, LiveIoApicError> {
        if !matches!(offset, IOREGSEL | IOWIN) {
            return Err(LiveIoApicError::InvalidRegisterOffset);
        }
        Ok((self.base + u64::from(offset)) as *mut u32)
    }

    #[allow(
        unsafe_code,
        reason = "the E2A UC/NX IOAPIC mapping permits only aligned volatile IOREGSEL/IOWIN u32 transactions"
    )]
    pub(crate) fn read_register(&mut self, register: u32) -> Result<u32, LiveIoApicError> {
        let selector = self.address(IOREGSEL)?;
        let window = self.address(IOWIN)?;
        unsafe {
            core::ptr::write_volatile(selector, register);
            Ok(core::ptr::read_volatile(window.cast_const()))
        }
    }

    #[allow(
        unsafe_code,
        reason = "the E2A UC/NX IOAPIC mapping permits only aligned volatile IOREGSEL/IOWIN u32 transactions"
    )]
    pub(crate) fn write_register(
        &mut self,
        register: u32,
        value: u32,
    ) -> Result<(), LiveIoApicError> {
        let selector = self.address(IOREGSEL)?;
        let window = self.address(IOWIN)?;
        unsafe {
            core::ptr::write_volatile(selector, register);
            core::ptr::write_volatile(window, value);
        }
        Ok(())
    }

    fn probe(&mut self, descriptor: IoApicDescriptor) -> Result<LiveIoApicProbe, LiveIoApicError> {
        decode_probe(
            descriptor,
            self.read_register(IOAPIC_REG_ID)?,
            self.read_register(IOAPIC_REG_VERSION)?,
        )
    }
}

fn decode_probe(
    descriptor: IoApicDescriptor,
    id_register: u32,
    version_register: u32,
) -> Result<LiveIoApicProbe, LiveIoApicError> {
    let id = (id_register >> 24) as u8;
    if id != descriptor.id() {
        return Err(LiveIoApicError::ControllerId {
            expected: descriptor.id(),
            observed: id,
        });
    }
    let revision = version_register as u8;
    let redirection_entries = u32::from(((version_register >> 16) & 0xff) as u8) + 1;
    if revision == 0 {
        return Err(LiveIoApicError::InvalidVersion);
    }
    if redirection_entries == 0 {
        return Err(LiveIoApicError::InvalidCapacity);
    }
    Ok(LiveIoApicProbe {
        id,
        version: revision,
        redirection_entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_decodes_the_inclusive_redirection_capacity() {
        let descriptor = IoApicDescriptor::test_descriptor(2, 0xfec0_0000, 0);
        assert_eq!(
            decode_probe(descriptor, 2 << 24, 0x0017_0011),
            Ok(LiveIoApicProbe {
                id: 2,
                version: 0x11,
                redirection_entries: 24,
            })
        );
    }

    #[test]
    fn probe_rejects_a_controller_id_mismatch() {
        let descriptor = IoApicDescriptor::test_descriptor(2, 0xfec0_0000, 0);
        assert_eq!(
            decode_probe(descriptor, 3 << 24, 0x0017_0011),
            Err(LiveIoApicError::ControllerId {
                expected: 2,
                observed: 3,
            })
        );
    }
}
