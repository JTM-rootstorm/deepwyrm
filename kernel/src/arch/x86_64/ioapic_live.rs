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
    reason = "the selected DW1-E product cfg reaches this target-only boundary after build registration"
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
const IOAPIC_REG_REDIR_BASE: u32 = 0x10;
const IOAPIC_REDIR_MASK: u32 = 1 << 16;
const IOAPIC_MAX_SELECTOR: u32 = 0xff;
const IOAPIC_MAX_REDIRECTION_ENTRIES: u32 = 120;
const SLOT_EMPTY: u8 = 0;
const SLOT_PUBLISHING: u8 = 1;
const SLOT_READY: u8 = 2;
const SLOT_FAULTED: u8 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveIoApicError {
    Mapping,
    InvalidMmioBase,
    InvalidRegisterOffset,
    InvalidRegisterSelector(u32),
    ControllerId {
        expected: u8,
        observed: u8,
    },
    InvalidVersion,
    InvalidCapacity,
    ProbeDrift,
    SelectedGsiOutsideController {
        gsi: u32,
        gsi_base: u32,
        redirection_entries: u32,
    },
    RedirectionRegisterOverflow,
    SelectedRedirectionUnmasked {
        register: u32,
    },
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
    let selected_low_register = selected_redirection_low_register(
        route.gsi(),
        route.controller().gsi_base(),
        measured.redirection_entries(),
    )?;
    let owner = ValidatedQ35IoApic {
        route,
        probe: measured,
        registers: IrqSpinMutex::new(controller),
    };
    let selected_low = owner.read_register(selected_low_register)?;
    require_masked_redirection(selected_low_register, selected_low)?;
    Q35_IOAPIC.publish(owner)
}

fn selected_redirection_low_register(
    gsi: u32,
    gsi_base: u32,
    redirection_entries: u32,
) -> Result<u32, LiveIoApicError> {
    if redirection_entries == 0 || redirection_entries > IOAPIC_MAX_REDIRECTION_ENTRIES {
        return Err(LiveIoApicError::InvalidCapacity);
    }
    let index = gsi
        .checked_sub(gsi_base)
        .ok_or(LiveIoApicError::SelectedGsiOutsideController {
            gsi,
            gsi_base,
            redirection_entries,
        })?;
    if index >= redirection_entries {
        return Err(LiveIoApicError::SelectedGsiOutsideController {
            gsi,
            gsi_base,
            redirection_entries,
        });
    }
    index
        .checked_mul(2)
        .and_then(|offset| IOAPIC_REG_REDIR_BASE.checked_add(offset))
        .filter(|register| *register <= IOAPIC_MAX_SELECTOR)
        .ok_or(LiveIoApicError::RedirectionRegisterOverflow)
}

fn require_masked_redirection(register: u32, redirection_low: u32) -> Result<(), LiveIoApicError> {
    if redirection_low & IOAPIC_REDIR_MASK == 0 {
        return Err(LiveIoApicError::SelectedRedirectionUnmasked { register });
    }
    Ok(())
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn probe_candidate<'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    active: &mut ActiveDeepPaging<LiveActivePagingTarget<'root, RANGE_CAPACITY, ROLE_CAPACITY>>,
    descriptor: IoApicDescriptor,
) -> Result<LiveIoApicProbe, LiveIoApicError> {
    let frame = frame_for(active, descriptor)?;
    active
        .with_bootstrap_kernel_mmio_page(frame, |base| {
            let mut controller = LiveIoApicMmio::new(base)?;
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
        validate_register_selector(register)?;
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
        validate_register_selector(register)?;
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
    if redirection_entries == 0 || redirection_entries > IOAPIC_MAX_REDIRECTION_ENTRIES {
        return Err(LiveIoApicError::InvalidCapacity);
    }
    Ok(LiveIoApicProbe {
        id,
        version: revision,
        redirection_entries,
    })
}

fn validate_register_selector(register: u32) -> Result<(), LiveIoApicError> {
    if register > IOAPIC_MAX_SELECTOR {
        return Err(LiveIoApicError::InvalidRegisterSelector(register));
    }
    Ok(())
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

    #[test]
    fn probe_accepts_the_largest_selector_representable_redirection_table() {
        let descriptor = IoApicDescriptor::test_descriptor(2, 0xfec0_0000, 0);
        assert_eq!(
            decode_probe(descriptor, 2 << 24, 0x0077_0011),
            Ok(LiveIoApicProbe {
                id: 2,
                version: 0x11,
                redirection_entries: 120,
            })
        );
    }

    #[test]
    fn probe_rejects_a_redirection_table_beyond_the_selector_width() {
        let descriptor = IoApicDescriptor::test_descriptor(2, 0xfec0_0000, 0);
        assert_eq!(
            decode_probe(descriptor, 2 << 24, 0x0078_0011),
            Err(LiveIoApicError::InvalidCapacity)
        );
    }

    #[test]
    fn selector_validation_accepts_the_eight_bit_upper_bound() {
        assert_eq!(validate_register_selector(0xff), Ok(()));
    }

    #[test]
    fn selector_validation_rejects_reserved_selector_bits() {
        assert_eq!(
            validate_register_selector(0x100),
            Err(LiveIoApicError::InvalidRegisterSelector(0x100))
        );
    }

    #[test]
    fn selected_redirection_low_register_uses_the_exact_gsi_relative_boundary() {
        assert_eq!(selected_redirection_low_register(27, 4, 24), Ok(0x3e));
        assert_eq!(
            selected_redirection_low_register(28, 4, 24),
            Err(LiveIoApicError::SelectedGsiOutsideController {
                gsi: 28,
                gsi_base: 4,
                redirection_entries: 24,
            })
        );
    }

    #[test]
    fn selected_redirection_readback_accepts_a_masked_route() {
        assert_eq!(require_masked_redirection(0x16, 0x0001_0030), Ok(()));
    }

    #[test]
    fn selected_redirection_readback_rejects_an_unmasked_route() {
        assert_eq!(
            require_masked_redirection(0x16, 0x0000_0030),
            Err(LiveIoApicError::SelectedRedirectionUnmasked { register: 0x16 })
        );
    }
}
