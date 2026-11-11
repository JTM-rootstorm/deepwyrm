//! The live VT-d binding for DMA domains: a boot-time table pool mapped
//! strong-uncacheable, the remapping units, and one lock over both.

use super::{
    DMA_DOMAINS, DMA_MAPPINGS_PER_DOMAIN, DmaDomains, DmaError, DmaHardware, DmaService, DomainPins,
};
use crate::arch::x86_64::acpi::dmar::MAX_DMAR_UNITS;
use crate::arch::x86_64::vtd::tables::{
    DeviceAccess, FOUR_LEVEL_INPUT_BITS, TABLE_ENTRIES, TableMemory,
};
use crate::arch::x86_64::vtd::{self, LiveVtdMmio, UnitFeatures, VtdError};
use crate::object::{InternalRef, ObjectId};
use crate::sync::IrqSpinMutex;

pub(crate) use super::VTD_TABLE_POOL_FRAMES as TABLE_POOL_FRAMES;
// The allocation bitmap is one u64.
const _: () = assert!(TABLE_POOL_FRAMES <= 64);

/// Fixed frames, each with its permanent kernel UC/NX address.
pub(crate) struct LiveTablePool {
    physical: [u64; TABLE_POOL_FRAMES],
    virtual_: [u64; TABLE_POOL_FRAMES],
    count: usize,
    used: u64,
}

impl LiveTablePool {
    pub(crate) const fn new() -> Self {
        Self {
            physical: [0; TABLE_POOL_FRAMES],
            virtual_: [0; TABLE_POOL_FRAMES],
            count: 0,
            used: 0,
        }
    }

    /// Adds one zeroed frame mapped UC at `virtual_address`.
    pub(crate) fn add(&mut self, physical: u64, virtual_address: u64) {
        assert!(self.count < TABLE_POOL_FRAMES, "VT-d table pool overfilled");
        self.physical[self.count] = physical;
        self.virtual_[self.count] = virtual_address;
        self.count += 1;
    }

    fn entry_address(&self, table: u64, index: usize) -> u64 {
        assert!(index < TABLE_ENTRIES, "VT-d table index out of range");
        let slot = self.physical[..self.count]
            .iter()
            .position(|&frame| frame == table)
            .expect("VT-d table address names a pool frame");
        assert!(
            self.used & (1 << slot) != 0,
            "VT-d table frame is not allocated"
        );
        self.virtual_[slot] + (index as u64) * 8
    }
}

#[allow(
    unsafe_code,
    reason = "pool frames are permanently mapped UC/NX kernel pages owned only by this pool"
)]
impl TableMemory for LiveTablePool {
    fn allocate(&mut self) -> Option<u64> {
        let slot = (0..self.count).find(|&slot| self.used & (1 << slot) == 0)?;
        self.used |= 1 << slot;
        Some(self.physical[slot])
    }

    fn free(&mut self, table: u64) {
        let slot = self.physical[..self.count]
            .iter()
            .position(|&frame| frame == table)
            .expect("freed VT-d table names a pool frame");
        assert!(self.used & (1 << slot) != 0, "VT-d table frame freed twice");
        for index in 0..TABLE_ENTRIES {
            debug_assert_eq!(self.read(table, index), 0, "freed VT-d table is not empty");
        }
        self.used &= !(1 << slot);
    }

    fn read(&self, table: u64, index: usize) -> u64 {
        // SAFETY: an aligned entry inside one allocated pool frame.
        unsafe { core::ptr::read_volatile(self.entry_address(table, index) as *const u64) }
    }

    fn write(&mut self, table: u64, index: usize, value: u64) {
        // SAFETY: an aligned entry inside one allocated pool frame.
        unsafe { core::ptr::write_volatile(self.entry_address(table, index) as *mut u64, value) }
    }
}

/// The pool, every remapping unit, and the limits all units share.
pub(crate) struct LiveIommu {
    pool: LiveTablePool,
    units: [Option<(LiveVtdMmio, UnitFeatures)>; MAX_DMAR_UNITS],
    context_table: u64,
    iova_end: u64,
    max_domain_id: u16,
    caching_mode: bool,
}

impl LiveIommu {
    /// `None` when some unit cannot give a function a 4-level domain; DMA is
    /// then never admitted, and every function stays blocked.
    pub(crate) fn new(
        pool: LiveTablePool,
        units: [Option<(LiveVtdMmio, UnitFeatures)>; MAX_DMAR_UNITS],
        context_table: u64,
    ) -> Option<Self> {
        let mut input_bits = FOUR_LEVEL_INPUT_BITS;
        let mut domains = u32::MAX;
        let mut caching_mode = false;
        let mut any = false;
        for (_, features) in units.iter().flatten() {
            if !features.four_level() {
                return None;
            }
            any = true;
            input_bits = input_bits.min(features.input_bits());
            domains = domains.min(features.domains());
            caching_mode |= features.caching_mode();
        }
        // Domain ID 0 is reserved under caching mode; IDs start at 1 anyway.
        let max_domain_id = u16::try_from(domains.saturating_sub(1)).unwrap_or(u16::MAX);
        if !any || max_domain_id == 0 || input_bits <= 20 {
            return None;
        }
        Some(Self {
            pool,
            units,
            context_table,
            iova_end: 1 << input_bits,
            max_domain_id,
            caching_mode,
        })
    }

    fn each_unit(
        &mut self,
        mut command: impl FnMut(&mut LiveVtdMmio, UnitFeatures) -> Result<(), VtdError>,
    ) {
        for (registers, features) in self.units.iter_mut().flatten() {
            // A unit that never completes an invalidation could still be
            // using a translation the kernel is about to free; stop instead.
            if let Err(error) = command(registers, *features) {
                panic!("VT-d unit failed an invalidation: {error:?}");
            }
        }
    }
}

impl TableMemory for LiveIommu {
    fn allocate(&mut self) -> Option<u64> {
        self.pool.allocate()
    }
    fn free(&mut self, table: u64) {
        self.pool.free(table)
    }
    fn read(&self, table: u64, index: usize) -> u64 {
        self.pool.read(table, index)
    }
    fn write(&mut self, table: u64, index: usize, value: u64) {
        self.pool.write(table, index, value)
    }
}

impl DmaHardware for LiveIommu {
    fn context_table(&self) -> u64 {
        self.context_table
    }

    fn iova_end(&self) -> u64 {
        self.iova_end
    }

    fn max_domain_id(&self) -> u16 {
        self.max_domain_id
    }

    fn after_install(&mut self, domain_id: u16) {
        if self.caching_mode {
            // Caching mode lets a unit cache not-present entries.
            self.each_unit(|registers, features| {
                vtd::invalidate_domain_iotlb(registers, features, domain_id)
            });
        } else {
            self.each_unit(vtd::flush_write_buffer);
        }
    }

    fn invalidate_domain(&mut self, domain_id: u16) {
        self.each_unit(|registers, features| {
            vtd::invalidate_domain_iotlb(registers, features, domain_id)
        });
    }

    fn invalidate_context(&mut self) {
        self.each_unit(|registers, _| vtd::invalidate_context_cache(registers));
    }
}

struct LiveDma {
    iommu: LiveIommu,
    domains: DmaDomains<DMA_DOMAINS, DMA_MAPPINGS_PER_DOMAIN>,
}

static LIVE_DMA: IrqSpinMutex<Option<LiveDma>> = IrqSpinMutex::new(None);

/// Called once at boot, after every unit is in default deny.
pub(crate) fn install(iommu: LiveIommu) {
    let mut live = LIVE_DMA.lock();
    assert!(live.is_none(), "DMA domains installed twice");
    *live = Some(LiveDma {
        iommu,
        domains: DmaDomains::new(),
    });
}

/// The syscall-side view of the live domains.
pub(crate) struct LiveDmaService;

impl DmaService for LiveDmaService {
    fn revoke_foreign(
        &mut self,
        resource: ObjectId,
        process: ObjectId,
        release: &mut dyn FnMut(InternalRef),
    ) {
        let pins = {
            let mut live = LIVE_DMA.lock();
            let Some(live) = live.as_mut() else {
                return;
            };
            if !live
                .domains
                .owner(resource)
                .is_some_and(|owner| owner != process)
            {
                return;
            }
            clear_bus_master_and_teardown(live, resource)
        };
        // References are released outside the lock: one may be the last.
        for pin in pins.into_pins() {
            release(pin);
        }
    }

    fn map(
        &mut self,
        resource: ObjectId,
        owner: ObjectId,
        devfn: u8,
        physical: u64,
        pages: u64,
        access: DeviceAccess,
        pin: InternalRef,
    ) -> Result<u64, (DmaError, InternalRef)> {
        // A function no unit in default deny translates sits outside every
        // unit's scope, where a domain would confine nothing.
        if !crate::device::pci::dma_confined_devfn(devfn) {
            return Err((DmaError::NotSupported, pin));
        }
        let mut live = LIVE_DMA.lock();
        let Some(live) = live.as_mut() else {
            return Err((DmaError::NotSupported, pin));
        };
        live.domains.map(
            &mut live.iommu,
            resource,
            owner,
            devfn,
            physical,
            pages,
            access,
            pin,
        )
    }

    fn unmap(
        &mut self,
        resource: ObjectId,
        owner: ObjectId,
        iova: u64,
        pages: u64,
    ) -> Result<InternalRef, DmaError> {
        let mut live = LIVE_DMA.lock();
        let Some(live) = live.as_mut() else {
            return Err(DmaError::NotSupported);
        };
        live.domains
            .unmap(&mut live.iommu, resource, owner, iova, pages)
    }
}

/// Tears down `resource`'s domain when the DeviceResource finalizes: bus
/// mastering is cleared first, so the function issues no new DMA, then the
/// domain goes (see [`DmaDomains::teardown`]).
pub(crate) fn teardown(resource: ObjectId) -> DomainPins<DMA_MAPPINGS_PER_DOMAIN> {
    let mut live = LIVE_DMA.lock();
    let Some(live) = live.as_mut() else {
        return DomainPins::empty();
    };
    clear_bus_master_and_teardown(live, resource)
}

/// Clears the function's bus mastering, so it issues no new DMA, then tears
/// its domain down.
fn clear_bus_master_and_teardown(
    live: &mut LiveDma,
    resource: ObjectId,
) -> DomainPins<DMA_MAPPINGS_PER_DOMAIN> {
    if let Some(devfn) = live.domains.devfn(resource) {
        let address = crate::device::pci::PciAddress::from_boot(u32::from(devfn))
            .expect("a bus-0 device/function is a valid PCI address");
        let mut ports = crate::arch::x86_64::io_port::X86PortIo;
        let mut config = crate::arch::x86_64::pci_config::Mechanism1::new(&mut ports);
        crate::device::pci::set_command(&mut config, address, false, false, true)
            .expect("clearing bus mastering is always allowed");
    }
    live.domains.teardown(&mut live.iommu, resource)
}
