//! Intel VT-d bring-up: every PCI function starts with DMA blocked.
//!
//! Root `STORAGE_PLAN.md` K0. The kernel points each remapping unit at one
//! all-zero root table, invalidates the unit's caches, and turns translation
//! on. With no context entry for any bus/device/function, the hardware blocks
//! and reports every DMA. Later steps (K4) give a driver a domain for its own
//! function only.
//!
//! The register sequence is written against [`VtdRegisters`] so host tests can
//! drive it through a model of the unit; the live boundary maps one UC/NX page
//! per unit.

/// Version, capability and extended-capability registers.
const REG_VERSION: u32 = 0x00;
const REG_CAPABILITY: u32 = 0x08;
const REG_EXTENDED_CAPABILITY: u32 = 0x10;
const REG_GLOBAL_COMMAND: u32 = 0x18;
const REG_GLOBAL_STATUS: u32 = 0x1c;
const REG_ROOT_TABLE_ADDRESS: u32 = 0x20;
const REG_CONTEXT_COMMAND: u32 = 0x28;

pub(crate) const GLOBAL_TRANSLATION_ENABLE: u32 = 1 << 31;
pub(crate) const GLOBAL_SET_ROOT_TABLE: u32 = 1 << 30;
/// Status bits that persist; one-shot command bits must not be written back.
/// This is the mask the VT-d specification's command programming note uses.
const GLOBAL_PERSISTENT_STATUS: u32 = 0x96ff_ffff;

const CONTEXT_INVALIDATE: u64 = 1 << 63;
const CONTEXT_GLOBAL: u64 = 1 << 61;
const IOTLB_INVALIDATE: u64 = 1 << 63;
const IOTLB_GLOBAL: u64 = 1 << 60;
const IOTLB_DRAIN_READS: u64 = 1 << 49;
const IOTLB_DRAIN_WRITES: u64 = 1 << 48;

const EXTENDED_COHERENT: u64 = 1;
const EXTENDED_IOTLB_OFFSET_SHIFT: u32 = 8;
const EXTENDED_IOTLB_OFFSET_MASK: u64 = 0x3ff;
const CAPABILITY_DRAIN_READ: u64 = 1 << 55;
const CAPABILITY_DRAIN_WRITE: u64 = 1 << 54;
const CAPABILITY_NUMBER_OF_DOMAINS_MASK: u64 = 0x7;
const CAPABILITY_REQUIRED_WRITE_BUFFER_FLUSH: u64 = 1 << 4;
const CAPABILITY_CACHING_MODE: u64 = 1 << 7;
const CAPABILITY_SAGAW_SHIFT: u32 = 8;
const SAGAW_4_LEVEL: u64 = 1 << 2;
const CAPABILITY_MGAW_SHIFT: u32 = 16;
const CAPABILITY_MGAW_MASK: u64 = 0x3f;
const GLOBAL_WRITE_BUFFER_FLUSH: u32 = 1 << 27;
const IOTLB_DOMAIN: u64 = 2 << 60;
const IOTLB_DOMAIN_ID_SHIFT: u32 = 32;

/// The live boundary maps exactly one register page per unit.
pub(crate) const REGISTER_PAGE_BYTES: u32 = 4096;
const POLL_LIMIT: u32 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VtdError {
    /// The unit reports major version 0, which no VT-d specification defines.
    UnsupportedVersion(u32),
    /// The IOTLB invalidation register lies outside the mapped page.
    IotlbOutsideRegisterPage(u32),
    /// Firmware left translation on; the kernel will not inherit its tables.
    FirmwareTranslationEnabled,
    /// The root table is not page-aligned or beyond the unit's address width.
    InvalidRootTable(u64),
    /// The unit never acknowledged a command.
    Timeout(&'static str),
}

/// Aligned register access to one remapping unit.
pub(crate) trait VtdRegisters {
    fn read32(&mut self, offset: u32) -> u32;
    fn write32(&mut self, offset: u32, value: u32);
    fn read64(&mut self, offset: u32) -> u64;
    fn write64(&mut self, offset: u32, value: u64);
    /// Called when the unit cannot snoop CPU caches, before it reads the root
    /// table from memory.
    fn flush_cpu_caches(&mut self);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VtdUnitState {
    version: u32,
    features: UnitFeatures,
}

impl VtdUnitState {
    #[cfg(test)]
    pub(crate) const fn version(self) -> u32 {
        self.version
    }

    pub(crate) const fn features(self) -> UnitFeatures {
        self.features
    }
}

/// What K4 needs to know about one unit, read once at bring-up.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UnitFeatures {
    iotlb: u32,
    drain: u64,
    caching_mode: bool,
    write_buffer_flush: bool,
    four_level: bool,
    /// Guest address bits the unit translates (MGAW + 1).
    input_bits: u32,
    /// Domain IDs the unit supports.
    domains: u32,
}

impl UnitFeatures {
    fn read(capability: u64, extended_capability: u64) -> Result<Self, VtdError> {
        let mut drain = 0;
        if capability & CAPABILITY_DRAIN_READ != 0 {
            drain |= IOTLB_DRAIN_READS;
        }
        if capability & CAPABILITY_DRAIN_WRITE != 0 {
            drain |= IOTLB_DRAIN_WRITES;
        }
        let number_of_domains = (capability & CAPABILITY_NUMBER_OF_DOMAINS_MASK) as u32;
        Ok(Self {
            iotlb: iotlb_register(extended_capability)?,
            drain,
            caching_mode: capability & CAPABILITY_CACHING_MODE != 0,
            write_buffer_flush: capability & CAPABILITY_REQUIRED_WRITE_BUFFER_FLUSH != 0,
            four_level: (capability >> CAPABILITY_SAGAW_SHIFT) & SAGAW_4_LEVEL != 0,
            input_bits: ((capability >> CAPABILITY_MGAW_SHIFT) & CAPABILITY_MGAW_MASK) as u32 + 1,
            // ND = n means 2^(4 + 2n) domains; 7 is reserved.
            domains: if number_of_domains > 6 {
                0
            } else {
                1 << (4 + 2 * number_of_domains)
            },
        })
    }

    pub(crate) const fn caching_mode(self) -> bool {
        self.caching_mode
    }

    pub(crate) const fn four_level(self) -> bool {
        self.four_level
    }

    pub(crate) const fn input_bits(self) -> u32 {
        self.input_bits
    }

    pub(crate) const fn domains(self) -> u32 {
        self.domains
    }
}

/// Points the unit at the all-zero `root_table`, invalidates its context and
/// IOTLB caches, and enables translation. On success every DMA through this
/// unit is blocked.
pub(crate) fn enable_default_deny<R: VtdRegisters>(
    registers: &mut R,
    root_table: u64,
    host_address_width: u8,
) -> Result<VtdUnitState, VtdError> {
    let version = registers.read32(REG_VERSION);
    if (version >> 4) & 0xf == 0 {
        return Err(VtdError::UnsupportedVersion(version));
    }
    let capability = registers.read64(REG_CAPABILITY);
    let extended_capability = registers.read64(REG_EXTENDED_CAPABILITY);
    let features = UnitFeatures::read(capability, extended_capability)?;
    if !root_table.is_multiple_of(4096)
        || root_table == 0
        || host_address_width >= 64
        || root_table >> host_address_width != 0
    {
        return Err(VtdError::InvalidRootTable(root_table));
    }
    if registers.read32(REG_GLOBAL_STATUS) & GLOBAL_TRANSLATION_ENABLE != 0 {
        return Err(VtdError::FirmwareTranslationEnabled);
    }
    if extended_capability & EXTENDED_COHERENT == 0 {
        registers.flush_cpu_caches();
    }

    // Legacy root-table format (RTADDR.TTM = 0).
    registers.write64(REG_ROOT_TABLE_ADDRESS, root_table);
    command(registers, GLOBAL_SET_ROOT_TABLE, "root-table pointer")?;

    invalidate_context_cache(registers)?;
    iotlb_command(registers, features, IOTLB_GLOBAL)?;

    command(registers, GLOBAL_TRANSLATION_ENABLE, "translation enable")?;
    Ok(VtdUnitState { version, features })
}

/// Invalidates every context-cache entry of the unit.
pub(crate) fn invalidate_context_cache<R: VtdRegisters>(registers: &mut R) -> Result<(), VtdError> {
    registers.write64(REG_CONTEXT_COMMAND, CONTEXT_INVALIDATE | CONTEXT_GLOBAL);
    poll(
        || registers.read64(REG_CONTEXT_COMMAND) & CONTEXT_INVALIDATE == 0,
        "context-cache invalidation",
    )
}

/// Invalidates one domain's IOTLB entries, draining in-flight DMA where the
/// unit supports it, so no later device access uses a removed translation.
pub(crate) fn invalidate_domain_iotlb<R: VtdRegisters>(
    registers: &mut R,
    features: UnitFeatures,
    domain_id: u16,
) -> Result<(), VtdError> {
    iotlb_command(
        registers,
        features,
        IOTLB_DOMAIN | (u64::from(domain_id) << IOTLB_DOMAIN_ID_SHIFT),
    )
}

fn iotlb_command<R: VtdRegisters>(
    registers: &mut R,
    features: UnitFeatures,
    granularity: u64,
) -> Result<(), VtdError> {
    registers.write64(
        features.iotlb,
        IOTLB_INVALIDATE | granularity | features.drain,
    );
    poll(
        || registers.read64(features.iotlb) & IOTLB_INVALIDATE == 0,
        "IOTLB invalidation",
    )
}

/// Makes table writes visible to a unit that reports RWBF; a no-op otherwise.
pub(crate) fn flush_write_buffer<R: VtdRegisters>(
    registers: &mut R,
    features: UnitFeatures,
) -> Result<(), VtdError> {
    if !features.write_buffer_flush {
        return Ok(());
    }
    let status = registers.read32(REG_GLOBAL_STATUS) & GLOBAL_PERSISTENT_STATUS;
    registers.write32(REG_GLOBAL_COMMAND, status | GLOBAL_WRITE_BUFFER_FLUSH);
    poll(
        || registers.read32(REG_GLOBAL_STATUS) & GLOBAL_WRITE_BUFFER_FLUSH == 0,
        "write-buffer flush",
    )
}

fn iotlb_register(extended_capability: u64) -> Result<u32, VtdError> {
    let base = ((extended_capability >> EXTENDED_IOTLB_OFFSET_SHIFT) & EXTENDED_IOTLB_OFFSET_MASK)
        as u32
        * 16;
    let register = base + 8;
    if register + 8 > REGISTER_PAGE_BYTES {
        return Err(VtdError::IotlbOutsideRegisterPage(register));
    }
    Ok(register)
}

/// Issues one global command and waits for its status bit.
fn command<R: VtdRegisters>(
    registers: &mut R,
    bit: u32,
    what: &'static str,
) -> Result<(), VtdError> {
    let status = registers.read32(REG_GLOBAL_STATUS) & GLOBAL_PERSISTENT_STATUS;
    registers.write32(REG_GLOBAL_COMMAND, status | bit);
    poll(|| registers.read32(REG_GLOBAL_STATUS) & bit != 0, what)
}

fn poll(mut done: impl FnMut() -> bool, what: &'static str) -> Result<(), VtdError> {
    for _ in 0..POLL_LIMIT {
        if done() {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(VtdError::Timeout(what))
}

/// Takes over every DMAR unit at boot, before any device driver exists.
///
/// No DMAR is a supported platform: the kernel then admits no device DMA. A
/// DMAR the kernel cannot take over completely stops the boot, so a machine
/// never runs with some units translating and others passing DMA through.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn initialize<'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    active: &mut crate::arch::x86_64::mm::ActiveDeepPaging<
        crate::arch::x86_64::mm::LiveActivePagingTarget<'root, RANGE_CAPACITY, ROLE_CAPACITY>,
    >,
    snapshot: Option<crate::arch::x86_64::acpi::dmar::DmarSnapshot>,
) -> Result<VtdBootState, VtdBootError> {
    use crate::arch::x86_64::mm::FrameAddress;
    use crate::memory::frame_roles::ArchitectureBootstrapKind;

    let Some(snapshot) = snapshot else {
        return Ok(VtdBootState::Absent);
    };
    let ceiling = 1_u64 << snapshot.host_address_width();
    let physical_limit = active.root().physical_limit();
    // Every table the units will ever walk comes from one fixed pool of
    // zeroed frames, each mapped UC for the life of the machine.
    let mut pool = crate::device::dma::live::LiveTablePool::new();
    for _ in 0..crate::device::dma::live::TABLE_POOL_FRAMES {
        let grant = active
            .allocate_zeroed_architecture_frame(ArchitectureBootstrapKind::X86VtdTable, ceiling)
            .map_err(|_| VtdBootError::RootTable)?;
        let physical = grant.physical_start();
        let frame =
            FrameAddress::new(physical, physical_limit).map_err(|_| VtdBootError::Mapping)?;
        let mapped = active
            .install_kernel_mmio_page(frame)
            .map_err(|_| VtdBootError::Mapping)?;
        // Pool frames are never freed: translation stays on for good.
        core::mem::forget(grant);
        pool.add(physical, mapped);
    }
    // The frames were zeroed through the write-back scratch window, so dirty
    // lines may still be cached. Write them back now, before any entry goes
    // through the UC aliases; a later eviction would otherwise overwrite a
    // table entry. Only the BSP runs here, so no other cache holds them.
    write_back_and_invalidate_caches();
    let root = tables::TableMemory::allocate(&mut pool).ok_or(VtdBootError::RootTable)?;
    let context = tables::TableMemory::allocate(&mut pool).ok_or(VtdBootError::RootTable)?;
    // Bus 0's context table is linked before translation starts. All its
    // entries are absent, so every function is still blocked.
    tables::install_root_entry(&mut pool, root, 0, context);

    let mut units: [Option<(LiveVtdMmio, UnitFeatures)>;
        crate::arch::x86_64::acpi::dmar::MAX_DMAR_UNITS] =
        [const { None }; crate::arch::x86_64::acpi::dmar::MAX_DMAR_UNITS];
    for (slot, unit) in units.iter_mut().zip(snapshot.units()) {
        let frame = FrameAddress::new(unit.register_base(), physical_limit)
            .map_err(|_| VtdBootError::Mapping)?;
        let base = active
            .install_kernel_mmio_page(frame)
            .map_err(|_| VtdBootError::Mapping)?;
        let mut registers = LiveVtdMmio::new(base)?;
        let state = enable_default_deny(&mut registers, root, snapshot.host_address_width())
            .map_err(VtdBootError::Unit)?;
        *slot = Some((registers, state.features()));
    }
    let dma_domains = match crate::device::dma::live::LiveIommu::new(pool, units, context) {
        Some(iommu) => {
            crate::device::dma::live::install(iommu);
            true
        }
        None => false,
    };
    Ok(VtdBootState::DefaultDeny {
        units: snapshot.units().len(),
        dma_domains,
    })
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "WBINVD has no memory operands; it writes back and invalidates this CPU's caches"
)]
fn write_back_and_invalidate_caches() {
    // SAFETY: see the reason above; it only costs time.
    unsafe { core::arch::asm!("wbinvd", options(nostack, preserves_flags)) }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VtdBootState {
    Absent,
    /// `dma_domains` says whether every unit can give a function a 4-level
    /// domain, so `dma_map` is available.
    DefaultDeny {
        units: usize,
        dma_domains: bool,
    },
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VtdBootError {
    RootTable,
    Mapping,
    InvalidMmioBase,
    Unit(VtdError),
}

/// One unit's registers through a permanent UC/NX kernel page.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) struct LiveVtdMmio {
    base: u64,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl LiveVtdMmio {
    pub(crate) fn new(base: u64) -> Result<Self, VtdBootError> {
        if base < 0xffff_8000_0000_0000 || !base.is_multiple_of(u64::from(REGISTER_PAGE_BYTES)) {
            return Err(VtdBootError::InvalidMmioBase);
        }
        Ok(Self { base })
    }

    fn address(&self, offset: u32, width: u32) -> u64 {
        assert!(
            offset.is_multiple_of(width) && offset + width <= REGISTER_PAGE_BYTES,
            "VT-d register access outside the mapped page"
        );
        self.base + u64::from(offset)
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "VT-d registers are aligned volatile accesses inside one permanent UC/NX kernel page"
)]
impl VtdRegisters for LiveVtdMmio {
    fn read32(&mut self, offset: u32) -> u32 {
        unsafe { core::ptr::read_volatile(self.address(offset, 4) as *const u32) }
    }

    fn write32(&mut self, offset: u32, value: u32) {
        unsafe { core::ptr::write_volatile(self.address(offset, 4) as *mut u32, value) }
    }

    fn read64(&mut self, offset: u32) -> u64 {
        unsafe { core::ptr::read_volatile(self.address(offset, 8) as *const u64) }
    }

    fn write64(&mut self, offset: u32, value: u64) {
        unsafe { core::ptr::write_volatile(self.address(offset, 8) as *mut u64, value) }
    }

    fn flush_cpu_caches(&mut self) {
        // SAFETY: WBINVD writes back and invalidates caches; it has no memory
        // operands and only costs time.
        unsafe { core::arch::asm!("wbinvd", options(nostack, preserves_flags)) }
    }
}

pub(crate) mod tables;

#[cfg(test)]
mod tests;
