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
const REG_FAULT_STATUS: u32 = 0x34;
const REG_QUEUE_HEAD: u32 = 0x80;
const REG_QUEUE_TAIL: u32 = 0x88;
const REG_QUEUE_ADDRESS: u32 = 0x90;
const REG_INTERRUPT_TABLE_ADDRESS: u32 = 0xb8;

pub(crate) const GLOBAL_TRANSLATION_ENABLE: u32 = 1 << 31;
pub(crate) const GLOBAL_SET_ROOT_TABLE: u32 = 1 << 30;
pub(crate) const GLOBAL_QUEUED_INVALIDATION: u32 = 1 << 26;
pub(crate) const GLOBAL_INTERRUPT_REMAPPING: u32 = 1 << 25;
pub(crate) const GLOBAL_SET_INTERRUPT_TABLE: u32 = 1 << 24;
/// Compatibility-format interrupts pass through untranslated. Never set.
pub(crate) const GLOBAL_COMPATIBILITY_INTERRUPTS: u32 = 1 << 23;
const FAULT_QUEUE_ERROR: u32 = 1 << 4;
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
const EXTENDED_QUEUED_INVALIDATION: u64 = 1 << 1;
const EXTENDED_INTERRUPT_REMAPPING: u64 = 1 << 3;

/// Interrupt-remapping table entries: one page of 16-byte entries, sized as
/// 2^(S + 1) with S = 7 (VT-d §11.4.9.4).
pub(crate) const INTERRUPT_TABLE_ENTRIES: usize = 256;
const INTERRUPT_TABLE_SIZE_FIELD: u64 = 7;
/// Invalidation descriptors (VT-d §6.5.2): 128 bits each in a 256-entry,
/// one-page queue (IQA.QS = 0).
const DESCRIPTOR_INTERRUPT_ENTRY_CACHE: u64 = 0x4;
const DESCRIPTOR_WAIT: u64 = 0x5;
const WAIT_STATUS_WRITE: u64 = 1 << 5;
const WAIT_STATUS_DONE: u64 = 1;
/// The wait descriptor's status lands in the queue page's last 8 bytes:
/// descriptor slot 255, which the hardware never fetches because only slots
/// 0 and 1 are ever queued.
const QUEUE_STATUS_INDEX: usize = 511;
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
    /// Firmware left queued invalidation, interrupt remapping or
    /// compatibility-format pass-through on.
    FirmwareInterruptState(u32),
    /// The unit rejected an invalidation descriptor.
    QueueError,
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
    /// ECAP.IR and ECAP.QI: interrupt remapping, and the queued invalidation
    /// its interrupt-entry cache needs.
    interrupt_remapping: bool,
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
            interrupt_remapping: extended_capability & EXTENDED_INTERRUPT_REMAPPING != 0
                && extended_capability & EXTENDED_QUEUED_INVALIDATION != 0,
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

    pub(crate) const fn interrupt_remapping(self) -> bool {
        self.interrupt_remapping
    }
}

/// One interrupt-remapping table entry (VT-d §9.10) for an IOAPIC route in
/// xAPIC mode: present, remapped (not posted), fixed delivery to physical
/// destination `destination`, accepted only from requester `source_id`
/// (SVT = 01b, SQ = 0: all 16 bits compared). Returns the low and high
/// quadwords.
pub(crate) const fn ioapic_interrupt_entry(
    vector: u8,
    destination: u8,
    level_triggered: bool,
    source_id: u16,
) -> (u64, u64) {
    let low = 1
        | ((level_triggered as u64) << 4)
        | ((vector as u64) << 16)
        | ((destination as u64) << 40);
    let high = (source_id as u64) | (1 << 18);
    (low, high)
}

/// Writes interrupt-remapping table entry `index` in the table frame `table`:
/// the high quadword first, so the present bit is the last thing set.
pub(crate) fn install_interrupt_entry<M: tables::TableMemory>(
    memory: &mut M,
    table: u64,
    index: usize,
    entry: (u64, u64),
) {
    assert!(
        index < INTERRUPT_TABLE_ENTRIES,
        "interrupt-remapping index out of range"
    );
    memory.write(table, index * 2 + 1, entry.1);
    memory.write(table, index * 2, entry.0);
}

/// Turns interrupt remapping on for one unit that already translates DMA
/// (`enable_default_deny`), over the interrupt-remapping table `table`, with
/// compatibility-format interrupts blocked. Afterwards the unit delivers only
/// interrupts a present entry names, from that entry's requester; every other
/// write to the interrupt address range faults instead. Device DMA can then
/// no longer forge an interrupt (no vector, NMI or INIT of its choosing).
///
/// The interrupt-entry cache can only be invalidated through the queue, so
/// queued invalidation is on just long enough to invalidate it once after the
/// table pointer is set, using the one-page queue frame `queue`; then it is
/// turned off again and DMA invalidations stay register-based. Entries are
/// written before this and never change while remapping is on, so no later
/// interrupt-entry invalidation is needed.
pub(crate) fn enable_interrupt_remapping<R: VtdRegisters, M: tables::TableMemory>(
    registers: &mut R,
    memory: &mut M,
    queue: u64,
    table: u64,
) -> Result<(), VtdError> {
    let status = registers.read32(REG_GLOBAL_STATUS);
    let inherited = status
        & (GLOBAL_QUEUED_INVALIDATION
            | GLOBAL_INTERRUPT_REMAPPING
            | GLOBAL_COMPATIBILITY_INTERRUPTS);
    if inherited != 0 {
        return Err(VtdError::FirmwareInterruptState(inherited));
    }

    memory.write(queue, QUEUE_STATUS_INDEX, 0);
    registers.write64(REG_QUEUE_TAIL, 0);
    // 128-bit descriptors (DW = 0), 256 of them (QS = 0).
    registers.write64(REG_QUEUE_ADDRESS, queue);
    command(
        registers,
        GLOBAL_QUEUED_INVALIDATION,
        "queued-invalidation enable",
    )?;

    // x2APIC destinations are not used (EIME = 0): the kernel runs xAPIC.
    registers.write64(
        REG_INTERRUPT_TABLE_ADDRESS,
        table | INTERRUPT_TABLE_SIZE_FIELD,
    );
    command(
        registers,
        GLOBAL_SET_INTERRUPT_TABLE,
        "interrupt-table pointer",
    )?;

    // A global interrupt-entry-cache invalidation, then a wait whose status
    // write says the unit has finished it.
    memory.write(queue, 0, DESCRIPTOR_INTERRUPT_ENTRY_CACHE);
    memory.write(queue, 1, 0);
    memory.write(
        queue,
        2,
        DESCRIPTOR_WAIT | WAIT_STATUS_WRITE | (WAIT_STATUS_DONE << 32),
    );
    memory.write(queue, 3, queue + (QUEUE_STATUS_INDEX as u64) * 8);
    let tail = 2 * 16;
    registers.write64(REG_QUEUE_TAIL, tail);
    let mut queue_error = false;
    poll(
        || {
            queue_error = registers.read32(REG_FAULT_STATUS) & FAULT_QUEUE_ERROR != 0;
            queue_error || memory.read(queue, QUEUE_STATUS_INDEX) as u32 == WAIT_STATUS_DONE as u32
        },
        "interrupt-entry-cache invalidation",
    )?;
    if queue_error {
        return Err(VtdError::QueueError);
    }
    // Queued invalidation may only be disabled with the queue empty.
    poll(
        || registers.read64(REG_QUEUE_HEAD) == tail,
        "invalidation queue drain",
    )?;
    let status = registers.read32(REG_GLOBAL_STATUS) & GLOBAL_PERSISTENT_STATUS;
    registers.write32(REG_GLOBAL_COMMAND, status & !GLOBAL_QUEUED_INVALIDATION);
    poll(
        || registers.read32(REG_GLOBAL_STATUS) & GLOBAL_QUEUED_INVALIDATION == 0,
        "queued-invalidation disable",
    )?;

    command(
        registers,
        GLOBAL_INTERRUPT_REMAPPING,
        "interrupt-remapping enable",
    )?;
    if registers.read32(REG_GLOBAL_STATUS) & GLOBAL_COMPATIBILITY_INTERRUPTS != 0 {
        return Err(VtdError::FirmwareInterruptState(
            GLOBAL_COMPATIBILITY_INTERRUPTS,
        ));
    }
    Ok(())
}

/// Set once at boot, after every unit remaps interrupts with
/// compatibility-format interrupts blocked; never cleared.
static INTERRUPTS_REMAPPED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Whether every remapping unit remaps interrupts. Interrupt routes are then
/// programmed in remappable format, and only then is any function confined
/// (bus mastering and DMA domains are admitted).
pub(crate) fn interrupts_remapped() -> bool {
    INTERRUPTS_REMAPPED.load(core::sync::atomic::Ordering::Acquire)
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
    let interrupts_remapped = remap_interrupts(&mut pool, &mut units, &snapshot)?;
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
        interrupts_remapped,
    })
}

/// Turns interrupt remapping on in every unit when the platform supports it
/// (the DMAR's INTR_REMAP flag, every unit's ECAP.IR and ECAP.QI, and a
/// single-hop IOAPIC scope naming the q35 IOAPIC's requester ID). The table
/// holds exactly one entry, the q35 COM2 route at
/// [`crate::arch::x86_64::acpi::Q35_COM2_INTERRUPT_INDEX`]. Returns whether
/// interrupts are remapped; when they are not, no function is ever confined,
/// so bus mastering stays refused.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn remap_interrupts(
    pool: &mut crate::device::dma::live::LiveTablePool,
    units: &mut [Option<(LiveVtdMmio, UnitFeatures)>],
    snapshot: &crate::arch::x86_64::acpi::dmar::DmarSnapshot,
) -> Result<bool, VtdBootError> {
    use tables::TableMemory;
    if !snapshot.interrupt_remapping()
        || units
            .iter()
            .flatten()
            .any(|(_, features)| !features.interrupt_remapping())
    {
        return Ok(false);
    }
    let Some(ioapic) = crate::arch::x86_64::ioapic_live::q35_ioapic() else {
        return Ok(false);
    };
    let Some(source_id) = snapshot.ioapic_source_id(ioapic.probe().id()) else {
        return Ok(false);
    };
    let queue = pool.allocate().ok_or(VtdBootError::RootTable)?;
    let table = pool.allocate().ok_or(VtdBootError::RootTable)?;
    install_interrupt_entry(
        pool,
        table,
        crate::arch::x86_64::acpi::Q35_COM2_INTERRUPT_INDEX,
        ioapic_interrupt_entry(
            crate::arch::x86_64::acpi::Q35_COM2_VECTOR,
            ioapic.route().bsp_local_apic_id(),
            false,
            source_id,
        ),
    );
    for (registers, _) in units.iter_mut().flatten() {
        enable_interrupt_remapping(registers, pool, queue, table).map_err(VtdBootError::Unit)?;
    }
    // The queue and table frames stay allocated for good.
    INTERRUPTS_REMAPPED.store(true, core::sync::atomic::Ordering::Release);
    Ok(true)
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
        /// Every unit remaps interrupts with compatibility format blocked.
        interrupts_remapped: bool,
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
