#![cfg_attr(
    not(all(target_os = "none", target_arch = "x86_64")),
    allow(
        dead_code,
        reason = "F3 ACPI discovery is target boot code with host model tests"
    )
)]

//! Bounded, snapshot-based ACPI discovery for the DW0-F3 reference clock.
//!
//! Firmware bytes are copied once into kernel-owned workspace, checksummed, and
//! parsed only from that immutable observation. Discovery yields a resource
//! proposal. The locked q35 profile separately authorizes the exact PM I/O port.

use crate::time::{PmTimerDescriptor, PmTimerWidth};

const RSDP_V1_BYTES: usize = 20;
const RSDP_V2_BYTES: usize = 36;
const MAX_RSDP_BYTES: usize = 4096;
const SDT_HEADER_BYTES: usize = 36;
const MAX_ACPI_TABLE_BYTES: usize = 64 * 1024;
const MAX_ROOT_ENTRIES: usize = 128;
pub(crate) const MAX_DW0_CPUS: usize = 64;
const MADT_HEADER_BYTES: usize = SDT_HEADER_BYTES + 8;
const MADT_LOCAL_APIC_ADDRESS: usize = SDT_HEADER_BYTES;
const MADT_FLAGS: usize = SDT_HEADER_BYTES + 4;
const MADT_PCAT_COMPAT: u32 = 1;
const MADT_ENTRY_PROCESSOR_LOCAL_APIC: u8 = 0;
const MADT_ENTRY_IOAPIC: u8 = 1;
const MADT_ENTRY_INTERRUPT_SOURCE_OVERRIDE: u8 = 2;
const MADT_ENTRY_LOCAL_APIC_ADDRESS_OVERRIDE: u8 = 5;
const MADT_ENTRY_PROCESSOR_LOCAL_X2APIC: u8 = 9;
const MADT_PROCESSOR_LOCAL_APIC_BYTES: usize = 8;
const MADT_IOAPIC_BYTES: usize = 12;
const MADT_INTERRUPT_SOURCE_OVERRIDE_BYTES: usize = 10;
const MADT_LOCAL_APIC_ADDRESS_OVERRIDE_BYTES: usize = 12;
const MADT_PROCESSOR_LOCAL_X2APIC_BYTES: usize = 16;
const MADT_PROCESSOR_ENABLED: u32 = 1;
const MAX_MADT_IOAPICS: usize = 8;
const MAX_MADT_ISO_OVERRIDES: usize = 16;
const Q35_COM2_ISA_IRQ: u8 = 3;
const Q35_COM2_VECTOR: u8 = 0x30;
const FADT_PM_TMR_BLK: usize = 76;
const FADT_PM_TMR_LEN: usize = 91;
const FADT_FLAGS: usize = 112;
const FADT_X_PM_TMR_BLK: usize = 208;
const FADT_MINIMUM_FLAGS_BYTES: usize = 116;
const FADT_X_PM_TIMER_END: usize = 220;
const FADT_TMR_VAL_EXT: u32 = 1 << 8;
const FADT_HW_REDUCED_ACPI: u32 = 1 << 20;
const GAS_SYSTEM_IO: u8 = 1;
const GAS_DWORD_ACCESS: u8 = 3;
pub(crate) const Q35_PM_TIMER_PORT: u16 = 0x608;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AcpiTimeError {
    ReadFailure,
    InvalidRsdp,
    InvalidRootTable,
    RootEntryLimit,
    MissingFadt,
    DuplicateFadt,
    InvalidFadt,
    HardwareReduced,
    MissingPmTimer,
    ConflictingPmTimer,
    UnauthorizedPmTimerPort,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PmTimerProposal {
    port: u16,
    width: PmTimerWidth,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CpuTopologyEntry {
    logical_index: u16,
    local_apic_id: u8,
    acpi_processor_uid: u8,
}

impl CpuTopologyEntry {
    pub(crate) const fn logical_index(self) -> u16 {
        self.logical_index
    }

    pub(crate) const fn local_apic_id(self) -> u8 {
        self.local_apic_id
    }

    #[cfg(test)]
    pub(crate) const fn acpi_processor_uid(self) -> u8 {
        self.acpi_processor_uid
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CpuTopology {
    local_apic_physical_address: u64,
    pc_at_compatible: bool,
    entries: [Option<CpuTopologyEntry>; MAX_DW0_CPUS],
    len: usize,
}

impl CpuTopology {
    pub(crate) const fn local_apic_physical_address(self) -> u64 {
        self.local_apic_physical_address
    }

    #[cfg(test)]
    pub(crate) const fn pc_at_compatible(self) -> bool {
        self.pc_at_compatible
    }

    pub(crate) const fn len(self) -> usize {
        self.len
    }

    #[cfg(test)]
    pub(crate) const fn is_empty(self) -> bool {
        self.len == 0
    }

    pub(crate) fn entries(&self) -> impl ExactSizeIterator<Item = CpuTopologyEntry> + '_ {
        self.entries[..self.len]
            .iter()
            .map(|entry| entry.expect("published CPU topology prefix contains an entry"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CpuTopologyError {
    ReadFailure,
    InvalidRsdp,
    InvalidRootTable,
    RootEntryLimit,
    MissingMadt,
    DuplicateMadt,
    InvalidMadt,
    DuplicateLocalApicId(u8),
    DuplicateProcessorUid(u8),
    UnsupportedEnabledX2Apic(u32),
    InvalidLocalApicAddress(u64),
    DuplicateLocalApicAddressOverride,
    LiveCpuIsNotBootstrapProcessor,
    MissingBootstrapProcessor(u8),
    CpuCapacity { observed: usize, capacity: usize },
}

/// A firmware-proposed IOAPIC.  The redirection count is deliberately absent:
/// E2 obtains it from the controller version register before publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IoApicDescriptor {
    id: u8,
    physical_address: u64,
    gsi_base: u32,
}

impl IoApicDescriptor {
    pub(crate) const fn id(self) -> u8 {
        self.id
    }

    pub(crate) const fn physical_address(self) -> u64 {
        self.physical_address
    }

    pub(crate) const fn gsi_base(self) -> u32 {
        self.gsi_base
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IoApicProbe {
    descriptor: IoApicDescriptor,
    redirection_entries: u32,
}

impl IoApicProbe {
    pub(crate) const fn new(descriptor: IoApicDescriptor, redirection_entries: u32) -> Self {
        Self {
            descriptor,
            redirection_entries,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PlatformIrqPolarity {
    ActiveHigh,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PlatformIrqTrigger {
    Edge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PlatformIrqRoute {
    gsi: u32,
    polarity: PlatformIrqPolarity,
    trigger: PlatformIrqTrigger,
    vector: u8,
    bsp_local_apic_id: u8,
    controller: IoApicDescriptor,
}

impl PlatformIrqRoute {
    pub(crate) const fn gsi(self) -> u32 {
        self.gsi
    }

    pub(crate) const fn polarity(self) -> PlatformIrqPolarity {
        self.polarity
    }

    pub(crate) const fn trigger(self) -> PlatformIrqTrigger {
        self.trigger
    }

    pub(crate) const fn vector(self) -> u8 {
        self.vector
    }

    pub(crate) const fn bsp_local_apic_id(self) -> u8 {
        self.bsp_local_apic_id
    }

    pub(crate) const fn controller(self) -> IoApicDescriptor {
        self.controller
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Q35Com2RouteError {
    InvalidMadt,
    Topology(CpuTopologyError),
    IoApicCapacity,
    DuplicateIoApicId(u8),
    DuplicateIoApicAddress(u64),
    DuplicateIoApicGsiBase(u32),
    InvalidIoApicAddress(u64),
    IoApicCapacityExceeded,
    IsoCapacityExceeded,
    DuplicateIrq3Override,
    ReservedPolarity,
    ReservedTrigger,
    UnsupportedPolarity,
    UnsupportedTrigger,
    MissingIoApic,
    ProbeDoesNotMatchMadt,
    InvalidProbeCapacity,
    GsiRangeOverflow,
    OverlappingIoApicGsiRanges,
    UncoveredGsi(u32),
    AmbiguousGsi(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InterruptSourceOverride {
    gsi: u32,
    flags: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Q35Com2MadtSnapshot {
    topology: CpuTopology,
    ioapics: [Option<IoApicDescriptor>; MAX_MADT_IOAPICS],
    ioapic_len: usize,
    irq3_override: Option<InterruptSourceOverride>,
}

/// Snapshot and resolve only the q35 COM2 route.  This function is deliberately
/// independent of target MMIO and is not invoked by the live BSP in E1.
pub(crate) fn discover_q35_com2_route<R: AcpiByteReader>(
    reader: &mut R,
    rsdp_physical: u64,
    live_bsp_local_apic_id: u8,
    live_cpu_is_bsp: bool,
    probes: &[IoApicProbe],
    workspace: &mut AcpiSnapshotWorkspace,
) -> Result<PlatformIrqRoute, Q35Com2RouteError> {
    if !live_cpu_is_bsp {
        return Err(Q35Com2RouteError::Topology(
            CpuTopologyError::LiveCpuIsNotBootstrapProcessor,
        ));
    }
    let madt_len = snapshot_selected_madt(reader, rsdp_physical, workspace)?;
    let snapshot = parse_q35_com2_madt(&workspace.table[..madt_len], live_bsp_local_apic_id)?;
    resolve_q35_com2_route(snapshot, probes)
}

fn resolve_q35_com2_route(
    snapshot: Q35Com2MadtSnapshot,
    probes: &[IoApicProbe],
) -> Result<PlatformIrqRoute, Q35Com2RouteError> {
    if snapshot.ioapic_len == 0 {
        return Err(Q35Com2RouteError::MissingIoApic);
    }
    if probes.len() != snapshot.ioapic_len {
        return Err(Q35Com2RouteError::ProbeDoesNotMatchMadt);
    }
    let gsi = snapshot
        .irq3_override
        .map_or(u32::from(Q35_COM2_ISA_IRQ), |override_| override_.gsi);
    if let Some(override_) = snapshot.irq3_override {
        validate_irq3_override(override_.flags)?;
    }

    // Validate every probed interval before selecting IRQ3.  A non-selected
    // overlap is still ambiguous firmware topology and must never become an
    // order-dependent controller choice in E2.
    for left_index in 0..snapshot.ioapic_len {
        let left = snapshot.ioapics[left_index].unwrap();
        let left_end = probed_gsi_end(left, probes)?;
        for right_index in left_index + 1..snapshot.ioapic_len {
            let right = snapshot.ioapics[right_index].unwrap();
            let right_end = probed_gsi_end(right, probes)?;
            if left.gsi_base < right_end && right.gsi_base < left_end {
                return Err(Q35Com2RouteError::OverlappingIoApicGsiRanges);
            }
        }
    }

    let mut covering = None;
    for descriptor in snapshot.ioapics[..snapshot.ioapic_len].iter().flatten() {
        let end = probed_gsi_end(*descriptor, probes)?;
        if gsi >= descriptor.gsi_base && gsi < end && covering.replace(*descriptor).is_some() {
            return Err(Q35Com2RouteError::AmbiguousGsi(gsi));
        }
    }
    let controller = covering.ok_or(Q35Com2RouteError::UncoveredGsi(gsi))?;
    Ok(PlatformIrqRoute {
        gsi,
        polarity: PlatformIrqPolarity::ActiveHigh,
        trigger: PlatformIrqTrigger::Edge,
        vector: Q35_COM2_VECTOR,
        bsp_local_apic_id: snapshot.topology.entries().next().unwrap().local_apic_id(),
        controller,
    })
}

fn probed_gsi_end(
    descriptor: IoApicDescriptor,
    probes: &[IoApicProbe],
) -> Result<u32, Q35Com2RouteError> {
    let probe = probes
        .iter()
        .find(|probe| probe.descriptor == descriptor)
        .ok_or(Q35Com2RouteError::ProbeDoesNotMatchMadt)?;
    if probe.redirection_entries == 0 {
        return Err(Q35Com2RouteError::InvalidProbeCapacity);
    }
    descriptor
        .gsi_base
        .checked_add(probe.redirection_entries)
        .ok_or(Q35Com2RouteError::GsiRangeOverflow)
}

fn validate_irq3_override(flags: u16) -> Result<(), Q35Com2RouteError> {
    if flags & !0x000f != 0 {
        return Err(Q35Com2RouteError::InvalidMadt);
    }
    match flags & 0b11 {
        0 | 1 => {}
        2 => return Err(Q35Com2RouteError::ReservedPolarity),
        3 => return Err(Q35Com2RouteError::UnsupportedPolarity),
        _ => unreachable!(),
    }
    match (flags >> 2) & 0b11 {
        0 | 1 => Ok(()),
        2 => Err(Q35Com2RouteError::ReservedTrigger),
        3 => Err(Q35Com2RouteError::UnsupportedTrigger),
        _ => unreachable!(),
    }
}

const IOAPIC_REDIR_VECTOR_MASK: u64 = 0xff;
const IOAPIC_REDIR_DELIVERY_STATUS: u64 = 1 << 12;
const IOAPIC_REDIR_MASK: u64 = 1 << 16;
const IOAPIC_REDIR_DESTINATION_SHIFT: u32 = 56;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IoApicDeliveryStatus {
    Idle,
    SendPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IoApicRedirectionEntry(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DecodedIoApicRedirectionEntry {
    vector: u8,
    masked: bool,
    destination: u8,
    delivery_status: IoApicDeliveryStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IoApicRedirectionError {
    UnsupportedBits(u64),
    WrongVector(u8),
}

impl IoApicRedirectionEntry {
    pub(crate) const fn encode_q35_com2(masked: bool, destination: u8) -> Self {
        let mask = if masked { IOAPIC_REDIR_MASK } else { 0 };
        Self(
            (Q35_COM2_VECTOR as u64)
                | mask
                | ((destination as u64) << IOAPIC_REDIR_DESTINATION_SHIFT),
        )
    }

    pub(crate) const fn bits(self) -> u64 {
        self.0
    }

    pub(crate) fn decode(self) -> Result<DecodedIoApicRedirectionEntry, IoApicRedirectionError> {
        let allowed = IOAPIC_REDIR_VECTOR_MASK
            | IOAPIC_REDIR_DELIVERY_STATUS
            | IOAPIC_REDIR_MASK
            | (0xff_u64 << IOAPIC_REDIR_DESTINATION_SHIFT);
        let unsupported = self.0 & !allowed;
        if unsupported != 0 {
            return Err(IoApicRedirectionError::UnsupportedBits(unsupported));
        }
        let vector = self.0 as u8;
        if vector != Q35_COM2_VECTOR {
            return Err(IoApicRedirectionError::WrongVector(vector));
        }
        Ok(DecodedIoApicRedirectionEntry {
            vector,
            masked: self.0 & IOAPIC_REDIR_MASK != 0,
            destination: (self.0 >> IOAPIC_REDIR_DESTINATION_SHIFT) as u8,
            delivery_status: if self.0 & IOAPIC_REDIR_DELIVERY_STATUS == 0 {
                IoApicDeliveryStatus::Idle
            } else {
                IoApicDeliveryStatus::SendPending
            },
        })
    }
}

impl DecodedIoApicRedirectionEntry {
    pub(crate) const fn vector(self) -> u8 {
        self.vector
    }

    pub(crate) const fn masked(self) -> bool {
        self.masked
    }

    pub(crate) const fn destination(self) -> u8 {
        self.destination
    }

    pub(crate) const fn delivery_status(self) -> IoApicDeliveryStatus {
        self.delivery_status
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IoApicRouteState {
    Vacant,
    ReservedMasked { generation: u64 },
    LiveUnmasked { generation: u64 },
    Retiring { generation: u64 },
    RetiringMasked { generation: u64 },
    Exhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IoApicRouteTransitionError {
    Busy,
    WrongGeneration,
    WrongState,
    GenerationExhausted,
}

/// A pure, single-route lifecycle.  E2 couples these transitions to masked
/// MMIO transactions; E1 intentionally does not own volatile controller state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IoApicRouteLifecycle {
    state: IoApicRouteState,
    next_generation: u64,
}

impl IoApicRouteLifecycle {
    pub(crate) const fn new() -> Self {
        Self {
            state: IoApicRouteState::Vacant,
            next_generation: 1,
        }
    }

    pub(crate) const fn state(self) -> IoApicRouteState {
        self.state
    }

    pub(crate) fn reserve(&mut self) -> Result<u64, IoApicRouteTransitionError> {
        if self.state != IoApicRouteState::Vacant {
            return Err(IoApicRouteTransitionError::Busy);
        }
        if self.next_generation == 0 {
            self.state = IoApicRouteState::Exhausted;
            return Err(IoApicRouteTransitionError::GenerationExhausted);
        }
        let generation = self.next_generation;
        self.next_generation = self.next_generation.checked_add(1).unwrap_or(0);
        self.state = IoApicRouteState::ReservedMasked { generation };
        Ok(generation)
    }

    pub(crate) fn commit(&mut self, generation: u64) -> Result<(), IoApicRouteTransitionError> {
        match self.state {
            IoApicRouteState::ReservedMasked {
                generation: current,
            } if current == generation => {
                self.state = IoApicRouteState::LiveUnmasked { generation };
                Ok(())
            }
            IoApicRouteState::ReservedMasked { .. } => {
                Err(IoApicRouteTransitionError::WrongGeneration)
            }
            _ => Err(IoApicRouteTransitionError::WrongState),
        }
    }

    pub(crate) fn begin_retire(
        &mut self,
        generation: u64,
    ) -> Result<(), IoApicRouteTransitionError> {
        match self.state {
            IoApicRouteState::LiveUnmasked {
                generation: current,
            } if current == generation => {
                self.state = IoApicRouteState::Retiring { generation };
                Ok(())
            }
            IoApicRouteState::LiveUnmasked { .. } => {
                Err(IoApicRouteTransitionError::WrongGeneration)
            }
            _ => Err(IoApicRouteTransitionError::WrongState),
        }
    }

    pub(crate) fn mask(&mut self, generation: u64) -> Result<(), IoApicRouteTransitionError> {
        match self.state {
            IoApicRouteState::Retiring {
                generation: current,
            } if current == generation => {
                self.state = IoApicRouteState::RetiringMasked { generation };
                Ok(())
            }
            IoApicRouteState::Retiring { .. } => Err(IoApicRouteTransitionError::WrongGeneration),
            _ => Err(IoApicRouteTransitionError::WrongState),
        }
    }

    pub(crate) fn release(&mut self, generation: u64) -> Result<(), IoApicRouteTransitionError> {
        match self.state {
            IoApicRouteState::ReservedMasked {
                generation: current,
            }
            | IoApicRouteState::RetiringMasked {
                generation: current,
            } if current == generation => {
                self.state = IoApicRouteState::Vacant;
                Ok(())
            }
            IoApicRouteState::ReservedMasked { .. } | IoApicRouteState::RetiringMasked { .. } => {
                Err(IoApicRouteTransitionError::WrongGeneration)
            }
            _ => Err(IoApicRouteTransitionError::WrongState),
        }
    }
}

impl PmTimerProposal {
    #[allow(
        dead_code,
        reason = "host ACPI tests inspect the proposal before authorization"
    )]
    pub(crate) const fn port(self) -> u16 {
        self.port
    }
    #[allow(
        dead_code,
        reason = "host ACPI tests inspect the proposal before authorization"
    )]
    pub(crate) const fn width(self) -> PmTimerWidth {
        self.width
    }
}

pub(crate) struct AcpiSnapshotWorkspace {
    rsdp: [u8; MAX_RSDP_BYTES],
    table: [u8; MAX_ACPI_TABLE_BYTES],
    root_entries: [u64; MAX_ROOT_ENTRIES],
}

impl AcpiSnapshotWorkspace {
    #[allow(
        dead_code,
        reason = "host parser tests use value construction while the live BSP initializes its large workspace in place"
    )]
    pub(crate) const fn new() -> Self {
        Self {
            rsdp: [0; MAX_RSDP_BYTES],
            table: [0; MAX_ACPI_TABLE_BYTES],
            root_entries: [0; MAX_ROOT_ENTRIES],
        }
    }
}

pub(crate) trait AcpiByteReader {
    fn read_exact(&mut self, physical_start: u64, destination: &mut [u8]) -> Result<(), ()>;
}

#[derive(Clone, Copy)]
enum RootTable {
    Rsdt(u64),
    Xsdt(u64),
}

pub(crate) fn discover_pm_timer_proposal<R: AcpiByteReader>(
    reader: &mut R,
    rsdp_physical: u64,
    workspace: &mut AcpiSnapshotWorkspace,
) -> Result<PmTimerProposal, AcpiTimeError> {
    if rsdp_physical == 0 {
        return Err(AcpiTimeError::InvalidRsdp);
    }
    let root = snapshot_rsdp(reader, rsdp_physical, &mut workspace.rsdp)?;
    let (root_physical, entry_bytes, expected_signature) = match root {
        RootTable::Xsdt(address) => (address, 8_usize, *b"XSDT"),
        RootTable::Rsdt(address) => (address, 4_usize, *b"RSDT"),
    };
    let root_len = snapshot_sdt(
        reader,
        root_physical,
        &mut workspace.table,
        AcpiTimeError::InvalidRootTable,
    )?;
    let root_bytes = &workspace.table[..root_len];
    if root_bytes[..4] != expected_signature {
        return Err(AcpiTimeError::InvalidRootTable);
    }
    let payload = root_len
        .checked_sub(SDT_HEADER_BYTES)
        .ok_or(AcpiTimeError::InvalidRootTable)?;
    if payload % entry_bytes != 0 {
        return Err(AcpiTimeError::InvalidRootTable);
    }
    let count = payload / entry_bytes;
    if count == 0 || count > MAX_ROOT_ENTRIES {
        return Err(AcpiTimeError::RootEntryLimit);
    }
    for index in 0..count {
        let start = SDT_HEADER_BYTES + index * entry_bytes;
        workspace.root_entries[index] = if entry_bytes == 8 {
            u64::from_le_bytes(root_bytes[start..start + 8].try_into().unwrap())
        } else {
            u64::from(u32::from_le_bytes(
                root_bytes[start..start + 4].try_into().unwrap(),
            ))
        };
    }

    let mut proposal = None;
    for index in 0..count {
        let physical = workspace.root_entries[index];
        if physical == 0 {
            continue;
        }
        let header_len = snapshot_sdt_header(reader, physical, &mut workspace.table)?;
        if workspace.table[..4] != *b"FACP" {
            continue;
        }
        if proposal.is_some() {
            return Err(AcpiTimeError::DuplicateFadt);
        }
        let fadt_len = finish_sdt_snapshot(
            reader,
            physical,
            header_len,
            &mut workspace.table,
            AcpiTimeError::InvalidFadt,
        )?;
        proposal = Some(parse_fadt_pm_timer(&workspace.table[..fadt_len])?);
    }
    proposal.ok_or(AcpiTimeError::MissingFadt)
}

pub(crate) fn discover_cpu_topology<R: AcpiByteReader>(
    reader: &mut R,
    rsdp_physical: u64,
    live_bsp_local_apic_id: u8,
    live_cpu_is_bsp: bool,
    workspace: &mut AcpiSnapshotWorkspace,
) -> Result<CpuTopology, CpuTopologyError> {
    if !live_cpu_is_bsp {
        return Err(CpuTopologyError::LiveCpuIsNotBootstrapProcessor);
    }
    if rsdp_physical == 0 {
        return Err(CpuTopologyError::InvalidRsdp);
    }
    let root = snapshot_rsdp(reader, rsdp_physical, &mut workspace.rsdp)
        .map_err(map_topology_acpi_error)?;
    let (root_physical, entry_bytes, expected_signature) = match root {
        RootTable::Xsdt(address) => (address, 8_usize, *b"XSDT"),
        RootTable::Rsdt(address) => (address, 4_usize, *b"RSDT"),
    };
    let root_len = snapshot_sdt(
        reader,
        root_physical,
        &mut workspace.table,
        AcpiTimeError::InvalidRootTable,
    )
    .map_err(map_topology_acpi_error)?;
    let root_bytes = &workspace.table[..root_len];
    if root_bytes[..4] != expected_signature {
        return Err(CpuTopologyError::InvalidRootTable);
    }
    let payload = root_len
        .checked_sub(SDT_HEADER_BYTES)
        .ok_or(CpuTopologyError::InvalidRootTable)?;
    if payload % entry_bytes != 0 {
        return Err(CpuTopologyError::InvalidRootTable);
    }
    let count = payload / entry_bytes;
    if count == 0 || count > MAX_ROOT_ENTRIES {
        return Err(CpuTopologyError::RootEntryLimit);
    }
    for index in 0..count {
        let start = SDT_HEADER_BYTES + index * entry_bytes;
        workspace.root_entries[index] = if entry_bytes == 8 {
            u64::from_le_bytes(root_bytes[start..start + 8].try_into().unwrap())
        } else {
            u64::from(u32::from_le_bytes(
                root_bytes[start..start + 4].try_into().unwrap(),
            ))
        };
    }

    let mut topology = None;
    for index in 0..count {
        let physical = workspace.root_entries[index];
        if physical == 0 {
            continue;
        }
        let header_len = snapshot_sdt_header(reader, physical, &mut workspace.table)
            .map_err(map_topology_acpi_error)?;
        if workspace.table[..4] != *b"APIC" {
            continue;
        }
        if topology.is_some() {
            return Err(CpuTopologyError::DuplicateMadt);
        }
        let madt_len = finish_sdt_snapshot(
            reader,
            physical,
            header_len,
            &mut workspace.table,
            AcpiTimeError::InvalidRootTable,
        )
        .map_err(|error| match error {
            AcpiTimeError::ReadFailure => CpuTopologyError::ReadFailure,
            _ => CpuTopologyError::InvalidMadt,
        })?;
        topology = Some(parse_madt(
            &workspace.table[..madt_len],
            live_bsp_local_apic_id,
        )?);
    }
    topology.ok_or(CpuTopologyError::MissingMadt)
}

fn snapshot_selected_madt<R: AcpiByteReader>(
    reader: &mut R,
    rsdp_physical: u64,
    workspace: &mut AcpiSnapshotWorkspace,
) -> Result<usize, Q35Com2RouteError> {
    if rsdp_physical == 0 {
        return Err(Q35Com2RouteError::InvalidMadt);
    }
    let root = snapshot_rsdp(reader, rsdp_physical, &mut workspace.rsdp)
        .map_err(|_| Q35Com2RouteError::InvalidMadt)?;
    let (root_physical, entry_bytes, expected_signature) = match root {
        RootTable::Xsdt(address) => (address, 8_usize, *b"XSDT"),
        RootTable::Rsdt(address) => (address, 4_usize, *b"RSDT"),
    };
    let root_len = snapshot_sdt(
        reader,
        root_physical,
        &mut workspace.table,
        AcpiTimeError::InvalidRootTable,
    )
    .map_err(|_| Q35Com2RouteError::InvalidMadt)?;
    let root_bytes = &workspace.table[..root_len];
    if root_bytes[..4] != expected_signature {
        return Err(Q35Com2RouteError::InvalidMadt);
    }
    let payload = root_len
        .checked_sub(SDT_HEADER_BYTES)
        .ok_or(Q35Com2RouteError::InvalidMadt)?;
    if payload % entry_bytes != 0 {
        return Err(Q35Com2RouteError::InvalidMadt);
    }
    let count = payload / entry_bytes;
    if count == 0 || count > MAX_ROOT_ENTRIES {
        return Err(Q35Com2RouteError::InvalidMadt);
    }
    for index in 0..count {
        let start = SDT_HEADER_BYTES + index * entry_bytes;
        workspace.root_entries[index] = if entry_bytes == 8 {
            u64::from_le_bytes(root_bytes[start..start + 8].try_into().unwrap())
        } else {
            u64::from(u32::from_le_bytes(
                root_bytes[start..start + 4].try_into().unwrap(),
            ))
        };
    }
    let mut selected = None;
    for index in 0..count {
        let physical = workspace.root_entries[index];
        if physical == 0 {
            continue;
        }
        let header_len = snapshot_sdt_header(reader, physical, &mut workspace.table)
            .map_err(|_| Q35Com2RouteError::InvalidMadt)?;
        if workspace.table[..4] != *b"APIC" {
            continue;
        }
        if selected.is_some() {
            return Err(Q35Com2RouteError::InvalidMadt);
        }
        selected = Some(
            finish_sdt_snapshot(
                reader,
                physical,
                header_len,
                &mut workspace.table,
                AcpiTimeError::InvalidRootTable,
            )
            .map_err(|_| Q35Com2RouteError::InvalidMadt)?,
        );
    }
    selected.ok_or(Q35Com2RouteError::InvalidMadt)
}

fn parse_q35_com2_madt(
    bytes: &[u8],
    live_bsp_local_apic_id: u8,
) -> Result<Q35Com2MadtSnapshot, Q35Com2RouteError> {
    let topology =
        parse_madt(bytes, live_bsp_local_apic_id).map_err(Q35Com2RouteError::Topology)?;
    let mut ioapics: [Option<IoApicDescriptor>; MAX_MADT_IOAPICS] = [None; MAX_MADT_IOAPICS];
    let mut ioapic_len = 0;
    let mut irq3_override = None;
    let mut ignored_iso_count = 0;
    let mut cursor = MADT_HEADER_BYTES;
    while cursor < bytes.len() {
        let entry_len = usize::from(
            *bytes
                .get(cursor + 1)
                .ok_or(Q35Com2RouteError::InvalidMadt)?,
        );
        if entry_len < 2 {
            return Err(Q35Com2RouteError::InvalidMadt);
        }
        let end = cursor
            .checked_add(entry_len)
            .ok_or(Q35Com2RouteError::InvalidMadt)?;
        if end > bytes.len() {
            return Err(Q35Com2RouteError::InvalidMadt);
        }
        let entry = &bytes[cursor..end];
        match entry[0] {
            MADT_ENTRY_IOAPIC => {
                if entry_len != MADT_IOAPIC_BYTES {
                    return Err(Q35Com2RouteError::InvalidMadt);
                }
                let descriptor = IoApicDescriptor {
                    id: entry[2],
                    physical_address: u64::from(u32::from_le_bytes(
                        entry[4..8].try_into().unwrap(),
                    )),
                    gsi_base: u32::from_le_bytes(entry[8..12].try_into().unwrap()),
                };
                if descriptor.physical_address == 0 || descriptor.physical_address & 0xfff != 0 {
                    return Err(Q35Com2RouteError::InvalidIoApicAddress(
                        descriptor.physical_address,
                    ));
                }
                for existing in ioapics[..ioapic_len].iter().flatten() {
                    if existing.id == descriptor.id {
                        return Err(Q35Com2RouteError::DuplicateIoApicId(descriptor.id));
                    }
                    if existing.physical_address == descriptor.physical_address {
                        return Err(Q35Com2RouteError::DuplicateIoApicAddress(
                            descriptor.physical_address,
                        ));
                    }
                    if existing.gsi_base == descriptor.gsi_base {
                        return Err(Q35Com2RouteError::DuplicateIoApicGsiBase(
                            descriptor.gsi_base,
                        ));
                    }
                }
                if ioapic_len == MAX_MADT_IOAPICS {
                    return Err(Q35Com2RouteError::IoApicCapacityExceeded);
                }
                ioapics[ioapic_len] = Some(descriptor);
                ioapic_len += 1;
            }
            MADT_ENTRY_INTERRUPT_SOURCE_OVERRIDE => {
                if entry_len != MADT_INTERRUPT_SOURCE_OVERRIDE_BYTES {
                    return Err(Q35Com2RouteError::InvalidMadt);
                }
                let bus = entry[2];
                let source = entry[3];
                if bus == 0 && source == Q35_COM2_ISA_IRQ {
                    if irq3_override.is_some() {
                        return Err(Q35Com2RouteError::DuplicateIrq3Override);
                    }
                    irq3_override = Some(InterruptSourceOverride {
                        gsi: u32::from_le_bytes(entry[4..8].try_into().unwrap()),
                        flags: u16::from_le_bytes(entry[8..10].try_into().unwrap()),
                    });
                } else {
                    ignored_iso_count += 1;
                    if ignored_iso_count > MAX_MADT_ISO_OVERRIDES {
                        return Err(Q35Com2RouteError::IsoCapacityExceeded);
                    }
                }
            }
            _ => {}
        }
        cursor = end;
    }
    Ok(Q35Com2MadtSnapshot {
        topology,
        ioapics,
        ioapic_len,
        irq3_override,
    })
}

fn map_topology_acpi_error(error: AcpiTimeError) -> CpuTopologyError {
    match error {
        AcpiTimeError::ReadFailure => CpuTopologyError::ReadFailure,
        AcpiTimeError::InvalidRsdp => CpuTopologyError::InvalidRsdp,
        AcpiTimeError::RootEntryLimit => CpuTopologyError::RootEntryLimit,
        _ => CpuTopologyError::InvalidRootTable,
    }
}

fn parse_madt(bytes: &[u8], live_bsp_local_apic_id: u8) -> Result<CpuTopology, CpuTopologyError> {
    if bytes.len() < MADT_HEADER_BYTES || bytes[..4] != *b"APIC" {
        return Err(CpuTopologyError::InvalidMadt);
    }
    let legacy_address = u64::from(u32::from_le_bytes(
        bytes[MADT_LOCAL_APIC_ADDRESS..MADT_LOCAL_APIC_ADDRESS + 4]
            .try_into()
            .unwrap(),
    ));
    validate_local_apic_address(legacy_address)?;
    let flags = u32::from_le_bytes(bytes[MADT_FLAGS..MADT_FLAGS + 4].try_into().unwrap());

    let mut seen_apic_ids = [false; 256];
    let mut seen_uids = [false; 256];
    let mut enabled = [None; MAX_DW0_CPUS];
    let mut enabled_len = 0_usize;
    let mut local_apic_address = legacy_address;
    let mut saw_override = false;
    let mut cursor = MADT_HEADER_BYTES;
    while cursor < bytes.len() {
        let header_end = cursor.checked_add(2).ok_or(CpuTopologyError::InvalidMadt)?;
        if header_end > bytes.len() {
            return Err(CpuTopologyError::InvalidMadt);
        }
        let entry_type = bytes[cursor];
        let entry_len = usize::from(bytes[cursor + 1]);
        if entry_len < 2 {
            return Err(CpuTopologyError::InvalidMadt);
        }
        let end = cursor
            .checked_add(entry_len)
            .ok_or(CpuTopologyError::InvalidMadt)?;
        if end > bytes.len() {
            return Err(CpuTopologyError::InvalidMadt);
        }
        let entry = &bytes[cursor..end];
        match entry_type {
            MADT_ENTRY_PROCESSOR_LOCAL_APIC => {
                if entry_len != MADT_PROCESSOR_LOCAL_APIC_BYTES {
                    return Err(CpuTopologyError::InvalidMadt);
                }
                let uid = entry[2];
                let apic_id = entry[3];
                if core::mem::replace(&mut seen_uids[usize::from(uid)], true) {
                    return Err(CpuTopologyError::DuplicateProcessorUid(uid));
                }
                if core::mem::replace(&mut seen_apic_ids[usize::from(apic_id)], true) {
                    return Err(CpuTopologyError::DuplicateLocalApicId(apic_id));
                }
                let processor_flags = u32::from_le_bytes(entry[4..8].try_into().unwrap());
                if processor_flags & MADT_PROCESSOR_ENABLED != 0 {
                    if enabled_len == MAX_DW0_CPUS {
                        return Err(CpuTopologyError::CpuCapacity {
                            observed: enabled_len + 1,
                            capacity: MAX_DW0_CPUS,
                        });
                    }
                    enabled[enabled_len] = Some((apic_id, uid));
                    enabled_len += 1;
                }
            }
            MADT_ENTRY_LOCAL_APIC_ADDRESS_OVERRIDE => {
                if entry_len != MADT_LOCAL_APIC_ADDRESS_OVERRIDE_BYTES || saw_override {
                    return if saw_override {
                        Err(CpuTopologyError::DuplicateLocalApicAddressOverride)
                    } else {
                        Err(CpuTopologyError::InvalidMadt)
                    };
                }
                let address = u64::from_le_bytes(entry[4..12].try_into().unwrap());
                validate_local_apic_address(address)?;
                local_apic_address = address;
                saw_override = true;
            }
            MADT_ENTRY_PROCESSOR_LOCAL_X2APIC => {
                if entry_len != MADT_PROCESSOR_LOCAL_X2APIC_BYTES {
                    return Err(CpuTopologyError::InvalidMadt);
                }
                let x2apic_id = u32::from_le_bytes(entry[4..8].try_into().unwrap());
                let processor_flags = u32::from_le_bytes(entry[8..12].try_into().unwrap());
                if processor_flags & MADT_PROCESSOR_ENABLED != 0 {
                    return Err(CpuTopologyError::UnsupportedEnabledX2Apic(x2apic_id));
                }
            }
            _ => {}
        }
        cursor = end;
    }

    if enabled_len == 0 {
        return Err(CpuTopologyError::MissingBootstrapProcessor(
            live_bsp_local_apic_id,
        ));
    }
    enabled[..enabled_len]
        .sort_unstable_by_key(|entry| entry.expect("enabled CPU prefix contains an entry").0);
    let bsp_position = enabled[..enabled_len]
        .iter()
        .position(|entry| entry.is_some_and(|(id, _)| id == live_bsp_local_apic_id))
        .ok_or(CpuTopologyError::MissingBootstrapProcessor(
            live_bsp_local_apic_id,
        ))?;
    let bsp = enabled[bsp_position].take().unwrap();
    for index in bsp_position..enabled_len - 1 {
        enabled[index] = enabled[index + 1].take();
    }
    enabled[enabled_len - 1] = None;

    let mut entries = [None; MAX_DW0_CPUS];
    entries[0] = Some(CpuTopologyEntry {
        logical_index: 0,
        local_apic_id: bsp.0,
        acpi_processor_uid: bsp.1,
    });
    for index in 1..enabled_len {
        let (local_apic_id, acpi_processor_uid) = enabled[index - 1].unwrap();
        entries[index] = Some(CpuTopologyEntry {
            logical_index: index as u16,
            local_apic_id,
            acpi_processor_uid,
        });
    }
    Ok(CpuTopology {
        local_apic_physical_address: local_apic_address,
        pc_at_compatible: flags & MADT_PCAT_COMPAT != 0,
        entries,
        len: enabled_len,
    })
}

fn validate_local_apic_address(address: u64) -> Result<(), CpuTopologyError> {
    if address == 0 || address & 0xfff != 0 || address > 0x000f_ffff_ffff_f000 {
        return Err(CpuTopologyError::InvalidLocalApicAddress(address));
    }
    Ok(())
}

pub(crate) fn authorize_q35_pm_timer(
    proposal: PmTimerProposal,
) -> Result<PmTimerDescriptor, AcpiTimeError> {
    if proposal.port != Q35_PM_TIMER_PORT {
        return Err(AcpiTimeError::UnauthorizedPmTimerPort);
    }
    PmTimerDescriptor::new(proposal.port, proposal.width).map_err(|_| AcpiTimeError::InvalidFadt)
}

fn snapshot_rsdp<R: AcpiByteReader>(
    reader: &mut R,
    physical: u64,
    storage: &mut [u8; MAX_RSDP_BYTES],
) -> Result<RootTable, AcpiTimeError> {
    read(reader, physical, &mut storage[..RSDP_V1_BYTES])?;
    if &storage[..8] != b"RSD PTR " || checksum(&storage[..RSDP_V1_BYTES]) != 0 {
        return Err(AcpiTimeError::InvalidRsdp);
    }
    let revision = storage[15];
    let rsdt = u64::from(u32::from_le_bytes(storage[16..20].try_into().unwrap()));
    if revision < 2 {
        return (rsdt != 0)
            .then_some(RootTable::Rsdt(rsdt))
            .ok_or(AcpiTimeError::InvalidRsdp);
    }
    read(
        reader,
        physical
            .checked_add(RSDP_V1_BYTES as u64)
            .ok_or(AcpiTimeError::InvalidRsdp)?,
        &mut storage[RSDP_V1_BYTES..RSDP_V2_BYTES],
    )?;
    let length = usize::try_from(u32::from_le_bytes(storage[20..24].try_into().unwrap()))
        .map_err(|_| AcpiTimeError::InvalidRsdp)?;
    if !(RSDP_V2_BYTES..=MAX_RSDP_BYTES).contains(&length) {
        return Err(AcpiTimeError::InvalidRsdp);
    }
    if length > RSDP_V2_BYTES {
        read(
            reader,
            physical
                .checked_add(RSDP_V2_BYTES as u64)
                .ok_or(AcpiTimeError::InvalidRsdp)?,
            &mut storage[RSDP_V2_BYTES..length],
        )?;
    }
    if checksum(&storage[..length]) != 0 {
        return Err(AcpiTimeError::InvalidRsdp);
    }
    let xsdt = u64::from_le_bytes(storage[24..32].try_into().unwrap());
    if xsdt != 0 {
        return Ok(RootTable::Xsdt(xsdt));
    }
    (rsdt != 0)
        .then_some(RootTable::Rsdt(rsdt))
        .ok_or(AcpiTimeError::InvalidRsdp)
}

fn snapshot_sdt<R: AcpiByteReader>(
    reader: &mut R,
    physical: u64,
    storage: &mut [u8; MAX_ACPI_TABLE_BYTES],
    invalid: AcpiTimeError,
) -> Result<usize, AcpiTimeError> {
    let length = snapshot_sdt_header(reader, physical, storage).map_err(|_| invalid)?;
    finish_sdt_snapshot(reader, physical, length, storage, invalid)
}

fn snapshot_sdt_header<R: AcpiByteReader>(
    reader: &mut R,
    physical: u64,
    storage: &mut [u8; MAX_ACPI_TABLE_BYTES],
) -> Result<usize, AcpiTimeError> {
    read(reader, physical, &mut storage[..SDT_HEADER_BYTES])?;
    let length = usize::try_from(u32::from_le_bytes(storage[4..8].try_into().unwrap()))
        .map_err(|_| AcpiTimeError::InvalidRootTable)?;
    if !(SDT_HEADER_BYTES..=MAX_ACPI_TABLE_BYTES).contains(&length) {
        return Err(AcpiTimeError::InvalidRootTable);
    }
    Ok(length)
}

fn finish_sdt_snapshot<R: AcpiByteReader>(
    reader: &mut R,
    physical: u64,
    length: usize,
    storage: &mut [u8; MAX_ACPI_TABLE_BYTES],
    invalid: AcpiTimeError,
) -> Result<usize, AcpiTimeError> {
    if length > SDT_HEADER_BYTES {
        read(
            reader,
            physical
                .checked_add(SDT_HEADER_BYTES as u64)
                .ok_or(invalid)?,
            &mut storage[SDT_HEADER_BYTES..length],
        )?;
    }
    if checksum(&storage[..length]) != 0 {
        return Err(invalid);
    }
    Ok(length)
}

fn parse_fadt_pm_timer(bytes: &[u8]) -> Result<PmTimerProposal, AcpiTimeError> {
    if bytes.len() < FADT_MINIMUM_FLAGS_BYTES {
        return Err(AcpiTimeError::InvalidFadt);
    }
    let flags = u32::from_le_bytes(bytes[FADT_FLAGS..FADT_FLAGS + 4].try_into().unwrap());
    if flags & FADT_HW_REDUCED_ACPI != 0 {
        return Err(AcpiTimeError::HardwareReduced);
    }
    let width = if flags & FADT_TMR_VAL_EXT != 0 {
        PmTimerWidth::Bits32
    } else {
        PmTimerWidth::Bits24
    };

    let legacy_address = u32::from_le_bytes(
        bytes[FADT_PM_TMR_BLK..FADT_PM_TMR_BLK + 4]
            .try_into()
            .unwrap(),
    );
    let legacy = (bytes[FADT_PM_TMR_LEN] == 4
        && legacy_address != 0
        && legacy_address <= u32::from(u16::MAX))
    .then_some(legacy_address as u16);
    let extended = (bytes.len() >= FADT_X_PM_TIMER_END)
        .then(|| {
            let mut gas = [0_u8; 12];
            gas.copy_from_slice(&bytes[FADT_X_PM_TMR_BLK..FADT_X_PM_TMR_BLK + 12]);
            usable_pm_timer_gas(gas)
        })
        .flatten();
    if let (Some(extended), Some(legacy)) = (extended, legacy)
        && extended != legacy
    {
        return Err(AcpiTimeError::ConflictingPmTimer);
    }
    let port = extended.or(legacy).ok_or(AcpiTimeError::MissingPmTimer)?;
    Ok(PmTimerProposal { port, width })
}

fn usable_pm_timer_gas(gas: [u8; 12]) -> Option<u16> {
    let address = u64::from_le_bytes(gas[4..12].try_into().ok()?);
    (gas[0] == GAS_SYSTEM_IO
        && gas[1] == 32
        && gas[2] == 0
        && matches!(gas[3], 0 | GAS_DWORD_ACCESS)
        && address != 0
        && address <= u64::from(u16::MAX))
    .then_some(address as u16)
}

fn read<R: AcpiByteReader>(
    reader: &mut R,
    physical: u64,
    destination: &mut [u8],
) -> Result<(), AcpiTimeError> {
    reader
        .read_exact(physical, destination)
        .map_err(|()| AcpiTimeError::ReadFailure)
}

fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::boxed::Box;
    use std::collections::BTreeMap;
    use std::vec;
    use std::vec::Vec;

    #[derive(Default, Clone)]
    struct Memory(BTreeMap<u64, u8>);
    impl Memory {
        fn place(&mut self, address: u64, bytes: &[u8]) {
            for (offset, byte) in bytes.iter().copied().enumerate() {
                self.0.insert(address + offset as u64, byte);
            }
        }
    }
    impl AcpiByteReader for Memory {
        fn read_exact(&mut self, physical_start: u64, destination: &mut [u8]) -> Result<(), ()> {
            for (offset, byte) in destination.iter_mut().enumerate() {
                *byte = *self.0.get(&(physical_start + offset as u64)).ok_or(())?;
            }
            Ok(())
        }
    }

    struct MutatingMemory {
        memory: Memory,
        reads: usize,
    }
    impl AcpiByteReader for MutatingMemory {
        fn read_exact(&mut self, physical_start: u64, destination: &mut [u8]) -> Result<(), ()> {
            self.memory.read_exact(physical_start, destination)?;
            self.reads += 1;
            for offset in 0..destination.len() {
                if let Some(byte) = self.memory.0.get_mut(&(physical_start + offset as u64)) {
                    *byte ^= 0x5a;
                }
            }
            Ok(())
        }
    }

    fn workspace() -> Box<AcpiSnapshotWorkspace> {
        Box::new(AcpiSnapshotWorkspace::new())
    }
    fn fix_checksum(bytes: &mut [u8], checksum_offset: usize) {
        bytes[checksum_offset] = 0;
        bytes[checksum_offset] = 0_u8.wrapping_sub(checksum(bytes));
    }
    fn sdt(signature: [u8; 4], length: usize) -> Vec<u8> {
        let mut bytes = vec![0_u8; length];
        bytes[..4].copy_from_slice(&signature);
        bytes[4..8].copy_from_slice(&(length as u32).to_le_bytes());
        bytes[8] = 1;
        bytes
    }
    fn fixture(extended_port: Option<u16>, legacy_port: u16, flags: u32) -> (Memory, u64) {
        const RSDP: u64 = 0x1000;
        const XSDT: u64 = 0x2000;
        const FADT: u64 = 0x3000;
        let mut memory = Memory::default();
        let mut fadt = sdt(*b"FACP", FADT_X_PM_TIMER_END);
        fadt[FADT_PM_TMR_BLK..FADT_PM_TMR_BLK + 4]
            .copy_from_slice(&u32::from(legacy_port).to_le_bytes());
        fadt[FADT_PM_TMR_LEN] = 4;
        fadt[FADT_FLAGS..FADT_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
        if let Some(port) = extended_port {
            let gas = &mut fadt[FADT_X_PM_TMR_BLK..FADT_X_PM_TMR_BLK + 12];
            gas[0] = GAS_SYSTEM_IO;
            gas[1] = 32;
            gas[2] = 0;
            gas[3] = GAS_DWORD_ACCESS;
            gas[4..12].copy_from_slice(&u64::from(port).to_le_bytes());
        }
        fix_checksum(&mut fadt, 9);
        memory.place(FADT, &fadt);
        let mut xsdt = sdt(*b"XSDT", SDT_HEADER_BYTES + 8);
        xsdt[SDT_HEADER_BYTES..].copy_from_slice(&FADT.to_le_bytes());
        fix_checksum(&mut xsdt, 9);
        memory.place(XSDT, &xsdt);
        let mut rsdp = [0_u8; RSDP_V2_BYTES];
        rsdp[..8].copy_from_slice(b"RSD PTR ");
        rsdp[15] = 2;
        rsdp[20..24].copy_from_slice(&(RSDP_V2_BYTES as u32).to_le_bytes());
        rsdp[24..32].copy_from_slice(&XSDT.to_le_bytes());
        fix_checksum(&mut rsdp[..RSDP_V1_BYTES], 8);
        fix_checksum(&mut rsdp, 32);
        memory.place(RSDP, &rsdp);
        (memory, RSDP)
    }
    fn proposal(
        memory: &mut impl AcpiByteReader,
        rsdp: u64,
    ) -> Result<PmTimerProposal, AcpiTimeError> {
        discover_pm_timer_proposal(memory, rsdp, &mut workspace())
    }

    fn topology_fixture(madts: &[Vec<u8>]) -> (Memory, u64) {
        const RSDP: u64 = 0x1000;
        const XSDT: u64 = 0x2000;
        const FIRST_MADT: u64 = 0x3000;
        let mut memory = Memory::default();
        let mut xsdt = sdt(*b"XSDT", SDT_HEADER_BYTES + madts.len() * 8);
        for (index, madt) in madts.iter().enumerate() {
            let address = FIRST_MADT + index as u64 * 0x1_0000;
            memory.place(address, madt);
            let start = SDT_HEADER_BYTES + index * 8;
            xsdt[start..start + 8].copy_from_slice(&address.to_le_bytes());
        }
        fix_checksum(&mut xsdt, 9);
        memory.place(XSDT, &xsdt);

        let mut rsdp = [0_u8; RSDP_V2_BYTES];
        rsdp[..8].copy_from_slice(b"RSD PTR ");
        rsdp[15] = 2;
        rsdp[20..24].copy_from_slice(&(RSDP_V2_BYTES as u32).to_le_bytes());
        rsdp[24..32].copy_from_slice(&XSDT.to_le_bytes());
        fix_checksum(&mut rsdp[..RSDP_V1_BYTES], 8);
        fix_checksum(&mut rsdp, 32);
        memory.place(RSDP, &rsdp);
        (memory, RSDP)
    }

    fn madt(entries: &[&[u8]]) -> Vec<u8> {
        let length = MADT_HEADER_BYTES + entries.iter().map(|entry| entry.len()).sum::<usize>();
        let mut bytes = sdt(*b"APIC", length);
        bytes[MADT_LOCAL_APIC_ADDRESS..MADT_LOCAL_APIC_ADDRESS + 4]
            .copy_from_slice(&0xfee0_0000_u32.to_le_bytes());
        bytes[MADT_FLAGS..MADT_FLAGS + 4].copy_from_slice(&MADT_PCAT_COMPAT.to_le_bytes());
        let mut cursor = MADT_HEADER_BYTES;
        for entry in entries {
            bytes[cursor..cursor + entry.len()].copy_from_slice(entry);
            cursor += entry.len();
        }
        fix_checksum(&mut bytes, 9);
        bytes
    }

    fn local_apic(uid: u8, apic_id: u8, flags: u32) -> [u8; MADT_PROCESSOR_LOCAL_APIC_BYTES] {
        let mut entry = [0_u8; MADT_PROCESSOR_LOCAL_APIC_BYTES];
        entry[0] = MADT_ENTRY_PROCESSOR_LOCAL_APIC;
        entry[1] = MADT_PROCESSOR_LOCAL_APIC_BYTES as u8;
        entry[2] = uid;
        entry[3] = apic_id;
        entry[4..8].copy_from_slice(&flags.to_le_bytes());
        entry
    }

    fn x2apic(id: u32, flags: u32, uid: u32) -> [u8; MADT_PROCESSOR_LOCAL_X2APIC_BYTES] {
        let mut entry = [0_u8; MADT_PROCESSOR_LOCAL_X2APIC_BYTES];
        entry[0] = MADT_ENTRY_PROCESSOR_LOCAL_X2APIC;
        entry[1] = MADT_PROCESSOR_LOCAL_X2APIC_BYTES as u8;
        entry[4..8].copy_from_slice(&id.to_le_bytes());
        entry[8..12].copy_from_slice(&flags.to_le_bytes());
        entry[12..16].copy_from_slice(&uid.to_le_bytes());
        entry
    }

    fn ioapic(id: u8, address: u32, gsi_base: u32) -> [u8; MADT_IOAPIC_BYTES] {
        let mut entry = [0_u8; MADT_IOAPIC_BYTES];
        entry[0] = MADT_ENTRY_IOAPIC;
        entry[1] = MADT_IOAPIC_BYTES as u8;
        entry[2] = id;
        entry[4..8].copy_from_slice(&address.to_le_bytes());
        entry[8..12].copy_from_slice(&gsi_base.to_le_bytes());
        entry
    }

    fn iso(
        bus: u8,
        source: u8,
        gsi: u32,
        flags: u16,
    ) -> [u8; MADT_INTERRUPT_SOURCE_OVERRIDE_BYTES] {
        let mut entry = [0_u8; MADT_INTERRUPT_SOURCE_OVERRIDE_BYTES];
        entry[0] = MADT_ENTRY_INTERRUPT_SOURCE_OVERRIDE;
        entry[1] = MADT_INTERRUPT_SOURCE_OVERRIDE_BYTES as u8;
        entry[2] = bus;
        entry[3] = source;
        entry[4..8].copy_from_slice(&gsi.to_le_bytes());
        entry[8..10].copy_from_slice(&flags.to_le_bytes());
        entry
    }

    fn q35_route(
        memory: &mut impl AcpiByteReader,
        rsdp: u64,
        probes: &[IoApicProbe],
    ) -> Result<PlatformIrqRoute, Q35Com2RouteError> {
        discover_q35_com2_route(memory, rsdp, 2, true, probes, &mut workspace())
    }

    fn topology(
        memory: &mut impl AcpiByteReader,
        rsdp: u64,
        bsp_id: u8,
    ) -> Result<CpuTopology, CpuTopologyError> {
        discover_cpu_topology(memory, rsdp, bsp_id, true, &mut workspace())
    }

    #[test]
    fn q35_extended_timer_is_snapshot_parsed_and_authorized() {
        let (mut memory, rsdp) =
            fixture(Some(Q35_PM_TIMER_PORT), Q35_PM_TIMER_PORT, FADT_TMR_VAL_EXT);
        let proposal = proposal(&mut memory, rsdp).unwrap();
        assert_eq!(proposal.port(), Q35_PM_TIMER_PORT);
        assert_eq!(proposal.width(), PmTimerWidth::Bits32);
        assert_eq!(
            authorize_q35_pm_timer(proposal).unwrap().port(),
            Q35_PM_TIMER_PORT
        );
    }
    #[test]
    fn unusable_extended_gas_falls_back_to_matching_q35_legacy_timer() {
        let (mut memory, rsdp) = fixture(Some(Q35_PM_TIMER_PORT), Q35_PM_TIMER_PORT, 0);
        *memory
            .0
            .get_mut(&(0x3000 + FADT_X_PM_TMR_BLK as u64))
            .unwrap() = 0;
        let mut fadt = (0..FADT_X_PM_TIMER_END)
            .map(|o| *memory.0.get(&(0x3000 + o as u64)).unwrap())
            .collect::<Vec<_>>();
        fix_checksum(&mut fadt, 9);
        memory.place(0x3000, &fadt);
        assert_eq!(
            authorize_q35_pm_timer(proposal(&mut memory, rsdp).unwrap())
                .unwrap()
                .port(),
            Q35_PM_TIMER_PORT
        );
    }
    #[test]
    fn conflicting_legacy_and_extended_ports_fail_closed() {
        let (mut memory, rsdp) = fixture(Some(Q35_PM_TIMER_PORT), 0x1234, 0);
        assert_eq!(
            proposal(&mut memory, rsdp),
            Err(AcpiTimeError::ConflictingPmTimer)
        );
    }
    #[test]
    fn firmware_port_number_is_only_a_proposal_not_io_authority() {
        for port in [1_u16, 0x80, 0x607, 0x609, u16::MAX] {
            let (mut memory, rsdp) = fixture(None, port, 0);
            let proposal = proposal(&mut memory, rsdp).unwrap();
            assert_eq!(
                authorize_q35_pm_timer(proposal),
                Err(AcpiTimeError::UnauthorizedPmTimerPort)
            );
        }
    }
    #[test]
    fn snapshot_parsing_survives_mutation_after_each_physical_read() {
        let (memory, rsdp) = fixture(Some(Q35_PM_TIMER_PORT), Q35_PM_TIMER_PORT, 0);
        let mut mutating = MutatingMemory { memory, reads: 0 };
        let proposal = proposal(&mut mutating, rsdp).unwrap();
        assert_eq!(proposal.port(), Q35_PM_TIMER_PORT);
        assert!(mutating.reads >= 6);
    }
    #[test]
    fn bad_root_checksum_fails_closed() {
        let (mut memory, rsdp) = fixture(Some(Q35_PM_TIMER_PORT), Q35_PM_TIMER_PORT, 0);
        *memory.0.get_mut(&(0x2000 + 10)).unwrap() ^= 1;
        assert_eq!(
            proposal(&mut memory, rsdp),
            Err(AcpiTimeError::InvalidRootTable)
        );
    }
    #[test]
    fn hardware_reduced_fadt_rejects_fixed_pm_timer_fields() {
        let (mut memory, rsdp) = fixture(
            Some(Q35_PM_TIMER_PORT),
            Q35_PM_TIMER_PORT,
            FADT_HW_REDUCED_ACPI,
        );
        assert_eq!(
            proposal(&mut memory, rsdp),
            Err(AcpiTimeError::HardwareReduced)
        );
    }

    #[test]
    fn madt_assigns_bsp_zero_and_sorts_enabled_aps_by_apic_id() {
        let ap4 = local_apic(4, 4, MADT_PROCESSOR_ENABLED);
        let bsp = local_apic(2, 2, MADT_PROCESSOR_ENABLED);
        let disabled = local_apic(1, 1, 1 << 1);
        let ap0 = local_apic(0, 0, MADT_PROCESSOR_ENABLED);
        let table = madt(&[&ap4, &bsp, &disabled, &ap0, &[0x7f, 2]]);
        let (mut memory, rsdp) = topology_fixture(&[table]);
        let topology = topology(&mut memory, rsdp, 2).unwrap();
        assert_eq!(topology.local_apic_physical_address(), 0xfee0_0000);
        assert!(topology.pc_at_compatible());
        assert_eq!(topology.len(), 3);
        assert!(!topology.is_empty());
        let entries = topology.entries().collect::<Vec<_>>();
        assert_eq!(
            entries
                .iter()
                .map(|entry| (
                    entry.logical_index(),
                    entry.local_apic_id(),
                    entry.acpi_processor_uid()
                ))
                .collect::<Vec<_>>(),
            vec![(0, 2, 2), (1, 0, 0), (2, 4, 4)]
        );
    }

    #[test]
    fn madt_rejects_duplicate_ids_uids_and_missing_bsp() {
        let enabled = local_apic(1, 1, MADT_PROCESSOR_ENABLED);
        let duplicate_id = local_apic(2, 1, 0);
        let table = madt(&[&enabled, &duplicate_id]);
        let (mut memory, rsdp) = topology_fixture(&[table]);
        assert_eq!(
            topology(&mut memory, rsdp, 1),
            Err(CpuTopologyError::DuplicateLocalApicId(1))
        );

        let duplicate_uid = local_apic(1, 2, MADT_PROCESSOR_ENABLED);
        let table = madt(&[&enabled, &duplicate_uid]);
        let (mut memory, rsdp) = topology_fixture(&[table]);
        assert_eq!(
            topology(&mut memory, rsdp, 1),
            Err(CpuTopologyError::DuplicateProcessorUid(1))
        );

        let only_ap = local_apic(3, 3, MADT_PROCESSOR_ENABLED);
        let table = madt(&[&only_ap]);
        let (mut memory, rsdp) = topology_fixture(&[table]);
        assert_eq!(
            topology(&mut memory, rsdp, 1),
            Err(CpuTopologyError::MissingBootstrapProcessor(1))
        );
    }

    #[test]
    fn madt_rejects_malformed_entries_enabled_x2apic_and_duplicate_tables() {
        let bsp = local_apic(0, 0, MADT_PROCESSOR_ENABLED);
        let malformed = [MADT_ENTRY_PROCESSOR_LOCAL_APIC, 1];
        let table = madt(&[&bsp, &malformed]);
        let (mut memory, rsdp) = topology_fixture(&[table]);
        assert_eq!(
            topology(&mut memory, rsdp, 0),
            Err(CpuTopologyError::InvalidMadt)
        );

        let x2 = x2apic(0x1234, MADT_PROCESSOR_ENABLED, 9);
        let table = madt(&[&bsp, &x2]);
        let (mut memory, rsdp) = topology_fixture(&[table]);
        assert_eq!(
            topology(&mut memory, rsdp, 0),
            Err(CpuTopologyError::UnsupportedEnabledX2Apic(0x1234))
        );

        let first = madt(&[&bsp]);
        let second = madt(&[&bsp]);
        let (mut memory, rsdp) = topology_fixture(&[first, second]);
        assert_eq!(
            topology(&mut memory, rsdp, 0),
            Err(CpuTopologyError::DuplicateMadt)
        );
    }

    #[test]
    fn madt_rejects_capacity_overflow_and_non_bsp_discovery() {
        let entries = (0..=MAX_DW0_CPUS)
            .map(|id| local_apic(id as u8, id as u8, MADT_PROCESSOR_ENABLED))
            .collect::<Vec<_>>();
        let references = entries.iter().map(<[_; 8]>::as_slice).collect::<Vec<_>>();
        let table = madt(&references);
        let (mut memory, rsdp) = topology_fixture(&[table]);
        assert_eq!(
            topology(&mut memory, rsdp, 0),
            Err(CpuTopologyError::CpuCapacity {
                observed: MAX_DW0_CPUS + 1,
                capacity: MAX_DW0_CPUS,
            })
        );

        let bsp = local_apic(0, 0, MADT_PROCESSOR_ENABLED);
        let table = madt(&[&bsp]);
        let (mut memory, rsdp) = topology_fixture(&[table]);
        assert_eq!(
            discover_cpu_topology(&mut memory, rsdp, 0, false, &mut workspace()),
            Err(CpuTopologyError::LiveCpuIsNotBootstrapProcessor)
        );
    }

    #[test]
    fn madt_accepts_one_aligned_xapic_address_override() {
        let bsp = local_apic(0, 0, MADT_PROCESSOR_ENABLED);
        let mut override_entry = [0_u8; MADT_LOCAL_APIC_ADDRESS_OVERRIDE_BYTES];
        override_entry[0] = MADT_ENTRY_LOCAL_APIC_ADDRESS_OVERRIDE;
        override_entry[1] = MADT_LOCAL_APIC_ADDRESS_OVERRIDE_BYTES as u8;
        override_entry[4..12].copy_from_slice(&0x0000_0001_fee0_0000_u64.to_le_bytes());
        let table = madt(&[&bsp, &override_entry]);
        let (mut memory, rsdp) = topology_fixture(&[table]);
        assert_eq!(
            topology(&mut memory, rsdp, 0)
                .unwrap()
                .local_apic_physical_address(),
            0x0000_0001_fee0_0000
        );
    }

    #[test]
    fn q35_com2_route_snapshots_topology_and_resolves_default_or_explicit_edge_high() {
        let bsp = local_apic(0, 2, MADT_PROCESSOR_ENABLED);
        let ap = local_apic(1, 7, MADT_PROCESSOR_ENABLED);
        let controller = ioapic(1, 0xfec0_0000, 0);
        let table = madt(&[&ap, &bsp, &controller]);
        let (mut memory, rsdp) = topology_fixture(&[table]);
        let descriptor = IoApicDescriptor {
            id: 1,
            physical_address: 0xfec0_0000,
            gsi_base: 0,
        };
        let route = q35_route(&mut memory, rsdp, &[IoApicProbe::new(descriptor, 24)]).unwrap();
        assert_eq!(route.gsi(), 3);
        assert_eq!(route.polarity(), PlatformIrqPolarity::ActiveHigh);
        assert_eq!(route.trigger(), PlatformIrqTrigger::Edge);
        assert_eq!(route.vector(), Q35_COM2_VECTOR);
        assert_eq!(route.bsp_local_apic_id(), 2);
        assert_eq!(route.controller(), descriptor);

        let disjoint = ioapic(2, 0xfec0_1000, 24);
        let disjoint_descriptor = IoApicDescriptor {
            id: 2,
            physical_address: 0xfec0_1000,
            gsi_base: 24,
        };
        let table = madt(&[&ap, &bsp, &controller, &disjoint]);
        let (mut memory, rsdp) = topology_fixture(&[table]);
        assert_eq!(
            q35_route(
                &mut memory,
                rsdp,
                &[
                    IoApicProbe::new(descriptor, 24),
                    IoApicProbe::new(disjoint_descriptor, 24),
                ],
            )
            .unwrap()
            .controller(),
            descriptor
        );

        let override_ = iso(0, Q35_COM2_ISA_IRQ, 19, 0b0101);
        let table = madt(&[&bsp, &controller, &override_]);
        let (mut memory, rsdp) = topology_fixture(&[table]);
        let route = q35_route(&mut memory, rsdp, &[IoApicProbe::new(descriptor, 24)]).unwrap();
        assert_eq!(route.gsi(), 19);
    }

    #[test]
    fn q35_com2_route_rejects_controller_and_coverage_nasties() {
        let bsp = local_apic(0, 2, MADT_PROCESSOR_ENABLED);
        let valid = ioapic(1, 0xfec0_0000, 0);
        let descriptor = IoApicDescriptor {
            id: 1,
            physical_address: 0xfec0_0000,
            gsi_base: 0,
        };
        let table = madt(&[&bsp]);
        let (mut memory, rsdp) = topology_fixture(&[table]);
        assert_eq!(
            q35_route(&mut memory, rsdp, &[]),
            Err(Q35Com2RouteError::MissingIoApic)
        );

        for (address, expected) in [
            (0, Q35Com2RouteError::InvalidIoApicAddress(0)),
            (
                0xfec0_0001,
                Q35Com2RouteError::InvalidIoApicAddress(0xfec0_0001),
            ),
        ] {
            let bad = ioapic(1, address, 0);
            let table = madt(&[&bsp, &bad]);
            let (mut memory, rsdp) = topology_fixture(&[table]);
            assert_eq!(q35_route(&mut memory, rsdp, &[]), Err(expected));
        }

        let table = madt(&[&bsp, &valid]);
        let (mut memory, rsdp) = topology_fixture(&[table]);
        assert_eq!(
            q35_route(&mut memory, rsdp, &[IoApicProbe::new(descriptor, 3)]),
            Err(Q35Com2RouteError::UncoveredGsi(3))
        );
        let overflow = ioapic(1, 0xfec0_0000, u32::MAX - 1);
        let overflow_descriptor = IoApicDescriptor {
            id: 1,
            physical_address: 0xfec0_0000,
            gsi_base: u32::MAX - 1,
        };
        let table = madt(&[&bsp, &overflow]);
        let (mut memory, rsdp) = topology_fixture(&[table]);
        assert_eq!(
            q35_route(
                &mut memory,
                rsdp,
                &[IoApicProbe::new(overflow_descriptor, 3)]
            ),
            Err(Q35Com2RouteError::GsiRangeOverflow)
        );

        // This second table does not cover IRQ3 but overlaps the first table's
        // probed [0, 24) interval at GSIs 20..=23.  It must still fail closed.
        let second = ioapic(2, 0xfec0_1000, 20);
        let second_descriptor = IoApicDescriptor {
            id: 2,
            physical_address: 0xfec0_1000,
            gsi_base: 20,
        };
        let table = madt(&[&bsp, &valid, &second]);
        let (mut memory, rsdp) = topology_fixture(&[table]);
        assert_eq!(
            q35_route(
                &mut memory,
                rsdp,
                &[
                    IoApicProbe::new(descriptor, 24),
                    IoApicProbe::new(second_descriptor, 24)
                ],
            ),
            Err(Q35Com2RouteError::OverlappingIoApicGsiRanges)
        );

        let duplicate_id = ioapic(1, 0xfec0_1000, 24);
        let table = madt(&[&bsp, &valid, &duplicate_id]);
        let (mut memory, rsdp) = topology_fixture(&[table]);
        assert_eq!(
            q35_route(&mut memory, rsdp, &[]),
            Err(Q35Com2RouteError::DuplicateIoApicId(1))
        );
    }

    #[test]
    fn q35_com2_route_rejects_override_flags_duplicates_and_malformed_records() {
        let bsp = local_apic(0, 2, MADT_PROCESSOR_ENABLED);
        let controller = ioapic(1, 0xfec0_0000, 0);
        let descriptor = IoApicDescriptor {
            id: 1,
            physical_address: 0xfec0_0000,
            gsi_base: 0,
        };
        let probes = [IoApicProbe::new(descriptor, 24)];
        for (flags, expected) in [
            (0b0010, Q35Com2RouteError::ReservedPolarity),
            (0b1000, Q35Com2RouteError::ReservedTrigger),
            (0b0011, Q35Com2RouteError::UnsupportedPolarity),
            (0b1100, Q35Com2RouteError::UnsupportedTrigger),
        ] {
            let override_ = iso(0, Q35_COM2_ISA_IRQ, 3, flags);
            let table = madt(&[&bsp, &controller, &override_]);
            let (mut memory, rsdp) = topology_fixture(&[table]);
            assert_eq!(q35_route(&mut memory, rsdp, &probes), Err(expected));
        }
        let first = iso(0, Q35_COM2_ISA_IRQ, 3, 0);
        let second = iso(0, Q35_COM2_ISA_IRQ, 3, 0);
        let table = madt(&[&bsp, &controller, &first, &second]);
        let (mut memory, rsdp) = topology_fixture(&[table]);
        assert_eq!(
            q35_route(&mut memory, rsdp, &probes),
            Err(Q35Com2RouteError::DuplicateIrq3Override)
        );

        let malformed_ioapic = [MADT_ENTRY_IOAPIC, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let table = madt(&[&bsp, &malformed_ioapic]);
        let (mut memory, rsdp) = topology_fixture(&[table]);
        assert_eq!(
            q35_route(&mut memory, rsdp, &[]),
            Err(Q35Com2RouteError::InvalidMadt)
        );
        let malformed_iso = [MADT_ENTRY_INTERRUPT_SOURCE_OVERRIDE, 9, 0, 3, 0, 0, 0, 0, 0];
        let table = madt(&[&bsp, &malformed_iso]);
        let (mut memory, rsdp) = topology_fixture(&[table]);
        assert_eq!(
            q35_route(&mut memory, rsdp, &[]),
            Err(Q35Com2RouteError::InvalidMadt)
        );
    }

    #[test]
    fn q35_redirection_encoding_and_route_lifecycle_are_pure_and_exact() {
        let masked = IoApicRedirectionEntry::encode_q35_com2(true, 2);
        assert_eq!(masked.bits(), 0x0200_0000_0001_0030);
        let decoded = masked.decode().unwrap();
        assert_eq!(decoded.vector(), Q35_COM2_VECTOR);
        assert!(decoded.masked());
        assert_eq!(decoded.destination(), 2);
        assert_eq!(decoded.delivery_status(), IoApicDeliveryStatus::Idle);
        let unmasked = IoApicRedirectionEntry::encode_q35_com2(false, 2);
        assert_eq!(unmasked.bits(), 0x0200_0000_0000_0030);
        assert!(!unmasked.decode().unwrap().masked());
        assert_eq!(
            IoApicRedirectionEntry(unmasked.bits() | IOAPIC_REDIR_DELIVERY_STATUS)
                .decode()
                .unwrap()
                .delivery_status(),
            IoApicDeliveryStatus::SendPending
        );
        assert_eq!(
            IoApicRedirectionEntry(unmasked.bits() | (1 << 13)).decode(),
            Err(IoApicRedirectionError::UnsupportedBits(1 << 13))
        );

        let mut lifecycle = IoApicRouteLifecycle::new();
        let generation = lifecycle.reserve().unwrap();
        assert_eq!(
            lifecycle.state(),
            IoApicRouteState::ReservedMasked { generation }
        );
        lifecycle.commit(generation).unwrap();
        lifecycle.begin_retire(generation).unwrap();
        lifecycle.mask(generation).unwrap();
        lifecycle.release(generation).unwrap();
        assert_eq!(lifecycle.state(), IoApicRouteState::Vacant);
        let replacement = lifecycle.reserve().unwrap();
        assert_ne!(replacement, generation);
        assert_eq!(
            lifecycle.commit(generation),
            Err(IoApicRouteTransitionError::WrongGeneration)
        );
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) struct AcpiScratchReader<
    'borrow,
    'root,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
> {
    paging: &'borrow mut crate::arch::x86_64::mm::ActiveDeepPaging<
        crate::arch::x86_64::mm::LiveActivePagingTarget<'root, RANGE_CAPACITY, ROLE_CAPACITY>,
    >,
    boot: &'borrow crate::boot::ValidatedBootInfo,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl<'borrow, 'root, const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    AcpiScratchReader<'borrow, 'root, RANGE_CAPACITY, ROLE_CAPACITY>
{
    pub(crate) fn new(
        paging: &'borrow mut crate::arch::x86_64::mm::ActiveDeepPaging<
            crate::arch::x86_64::mm::LiveActivePagingTarget<'root, RANGE_CAPACITY, ROLE_CAPACITY>,
        >,
        boot: &'borrow crate::boot::ValidatedBootInfo,
    ) -> Self {
        Self { paging, boot }
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize> AcpiByteReader
    for AcpiScratchReader<'_, '_, RANGE_CAPACITY, ROLE_CAPACITY>
{
    fn read_exact(&mut self, physical_start: u64, destination: &mut [u8]) -> Result<(), ()> {
        if !acpi_range_is_declared(self.boot, physical_start, destination.len()) {
            return Err(());
        }
        self.paging
            .read_bootstrap_physical_bytes(physical_start, destination)
            .map_err(|_| ())
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn acpi_range_is_declared(
    boot: &crate::boot::ValidatedBootInfo,
    physical_start: u64,
    byte_len: usize,
) -> bool {
    use deepwyrm_abi::{
        DW_BOOT_MEMORY_KIND_ACPI_NVS, DW_BOOT_MEMORY_KIND_ACPI_RECLAIM,
        DW_BOOT_MEMORY_KIND_RESERVED,
    };
    if byte_len == 0 {
        return true;
    }
    let Some(end) = physical_start.checked_add(byte_len as u64) else {
        return false;
    };
    let mut cursor = physical_start;
    for index in 0..boot.memory_map().entry_count() {
        let Ok(range) = boot.memory_range(index) else {
            return false;
        };
        let Some(range_end) = range
            .physical_start
            .checked_add(range.page_count.saturating_mul(4096))
        else {
            return false;
        };
        if range_end <= cursor {
            continue;
        }
        if range.physical_start > cursor {
            return false;
        }
        if range.kind != DW_BOOT_MEMORY_KIND_ACPI_RECLAIM
            && range.kind != DW_BOOT_MEMORY_KIND_ACPI_NVS
            && range.kind != DW_BOOT_MEMORY_KIND_RESERVED
        {
            return false;
        }
        cursor = range_end.min(end);
        if cursor == end {
            return true;
        }
    }
    false
}
