//! Bounded AP-startup and per-CPU architectural-storage model for DW0-H1.

#![allow(
    dead_code,
    reason = "H1 publishes this bounded substrate before the serialized live AP-startup join wires each operation"
)]

use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

pub(crate) const H1_RUNTIME_CPU_CAPACITY: usize = 4;
const CPU_REGISTRY_CONFIGURING: u8 = u8::MAX;
pub(crate) const INIT_ASSERT_DELAY_NS: u64 = 10_000_000;
pub(crate) const INIT_TO_SIPI_DELAY_NS: u64 = 200_000;
pub(crate) const SIPI_RETRY_DELAY_NS: u64 = 200_000;

pub(crate) const PAGE_SIZE: u64 = 4096;
pub(crate) const AP_TRAMPOLINE_LIMIT: u64 = super::mm::AP_TRAMPOLINE_LIMIT;
pub(crate) const AP_TRAMPOLINE_MAX_BYTES: u64 = PAGE_SIZE;
pub(crate) const AP_BOOTSTRAP_STACK_BYTES: u64 = 64 * 1024;
pub(crate) const IST_STACK_BYTES: u64 = 16 * 1024;
pub(crate) const PRIVILEGE_ENTRY_STACK_BYTES: u64 = 16 * 1024;
pub(crate) const TERMINAL_REAPER_STACK_BYTES: u64 = 256 * 1024;

const STACKS_PER_CPU_BYTES: u64 = 3 * (PAGE_SIZE + IST_STACK_BYTES)
    + PAGE_SIZE
    + PRIVILEGE_ENTRY_STACK_BYTES
    + PAGE_SIZE
    + TERMINAL_REAPER_STACK_BYTES
    + PAGE_SIZE
    + AP_BOOTSTRAP_STACK_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum CpuLifecycle {
    Discovered = 0,
    Starting = 1,
    Online = 2,
    Parked = 3,
    Executing = 4,
    Stopping = 5,
    Offline = 6,
    Failed = 7,
}

impl CpuLifecycle {
    const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Discovered),
            1 => Some(Self::Starting),
            2 => Some(Self::Online),
            3 => Some(Self::Parked),
            4 => Some(Self::Executing),
            5 => Some(Self::Stopping),
            6 => Some(Self::Offline),
            7 => Some(Self::Failed),
            _ => None,
        }
    }
}

/// Returns the CPU-registry state required before the native scheduler binds
/// its runtime carrier. CPU0 is already executing the primordial carrier and
/// therefore remains Online; only application processors wait Parked.
pub(crate) const fn runtime_pre_admission_lifecycle(cpu_index: usize) -> CpuLifecycle {
    if cpu_index == 0 {
        CpuLifecycle::Online
    } else {
        CpuLifecycle::Parked
    }
}

#[derive(Debug)]
pub(crate) struct CpuSlotState {
    lifecycle: AtomicU8,
    local_apic_id: AtomicU8,
    online_generation: AtomicU64,
    failure_reason: AtomicU32,
}

impl CpuSlotState {
    pub(crate) const fn new() -> Self {
        Self {
            lifecycle: AtomicU8::new(CpuLifecycle::Offline as u8),
            local_apic_id: AtomicU8::new(0),
            online_generation: AtomicU64::new(0),
            failure_reason: AtomicU32::new(0),
        }
    }

    pub(crate) fn discover(&self, local_apic_id: u8) -> Result<(), CpuStateError> {
        self.lifecycle
            .compare_exchange(
                CpuLifecycle::Offline as u8,
                CpuLifecycle::Discovered as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(CpuStateError::UnexpectedState)?;
        self.local_apic_id.store(local_apic_id, Ordering::Relaxed);
        Ok(())
    }

    pub(crate) fn begin_start(&self) -> Result<(), CpuStateError> {
        self.transition(CpuLifecycle::Discovered, CpuLifecycle::Starting)
    }

    /// Publishes all private architectural initialization performed before this call.
    pub(crate) fn publish_online(&self, generation: u64) -> Result<(), CpuStateError> {
        if generation == 0 {
            return Err(CpuStateError::ZeroGeneration);
        }
        self.online_generation.store(generation, Ordering::Relaxed);
        self.transition(CpuLifecycle::Starting, CpuLifecycle::Online)
    }

    pub(crate) fn park(&self) -> Result<(), CpuStateError> {
        self.transition(CpuLifecycle::Online, CpuLifecycle::Parked)
    }

    /// Releases a fully published CPU-local carrier into the common runtime
    /// lifecycle. The caller must have completed the separate scheduler,
    /// remote-stop, and TLB-acknowledgement join; this state transition itself
    /// never wakes the CPU or grants it runnable work.
    pub(crate) fn begin_execution(&self) -> Result<(), CpuStateError> {
        self.transition(CpuLifecycle::Parked, CpuLifecycle::Executing)
    }

    pub(crate) fn fail(&self, reason: u32) -> Result<(), CpuStateError> {
        if reason == 0 {
            return Err(CpuStateError::ZeroFailureReason);
        }
        self.failure_reason.store(reason, Ordering::Relaxed);
        let observed = self.lifecycle.load(Ordering::Acquire);
        if observed != CpuLifecycle::Starting as u8 && observed != CpuLifecycle::Discovered as u8 {
            return Err(CpuStateError::UnexpectedState(observed));
        }
        self.lifecycle
            .compare_exchange(
                observed,
                CpuLifecycle::Failed as u8,
                Ordering::Release,
                Ordering::Acquire,
            )
            .map_err(CpuStateError::UnexpectedState)?;
        Ok(())
    }

    pub(crate) fn snapshot(&self) -> Result<CpuStateSnapshot, CpuStateError> {
        let lifecycle = CpuLifecycle::from_raw(self.lifecycle.load(Ordering::Acquire))
            .ok_or(CpuStateError::CorruptState)?;
        Ok(CpuStateSnapshot {
            lifecycle,
            local_apic_id: self.local_apic_id.load(Ordering::Relaxed),
            online_generation: self.online_generation.load(Ordering::Relaxed),
            failure_reason: self.failure_reason.load(Ordering::Relaxed),
        })
    }

    fn transition(&self, expected: CpuLifecycle, next: CpuLifecycle) -> Result<(), CpuStateError> {
        self.lifecycle
            .compare_exchange(
                expected as u8,
                next as u8,
                Ordering::Release,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(CpuStateError::UnexpectedState)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CpuStateSnapshot {
    pub(crate) lifecycle: CpuLifecycle,
    pub(crate) local_apic_id: u8,
    pub(crate) online_generation: u64,
    pub(crate) failure_reason: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CpuStateError {
    UnexpectedState(u8),
    CorruptState,
    ZeroGeneration,
    ZeroFailureReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CpuRegistryError {
    EmptyTopology,
    Capacity { observed: usize },
    DuplicateLocalApicId(u8),
    AlreadyConfigured,
    InvalidCpuIndex(usize),
    LocalApicMismatch { expected: u8, observed: u8 },
    State(CpuStateError),
    Timeout,
    Failed(u32),
}

pub(crate) struct CpuRegistry {
    slots: [CpuSlotState; H1_RUNTIME_CPU_CAPACITY],
    discovered: AtomicU8,
}

impl CpuRegistry {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [const { CpuSlotState::new() }; H1_RUNTIME_CPU_CAPACITY],
            discovered: AtomicU8::new(0),
        }
    }

    /// Publishes the canonical BSP-first APIC-ID prefix exactly once.
    pub(crate) fn discover(&self, local_apic_ids: &[u8]) -> Result<(), CpuRegistryError> {
        if local_apic_ids.is_empty() {
            return Err(CpuRegistryError::EmptyTopology);
        }
        if local_apic_ids.len() > H1_RUNTIME_CPU_CAPACITY {
            return Err(CpuRegistryError::Capacity {
                observed: local_apic_ids.len(),
            });
        }
        for (index, id) in local_apic_ids.iter().copied().enumerate() {
            if local_apic_ids[..index].contains(&id) {
                return Err(CpuRegistryError::DuplicateLocalApicId(id));
            }
        }
        self.discovered
            .compare_exchange(
                0,
                CPU_REGISTRY_CONFIGURING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| CpuRegistryError::AlreadyConfigured)?;
        for (index, id) in local_apic_ids.iter().copied().enumerate() {
            self.slots[index]
                .discover(id)
                .map_err(CpuRegistryError::State)?;
        }
        self.discovered.store(
            u8::try_from(local_apic_ids.len()).unwrap(),
            Ordering::Release,
        );
        Ok(())
    }

    pub(crate) fn len(&self) -> usize {
        match self.discovered.load(Ordering::Acquire) {
            CPU_REGISTRY_CONFIGURING => 0,
            published => usize::from(published),
        }
    }

    pub(crate) fn begin_start(&self, cpu_index: usize) -> Result<(), CpuRegistryError> {
        if cpu_index >= self.len() {
            return Err(CpuRegistryError::InvalidCpuIndex(cpu_index));
        }
        self.slots[cpu_index]
            .begin_start()
            .map_err(CpuRegistryError::State)
    }

    pub(crate) fn publish_online(
        &self,
        cpu_index: usize,
        local_apic_id: u8,
        generation: u64,
    ) -> Result<(), CpuRegistryError> {
        let snapshot = self.snapshot(cpu_index)?;
        if snapshot.local_apic_id != local_apic_id {
            return Err(CpuRegistryError::LocalApicMismatch {
                expected: snapshot.local_apic_id,
                observed: local_apic_id,
            });
        }
        self.slots[cpu_index]
            .publish_online(generation)
            .map_err(CpuRegistryError::State)
    }

    pub(crate) fn park(&self, cpu_index: usize) -> Result<(), CpuRegistryError> {
        if cpu_index >= self.len() {
            return Err(CpuRegistryError::InvalidCpuIndex(cpu_index));
        }
        self.slots[cpu_index]
            .park()
            .map_err(CpuRegistryError::State)
    }

    pub(crate) fn begin_execution(&self, cpu_index: usize) -> Result<(), CpuRegistryError> {
        if cpu_index >= self.len() {
            return Err(CpuRegistryError::InvalidCpuIndex(cpu_index));
        }
        self.slots[cpu_index]
            .begin_execution()
            .map_err(CpuRegistryError::State)
    }

    pub(crate) fn fail(&self, cpu_index: usize, reason: u32) -> Result<(), CpuRegistryError> {
        if cpu_index >= self.len() {
            return Err(CpuRegistryError::InvalidCpuIndex(cpu_index));
        }
        self.slots[cpu_index]
            .fail(reason)
            .map_err(CpuRegistryError::State)
    }

    pub(crate) fn snapshot(&self, cpu_index: usize) -> Result<CpuStateSnapshot, CpuRegistryError> {
        if cpu_index >= self.len() {
            return Err(CpuRegistryError::InvalidCpuIndex(cpu_index));
        }
        self.slots[cpu_index]
            .snapshot()
            .map_err(CpuRegistryError::State)
    }

    pub(crate) fn wait_until_parked(
        &self,
        cpu_index: usize,
        poll_limit: usize,
    ) -> Result<CpuStateSnapshot, CpuRegistryError> {
        if poll_limit == 0 {
            return Err(CpuRegistryError::Timeout);
        }
        for _ in 0..poll_limit {
            let snapshot = self.snapshot(cpu_index)?;
            match snapshot.lifecycle {
                CpuLifecycle::Parked => return Ok(snapshot),
                CpuLifecycle::Failed => {
                    return Err(CpuRegistryError::Failed(snapshot.failure_reason));
                }
                _ => core::hint::spin_loop(),
            }
        }
        Err(CpuRegistryError::Timeout)
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static LIVE_CPU_REGISTRY: CpuRegistry = CpuRegistry::new();
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static LIVE_LOCAL_APIC_PHYSICAL_BASE: AtomicU64 = AtomicU64::new(0);

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn configure_live_cpu_registry(
    topology: &super::acpi::CpuTopology,
) -> Result<(), CpuRegistryError> {
    if topology.len() > H1_RUNTIME_CPU_CAPACITY {
        return Err(CpuRegistryError::Capacity {
            observed: topology.len(),
        });
    }
    let mut ids = [0_u8; H1_RUNTIME_CPU_CAPACITY];
    for (index, entry) in topology.entries().enumerate() {
        if usize::from(entry.logical_index()) != index {
            return Err(CpuRegistryError::InvalidCpuIndex(usize::from(
                entry.logical_index(),
            )));
        }
        ids[index] = entry.local_apic_id();
    }
    LIVE_CPU_REGISTRY.discover(&ids[..topology.len()])?;
    LIVE_LOCAL_APIC_PHYSICAL_BASE.store(topology.local_apic_physical_address(), Ordering::Release);
    Ok(())
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn live_cpu_registry() -> &'static CpuRegistry {
    &LIVE_CPU_REGISTRY
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn live_local_apic_physical_base() -> Result<u64, CpuRegistryError> {
    let base = LIVE_LOCAL_APIC_PHYSICAL_BASE.load(Ordering::Acquire);
    if base == 0 {
        return Err(CpuRegistryError::EmptyTopology);
    }
    Ok(base)
}

pub(crate) trait ApStartupPlatform {
    type Error;

    fn send_ipi(
        &mut self,
        destination: u8,
        operation: super::apic::IpiOperation,
    ) -> Result<(), Self::Error>;

    fn busy_wait_nanoseconds(&mut self, delay: u64) -> Result<(), Self::Error>;
}

/// Delivers the exact bounded INIT/deassert/SIPI/SIPI sequence required by H1.
pub(crate) fn deliver_ap_startup_sequence<P: ApStartupPlatform>(
    platform: &mut P,
    local_apic_id: u8,
    trampoline_page: u64,
) -> Result<(), P::Error> {
    platform.send_ipi(local_apic_id, super::apic::IpiOperation::InitAssert)?;
    platform.busy_wait_nanoseconds(INIT_ASSERT_DELAY_NS)?;
    platform.send_ipi(local_apic_id, super::apic::IpiOperation::InitDeassert)?;
    platform.busy_wait_nanoseconds(INIT_TO_SIPI_DELAY_NS)?;
    platform.send_ipi(
        local_apic_id,
        super::apic::IpiOperation::Startup { trampoline_page },
    )?;
    platform.busy_wait_nanoseconds(SIPI_RETRY_DELAY_NS)?;
    platform.send_ipi(
        local_apic_id,
        super::apic::IpiOperation::Startup { trampoline_page },
    )
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) struct LiveApStartupPlatform;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl ApStartupPlatform for LiveApStartupPlatform {
    type Error = crate::time::LiveTimeError;

    fn send_ipi(
        &mut self,
        destination: u8,
        operation: super::apic::IpiOperation,
    ) -> Result<(), Self::Error> {
        crate::time::send_bsp_ipi(destination, operation)
    }

    fn busy_wait_nanoseconds(&mut self, delay: u64) -> Result<(), Self::Error> {
        crate::time::busy_wait_nanoseconds(delay)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GuardedStack {
    pub(crate) guard: u64,
    pub(crate) bottom: u64,
    pub(crate) top: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PerCpuStackLayout {
    pub(crate) interrupt_stacks: [GuardedStack; 3],
    pub(crate) privilege_entry: GuardedStack,
    pub(crate) terminal_reaper: GuardedStack,
    pub(crate) ap_bootstrap: GuardedStack,
}

impl PerCpuStackLayout {
    pub(crate) fn from_arena(
        arena_start: u64,
        cpu_index: usize,
    ) -> Result<Self, PerCpuLayoutError> {
        if cpu_index >= H1_RUNTIME_CPU_CAPACITY || !arena_start.is_multiple_of(PAGE_SIZE) {
            return Err(PerCpuLayoutError::InvalidInput);
        }
        let slot_start = (cpu_index as u64)
            .checked_mul(STACKS_PER_CPU_BYTES)
            .and_then(|offset| arena_start.checked_add(offset))
            .ok_or(PerCpuLayoutError::Overflow)?;
        let mut cursor = slot_start;
        let interrupt_stacks = [
            next_stack(&mut cursor, IST_STACK_BYTES)?,
            next_stack(&mut cursor, IST_STACK_BYTES)?,
            next_stack(&mut cursor, IST_STACK_BYTES)?,
        ];
        let privilege_entry = next_stack(&mut cursor, PRIVILEGE_ENTRY_STACK_BYTES)?;
        let terminal_reaper = next_stack(&mut cursor, TERMINAL_REAPER_STACK_BYTES)?;
        let ap_bootstrap = next_stack(&mut cursor, AP_BOOTSTRAP_STACK_BYTES)?;
        if cursor != slot_start + STACKS_PER_CPU_BYTES {
            return Err(PerCpuLayoutError::Overflow);
        }
        Ok(Self {
            interrupt_stacks,
            privilege_entry,
            terminal_reaper,
            ap_bootstrap,
        })
    }

    pub(crate) const fn arena_bytes() -> u64 {
        STACKS_PER_CPU_BYTES * H1_RUNTIME_CPU_CAPACITY as u64
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PerCpuLayoutError {
    InvalidInput,
    Overflow,
}

fn next_stack(cursor: &mut u64, bytes: u64) -> Result<GuardedStack, PerCpuLayoutError> {
    let guard = *cursor;
    let bottom = guard
        .checked_add(PAGE_SIZE)
        .ok_or(PerCpuLayoutError::Overflow)?;
    let top = bottom
        .checked_add(bytes)
        .ok_or(PerCpuLayoutError::Overflow)?;
    *cursor = top;
    Ok(GuardedStack { guard, bottom, top })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TrampolinePlan {
    pub(crate) physical_start: u64,
    pub(crate) byte_len: u16,
    pub(crate) startup_vector: u8,
    pub(crate) page_table_root: u64,
    pub(crate) higher_half_entry: u64,
}

impl TrampolinePlan {
    pub(crate) fn new(
        physical_start: u64,
        byte_len: u64,
        page_table_root: u64,
        higher_half_entry: u64,
    ) -> Result<Self, TrampolinePlanError> {
        let physical_end = physical_start
            .checked_add(byte_len)
            .ok_or(TrampolinePlanError::Overflow)?;
        if physical_start < PAGE_SIZE
            || !physical_start.is_multiple_of(PAGE_SIZE)
            || byte_len == 0
            || byte_len > AP_TRAMPOLINE_MAX_BYTES
            || physical_end > AP_TRAMPOLINE_LIMIT
        {
            return Err(TrampolinePlanError::InvalidPlacement);
        }
        if !page_table_root.is_multiple_of(PAGE_SIZE) || page_table_root >= 1_u64 << 32 {
            return Err(TrampolinePlanError::InvalidPageTableRoot);
        }
        if higher_half_entry < 0xffff_8000_0000_0000 {
            return Err(TrampolinePlanError::InvalidEntry);
        }
        Ok(Self {
            physical_start,
            byte_len: byte_len as u16,
            startup_vector: (physical_start >> 12) as u8,
            page_table_root,
            higher_half_entry,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TrampolinePlanError {
    Overflow,
    InvalidPlacement,
    InvalidPageTableRoot,
    InvalidEntry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TrampolineTemplateLayout {
    pub(crate) physical_base_patch: usize,
    pub(crate) gdt_offset: usize,
    pub(crate) gdt_base_patch: usize,
    pub(crate) protected_entry_offset: usize,
    pub(crate) protected_pointer_patch: usize,
    pub(crate) long_entry_offset: usize,
    pub(crate) long_pointer_patch: usize,
    pub(crate) page_table_root_patch: usize,
    pub(crate) cpu_index_patch: usize,
    pub(crate) local_apic_id_patch: usize,
    pub(crate) stack_top_patch: usize,
    pub(crate) higher_half_entry_patch: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TrampolineImageError {
    TemplateSize,
    Layout,
    PlanMismatch,
    InvalidCpu,
    InvalidStack,
    PhysicalOverflow,
}

pub(crate) fn build_trampoline_image(
    destination: &mut [u8; PAGE_SIZE as usize],
    template: &[u8],
    layout: TrampolineTemplateLayout,
    plan: TrampolinePlan,
    cpu_index: usize,
    local_apic_id: u8,
    stack_top: u64,
) -> Result<(), TrampolineImageError> {
    if template.is_empty() || template.len() > destination.len() {
        return Err(TrampolineImageError::TemplateSize);
    }
    if usize::from(plan.byte_len) != template.len() {
        return Err(TrampolineImageError::PlanMismatch);
    }
    if cpu_index == 0 || cpu_index >= H1_RUNTIME_CPU_CAPACITY {
        return Err(TrampolineImageError::InvalidCpu);
    }
    if stack_top < 0xffff_8000_0000_0000 || !stack_top.is_multiple_of(16) {
        return Err(TrampolineImageError::InvalidStack);
    }
    validate_template_layout(layout, template.len())?;
    let gdt = checked_low_address(plan.physical_start, layout.gdt_offset)?;
    let protected = checked_low_address(plan.physical_start, layout.protected_entry_offset)?;
    let long = checked_low_address(plan.physical_start, layout.long_entry_offset)?;

    destination.fill(0);
    destination[..template.len()].copy_from_slice(template);
    write_u32(
        destination,
        layout.physical_base_patch,
        u32::try_from(plan.physical_start).map_err(|_| TrampolineImageError::PhysicalOverflow)?,
    );
    write_u32(destination, layout.gdt_base_patch, gdt);
    write_u32(destination, layout.protected_pointer_patch, protected);
    write_u32(destination, layout.long_pointer_patch, long);
    write_u32(
        destination,
        layout.page_table_root_patch,
        plan.page_table_root as u32,
    );
    write_u32(destination, layout.cpu_index_patch, cpu_index as u32);
    write_u32(
        destination,
        layout.local_apic_id_patch,
        u32::from(local_apic_id),
    );
    write_u64(destination, layout.stack_top_patch, stack_top);
    write_u64(
        destination,
        layout.higher_half_entry_patch,
        plan.higher_half_entry,
    );
    Ok(())
}

fn validate_template_layout(
    layout: TrampolineTemplateLayout,
    template_len: usize,
) -> Result<(), TrampolineImageError> {
    for (offset, width) in [
        (layout.physical_base_patch, 4),
        (layout.gdt_base_patch, 4),
        (layout.protected_pointer_patch, 4),
        (layout.long_pointer_patch, 4),
        (layout.page_table_root_patch, 4),
        (layout.cpu_index_patch, 4),
        (layout.local_apic_id_patch, 4),
        (layout.stack_top_patch, 8),
        (layout.higher_half_entry_patch, 8),
    ] {
        if offset
            .checked_add(width)
            .is_none_or(|end| end > template_len)
        {
            return Err(TrampolineImageError::Layout);
        }
    }
    if layout.gdt_offset >= template_len
        || layout.protected_entry_offset >= template_len
        || layout.long_entry_offset >= template_len
    {
        return Err(TrampolineImageError::Layout);
    }
    Ok(())
}

fn checked_low_address(base: u64, offset: usize) -> Result<u32, TrampolineImageError> {
    base.checked_add(offset as u64)
        .and_then(|address| u32::try_from(address).ok())
        .ok_or(TrampolineImageError::PhysicalOverflow)
}

fn write_u32(destination: &mut [u8], offset: usize, value: u32) {
    destination[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(destination: &mut [u8], offset: usize, value: u64) {
    destination[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "linker-defined trampoline symbols delimit one immutable template section"
)]
pub(crate) fn linked_trampoline_template() -> (&'static [u8], TrampolineTemplateLayout) {
    unsafe extern "C" {
        static __dw_ap_trampoline_template_start: u8;
        static __dw_ap_trampoline_template_end: u8;
        static __dw_ap_trampoline_physical_base: u8;
        static __dw_ap_trampoline_gdt: u8;
        static __dw_ap_trampoline_gdt_base: u8;
        static __dw_ap_trampoline_protected_entry: u8;
        static __dw_ap_trampoline_protected_pointer: u8;
        static __dw_ap_trampoline_long_entry: u8;
        static __dw_ap_trampoline_long_pointer: u8;
        static __dw_ap_trampoline_page_table_root: u8;
        static __dw_ap_trampoline_cpu_index: u8;
        static __dw_ap_trampoline_local_apic_id: u8;
        static __dw_ap_trampoline_stack_top: u8;
        static __dw_ap_trampoline_higher_half_entry: u8;
    }
    let start = core::ptr::addr_of!(__dw_ap_trampoline_template_start) as usize;
    let end = core::ptr::addr_of!(__dw_ap_trampoline_template_end) as usize;
    assert!(start < end, "AP trampoline template bounds are ordered");
    let offset = |symbol: *const u8| {
        (symbol as usize)
            .checked_sub(start)
            .expect("AP trampoline patch symbol follows template start")
    };
    // SAFETY: the linker retains one contiguous immutable template from `start..end`.
    let template = unsafe { core::slice::from_raw_parts(start as *const u8, end - start) };
    let layout = TrampolineTemplateLayout {
        physical_base_patch: offset(core::ptr::addr_of!(__dw_ap_trampoline_physical_base)),
        gdt_offset: offset(core::ptr::addr_of!(__dw_ap_trampoline_gdt)),
        gdt_base_patch: offset(core::ptr::addr_of!(__dw_ap_trampoline_gdt_base)),
        protected_entry_offset: offset(core::ptr::addr_of!(__dw_ap_trampoline_protected_entry)),
        protected_pointer_patch: offset(core::ptr::addr_of!(__dw_ap_trampoline_protected_pointer)),
        long_entry_offset: offset(core::ptr::addr_of!(__dw_ap_trampoline_long_entry)),
        long_pointer_patch: offset(core::ptr::addr_of!(__dw_ap_trampoline_long_pointer)),
        page_table_root_patch: offset(core::ptr::addr_of!(__dw_ap_trampoline_page_table_root)),
        cpu_index_patch: offset(core::ptr::addr_of!(__dw_ap_trampoline_cpu_index)),
        local_apic_id_patch: offset(core::ptr::addr_of!(__dw_ap_trampoline_local_apic_id)),
        stack_top_patch: offset(core::ptr::addr_of!(__dw_ap_trampoline_stack_top)),
        higher_half_entry_patch: offset(core::ptr::addr_of!(__dw_ap_trampoline_higher_half_entry)),
    };
    (template, layout)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn runtime_pre_admission_keeps_bsp_online_and_aps_parked() {
        assert_eq!(runtime_pre_admission_lifecycle(0), CpuLifecycle::Online);
        for cpu_index in 1..H1_RUNTIME_CPU_CAPACITY {
            assert_eq!(
                runtime_pre_admission_lifecycle(cpu_index),
                CpuLifecycle::Parked
            );
        }
    }

    #[test]
    fn lifecycle_publication_is_monotonic_and_generation_bound() {
        let slot = CpuSlotState::new();
        slot.discover(9).unwrap();
        slot.begin_start().unwrap();
        assert_eq!(slot.publish_online(0), Err(CpuStateError::ZeroGeneration));
        slot.publish_online(3).unwrap();
        slot.park().unwrap();
        assert_eq!(
            slot.snapshot().unwrap(),
            CpuStateSnapshot {
                lifecycle: CpuLifecycle::Parked,
                local_apic_id: 9,
                online_generation: 3,
                failure_reason: 0,
            }
        );
        assert!(slot.begin_start().is_err());

        let failed = CpuSlotState::new();
        failed.discover(10).unwrap();
        assert_eq!(failed.fail(0), Err(CpuStateError::ZeroFailureReason));
        failed.fail(0x21).unwrap();
        assert_eq!(failed.snapshot().unwrap().lifecycle, CpuLifecycle::Failed);
        assert_eq!(failed.snapshot().unwrap().failure_reason, 0x21);
    }

    #[test]
    fn every_cpu_stack_and_guard_range_is_private() {
        let base = 0xffff_9000_0000_0000;
        assert_eq!(
            PerCpuStackLayout::arena_bytes(),
            STACKS_PER_CPU_BYTES * H1_RUNTIME_CPU_CAPACITY as u64
        );
        let first = PerCpuStackLayout::from_arena(base, 0).unwrap();
        let second = PerCpuStackLayout::from_arena(base, 1).unwrap();
        assert!(first.ap_bootstrap.top <= second.interrupt_stacks[0].guard);
        for layout in [first, second] {
            let stacks = [
                layout.interrupt_stacks[0],
                layout.interrupt_stacks[1],
                layout.interrupt_stacks[2],
                layout.privilege_entry,
                layout.terminal_reaper,
                layout.ap_bootstrap,
            ];
            for pair in stacks.windows(2) {
                assert_eq!(pair[0].top, pair[1].guard);
            }
            assert!(stacks.iter().all(|stack| {
                stack.bottom - stack.guard == PAGE_SIZE
                    && stack.guard.is_multiple_of(PAGE_SIZE)
                    && stack.top.is_multiple_of(16)
            }));
        }
    }

    #[test]
    fn trampoline_is_one_low_nonzero_page_with_32_bit_cr3() {
        let plan = TrampolinePlan::new(0x8000, 2048, 0x20_0000, 0xffff_8000_0010_0000).unwrap();
        assert_eq!(plan.startup_vector, 8);
        assert_eq!(plan.byte_len, 2048);
        assert!(TrampolinePlan::new(0, 1, 0x1000, plan.higher_half_entry).is_err());
        assert!(TrampolinePlan::new(0x8000, 4097, 0x1000, plan.higher_half_entry).is_err());
        assert!(TrampolinePlan::new(0x8000, 1, 1_u64 << 32, plan.higher_half_entry).is_err());
        assert!(TrampolinePlan::new(0x8000, 1, 0x1000, 0x400000).is_err());
    }

    #[test]
    fn trampoline_image_patches_only_validated_runtime_fields() {
        let template = [0xa5_u8; 96];
        let layout = TrampolineTemplateLayout {
            physical_base_patch: 36,
            gdt_offset: 8,
            gdt_base_patch: 40,
            protected_entry_offset: 16,
            protected_pointer_patch: 44,
            long_entry_offset: 24,
            long_pointer_patch: 48,
            page_table_root_patch: 52,
            cpu_index_patch: 56,
            local_apic_id_patch: 60,
            stack_top_patch: 64,
            higher_half_entry_patch: 72,
        };
        let plan = TrampolinePlan::new(
            0x8000,
            template.len() as u64,
            0x20_0000,
            0xffff_8000_0010_0000,
        )
        .unwrap();
        let mut page = [0xff; PAGE_SIZE as usize];
        build_trampoline_image(
            &mut page,
            &template,
            layout,
            plan,
            2,
            7,
            0xffff_9000_0001_0000,
        )
        .unwrap();
        assert_eq!(&page[36..40], &0x8000_u32.to_le_bytes());
        assert_eq!(&page[40..44], &0x8008_u32.to_le_bytes());
        assert_eq!(&page[44..48], &0x8010_u32.to_le_bytes());
        assert_eq!(&page[48..52], &0x8018_u32.to_le_bytes());
        assert_eq!(&page[52..56], &0x20_0000_u32.to_le_bytes());
        assert_eq!(&page[56..60], &2_u32.to_le_bytes());
        assert_eq!(&page[60..64], &7_u32.to_le_bytes());
        assert_eq!(&page[64..72], &0xffff_9000_0001_0000_u64.to_le_bytes());
        assert_eq!(&page[72..80], &0xffff_8000_0010_0000_u64.to_le_bytes());
        assert!(page[template.len()..].iter().all(|byte| *byte == 0));
        assert_eq!(
            build_trampoline_image(&mut page, &template, layout, plan, 0, 0, 0),
            Err(TrampolineImageError::InvalidCpu)
        );
    }

    #[test]
    fn cpu_registry_is_bsp_first_bounded_and_release_publishes_parked_aps() {
        let registry = CpuRegistry::new();
        assert_eq!(registry.discover(&[]), Err(CpuRegistryError::EmptyTopology));
        assert_eq!(
            registry.discover(&[0, 1, 2, 3, 4]),
            Err(CpuRegistryError::Capacity { observed: 5 })
        );
        assert_eq!(
            registry.discover(&[2, 2]),
            Err(CpuRegistryError::DuplicateLocalApicId(2))
        );
        registry
            .discovered
            .store(CPU_REGISTRY_CONFIGURING, Ordering::Release);
        assert_eq!(
            registry.len(),
            0,
            "an in-progress prefix must never publish length 255"
        );
        registry.discovered.store(0, Ordering::Release);
        registry.discover(&[2, 4, 7, 9]).unwrap();
        assert_eq!(
            registry.discover(&[2]),
            Err(CpuRegistryError::AlreadyConfigured)
        );
        assert_eq!(registry.len(), 4);
        registry.begin_start(0).unwrap();
        registry.publish_online(0, 2, 1).unwrap();
        registry.begin_start(1).unwrap();
        assert_eq!(
            registry.publish_online(1, 5, 1),
            Err(CpuRegistryError::LocalApicMismatch {
                expected: 4,
                observed: 5,
            })
        );
        registry.publish_online(1, 4, 1).unwrap();
        registry.park(1).unwrap();
        assert_eq!(
            registry.wait_until_parked(1, 1).unwrap().lifecycle,
            CpuLifecycle::Parked
        );
        assert_eq!(
            registry.wait_until_parked(2, 1),
            Err(CpuRegistryError::Timeout)
        );
        registry.begin_execution(1).unwrap();
        assert_eq!(
            registry.snapshot(1).unwrap().lifecycle,
            CpuLifecycle::Executing
        );
        assert!(matches!(
            registry.begin_execution(1),
            Err(CpuRegistryError::State(CpuStateError::UnexpectedState(_)))
        ));
    }

    #[test]
    fn startup_sequence_has_exact_architectural_order_and_delays() {
        #[derive(Debug, Eq, PartialEq)]
        enum Event {
            Ipi(u8, super::super::apic::IpiOperation),
            Delay(u64),
        }
        struct Platform(std::vec::Vec<Event>);
        impl ApStartupPlatform for Platform {
            type Error = ();

            fn send_ipi(
                &mut self,
                destination: u8,
                operation: super::super::apic::IpiOperation,
            ) -> Result<(), Self::Error> {
                self.0.push(Event::Ipi(destination, operation));
                Ok(())
            }

            fn busy_wait_nanoseconds(&mut self, delay: u64) -> Result<(), Self::Error> {
                self.0.push(Event::Delay(delay));
                Ok(())
            }
        }

        let mut platform = Platform(std::vec::Vec::new());
        deliver_ap_startup_sequence(&mut platform, 7, 0x8000).unwrap();
        assert_eq!(
            platform.0,
            [
                Event::Ipi(7, super::super::apic::IpiOperation::InitAssert),
                Event::Delay(INIT_ASSERT_DELAY_NS),
                Event::Ipi(7, super::super::apic::IpiOperation::InitDeassert),
                Event::Delay(INIT_TO_SIPI_DELAY_NS),
                Event::Ipi(
                    7,
                    super::super::apic::IpiOperation::Startup {
                        trampoline_page: 0x8000,
                    },
                ),
                Event::Delay(SIPI_RETRY_DELAY_NS),
                Event::Ipi(
                    7,
                    super::super::apic::IpiOperation::Startup {
                        trampoline_page: 0x8000,
                    },
                ),
            ]
        );
    }
}
