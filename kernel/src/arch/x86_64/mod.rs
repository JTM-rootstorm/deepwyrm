//! x86_64 descriptor-table and terminal-exception bring-up.
//!
//! `install_early_descriptors` is the sole callable DW0-B transition: it
//! initializes COM1, installs a Deepwyrm-owned GDT/TSS, and finally replaces
//! the emergency IDT before any BootInfo parsing. It intentionally preserves
//! `IF=0` and does not rely on loader descriptor or TLS state.

pub(crate) mod acpi;
pub mod apic;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) mod apic_live;
pub(crate) mod context;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod entry;
pub mod exceptions;
pub mod gdt;
pub mod idt;
pub mod mm;
pub(crate) mod smp;
pub(crate) mod syscall;
pub mod tss;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use mm::transition::{IstStackBounds, IstStackLayout};

#[cfg(test)]
mod bootstrap_cpu_policy_tests {
    const CR4_SMAP: u64 = 1 << 21;
    const RFLAGS_AC: u64 = 1 << 18;

    const fn normalized_cr4(cr4: u64) -> u64 {
        cr4 & !CR4_SMAP
    }

    const fn normalized_rflags(rflags: u64) -> u64 {
        rflags & !RFLAGS_AC
    }

    #[test]
    fn dw0_c_normalization_preserves_every_unrelated_control_and_flag_bit() {
        for value in [0, u64::MAX, 0x0123_4567_89ab_cdef, CR4_SMAP, RFLAGS_AC] {
            assert_eq!(normalized_cr4(value) & CR4_SMAP, 0);
            assert_eq!(normalized_cr4(value) & !CR4_SMAP, value & !CR4_SMAP);
            assert_eq!(normalized_rflags(value) & RFLAGS_AC, 0);
            assert_eq!(normalized_rflags(value) & !RFLAGS_AC, value & !RFLAGS_AC);
        }
    }
}

use crate::memory::physical::BASE_PAGE_SIZE;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use core::cell::UnsafeCell;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use core::mem::MaybeUninit;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use core::sync::atomic::{AtomicU8, Ordering};

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use exceptions::EXCEPTION_HANDLER_COUNT;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use gdt::GlobalDescriptorTable;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use idt::{EarlyIdtHandlers, ExceptionHandlerTable, HandlerAddress, InterruptDescriptorTable};
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use tss::{InterruptStackIndex, TaskStateSegment};

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
const IST_GUARD_BYTES: u64 = BASE_PAGE_SIZE;

/// Returns one linker-defined boundary without allowing LLVM to infer that
/// separately declared boundary symbols must have distinct addresses.
///
/// The linker intentionally aliases the top of each IST stack with the next
/// guard boundary. Passing the address through an opaque register operand
/// preserves that linker-time equality for the runtime geometry checks.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "an empty x86 register barrier preserves linker-defined symbol aliasing"
)]
#[inline(always)]
fn opaque_linker_symbol_address(symbol: *const u8) -> u64 {
    let mut address = symbol as u64;
    unsafe {
        core::arch::asm!(
            "/* {address} */",
            address = inout(reg) address,
            options(nomem, nostack, preserves_flags),
        );
    }
    address
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
const INSTALL_UNSTARTED: u8 = 0;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
const INSTALLING: u8 = 1;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
const INSTALLED: u8 = 2;

/// A mutable static object accessed only by the single-CPU, IF-clear early
/// entry sequence. Its `Sync` implementation is sound because the installer
/// is one-shot and publishes initialized values before obtaining references.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
struct EarlyStorage<T> {
    value: UnsafeCell<MaybeUninit<T>>,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl<T> EarlyStorage<T> {
    const fn uninit() -> Self {
        Self {
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "one-shot bootstrap storage is synchronized by the installation state machine"
)]
unsafe impl<T> Sync for EarlyStorage<T> {}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static INSTALL_STATE: AtomicU8 = AtomicU8::new(INSTALL_UNSTARTED);
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static TSS: EarlyStorage<TaskStateSegment> = EarlyStorage::uninit();
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static GDT: EarlyStorage<GlobalDescriptorTable> = EarlyStorage::uninit();
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static EMERGENCY_IDT: EarlyStorage<InterruptDescriptorTable> = EarlyStorage::uninit();
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static FINAL_IDT: EarlyStorage<InterruptDescriptorTable> = EarlyStorage::uninit();
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
/// Exact static descriptor objects retained by the first Deep-owned root.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[derive(Clone, Copy)]
pub(crate) struct EarlyDescriptorAddresses {
    pub(crate) gdt: u64,
    pub(crate) gdt_limit: u16,
    pub(crate) idt: u64,
    pub(crate) idt_limit: u16,
    pub(crate) tss: u64,
    pub(crate) tss_limit: u16,
    pub(crate) ist: IstStackLayout,
    pub(crate) installed_ist_tops: [u64; 3],
    pub(crate) privilege_stack0: u64,
}

/// Returns the installed one-shot descriptor object addresses without
/// exposing mutation authority over their static storage.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "the published installed state makes the one-shot TSS and final IDT immutable"
)]
pub(crate) fn early_descriptor_addresses() -> Option<EarlyDescriptorAddresses> {
    if INSTALL_STATE.load(Ordering::Acquire) != INSTALLED {
        return None;
    }
    let ist = linked_ist_stack_layout().ok()?;
    // SAFETY: the installed state is published only after the complete TSS is
    // written, and no later code mutates the one-shot descriptor object.
    let tss = unsafe { &*(*TSS.value.get()).as_ptr() };
    // SAFETY: the same published installed state makes the final IDT immutable.
    let idt = unsafe { &*(*FINAL_IDT.value.get()).as_ptr() };
    if !idt.has_exact_terminal_ist_assignment() {
        return None;
    }
    Some(EarlyDescriptorAddresses {
        gdt: GDT.value.get() as u64,
        gdt_limit: gdt::GDT_HARDWARE_LIMIT,
        idt: FINAL_IDT.value.get() as u64,
        idt_limit: (core::mem::size_of::<InterruptDescriptorTable>() - 1) as u16,
        tss: TSS.value.get() as u64,
        tss_limit: (core::mem::size_of::<TaskStateSegment>() - 1) as u16,
        ist,
        installed_ist_tops: [
            tss.interrupt_stack(InterruptStackIndex::One),
            tss.interrupt_stack(InterruptStackIndex::Two),
            tss.interrupt_stack(InterruptStackIndex::Three),
        ],
        privilege_stack0: tss.privilege_stack0(),
    })
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "linker-defined IST bounds are immutable kernel-layout facts"
)]
pub(crate) fn linked_ist_stack_layout() -> Result<IstStackLayout, EarlyDescriptorInstallError> {
    unsafe extern "C" {
        static __dw_ist_region_start: u8;
        static __dw_ist_region_end: u8;
        static __dw_double_fault_ist_guard: u8;
        static __dw_double_fault_ist_bottom: u8;
        static __dw_double_fault_ist_top: u8;
        static __dw_nmi_ist_guard: u8;
        static __dw_nmi_ist_bottom: u8;
        static __dw_nmi_ist_top: u8;
        static __dw_machine_check_ist_guard: u8;
        static __dw_machine_check_ist_bottom: u8;
        static __dw_machine_check_ist_top: u8;
    }
    let double_fault_guard = core::ptr::addr_of!(__dw_double_fault_ist_guard);
    let double_fault_bottom = core::ptr::addr_of!(__dw_double_fault_ist_bottom);
    let double_fault_top = core::ptr::addr_of!(__dw_double_fault_ist_top);
    let nmi_guard = core::ptr::addr_of!(__dw_nmi_ist_guard);
    let nmi_bottom = core::ptr::addr_of!(__dw_nmi_ist_bottom);
    let nmi_top = core::ptr::addr_of!(__dw_nmi_ist_top);
    let machine_check_guard = core::ptr::addr_of!(__dw_machine_check_ist_guard);
    let machine_check_bottom = core::ptr::addr_of!(__dw_machine_check_ist_bottom);
    let machine_check_top = core::ptr::addr_of!(__dw_machine_check_ist_top);
    let layout = IstStackLayout {
        double_fault: IstStackBounds {
            guard_page: opaque_linker_symbol_address(double_fault_guard),
            bottom: opaque_linker_symbol_address(double_fault_bottom),
            top: opaque_linker_symbol_address(double_fault_top),
        },
        non_maskable_interrupt: IstStackBounds {
            guard_page: opaque_linker_symbol_address(nmi_guard),
            bottom: opaque_linker_symbol_address(nmi_bottom),
            top: opaque_linker_symbol_address(nmi_top),
        },
        machine_check: IstStackBounds {
            guard_page: opaque_linker_symbol_address(machine_check_guard),
            bottom: opaque_linker_symbol_address(machine_check_bottom),
            top: opaque_linker_symbol_address(machine_check_top),
        },
    };
    let region_start_symbol = core::ptr::addr_of!(__dw_ist_region_start);
    let region_end_symbol = core::ptr::addr_of!(__dw_ist_region_end);
    let region_start = opaque_linker_symbol_address(region_start_symbol);
    let region_end = opaque_linker_symbol_address(region_end_symbol);
    let stacks = layout.stacks();
    let valid = layout.has_exact_shape()
        && region_start == stacks[0].guard_page
        && region_end == stacks[2].top
        && region_end
            .checked_sub(region_start)
            .is_some_and(|bytes| bytes == 15 * IST_GUARD_BYTES);
    if !valid {
        return Err(EarlyDescriptorInstallError::InvalidEmergencyStack);
    }
    Ok(layout)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadKernelStackLayoutError {
    InvalidGeometry,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "linker-defined E3 thread stack arena bounds are immutable kernel-layout facts"
)]
pub(crate) fn linked_thread_kernel_stack_layout() -> Result<
    [crate::memory::kernel_stack::KernelStackBounds;
        crate::memory::kernel_stack::E3_THREAD_STACK_COUNT],
    ThreadKernelStackLayoutError,
> {
    unsafe extern "C" {
        static __dw_thread_kernel_stack_region_start: u8;
        static __dw_thread_kernel_stack_region_end: u8;
    }
    let region_start_symbol = core::ptr::addr_of!(__dw_thread_kernel_stack_region_start);
    let region_end_symbol = core::ptr::addr_of!(__dw_thread_kernel_stack_region_end);
    let region_start = opaque_linker_symbol_address(region_start_symbol);
    let region_end = opaque_linker_symbol_address(region_end_symbol);
    let expected_bytes = crate::memory::kernel_stack::E3_THREAD_STACK_STRIDE
        .checked_mul(crate::memory::kernel_stack::E3_THREAD_STACK_COUNT as u64)
        .ok_or(ThreadKernelStackLayoutError::InvalidGeometry)?;
    if !region_start.is_multiple_of(crate::memory::kernel_stack::E3_THREAD_STACK_ALIGNMENT)
        || region_end.checked_sub(region_start) != Some(expected_bytes)
    {
        return Err(ThreadKernelStackLayoutError::InvalidGeometry);
    }
    let placeholder = crate::memory::kernel_stack::KernelStackBounds::new(
        crate::memory::kernel_stack::E3_BASE_PAGE_SIZE,
        crate::memory::kernel_stack::E3_BASE_PAGE_SIZE * 2,
        crate::memory::kernel_stack::E3_BASE_PAGE_SIZE * 2
            + crate::memory::kernel_stack::E3_THREAD_STACK_SIZE,
    )
    .map_err(|_| ThreadKernelStackLayoutError::InvalidGeometry)?;
    let mut stacks = [placeholder; crate::memory::kernel_stack::E3_THREAD_STACK_COUNT];
    for (index, stack) in stacks.iter_mut().enumerate() {
        let offset = crate::memory::kernel_stack::E3_THREAD_STACK_STRIDE
            .checked_mul(index as u64)
            .ok_or(ThreadKernelStackLayoutError::InvalidGeometry)?;
        let guard_page = region_start
            .checked_add(offset)
            .ok_or(ThreadKernelStackLayoutError::InvalidGeometry)?;
        let bottom = guard_page
            .checked_add(crate::memory::kernel_stack::E3_THREAD_STACK_GUARD_SIZE)
            .ok_or(ThreadKernelStackLayoutError::InvalidGeometry)?;
        let top = bottom
            .checked_add(crate::memory::kernel_stack::E3_THREAD_STACK_SIZE)
            .ok_or(ThreadKernelStackLayoutError::InvalidGeometry)?;
        *stack = crate::memory::kernel_stack::KernelStackBounds::new(guard_page, bottom, top)
            .map_err(|_| ThreadKernelStackLayoutError::InvalidGeometry)?;
    }
    if stacks.last().is_none_or(|stack| stack.top != region_end) {
        return Err(ThreadKernelStackLayoutError::InvalidGeometry);
    }
    Ok(stacks)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrivilegeEntryStackLayoutError {
    InvalidGeometry,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "linker-defined E4 privilege-entry stack bounds are immutable kernel-layout facts"
)]
pub(crate) fn linked_privilege_entry_stack_layout()
-> Result<crate::memory::kernel_stack::KernelStackBounds, PrivilegeEntryStackLayoutError> {
    unsafe extern "C" {
        static __dw_privilege_entry_stack_guard: u8;
        static __dw_privilege_entry_stack_bottom: u8;
        static __dw_privilege_entry_stack_top: u8;
    }
    let guard_symbol = core::ptr::addr_of!(__dw_privilege_entry_stack_guard);
    let bottom_symbol = core::ptr::addr_of!(__dw_privilege_entry_stack_bottom);
    let top_symbol = core::ptr::addr_of!(__dw_privilege_entry_stack_top);
    let guard = opaque_linker_symbol_address(guard_symbol);
    let bottom = opaque_linker_symbol_address(bottom_symbol);
    let top = opaque_linker_symbol_address(top_symbol);
    let bounds = crate::memory::kernel_stack::KernelStackBounds::new(guard, bottom, top)
        .map_err(|_| PrivilegeEntryStackLayoutError::InvalidGeometry)?;
    if crate::memory::kernel_stack::E4_PRIVILEGE_ENTRY_STACK_COUNT != 1
        || bounds.byte_len() != crate::memory::kernel_stack::E4_PRIVILEGE_ENTRY_STACK_SIZE
        || bottom.checked_sub(guard)
            != Some(crate::memory::kernel_stack::E4_PRIVILEGE_ENTRY_STACK_GUARD_SIZE)
        || !guard.is_multiple_of(crate::memory::kernel_stack::E4_PRIVILEGE_ENTRY_STACK_ALIGNMENT)
    {
        return Err(PrivilegeEntryStackLayoutError::InvalidGeometry);
    }
    Ok(bounds)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TerminalReaperStackLayoutError {
    InvalidGeometry,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "linker-defined terminal reaper stack bounds are immutable kernel-layout facts"
)]
pub(crate) fn linked_terminal_reaper_stack_layout()
-> Result<crate::memory::kernel_stack::KernelStackBounds, TerminalReaperStackLayoutError> {
    unsafe extern "C" {
        static __dw_terminal_reaper_stack_guard: u8;
        static __dw_terminal_reaper_stack_bottom: u8;
        static __dw_terminal_reaper_stack_top: u8;
    }
    let guard_symbol = core::ptr::addr_of!(__dw_terminal_reaper_stack_guard);
    let bottom_symbol = core::ptr::addr_of!(__dw_terminal_reaper_stack_bottom);
    let top_symbol = core::ptr::addr_of!(__dw_terminal_reaper_stack_top);
    let guard = opaque_linker_symbol_address(guard_symbol);
    let bottom = opaque_linker_symbol_address(bottom_symbol);
    let top = opaque_linker_symbol_address(top_symbol);
    let bounds = crate::memory::kernel_stack::KernelStackBounds::new(guard, bottom, top)
        .map_err(|_| TerminalReaperStackLayoutError::InvalidGeometry)?;
    if crate::memory::kernel_stack::TERMINAL_REAPER_STACK_COUNT != 1
        || bounds.byte_len() != crate::memory::kernel_stack::TERMINAL_REAPER_STACK_SIZE
        || bottom.checked_sub(guard)
            != Some(crate::memory::kernel_stack::TERMINAL_REAPER_STACK_GUARD_SIZE)
        || !guard.is_multiple_of(crate::memory::kernel_stack::TERMINAL_REAPER_STACK_ALIGNMENT)
    {
        return Err(TerminalReaperStackLayoutError::InvalidGeometry);
    }
    Ok(bounds)
}

/// Canonical H1 runtime CPU capacity. Firmware may describe more processors,
/// but DW0 brings at most these four slots into the shared runtime.
pub(crate) const H1_RUNTIME_CPU_SLOT_COUNT: usize = 4;
pub(crate) const H1_RUNTIME_AP_BOOTSTRAP_STACK_SIZE: u64 = 64 * 1024;
#[allow(
    dead_code,
    reason = "host integration builds do not resolve the target linker arena"
)]
const H1_RUNTIME_IST_STACK_SIZE: u64 = 16 * 1024;
#[allow(
    dead_code,
    reason = "host integration builds do not consume target runtime slot members"
)]
const H1_RUNTIME_STACKS_PER_SLOT: usize = 6;
#[allow(
    dead_code,
    reason = "host integration builds do not resolve the target linker arena"
)]
const H1_RUNTIME_CPU_SLOT_SIZE: u64 = 3 * (BASE_PAGE_SIZE + H1_RUNTIME_IST_STACK_SIZE)
    + BASE_PAGE_SIZE
    + crate::memory::kernel_stack::E4_PRIVILEGE_ENTRY_STACK_SIZE
    + BASE_PAGE_SIZE
    + crate::memory::kernel_stack::TERMINAL_REAPER_STACK_SIZE
    + BASE_PAGE_SIZE
    + H1_RUNTIME_AP_BOOTSTRAP_STACK_SIZE;

/// Linker-backed private stack carriers for one runtime CPU. The early BSP
/// carriers remain separate and are valid only until the BSP migrates here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeCpuStackLayout {
    pub(crate) interrupt_stacks: [crate::memory::kernel_stack::KernelStackBounds; 3],
    pub(crate) privilege_entry: crate::memory::kernel_stack::KernelStackBounds,
    pub(crate) terminal_reaper: crate::memory::kernel_stack::KernelStackBounds,
    pub(crate) ap_bootstrap: crate::memory::kernel_stack::KernelStackBounds,
}

impl RuntimeCpuStackLayout {
    #[allow(
        dead_code,
        reason = "host integration builds do not consume target runtime slot members"
    )]
    pub(crate) const fn stacks(
        self,
    ) -> [crate::memory::kernel_stack::KernelStackBounds; H1_RUNTIME_STACKS_PER_SLOT] {
        [
            self.interrupt_stacks[0],
            self.interrupt_stacks[1],
            self.interrupt_stacks[2],
            self.privilege_entry,
            self.terminal_reaper,
            self.ap_bootstrap,
        ]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "host integration builds retain the bounded parser for source-contract coverage"
)]
pub(crate) enum RuntimeCpuStackLayoutError {
    InvalidGeometry,
}

#[allow(
    dead_code,
    reason = "host integration builds do not resolve the target linker arena"
)]
fn next_runtime_stack(
    cursor: &mut u64,
    payload_size: u64,
) -> Result<crate::memory::kernel_stack::KernelStackBounds, RuntimeCpuStackLayoutError> {
    let guard_page = *cursor;
    let bottom = guard_page
        .checked_add(BASE_PAGE_SIZE)
        .ok_or(RuntimeCpuStackLayoutError::InvalidGeometry)?;
    let top = bottom
        .checked_add(payload_size)
        .ok_or(RuntimeCpuStackLayoutError::InvalidGeometry)?;
    let stack = crate::memory::kernel_stack::KernelStackBounds::new(guard_page, bottom, top)
        .map_err(|_| RuntimeCpuStackLayoutError::InvalidGeometry)?;
    *cursor = top;
    Ok(stack)
}

/// Derives all runtime CPU carriers from the two linker boundaries without
/// unchecked indexing or pointer arithmetic.
#[allow(
    dead_code,
    reason = "host integration builds do not resolve the target linker arena"
)]
pub(crate) fn runtime_cpu_stack_layout_from_arena(
    arena_start: u64,
    arena_end: u64,
) -> Result<[RuntimeCpuStackLayout; H1_RUNTIME_CPU_SLOT_COUNT], RuntimeCpuStackLayoutError> {
    let expected_size = H1_RUNTIME_CPU_SLOT_SIZE
        .checked_mul(H1_RUNTIME_CPU_SLOT_COUNT as u64)
        .ok_or(RuntimeCpuStackLayoutError::InvalidGeometry)?;
    if arena_start < 0xffff_8000_0000_0000
        || !arena_start.is_multiple_of(BASE_PAGE_SIZE)
        || arena_end.checked_sub(arena_start) != Some(expected_size)
    {
        return Err(RuntimeCpuStackLayoutError::InvalidGeometry);
    }

    let placeholder = RuntimeCpuStackLayout {
        interrupt_stacks: [crate::memory::kernel_stack::KernelStackBounds::new(
            BASE_PAGE_SIZE,
            2 * BASE_PAGE_SIZE,
            3 * BASE_PAGE_SIZE,
        )
        .map_err(|_| RuntimeCpuStackLayoutError::InvalidGeometry)?; 3],
        privilege_entry: crate::memory::kernel_stack::KernelStackBounds::new(
            BASE_PAGE_SIZE,
            2 * BASE_PAGE_SIZE,
            3 * BASE_PAGE_SIZE,
        )
        .map_err(|_| RuntimeCpuStackLayoutError::InvalidGeometry)?,
        terminal_reaper: crate::memory::kernel_stack::KernelStackBounds::new(
            BASE_PAGE_SIZE,
            2 * BASE_PAGE_SIZE,
            3 * BASE_PAGE_SIZE,
        )
        .map_err(|_| RuntimeCpuStackLayoutError::InvalidGeometry)?,
        ap_bootstrap: crate::memory::kernel_stack::KernelStackBounds::new(
            BASE_PAGE_SIZE,
            2 * BASE_PAGE_SIZE,
            3 * BASE_PAGE_SIZE,
        )
        .map_err(|_| RuntimeCpuStackLayoutError::InvalidGeometry)?,
    };
    let mut slots = [placeholder; H1_RUNTIME_CPU_SLOT_COUNT];
    let mut cursor = arena_start;
    for slot in &mut slots {
        let interrupt_stacks = [
            next_runtime_stack(&mut cursor, H1_RUNTIME_IST_STACK_SIZE)?,
            next_runtime_stack(&mut cursor, H1_RUNTIME_IST_STACK_SIZE)?,
            next_runtime_stack(&mut cursor, H1_RUNTIME_IST_STACK_SIZE)?,
        ];
        let privilege_entry = next_runtime_stack(
            &mut cursor,
            crate::memory::kernel_stack::E4_PRIVILEGE_ENTRY_STACK_SIZE,
        )?;
        let terminal_reaper = next_runtime_stack(
            &mut cursor,
            crate::memory::kernel_stack::TERMINAL_REAPER_STACK_SIZE,
        )?;
        let ap_bootstrap = next_runtime_stack(&mut cursor, H1_RUNTIME_AP_BOOTSTRAP_STACK_SIZE)?;
        *slot = RuntimeCpuStackLayout {
            interrupt_stacks,
            privilege_entry,
            terminal_reaper,
            ap_bootstrap,
        };
    }
    if cursor != arena_end {
        return Err(RuntimeCpuStackLayoutError::InvalidGeometry);
    }
    Ok(slots)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "linker-defined H1 runtime CPU arena bounds are immutable kernel-layout facts"
)]
pub(crate) fn linked_runtime_cpu_stack_layout()
-> Result<[RuntimeCpuStackLayout; H1_RUNTIME_CPU_SLOT_COUNT], RuntimeCpuStackLayoutError> {
    unsafe extern "C" {
        static __dw_runtime_cpu_stack_arena_start: u8;
        static __dw_runtime_cpu_stack_arena_end: u8;
    }
    runtime_cpu_stack_layout_from_arena(
        opaque_linker_symbol_address(core::ptr::addr_of!(__dw_runtime_cpu_stack_arena_start)),
        opaque_linker_symbol_address(core::ptr::addr_of!(__dw_runtime_cpu_stack_arena_end)),
    )
}

#[cfg(test)]
mod runtime_cpu_stack_tests {
    use super::*;

    const ARENA_START: u64 = 0xffff_8000_1000_0000;

    #[test]
    fn four_runtime_slots_have_exact_private_guarded_geometry() {
        let arena_end = ARENA_START
            + H1_RUNTIME_CPU_SLOT_SIZE * u64::try_from(H1_RUNTIME_CPU_SLOT_COUNT).unwrap();
        let slots = runtime_cpu_stack_layout_from_arena(ARENA_START, arena_end).unwrap();
        let mut expected_guard = ARENA_START;
        let mut guards = [0_u64; H1_RUNTIME_CPU_SLOT_COUNT * H1_RUNTIME_STACKS_PER_SLOT];
        let mut guard_count = 0;
        for slot in slots {
            let stacks = slot.stacks();
            for (index, stack) in stacks.into_iter().enumerate() {
                assert_eq!(stack.guard_page, expected_guard);
                assert_eq!(stack.bottom - stack.guard_page, BASE_PAGE_SIZE);
                let expected_payload = match index {
                    0..=2 => H1_RUNTIME_IST_STACK_SIZE,
                    3 => crate::memory::kernel_stack::E4_PRIVILEGE_ENTRY_STACK_SIZE,
                    4 => crate::memory::kernel_stack::TERMINAL_REAPER_STACK_SIZE,
                    5 => H1_RUNTIME_AP_BOOTSTRAP_STACK_SIZE,
                    _ => unreachable!(),
                };
                assert_eq!(stack.byte_len(), expected_payload);
                assert!(!guards[..guard_count].contains(&stack.guard_page));
                guards[guard_count] = stack.guard_page;
                guard_count += 1;
                expected_guard = stack.top;
            }
        }
        assert_eq!(
            guard_count,
            H1_RUNTIME_CPU_SLOT_COUNT * H1_RUNTIME_STACKS_PER_SLOT
        );
        assert_eq!(expected_guard, arena_end);
    }

    #[test]
    fn runtime_arena_rejects_unbounded_or_drifted_linker_geometry() {
        let arena_end = ARENA_START + H1_RUNTIME_CPU_SLOT_SIZE * 4;
        assert_eq!(
            runtime_cpu_stack_layout_from_arena(ARENA_START + 1, arena_end),
            Err(RuntimeCpuStackLayoutError::InvalidGeometry)
        );
        assert_eq!(
            runtime_cpu_stack_layout_from_arena(ARENA_START, arena_end - BASE_PAGE_SIZE),
            Err(RuntimeCpuStackLayoutError::InvalidGeometry)
        );
        assert_eq!(
            runtime_cpu_stack_layout_from_arena(u64::MAX - BASE_PAGE_SIZE + 1, u64::MAX),
            Err(RuntimeCpuStackLayoutError::InvalidGeometry)
        );
    }
}

/// Publication lifecycle for one bounded runtime-CPU descriptor slot.
///
/// `DescriptorsActive` means that the current CPU has loaded its private
/// GDT/TSS/IDT. `Online` is published only after that CPU has also installed
/// its private GS-selected SYSCALL entry state. The scheduler remains BSP-only
/// until H2 gives runtime execution carriers matching multi-CPU ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
#[cfg_attr(
    not(any(test, all(target_os = "none", target_arch = "x86_64"))),
    allow(
        dead_code,
        reason = "runtime descriptor publication is target-owned and host-tested"
    )
)]
pub(crate) enum RuntimeCpuDescriptorLifecycle {
    Vacant = 0,
    Building = 1,
    DescriptorsActive = 2,
    Online = 3,
    Failed = 4,
}

impl RuntimeCpuDescriptorLifecycle {
    #[cfg_attr(
        not(any(test, all(target_os = "none", target_arch = "x86_64"))),
        allow(
            dead_code,
            reason = "runtime descriptor publication is target-owned and host-tested"
        )
    )]
    const fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0 => Some(Self::Vacant),
            1 => Some(Self::Building),
            2 => Some(Self::DescriptorsActive),
            3 => Some(Self::Online),
            4 => Some(Self::Failed),
            _ => None,
        }
    }
}

#[cfg(test)]
mod runtime_cpu_descriptor_state_tests {
    use super::*;

    #[test]
    fn runtime_descriptor_publication_states_have_stable_bounded_encoding() {
        let expected = [
            RuntimeCpuDescriptorLifecycle::Vacant,
            RuntimeCpuDescriptorLifecycle::Building,
            RuntimeCpuDescriptorLifecycle::DescriptorsActive,
            RuntimeCpuDescriptorLifecycle::Online,
            RuntimeCpuDescriptorLifecycle::Failed,
        ];
        for (bits, state) in expected.into_iter().enumerate() {
            assert_eq!(
                RuntimeCpuDescriptorLifecycle::from_bits(bits as u8),
                Some(state)
            );
        }
        assert_eq!(RuntimeCpuDescriptorLifecycle::from_bits(5), None);
        assert_eq!(RuntimeCpuDescriptorLifecycle::from_bits(u8::MAX), None);
    }
}

/// Target-owned private descriptor objects for one runtime CPU.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
struct RuntimeCpuDescriptorSlot {
    lifecycle: AtomicU8,
    tss: UnsafeCell<MaybeUninit<TaskStateSegment>>,
    gdt: UnsafeCell<MaybeUninit<GlobalDescriptorTable>>,
    idt: UnsafeCell<MaybeUninit<InterruptDescriptorTable>>,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl RuntimeCpuDescriptorSlot {
    const fn vacant() -> Self {
        Self {
            lifecycle: AtomicU8::new(RuntimeCpuDescriptorLifecycle::Vacant as u8),
            tss: UnsafeCell::new(MaybeUninit::uninit()),
            gdt: UnsafeCell::new(MaybeUninit::uninit()),
            idt: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "each descriptor slot has one owning CPU and publishes immutable objects with release/acquire ordering"
)]
unsafe impl Sync for RuntimeCpuDescriptorSlot {}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static RUNTIME_CPU_DESCRIPTOR_SLOTS: [RuntimeCpuDescriptorSlot; H1_RUNTIME_CPU_SLOT_COUNT] =
    [const { RuntimeCpuDescriptorSlot::vacant() }; H1_RUNTIME_CPU_SLOT_COUNT];

/// Failure to establish one CPU's private runtime architecture carriers.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeCpuDescriptorError {
    InvalidCpuIndex,
    BootstrapDescriptorsUnavailable,
    SlotAlreadyClaimed,
    InvalidStackLayout,
    InvalidHandlerAddress(u64),
    Syscall(syscall::SyscallInstallError),
}

/// Acquire-loads one runtime descriptor publication state.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn runtime_cpu_descriptor_lifecycle(
    cpu_index: usize,
) -> Option<RuntimeCpuDescriptorLifecycle> {
    let slot = RUNTIME_CPU_DESCRIPTOR_SLOTS.get(cpu_index)?;
    RuntimeCpuDescriptorLifecycle::from_bits(slot.lifecycle.load(Ordering::Acquire))
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn runtime_cpu_stack_layout(
    cpu_index: usize,
) -> Result<RuntimeCpuStackLayout, RuntimeCpuDescriptorError> {
    linked_runtime_cpu_stack_layout()
        .map_err(|_| RuntimeCpuDescriptorError::InvalidStackLayout)?
        .get(cpu_index)
        .copied()
        .ok_or(RuntimeCpuDescriptorError::InvalidCpuIndex)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn fail_runtime_cpu_descriptor_slot(cpu_index: usize) {
    if let Some(slot) = RUNTIME_CPU_DESCRIPTOR_SLOTS.get(cpu_index) {
        slot.lifecycle.store(
            RuntimeCpuDescriptorLifecycle::Failed as u8,
            Ordering::Release,
        );
    }
}

/// Publishes that the current CPU completed private SYSCALL/GS installation.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn publish_runtime_cpu_online(cpu_index: usize) -> Result<(), RuntimeCpuDescriptorError> {
    let slot = RUNTIME_CPU_DESCRIPTOR_SLOTS
        .get(cpu_index)
        .ok_or(RuntimeCpuDescriptorError::InvalidCpuIndex)?;
    slot.lifecycle
        .compare_exchange(
            RuntimeCpuDescriptorLifecycle::DescriptorsActive as u8,
            RuntimeCpuDescriptorLifecycle::Online as u8,
            Ordering::Release,
            Ordering::Acquire,
        )
        .map_err(|_| RuntimeCpuDescriptorError::SlotAlreadyClaimed)?;
    Ok(())
}

/// Constructs and activates one runtime CPU's private TSS/GDT/IDT bundle.
///
/// # Safety
///
/// The caller must execute on `cpu_index` at CPL0 with IF clear, after the
/// runtime arena is mapped with its guard pages absent. This function must be
/// the only initializer for the selected slot. Once activated, the slot is
/// never mutated again.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "one owning CPU initializes static descriptor storage and executes the audited lgdt/ltr/lidt boundary"
)]
unsafe fn activate_runtime_cpu_descriptors(
    cpu_index: usize,
) -> Result<RuntimeCpuStackLayout, RuntimeCpuDescriptorError> {
    let slot = RUNTIME_CPU_DESCRIPTOR_SLOTS
        .get(cpu_index)
        .ok_or(RuntimeCpuDescriptorError::InvalidCpuIndex)?;
    slot.lifecycle
        .compare_exchange(
            RuntimeCpuDescriptorLifecycle::Vacant as u8,
            RuntimeCpuDescriptorLifecycle::Building as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map_err(|_| RuntimeCpuDescriptorError::SlotAlreadyClaimed)?;

    let result = (|| {
        let stacks = runtime_cpu_stack_layout(cpu_index)?;
        let handlers = unsafe { load_handler_addresses() }.map_err(|error| match error {
            EarlyDescriptorInstallError::InvalidHandlerAddress(address) => {
                RuntimeCpuDescriptorError::InvalidHandlerAddress(address)
            }
            _ => RuntimeCpuDescriptorError::InvalidStackLayout,
        })?;

        let mut tss = TaskStateSegment::empty();
        tss.set_privilege_stack0(stacks.privilege_entry.top)
            .map_err(|_| RuntimeCpuDescriptorError::InvalidStackLayout)?;
        tss.set_interrupt_stack(InterruptStackIndex::One, stacks.interrupt_stacks[0].top)
            .map_err(|_| RuntimeCpuDescriptorError::InvalidStackLayout)?;
        tss.set_interrupt_stack(InterruptStackIndex::Two, stacks.interrupt_stacks[1].top)
            .map_err(|_| RuntimeCpuDescriptorError::InvalidStackLayout)?;
        tss.set_interrupt_stack(InterruptStackIndex::Three, stacks.interrupt_stacks[2].top)
            .map_err(|_| RuntimeCpuDescriptorError::InvalidStackLayout)?;

        unsafe { (*slot.tss.get()).write(tss) };
        let tss = unsafe { &*(*slot.tss.get()).as_ptr() };
        unsafe { (*slot.gdt.get()).write(GlobalDescriptorTable::new(tss)) };
        unsafe { (*slot.idt.get()).write(InterruptDescriptorTable::new(handlers)) };
        let gdt = unsafe { &*(*slot.gdt.get()).as_ptr() };
        let idt = unsafe { &*(*slot.idt.get()).as_ptr() };
        if !idt.has_exact_terminal_ist_assignment() {
            return Err(RuntimeCpuDescriptorError::InvalidStackLayout);
        }

        unsafe { gdt::activate(gdt) };
        unsafe { idt::activate(idt) };
        Ok(stacks)
    })();

    match result {
        Ok(stacks) => {
            slot.lifecycle.store(
                RuntimeCpuDescriptorLifecycle::DescriptorsActive as u8,
                Ordering::Release,
            );
            Ok(stacks)
        }
        Err(error) => {
            fail_runtime_cpu_descriptor_slot(cpu_index);
            Err(error)
        }
    }
}

/// Moves the BSP from the one-shot early descriptor carriers onto runtime slot
/// zero after the Deep-owned page-table root is active.
///
/// # Safety
///
/// Must run exactly once on the BSP at CPL0 with IF clear, after Deep paging
/// maps the runtime arena and before any AP is released.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "the explicit BSP migration consumes the private runtime descriptor activation boundary"
)]
pub(crate) unsafe fn migrate_bsp_to_runtime_slot0_after_deep_paging()
-> Result<(), RuntimeCpuDescriptorError> {
    if early_descriptor_addresses().is_none() {
        return Err(RuntimeCpuDescriptorError::BootstrapDescriptorsUnavailable);
    }
    unsafe { activate_runtime_cpu_descriptors(0) }.map(|_| ())
}

/// Installs an AP's complete private H1 descriptor and GS-entry substrate.
///
/// APs remain parked in CPL0 after this function returns; this does not grant
/// access to the BSP-only native scheduler/runtime.
///
/// # Safety
///
/// Must run exactly once on the AP named by `cpu_index` with IF clear, after
/// Deep paging and the runtime stack arena are active for that CPU.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "the AP initializes its own private descriptor and privileged MSR state before online publication"
)]
pub(crate) unsafe fn initialize_ap_runtime_slot(
    cpu_index: usize,
) -> Result<(), RuntimeCpuDescriptorError> {
    if cpu_index == 0 {
        return Err(RuntimeCpuDescriptorError::InvalidCpuIndex);
    }
    let stacks = unsafe { activate_runtime_cpu_descriptors(cpu_index) }?;
    if let Err(error) = unsafe { syscall::install_syscall_boundary_for_slot(cpu_index, stacks) } {
        fail_runtime_cpu_descriptor_slot(cpu_index);
        return Err(RuntimeCpuDescriptorError::Syscall(error));
    }
    publish_runtime_cpu_online(cpu_index)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "linker-owned exception symbols are read only by the one-shot x86 descriptor installer"
)]
unsafe extern "C" {
    static dw_x86_64_exception_handler_table: [u64; EXCEPTION_HANDLER_COUNT];
    static dw_x86_64_apic_timer_entry: u8;
    static dw_x86_64_apic_error_entry: u8;
    static dw_x86_64_apic_spurious_entry: u8;
}

/// Failure to establish an early descriptor-table boundary.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EarlyDescriptorInstallError {
    AlreadyInstallingOrInstalled,
    InvalidHandlerAddress(u64),
    InvalidEmergencyStack,
    InvalidPrivilegeEntryStack,
}

/// Disables maskable interrupts, initializes fixed COM1 diagnostics, then
/// installs the Deepwyrm GDT/TSS and IDT. The function must run before
/// BootInfo parsing; it has no loader descriptor/TLS dependency.
///
/// # Safety
///
/// The caller must be executing the single-CPU bootstrap path on the
/// established kernel stack with the fixed higher-half kernel PT_LOAD mapping
/// active. The linked exception table and three emergency stacks must remain
/// supervisor-mapped for the life of the CPU. No second CPU may enter before
/// later SMP bring-up provides separate descriptor storage.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "one-shot static descriptor installation invokes the audited x86 activation instructions"
)]
pub unsafe fn install_early_descriptors() -> Result<(), EarlyDescriptorInstallError> {
    if INSTALL_STATE
        .compare_exchange(
            INSTALL_UNSTARTED,
            INSTALLING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return Err(EarlyDescriptorInstallError::AlreadyInstallingOrInstalled);
    }

    // SAFETY: this is the explicitly documented x86 bootstrap boundary. The
    // operation does not read loader descriptor state and precedes all parsing.
    unsafe { disable_interrupts() };
    crate::debug::initialize_early_com1();

    let result = unsafe { initialize_and_activate() };
    match result {
        Ok(()) => {
            INSTALL_STATE.store(INSTALLED, Ordering::Release);
            Ok(())
        }
        Err(error) => {
            INSTALL_STATE.store(INSTALL_UNSTARTED, Ordering::Release);
            Err(error)
        }
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "private helper initializes one-shot static storage and invokes audited descriptor instructions"
)]
unsafe fn initialize_and_activate() -> Result<(), EarlyDescriptorInstallError> {
    let handlers = unsafe { load_handler_addresses() }?;
    let current_selector = unsafe { current_code_selector() };
    let emergency_idt = InterruptDescriptorTable::emergency(handlers, current_selector);
    unsafe { (*EMERGENCY_IDT.value.get()).write(emergency_idt) };
    let emergency_idt = unsafe { &*(*EMERGENCY_IDT.value.get()).as_ptr() };
    // SAFETY: the current CS selector is live by definition and every gate
    // targets a retained terminal stub; this covers faults during GDT reset.
    unsafe { idt::activate(emergency_idt) };

    let ist = linked_ist_stack_layout()?;
    let privilege_entry = linked_privilege_entry_stack_layout()
        .map_err(|_| EarlyDescriptorInstallError::InvalidPrivilegeEntryStack)?;
    let mut tss = TaskStateSegment::empty();
    tss.set_privilege_stack0(privilege_entry.top)
        .map_err(|_| EarlyDescriptorInstallError::InvalidPrivilegeEntryStack)?;
    tss.set_interrupt_stack(InterruptStackIndex::One, ist.double_fault.top)
        .map_err(|_| EarlyDescriptorInstallError::InvalidEmergencyStack)?;
    tss.set_interrupt_stack(InterruptStackIndex::Two, ist.non_maskable_interrupt.top)
        .map_err(|_| EarlyDescriptorInstallError::InvalidEmergencyStack)?;
    tss.set_interrupt_stack(InterruptStackIndex::Three, ist.machine_check.top)
        .map_err(|_| EarlyDescriptorInstallError::InvalidEmergencyStack)?;

    // SAFETY: `INSTALL_STATE` excludes a second initializer. No reference is
    // formed until the complete value is written and then never mutated.
    unsafe { (*TSS.value.get()).write(tss) };
    let tss = unsafe { &*(*TSS.value.get()).as_ptr() };

    let gdt = GlobalDescriptorTable::new(tss);
    let idt = InterruptDescriptorTable::new(handlers);

    // SAFETY: as above, the values are fully initialized before static refs
    // are formed and the one-shot installer precludes mutation afterwards.
    unsafe { (*GDT.value.get()).write(gdt) };
    unsafe { (*FINAL_IDT.value.get()).write(idt) };
    let gdt = unsafe { &*(*GDT.value.get()).as_ptr() };
    let idt = unsafe { &*(*FINAL_IDT.value.get()).as_ptr() };

    // SAFETY: all static lifetime/mapping/stack/IF preconditions are asserted
    // by `install_early_descriptors` and this private setup sequence.
    unsafe { gdt::activate(gdt) };
    unsafe { idt::activate(idt) };
    Ok(())
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "reads the currently executing valid CS selector for the temporary emergency IDT"
)]
unsafe fn current_code_selector() -> gdt::SegmentSelector {
    let selector: u16;
    unsafe {
        core::arch::asm!("mov {0:x}, cs", out(reg) selector, options(nomem, nostack, preserves_flags));
    }
    gdt::SegmentSelector::from_bits(selector)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "reads the linker-owned fixed exception handler table during one-shot bootstrap"
)]
unsafe fn load_handler_addresses() -> Result<EarlyIdtHandlers, EarlyDescriptorInstallError> {
    let table = &raw const dw_x86_64_exception_handler_table;
    let mut handlers = [HandlerAddress::new(0xffff_8000_0000_0000)
        .map_err(|_| EarlyDescriptorInstallError::InvalidHandlerAddress(0))?;
        EXCEPTION_HANDLER_COUNT];
    let mut index = 0;
    while index < EXCEPTION_HANDLER_COUNT {
        // SAFETY: the linker retains this exact 32-word table in rodata, and
        // this one-shot boundary only reads within the declared array length.
        let address = unsafe { core::ptr::read(table.cast::<u64>().add(index)) };
        handlers[index] = HandlerAddress::new(address)
            .map_err(|_| EarlyDescriptorInstallError::InvalidHandlerAddress(address))?;
        index += 1;
    }
    // SAFETY: both symbols name sixteen-byte-aligned entry labels retained by
    // the same linked exception object.
    let apic_timer = &raw const dw_x86_64_apic_timer_entry as *const u8 as u64;
    let apic_error = &raw const dw_x86_64_apic_error_entry as *const u8 as u64;
    let apic_spurious = &raw const dw_x86_64_apic_spurious_entry as *const u8 as u64;
    Ok(EarlyIdtHandlers {
        exceptions: ExceptionHandlerTable::new(handlers),
        local_apic_timer: HandlerAddress::new(apic_timer)
            .map_err(|_| EarlyDescriptorInstallError::InvalidHandlerAddress(apic_timer))?,
        local_apic_error: HandlerAddress::new(apic_error)
            .map_err(|_| EarlyDescriptorInstallError::InvalidHandlerAddress(apic_error))?,
        local_apic_spurious: HandlerAddress::new(apic_spurious)
            .map_err(|_| EarlyDescriptorInstallError::InvalidHandlerAddress(apic_spurious))?,
    })
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "the early descriptor path must enforce IF=0 before serial and IDT setup"
)]
unsafe fn disable_interrupts() {
    // SAFETY: this is the first instruction-class operation in the one-shot
    // early descriptor path and has the intentionally narrow effect of CLI.
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
    }
}
