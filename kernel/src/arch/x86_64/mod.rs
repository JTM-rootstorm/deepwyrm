//! x86_64 descriptor-table and terminal-exception bring-up.
//!
//! `install_early_descriptors` is the sole callable DW0-B transition: it
//! initializes COM1, installs a Deepwyrm-owned GDT/TSS, and finally replaces
//! the emergency IDT before any BootInfo parsing. It intentionally preserves
//! `IF=0` and does not rely on loader descriptor or TLS state.

pub mod apic;
pub(crate) mod context;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod entry;
pub mod exceptions;
pub mod gdt;
pub mod idt;
pub mod mm;
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

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
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
    let layout = IstStackLayout {
        double_fault: IstStackBounds {
            guard_page: core::ptr::addr_of!(__dw_double_fault_ist_guard) as u64,
            bottom: core::ptr::addr_of!(__dw_double_fault_ist_bottom) as u64,
            top: core::ptr::addr_of!(__dw_double_fault_ist_top) as u64,
        },
        non_maskable_interrupt: IstStackBounds {
            guard_page: core::ptr::addr_of!(__dw_nmi_ist_guard) as u64,
            bottom: core::ptr::addr_of!(__dw_nmi_ist_bottom) as u64,
            top: core::ptr::addr_of!(__dw_nmi_ist_top) as u64,
        },
        machine_check: IstStackBounds {
            guard_page: core::ptr::addr_of!(__dw_machine_check_ist_guard) as u64,
            bottom: core::ptr::addr_of!(__dw_machine_check_ist_bottom) as u64,
            top: core::ptr::addr_of!(__dw_machine_check_ist_top) as u64,
        },
    };
    let region_start = core::ptr::addr_of!(__dw_ist_region_start) as u64;
    let region_end = core::ptr::addr_of!(__dw_ist_region_end) as u64;
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
    let region_start = core::ptr::addr_of!(__dw_thread_kernel_stack_region_start) as u64;
    let region_end = core::ptr::addr_of!(__dw_thread_kernel_stack_region_end) as u64;
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
    let guard = core::ptr::addr_of!(__dw_privilege_entry_stack_guard) as u64;
    let bottom = core::ptr::addr_of!(__dw_privilege_entry_stack_bottom) as u64;
    let top = core::ptr::addr_of!(__dw_privilege_entry_stack_top) as u64;
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
#[allow(
    unsafe_code,
    reason = "linker-owned exception symbols are read only by the one-shot x86 descriptor installer"
)]
unsafe extern "C" {
    static dw_x86_64_exception_handler_table: [u64; EXCEPTION_HANDLER_COUNT];
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
    let apic_error = &raw const dw_x86_64_apic_error_entry as *const u8 as u64;
    let apic_spurious = &raw const dw_x86_64_apic_spurious_entry as *const u8 as u64;
    Ok(EarlyIdtHandlers {
        exceptions: ExceptionHandlerTable::new(handlers),
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
