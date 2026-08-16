//! x86_64 descriptor-table and terminal-exception bring-up.
//!
//! `install_early_descriptors` is the sole callable DW0-B transition: it
//! initializes COM1, installs a Deepwyrm-owned GDT/TSS, and finally replaces
//! the emergency IDT before any BootInfo parsing. It intentionally preserves
//! `IF=0` and does not rely on loader descriptor or TLS state.

pub mod apic;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod entry;
pub mod exceptions;
pub mod gdt;
pub mod idt;
pub mod mm;
pub mod tss;

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
const EMERGENCY_IST_STACK_BYTES: usize = 16 * 1024;

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

/// A bounded, separately aligned interrupt stack. Guard pages are deferred to
/// DW0-C because the transition CR3 covers PT_LOAD memory but establishes no
/// independent guard-page mapping policy yet.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[repr(align(4096))]
struct EmergencyIstStack {
    bytes: UnsafeCell<[u8; EMERGENCY_IST_STACK_BYTES]>,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl EmergencyIstStack {
    const fn new() -> Self {
        Self {
            bytes: UnsafeCell::new([0; EMERGENCY_IST_STACK_BYTES]),
        }
    }

    fn top(&'static self) -> u64 {
        self.bytes.get() as u64 + EMERGENCY_IST_STACK_BYTES as u64
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "each static IST stack has one designated TSS slot and no shared Rust references"
)]
unsafe impl Sync for EmergencyIstStack {}

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
static DOUBLE_FAULT_IST: EmergencyIstStack = EmergencyIstStack::new();
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static NMI_IST: EmergencyIstStack = EmergencyIstStack::new();
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static MACHINE_CHECK_IST: EmergencyIstStack = EmergencyIstStack::new();

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
}

/// Returns the installed one-shot descriptor object addresses without
/// exposing mutation authority over their static storage.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn early_descriptor_addresses() -> Option<EarlyDescriptorAddresses> {
    if INSTALL_STATE.load(Ordering::Acquire) != INSTALLED {
        return None;
    }
    Some(EarlyDescriptorAddresses {
        gdt: GDT.value.get() as u64,
        gdt_limit: (core::mem::size_of::<GlobalDescriptorTable>() - 1) as u16,
        idt: FINAL_IDT.value.get() as u64,
        idt_limit: (core::mem::size_of::<InterruptDescriptorTable>() - 1) as u16,
        tss: TSS.value.get() as u64,
        tss_limit: (core::mem::size_of::<TaskStateSegment>() - 1) as u16,
    })
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

    let mut tss = TaskStateSegment::empty();
    tss.set_interrupt_stack(InterruptStackIndex::One, DOUBLE_FAULT_IST.top())
        .map_err(|_| EarlyDescriptorInstallError::InvalidEmergencyStack)?;
    tss.set_interrupt_stack(InterruptStackIndex::Two, NMI_IST.top())
        .map_err(|_| EarlyDescriptorInstallError::InvalidEmergencyStack)?;
    tss.set_interrupt_stack(InterruptStackIndex::Three, MACHINE_CHECK_IST.top())
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
