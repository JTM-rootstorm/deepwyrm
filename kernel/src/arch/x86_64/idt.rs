//! x86_64 interrupt-descriptor-table construction and activation.
//!
//! The table installs only DW0-B exception and local-APIC terminal handlers.
//! PIC, external, and future internal vectors remain absent until their
//! owning subsystems supply an entry convention and a handler.

use core::arch::asm;
use core::mem::size_of;

use crate::interrupt::{
    EXCEPTION_VECTOR_RANGE, LOCAL_APIC_ERROR_VECTOR, LOCAL_APIC_SPURIOUS_VECTOR, VectorClass,
    classify_vector,
};

use super::exceptions::EXCEPTION_HANDLER_COUNT;
use super::gdt::KERNEL_CODE_SELECTOR;
use super::tss::InterruptStackIndex;

const INTERRUPT_GATE_PRESENT_RING0: u8 = 0x8e;

/// A canonical x86_64 handler address suitable for an IDT gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct HandlerAddress(u64);

impl HandlerAddress {
    /// Validates an address under the locked four-level paging boundary.
    pub const fn new(address: u64) -> Result<Self, IdtBuildError> {
        if !is_kernel_handler_address(address) {
            return Err(IdtBuildError::NonCanonicalHandlerAddress(address));
        }
        Ok(Self(address))
    }

    const fn bits(self) -> u64 {
        self.0
    }
}

/// Per-vector exception-entry addresses supplied by the architecture assembly
/// boundary. Each stub is responsible for normalizing its vector and optional
/// hardware error code before entering `exceptions`.
#[derive(Clone, Copy)]
pub struct ExceptionHandlerTable {
    handlers: [HandlerAddress; EXCEPTION_HANDLER_COUNT],
}

impl ExceptionHandlerTable {
    #[must_use]
    pub const fn new(handlers: [HandlerAddress; EXCEPTION_HANDLER_COUNT]) -> Self {
        Self { handlers }
    }

    fn handler_for_vector(&self, vector: u8) -> HandlerAddress {
        self.handlers[usize::from(vector)]
    }
}

/// Handler addresses required before the local APIC can be brought online.
#[derive(Clone, Copy)]
pub struct EarlyIdtHandlers {
    pub exceptions: ExceptionHandlerTable,
    pub local_apic_error: HandlerAddress,
    pub local_apic_spurious: HandlerAddress,
}

/// Full x86_64 long-mode interrupt descriptor table.
#[repr(C, align(16))]
pub struct InterruptDescriptorTable {
    entries: [InterruptGate; 256],
}

impl InterruptDescriptorTable {
    /// Builds a DW0-B IDT from assembly entry stubs.
    ///
    /// #DF, NMI, and #MC use separate configured IST stacks. No gate is
    /// present for masked PIC, unallocated external, or future
    /// internal vectors. This prevents accidentally accepting an interrupt
    /// source before its ownership and entry convention are defined.
    pub fn new(handlers: EarlyIdtHandlers) -> Self {
        Self::with_selector(handlers, KERNEL_CODE_SELECTOR, true)
    }

    #[cfg_attr(not(any(test, target_os = "none")), allow(dead_code))]
    pub(crate) fn emergency(
        handlers: EarlyIdtHandlers,
        selector: super::gdt::SegmentSelector,
    ) -> Self {
        Self::with_selector(handlers, selector, false)
    }

    fn with_selector(
        handlers: EarlyIdtHandlers,
        selector: super::gdt::SegmentSelector,
        use_ist: bool,
    ) -> Self {
        let mut entries = [InterruptGate::missing(); 256];
        for vector in EXCEPTION_VECTOR_RANGE {
            debug_assert!(matches!(classify_vector(vector), VectorClass::Exception));
            let ist = match (use_ist, vector) {
                (true, 2) => Some(InterruptStackIndex::Two),
                (true, 8) => Some(InterruptStackIndex::One),
                (true, 18) => Some(InterruptStackIndex::Three),
                _ => None,
            };
            entries[usize::from(vector)] = InterruptGate::kernel_interrupt(
                handlers.exceptions.handler_for_vector(vector),
                ist,
                selector,
            );
        }
        entries[usize::from(LOCAL_APIC_ERROR_VECTOR)] =
            InterruptGate::kernel_interrupt(handlers.local_apic_error, None, selector);
        entries[usize::from(LOCAL_APIC_SPURIOUS_VECTOR)] =
            InterruptGate::kernel_interrupt(handlers.local_apic_spurious, None, selector);
        Self { entries }
    }

    /// Reports whether the named vector has a present hardware gate.
    #[must_use]
    pub fn is_present(&self, vector: u8) -> bool {
        self.entries[usize::from(vector)].is_present()
    }

    fn pointer(&self) -> DescriptorTablePointer {
        DescriptorTablePointer {
            limit: (size_of::<Self>() - 1) as u16,
            base: (self as *const Self).cast::<()>() as usize as u64,
        }
    }
}

/// Loads Deepwyrm's fully constructed IDT without enabling interrupts.
///
/// # Safety
///
/// The caller must ensure the table and every present handler address are
/// supervisor executable, remain mapped for as long as interrupts or
/// exceptions can occur, and obey the exact normalized-frame/error-code stub
/// convention described by `exceptions.S`. Deepwyrm's GDT and TSS (including
/// #DF/NMI/#MC IST stacks) must already be active, the emergency serial/IDT
/// path must remain usable until this replacement completes, and `IF` must
/// stay clear. This routine neither enables interrupts nor changes stack or
/// privilege state.
#[allow(
    unsafe_code,
    reason = "x86_64 lidt is the narrow, audited descriptor activation boundary"
)]
pub unsafe fn activate(idt: &'static InterruptDescriptorTable) {
    let pointer = idt.pointer();

    // SAFETY: the caller guarantees the IDT lifetime, mappings, and active
    // descriptor context. `lidt` reads exactly the byte-defined ten-byte
    // operand and does not dereference any untrusted data.
    unsafe {
        asm!("lidt [{}]", in(reg) &raw const pointer);
    }
}

/// Rejection of an entry address that cannot be loaded by the locked x86_64
/// kernel mapping policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdtBuildError {
    NonCanonicalHandlerAddress(u64),
}

/// One byte-defined x86_64 long-mode IDT entry.
#[repr(C)]
#[derive(Clone, Copy)]
struct InterruptGate {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attributes: u8,
    offset_middle: u16,
    offset_high: u32,
    reserved: u32,
}

impl InterruptGate {
    const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attributes: 0,
            offset_middle: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    const fn kernel_interrupt(
        handler: HandlerAddress,
        interrupt_stack: Option<InterruptStackIndex>,
        selector: super::gdt::SegmentSelector,
    ) -> Self {
        let address = handler.bits();
        Self {
            offset_low: address as u16,
            selector: selector.bits(),
            ist: match interrupt_stack {
                Some(index) => index.idt_bits(),
                None => 0,
            },
            type_attributes: INTERRUPT_GATE_PRESENT_RING0,
            offset_middle: (address >> 16) as u16,
            offset_high: (address >> 32) as u32,
            reserved: 0,
        }
    }

    const fn is_present(self) -> bool {
        self.type_attributes & 0x80 != 0
    }
}

/// The byte-defined operand consumed by `lidt` in long mode.
#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

const fn is_kernel_handler_address(address: u64) -> bool {
    let high = address >> 48;
    high == 0xffff && address >= 0xffff_8000_0000_0000 && address & 0xf == 0
}

#[cfg(test)]
mod tests {
    use super::super::gdt::SegmentSelector;
    use super::*;
    use crate::interrupt::{EXTERNAL_VECTOR_RANGE, INTERNAL_VECTOR_RANGE, LEGACY_PIC_VECTOR_RANGE};

    const HANDLER: HandlerAddress = match HandlerAddress::new(0xffff_ffff_8000_0100) {
        Ok(address) => address,
        Err(_) => panic!("test handler must be canonical"),
    };

    fn handlers() -> EarlyIdtHandlers {
        EarlyIdtHandlers {
            exceptions: ExceptionHandlerTable::new([HANDLER; EXCEPTION_HANDLER_COUNT]),
            local_apic_error: HANDLER,
            local_apic_spurious: HANDLER,
        }
    }

    #[test]
    fn idt_matches_the_long_mode_hardware_layout() {
        assert_eq!(size_of::<InterruptGate>(), 16);
        assert_eq!(size_of::<InterruptDescriptorTable>(), 4096);
        assert_eq!(size_of::<DescriptorTablePointer>(), 10);
    }

    #[test]
    fn only_approved_early_vectors_have_gates() {
        let idt = InterruptDescriptorTable::new(handlers());
        for vector in EXCEPTION_VECTOR_RANGE {
            assert!(idt.is_present(vector));
        }
        assert!(idt.is_present(LOCAL_APIC_ERROR_VECTOR));
        assert!(idt.is_present(LOCAL_APIC_SPURIOUS_VECTOR));
        for vector in LEGACY_PIC_VECTOR_RANGE {
            assert!(!idt.is_present(vector));
        }
        for vector in EXTERNAL_VECTOR_RANGE {
            assert!(!idt.is_present(vector));
        }
        for vector in INTERNAL_VECTOR_RANGE {
            assert!(!idt.is_present(vector));
        }
    }

    #[test]
    fn handler_addresses_must_be_canonical_for_the_locked_paging_mode() {
        assert!(HandlerAddress::new(0xffff_8000_0000_0000).is_ok());
        assert_eq!(
            HandlerAddress::new(0x0001_0000_0000_0000),
            Err(IdtBuildError::NonCanonicalHandlerAddress(
                0x0001_0000_0000_0000
            ))
        );
        assert_eq!(
            HandlerAddress::new(0x0000_0000_0040_0000),
            Err(IdtBuildError::NonCanonicalHandlerAddress(
                0x0000_0000_0040_0000
            ))
        );
        assert_eq!(
            HandlerAddress::new(0xffff_ffff_8000_0101),
            Err(IdtBuildError::NonCanonicalHandlerAddress(
                0xffff_ffff_8000_0101
            ))
        );
    }

    #[test]
    fn interrupt_gate_is_kernel_only_and_has_no_implicit_ist() {
        let gate = InterruptGate::kernel_interrupt(HANDLER, None, KERNEL_CODE_SELECTOR);
        assert_eq!(gate.selector, KERNEL_CODE_SELECTOR.bits());
        assert_eq!(gate.ist, 0);
        assert_eq!(gate.type_attributes, INTERRUPT_GATE_PRESENT_RING0);
        assert_eq!(gate.reserved, 0);
    }

    #[test]
    fn stack_failure_sensitive_exceptions_use_dedicated_ist_slots() {
        let idt = InterruptDescriptorTable::new(handlers());
        assert_eq!(idt.entries[2].ist, InterruptStackIndex::Two.idt_bits());
        assert_eq!(idt.entries[8].ist, InterruptStackIndex::One.idt_bits());
        assert_eq!(idt.entries[18].ist, InterruptStackIndex::Three.idt_bits());
        assert_eq!(idt.entries[14].ist, 0);
    }

    #[test]
    fn emergency_idt_uses_the_live_selector_without_loader_ist_assumptions() {
        let idt = InterruptDescriptorTable::emergency(handlers(), SegmentSelector::from_bits(0x28));
        assert_eq!(idt.entries[14].selector, 0x28);
        assert_eq!(idt.entries[8].ist, 0);
    }
}
