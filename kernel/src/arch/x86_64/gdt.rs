//! x86_64 Global Descriptor Table construction and activation.
//!
//! The loader's descriptor state is never reused as Deepwyrm policy. The
//! activation routine replaces it using the already-established kernel stack
//! and leaves interrupt enablement to the entry path.

use core::arch::asm;
use core::mem::size_of;

use super::tss::TaskStateSegment;

/// Deepwyrm's long-mode kernel code selector.
pub const KERNEL_CODE_SELECTOR: SegmentSelector = SegmentSelector(0x08);
/// Deepwyrm's long-mode kernel data selector.
pub const KERNEL_DATA_SELECTOR: SegmentSelector = SegmentSelector(0x10);
/// Deepwyrm's available 64-bit TSS selector.
pub const KERNEL_TSS_SELECTOR: SegmentSelector = SegmentSelector(0x18);
/// DW0-E user writable-data selector (GDT index 5, RPL3).
pub const USER_DATA_SELECTOR: SegmentSelector = SegmentSelector(0x2b);
/// DW0-E user long-mode code selector (GDT index 6, RPL3).
pub const USER_CODE_SELECTOR: SegmentSelector = SegmentSelector(0x33);
pub(crate) const GDT_HARDWARE_LIMIT: u16 = (7 * size_of::<u64>() - 1) as u16;

/// A selector in Deepwyrm's private GDT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct SegmentSelector(u16);

impl SegmentSelector {
    #[cfg_attr(not(any(test, target_os = "none")), allow(dead_code))]
    pub(crate) const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }
    pub(crate) const fn bits(self) -> u16 {
        self.0
    }
}

/// Global descriptor table containing null, kernel code/data, one TSS, and DW0-E user data/code.
#[repr(C, align(16))]
pub struct GlobalDescriptorTable {
    entries: [u64; 7],
}

impl GlobalDescriptorTable {
    /// Builds the complete Deepwyrm long-mode descriptor table.
    pub fn new(tss: &TaskStateSegment) -> Self {
        let tss_address = (tss as *const TaskStateSegment).cast::<()>() as usize as u64;
        let (tss_low, tss_high) = tss_descriptor(tss_address, size_of::<TaskStateSegment>() - 1);
        Self {
            entries: [
                0,
                kernel_code_descriptor(),
                kernel_data_descriptor(),
                tss_low,
                tss_high,
                user_data_descriptor(),
                user_code_descriptor(),
            ],
        }
    }

    fn pointer(&self) -> DescriptorTablePointer {
        DescriptorTablePointer {
            limit: GDT_HARDWARE_LIMIT,
            base: (self as *const Self).cast::<()>() as usize as u64,
        }
    }
}

/// Loads Deepwyrm's GDT, reloads every usable segment selector, and activates
/// the supplied TSS.
///
/// # Safety
///
/// The caller must ensure `gdt` and its referenced TSS are mapped for the
/// lifetime of the processor state, `RSP` names the established writable
/// kernel stack, and interrupts remain disabled throughout the transition.
/// The routine performs no allocation and makes no loader-descriptor or TLS
/// assumptions.
#[allow(
    unsafe_code,
    reason = "x86_64 lgdt, selector reload, and ltr are the audited descriptor activation boundary"
)]
pub unsafe fn activate(gdt: &'static GlobalDescriptorTable) {
    let pointer = gdt.pointer();

    // SAFETY: the caller guarantees descriptor and TSS lifetime/mapping and
    // supplies the established kernel stack. The sequence reloads CS through
    // a local far return before using the new data selectors, then loads the
    // TSS selector owned by this GDT. It does not enable interrupts.
    unsafe {
        asm!(
            "lgdt [{gdt_pointer}]",
            "push {code_selector}",
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            "mov ax, {data_selector}",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            "mov ax, 0",
            "mov fs, ax",
            "mov gs, ax",
            "mov ax, {tss_selector}",
            "ltr ax",
            gdt_pointer = in(reg) &raw const pointer,
            code_selector = const KERNEL_CODE_SELECTOR.bits(),
            data_selector = const KERNEL_DATA_SELECTOR.bits(),
            tss_selector = const KERNEL_TSS_SELECTOR.bits(),
            out("rax") _,
        );
    }
}

/// The byte-defined operand expected by `lgdt` in 64-bit mode.
#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

const fn kernel_code_descriptor() -> u64 {
    // Present, ring 0, executable/readable code, long mode, 4 KiB granularity.
    0x00af_9a00_0000_ffff
}

const fn user_data_descriptor() -> u64 {
    // Present, ring 3, writable data. RPL is supplied by the selector.
    0x00cf_f200_0000_ffff
}

const fn user_code_descriptor() -> u64 {
    // Present, ring 3, executable/readable 64-bit code.
    0x00af_fa00_0000_ffff
}

const fn kernel_data_descriptor() -> u64 {
    // Present, ring 0, writable data. L is reserved for data descriptors;
    // D/B is set for conventional compatibility-mode behavior.
    0x00cf_9200_0000_ffff
}

const fn tss_descriptor(base: u64, limit: usize) -> (u64, u64) {
    let limit = limit as u64;
    let low = (limit & 0xffff)
        | ((base & 0x00ff_ffff) << 16)
        | (0x89_u64 << 40)
        | ((limit & 0x000f_0000) << 32)
        | ((base & 0xff00_0000) << 32);
    (low, base >> 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_table_pointer_has_the_hardware_size() {
        assert_eq!(size_of::<DescriptorTablePointer>(), 10);
    }

    #[test]
    fn private_selectors_name_the_expected_gdt_entries() {
        assert_eq!(KERNEL_CODE_SELECTOR.bits(), 0x08);
        assert_eq!(KERNEL_DATA_SELECTOR.bits(), 0x10);
        assert_eq!(KERNEL_TSS_SELECTOR.bits(), 0x18);
        assert_eq!(USER_DATA_SELECTOR.bits(), 0x2b);
        assert_eq!(USER_CODE_SELECTOR.bits(), 0x33);
    }

    #[test]
    fn user_descriptors_are_exact_dpl3_long_mode_contract() {
        let tss = TaskStateSegment::empty();
        let gdt = GlobalDescriptorTable::new(&tss);
        assert_eq!(gdt.entries[5], 0x00cf_f200_0000_ffff);
        assert_eq!(gdt.entries[6], 0x00af_fa00_0000_ffff);
        let pointer = gdt.pointer();
        let limit = pointer.limit;
        assert_eq!(limit, GDT_HARDWARE_LIMIT);
        assert_eq!(GDT_HARDWARE_LIMIT, 55);
    }

    #[test]
    fn tss_descriptor_preserves_all_address_bits_and_limit_bits() {
        let base = 0x0123_4567_89ab_cdef;
        let limit = 0x0f_fff;
        let (low, high) = tss_descriptor(base, limit);
        assert_eq!(low & 0xffff, limit as u64 & 0xffff);
        assert_eq!((low >> 16) & 0x00ff_ffff, base & 0x00ff_ffff);
        assert_eq!((low >> 32) & 0xff00_0000, base & 0xff00_0000);
        assert_eq!(high, base >> 32);
        assert_eq!((low >> 40) & 0xff, 0x89);
        assert_eq!((low >> 48) & 0x0f, (limit as u64 >> 16) & 0x0f);
    }
}
