//! Target-only privileged xAPIC access used by DW0-F3.

use super::apic::{ApicBaseMsrAccess, CpuApicFeatures, LocalApicDiscovery, XApicRegisterAccess};

const IA32_APIC_BASE: u32 = 0x1b;
const IA32_PAT: u32 = 0x277;
const PAT_UNCACHEABLE: u8 = 0;
const CPUID_EXTENDED_MAX: u32 = 0x8000_0000;
const CPUID_ADDRESS_WIDTHS: u32 = 0x8000_0008;
const PAGE_SIZE: u64 = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveApicAccessError {
    UnsupportedCpuid,
    InvalidMmioBase,
    InvalidRegisterOffset,
}

pub(crate) struct LiveApicBaseMsr;

#[allow(
    unsafe_code,
    reason = "F3 target APIC discovery reads the architectural IA32_APIC_BASE MSR at CPL0"
)]
impl ApicBaseMsrAccess for LiveApicBaseMsr {
    type Error = LiveApicAccessError;

    fn read_apic_base(&mut self) -> Result<u64, Self::Error> {
        Ok(unsafe { read_msr(IA32_APIC_BASE) })
    }

    fn write_apic_base(&mut self, value: u64) -> Result<(), Self::Error> {
        unsafe { write_msr(IA32_APIC_BASE, value) };
        Ok(())
    }
}

pub(crate) struct LiveXApicMmio {
    base: u64,
}

impl LiveXApicMmio {
    pub(crate) const fn new(base: u64) -> Result<Self, LiveApicAccessError> {
        if base < 0xffff_8000_0000_0000 || !base.is_multiple_of(PAGE_SIZE) {
            return Err(LiveApicAccessError::InvalidMmioBase);
        }
        Ok(Self { base })
    }

    fn address(&self, offset: u32) -> Result<*mut u32, LiveApicAccessError> {
        if offset >= PAGE_SIZE as u32 || !offset.is_multiple_of(16) {
            return Err(LiveApicAccessError::InvalidRegisterOffset);
        }
        Ok((self.base + u64::from(offset)) as *mut u32)
    }
}

#[allow(
    unsafe_code,
    reason = "the F3 permanent UC xAPIC mapping is accessed only with aligned volatile 32-bit architectural register operations"
)]
impl XApicRegisterAccess for LiveXApicMmio {
    type Error = LiveApicAccessError;

    fn read(&mut self, offset: u32) -> Result<u32, Self::Error> {
        let address = self.address(offset)?;
        Ok(unsafe { core::ptr::read_volatile(address.cast_const()) })
    }

    fn write(&mut self, offset: u32, value: u32) -> Result<(), Self::Error> {
        let address = self.address(offset)?;
        unsafe { core::ptr::write_volatile(address, value) };
        Ok(())
    }
}

/// Proves that the PAT entry selected by a 4 KiB PTE with PWT=1, PCD=1, PAT=0
/// is architecturally UC before F3 publishes the permanent LAPIC mapping.
///
/// C2 has already proved PAT support before this target-only helper may run.
#[allow(
    unsafe_code,
    reason = "C2 has proved PAT support before F3 reads IA32_PAT to validate the selected UC entry"
)]
pub(crate) fn lapic_pat_entry_is_uncacheable() -> bool {
    let pat = unsafe { read_msr(IA32_PAT) };
    ((pat >> 24) as u8) == PAT_UNCACHEABLE
}

pub(crate) fn discover_local_apic() -> Result<LocalApicDiscovery, LiveApicAccessError> {
    let max = cpuid(CPUID_EXTENDED_MAX);
    if max.eax < CPUID_ADDRESS_WIDTHS {
        return Err(LiveApicAccessError::UnsupportedCpuid);
    }
    let leaf1 = cpuid(1);
    let widths = cpuid(CPUID_ADDRESS_WIDTHS);
    let features = CpuApicFeatures::from_cpuid_leaf1(leaf1.ecx, leaf1.edx);
    let physical_bits = widths.eax as u8;
    let raw_base = LiveApicBaseMsr.read_apic_base()?;
    LocalApicDiscovery::from_registers(features, raw_base, physical_bits)
        .map_err(|_| LiveApicAccessError::UnsupportedCpuid)
}

#[derive(Clone, Copy)]
struct CpuidResult {
    eax: u32,
    ecx: u32,
    edx: u32,
}

fn cpuid(leaf: u32) -> CpuidResult {
    let result = core::arch::x86_64::__cpuid(leaf);
    CpuidResult {
        eax: result.eax,
        ecx: result.ecx,
        edx: result.edx,
    }
}

#[allow(
    unsafe_code,
    reason = "privileged target helper performs one fixed MSR read for local-APIC discovery"
)]
unsafe fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags),
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

#[allow(
    unsafe_code,
    reason = "privileged target helper writes only IA32_APIC_BASE through the validated LocalApic state machine"
)]
unsafe fn write_msr(msr: u32, value: u64) {
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nostack, preserves_flags),
        );
    }
}
