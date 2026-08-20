#[path = "../src/arch/x86_64/apic.rs"]
mod apic;
#[path = "../src/interrupt/mod.rs"]
mod interrupt;

use apic::{
    ApicBaseMsrAccess, ApicDiscoveryError, ApicMode, CpuApicFeatures, LocalApic,
    LocalApicDiscovery, LocalApicError, XApicRegisterAccess,
};
use interrupt::{
    ControllerState, EXCEPTION_VECTOR_RANGE, EXTERNAL_VECTOR_RANGE, INTERNAL_VECTOR_RANGE,
    LEGACY_PIC_VECTOR_RANGE, LocalApicVectors, VectorClass, VectorLayoutError, classify_vector,
};

const APIC_PRESENT: u32 = 1 << 9;
const X2APIC_PRESENT: u32 = 1 << 21;
const APIC_BASE: u64 = 0xfee0_0000;
const APIC_ENABLED: u64 = 1 << 11;
const APIC_BSP: u64 = 1 << 8;
const APIC_X2_ENABLED: u64 = 1 << 10;

const APIC_ID: u32 = 0x020;
const APIC_VERSION: u32 = 0x030;
const APIC_TASK_PRIORITY: u32 = 0x080;
const APIC_EOI: u32 = 0x0b0;
const APIC_SPURIOUS: u32 = 0x0f0;
const APIC_ERROR_STATUS: u32 = 0x280;
const APIC_LVT_TIMER: u32 = 0x320;
const APIC_LVT_THERMAL: u32 = 0x330;
const APIC_LVT_PERFORMANCE: u32 = 0x340;
const APIC_LVT_LINT0: u32 = 0x350;
const APIC_LVT_LINT1: u32 = 0x360;
const APIC_LVT_ERROR: u32 = 0x370;
const APIC_TIMER_INITIAL_COUNT: u32 = 0x380;
const APIC_TIMER_CURRENT_COUNT: u32 = 0x390;
const APIC_TIMER_DIVIDE_CONFIG: u32 = 0x3e0;
const LVT_MASKED: u32 = 1 << 16;

#[test]
fn vector_policy_covers_the_entire_idt_without_overlap() {
    assert_eq!(EXCEPTION_VECTOR_RANGE, 0x00..=0x1f);
    assert_eq!(LEGACY_PIC_VECTOR_RANGE, 0x20..=0x2f);
    assert_eq!(EXTERNAL_VECTOR_RANGE, 0x30..=0xdf);
    assert_eq!(INTERNAL_VECTOR_RANGE, 0xe0..=0xfd);

    let expected = [
        (0x00, VectorClass::Exception),
        (0x1f, VectorClass::Exception),
        (0x20, VectorClass::LegacyPicReserved),
        (0x2f, VectorClass::LegacyPicReserved),
        (0x30, VectorClass::ExternalUnallocated),
        (0xdf, VectorClass::ExternalUnallocated),
        (0xe0, VectorClass::LocalApicTimer),
        (0xfd, VectorClass::InternalReserved),
        (0xfe, VectorClass::LocalApicError),
        (0xff, VectorClass::LocalApicSpurious),
    ];
    for (vector, class) in expected {
        assert_eq!(classify_vector(vector), class);
    }

    assert_eq!(
        LocalApicVectors::new(0xe0, 0xfd, 0xff),
        Err(VectorLayoutError::ErrorVectorOutsidePolicy)
    );
    assert_eq!(
        LocalApicVectors::new(0xe0, 0xfe, 0xfd),
        Err(VectorLayoutError::SpuriousVectorOutsidePolicy)
    );
    assert_eq!(
        LocalApicVectors::new(0xe0, 0xff, 0xff),
        Err(VectorLayoutError::DuplicateLocalApicVector)
    );
    assert_eq!(
        LocalApicVectors::new(0xe0, 0xfe, 0xff),
        Ok(LocalApicVectors::DW0)
    );
}

#[test]
fn discovery_decodes_cpuid_and_apic_base_state() {
    let features = CpuApicFeatures::from_cpuid_leaf1(X2APIC_PRESENT, APIC_PRESENT);
    let discovery =
        LocalApicDiscovery::from_registers(features, APIC_BASE | APIC_ENABLED | APIC_BSP, 48)
            .expect("valid xAPIC discovery");

    assert_eq!(discovery.physical_base(), APIC_BASE);
    assert_eq!(discovery.mode(), ApicMode::XApic);
    assert!(discovery.is_bootstrap_processor());
    assert!(discovery.x2apic_available());
}

#[test]
fn discovery_rejects_inconsistent_or_reserved_hardware_state() {
    let no_apic = CpuApicFeatures::from_cpuid_leaf1(0, 0);
    assert_eq!(
        LocalApicDiscovery::from_registers(no_apic, APIC_BASE | APIC_ENABLED, 48),
        Err(ApicDiscoveryError::MissingLocalApicFeature)
    );

    let apic_only = CpuApicFeatures::from_cpuid_leaf1(0, APIC_PRESENT);
    assert_eq!(
        LocalApicDiscovery::from_registers(apic_only, APIC_BASE | APIC_X2_ENABLED, 48),
        Err(ApicDiscoveryError::X2ApicWithoutGlobalEnable)
    );
    assert_eq!(
        LocalApicDiscovery::from_registers(
            apic_only,
            APIC_BASE | APIC_ENABLED | APIC_X2_ENABLED,
            48,
        ),
        Err(ApicDiscoveryError::X2ApicWithoutCpuSupport)
    );
    assert!(matches!(
        LocalApicDiscovery::from_registers(apic_only, APIC_BASE | APIC_ENABLED | 1, 48),
        Err(ApicDiscoveryError::ReservedApicBaseBits(1))
    ));
}

#[test]
fn disabled_xapic_is_enabled_without_selecting_x2apic() {
    let discovery = discovery(ApicMode::Disabled);
    let mut apic = LocalApic::discovered(discovery, LocalApicVectors::DW0);
    let mut msr = FakeMsr::default();

    apic.enable_xapic(&mut msr).expect("enable xAPIC");

    assert_eq!(msr.writes, vec![APIC_BASE | APIC_ENABLED]);
    assert_eq!(apic.discovery().mode(), ApicMode::XApic);
    assert_eq!(apic.state(), ControllerState::Discovered);
}

#[test]
fn failed_apic_base_readback_faults_the_controller() {
    let discovery = discovery(ApicMode::Disabled);
    let mut apic = LocalApic::discovered(discovery, LocalApicVectors::DW0);
    let mut msr = FakeMsr {
        latch_writes: false,
        ..FakeMsr::default()
    };

    assert_eq!(
        apic.enable_xapic(&mut msr),
        Err(LocalApicError::ApicBaseEnableNotLatched {
            observed: APIC_BASE,
        })
    );
    assert_eq!(apic.state(), ControllerState::Faulted);
}

#[test]
fn prepare_masks_every_dw0_b_source_before_online_transition() {
    let mut apic = LocalApic::discovered(discovery(ApicMode::XApic), LocalApicVectors::DW0);
    let mut registers = FakeRegisters::new();

    apic.prepare(&mut registers).expect("prepare local APIC");

    assert_eq!(apic.state(), ControllerState::Prepared);
    assert_eq!(apic.apic_id(), Some(0x2a));
    assert_eq!(apic.version().expect("version").maximum_lvt_entry, 5);
    assert_eq!(registers.value(APIC_TASK_PRIORITY), Some(0));
    assert_eq!(registers.value(APIC_LVT_TIMER), Some(LVT_MASKED | 0xe0));
    for offset in [
        APIC_LVT_THERMAL,
        APIC_LVT_PERFORMANCE,
        APIC_LVT_LINT0,
        APIC_LVT_LINT1,
    ] {
        assert_eq!(registers.value(offset), Some(LVT_MASKED));
    }
    assert_eq!(registers.value(APIC_LVT_ERROR), Some(LVT_MASKED | 0xfe));
    assert_eq!(registers.value(APIC_SPURIOUS), None);
}

#[test]
fn online_transition_enables_only_error_and_spurious_vectors() {
    let mut apic = LocalApic::discovered(discovery(ApicMode::XApic), LocalApicVectors::DW0);
    let mut registers = FakeRegisters::new();
    apic.prepare(&mut registers).expect("prepare local APIC");

    apic.bring_online(&mut registers)
        .expect("bring local APIC online");

    assert_eq!(apic.state(), ControllerState::Online);
    assert_eq!(registers.value(APIC_LVT_ERROR), Some(0xfe));
    assert_eq!(registers.value(APIC_SPURIOUS), Some((1 << 8) | 0xff));
    assert_eq!(registers.value(APIC_LVT_TIMER), Some(LVT_MASKED | 0xe0));
    for offset in [
        APIC_LVT_THERMAL,
        APIC_LVT_PERFORMANCE,
        APIC_LVT_LINT0,
        APIC_LVT_LINT1,
    ] {
        assert_eq!(registers.value(offset), Some(LVT_MASKED));
    }

    apic.end_of_interrupt(&mut registers).expect("EOI online");
    assert_eq!(registers.value(APIC_EOI), Some(0));
}

#[test]
fn one_shot_timer_programming_keeps_calibration_masked_and_rejects_zero() {
    let mut apic = LocalApic::discovered(discovery(ApicMode::XApic), LocalApicVectors::DW0);
    let mut registers = FakeRegisters::new();
    apic.prepare(&mut registers).unwrap();
    apic.bring_online(&mut registers).unwrap();
    apic.configure_one_shot_timer(&mut registers).unwrap();
    assert_eq!(registers.value(APIC_TIMER_DIVIDE_CONFIG), Some(0x3));
    assert_eq!(registers.value(APIC_LVT_TIMER), Some(LVT_MASKED | 0xe0));
    assert_eq!(registers.value(APIC_TIMER_INITIAL_COUNT), Some(0));
    assert_eq!(
        apic.start_timer_calibration(&mut registers, 0),
        Err(LocalApicError::ZeroTimerCount)
    );
    apic.start_timer_calibration(&mut registers, u32::MAX)
        .unwrap();
    assert_eq!(registers.value(APIC_LVT_TIMER), Some(LVT_MASKED | 0xe0));
    registers
        .values
        .insert(APIC_TIMER_CURRENT_COUNT, 0xf000_0000);
    assert_eq!(
        apic.timer_current_count(&mut registers).unwrap(),
        0xf000_0000
    );
    apic.program_one_shot_timer(&mut registers, 1234).unwrap();
    assert_eq!(registers.value(APIC_LVT_TIMER), Some(0xe0));
    assert_eq!(registers.value(APIC_TIMER_INITIAL_COUNT), Some(1234));
    apic.stop_timer(&mut registers).unwrap();
    assert_eq!(registers.value(APIC_LVT_TIMER), Some(LVT_MASKED | 0xe0));
}

#[test]
fn access_failure_faults_controller_and_prevents_unsafe_retry() {
    let mut apic = LocalApic::discovered(discovery(ApicMode::XApic), LocalApicVectors::DW0);
    let mut registers = FakeRegisters::new();
    registers.fail_after = Some(3);

    assert_eq!(
        apic.prepare(&mut registers),
        Err(LocalApicError::Access("injected access failure"))
    );
    assert_eq!(apic.state(), ControllerState::Faulted);
    assert!(matches!(
        apic.prepare(&mut registers),
        Err(LocalApicError::InvalidState(_))
    ));
}

#[test]
fn x2apic_is_discovered_but_not_silently_used_by_dw0_b() {
    let mut apic = LocalApic::discovered(discovery(ApicMode::X2Apic), LocalApicVectors::DW0);
    let mut msr = FakeMsr::default();
    let mut registers = FakeRegisters::new();

    assert_eq!(
        apic.enable_xapic(&mut msr),
        Err(LocalApicError::X2ApicModeUnsupported)
    );
    assert_eq!(
        apic.prepare(&mut registers),
        Err(LocalApicError::X2ApicModeUnsupported)
    );
    assert_eq!(apic.state(), ControllerState::Discovered);
    assert!(msr.writes.is_empty());
    assert_eq!(registers.operation_count, 0);
}

fn discovery(mode: ApicMode) -> LocalApicDiscovery {
    let mut raw = APIC_BASE;
    let features = match mode {
        ApicMode::Disabled => CpuApicFeatures::from_cpuid_leaf1(0, APIC_PRESENT),
        ApicMode::XApic => {
            raw |= APIC_ENABLED;
            CpuApicFeatures::from_cpuid_leaf1(0, APIC_PRESENT)
        }
        ApicMode::X2Apic => {
            raw |= APIC_ENABLED | APIC_X2_ENABLED;
            CpuApicFeatures::from_cpuid_leaf1(X2APIC_PRESENT, APIC_PRESENT)
        }
    };
    LocalApicDiscovery::from_registers(features, raw, 48).expect("test discovery")
}

struct FakeMsr {
    writes: Vec<u64>,
    value: u64,
    latch_writes: bool,
}

impl Default for FakeMsr {
    fn default() -> Self {
        Self {
            writes: Vec::new(),
            value: APIC_BASE,
            latch_writes: true,
        }
    }
}

impl ApicBaseMsrAccess for FakeMsr {
    type Error = &'static str;

    fn read_apic_base(&mut self) -> Result<u64, Self::Error> {
        Ok(self.value)
    }

    fn write_apic_base(&mut self, value: u64) -> Result<(), Self::Error> {
        self.writes.push(value);
        if self.latch_writes {
            self.value = value;
        }
        Ok(())
    }
}

struct FakeRegisters {
    values: std::collections::BTreeMap<u32, u32>,
    operation_count: usize,
    fail_after: Option<usize>,
}

impl FakeRegisters {
    fn new() -> Self {
        let mut values = std::collections::BTreeMap::new();
        values.insert(APIC_ID, 0x2a00_0000);
        values.insert(APIC_VERSION, 0x0005_0014);
        values.insert(APIC_ERROR_STATUS, 0);
        Self {
            values,
            operation_count: 0,
            fail_after: None,
        }
    }

    fn value(&self, offset: u32) -> Option<u32> {
        self.values.get(&offset).copied()
    }

    fn before_operation(&mut self) -> Result<(), &'static str> {
        self.operation_count += 1;
        if self.fail_after == Some(self.operation_count) {
            return Err("injected access failure");
        }
        Ok(())
    }
}

impl XApicRegisterAccess for FakeRegisters {
    type Error = &'static str;

    fn read(&mut self, offset: u32) -> Result<u32, Self::Error> {
        self.before_operation()?;
        Ok(self.values.get(&offset).copied().unwrap_or(0))
    }

    fn write(&mut self, offset: u32, value: u32) -> Result<(), Self::Error> {
        self.before_operation()?;
        self.values.insert(offset, value);
        Ok(())
    }
}
