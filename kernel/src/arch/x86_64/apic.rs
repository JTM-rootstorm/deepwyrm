//! x86_64 local-APIC discovery and bounded DW0-B bring-up.
//!
//! This module never executes `CPUID`, `RDMSR`, `WRMSR`, or MMIO itself.
//! Architecture entry code supplies captured register values and an access
//! implementation only after establishing the privilege level, mapping, and
//! volatile-access invariants documented by the traits below. This keeps the
//! unsafe hardware boundary out of the pure state and validation logic.

use crate::interrupt::{
    ControllerState, ControllerStateMachine, InvalidControllerTransition, LocalApicVectors,
};

const CPUID_LEAF1_ECX_X2APIC: u32 = 1 << 21;
const CPUID_LEAF1_EDX_APIC: u32 = 1 << 9;

const IA32_APIC_BASE_BSP: u64 = 1 << 8;
const IA32_APIC_BASE_X2APIC_ENABLE: u64 = 1 << 10;
const IA32_APIC_BASE_GLOBAL_ENABLE: u64 = 1 << 11;
const IA32_APIC_BASE_ADDRESS_MASK_52BIT: u64 = 0x000f_ffff_ffff_f000;
const IA32_APIC_BASE_CONTROL_MASK: u64 =
    IA32_APIC_BASE_BSP | IA32_APIC_BASE_X2APIC_ENABLE | IA32_APIC_BASE_GLOBAL_ENABLE;

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

const APIC_LVT_MASKED: u32 = 1 << 16;
const APIC_SOFTWARE_ENABLE: u32 = 1 << 8;
const MINIMUM_DW0_LVT_MAX_ENTRY: u8 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuApicFeatures {
    pub local_apic: bool,
    pub x2apic: bool,
}

impl CpuApicFeatures {
    #[must_use]
    pub const fn from_cpuid_leaf1(ecx: u32, edx: u32) -> Self {
        Self {
            local_apic: edx & CPUID_LEAF1_EDX_APIC != 0,
            x2apic: ecx & CPUID_LEAF1_ECX_X2APIC != 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApicMode {
    Disabled,
    XApic,
    X2Apic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApicDiscoveryError {
    InvalidPhysicalAddressWidth(u8),
    ReservedApicBaseBits(u64),
    MissingLocalApicFeature,
    InvalidApicBase,
    X2ApicWithoutGlobalEnable,
    X2ApicWithoutCpuSupport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalApicDiscovery {
    base_msr: u64,
    physical_base: u64,
    mode: ApicMode,
    bootstrap_processor: bool,
    x2apic_available: bool,
}

impl LocalApicDiscovery {
    pub fn from_registers(
        features: CpuApicFeatures,
        apic_base_msr: u64,
        physical_address_bits: u8,
    ) -> Result<Self, ApicDiscoveryError> {
        if !features.local_apic {
            return Err(ApicDiscoveryError::MissingLocalApicFeature);
        }
        if !(12..=52).contains(&physical_address_bits) {
            return Err(ApicDiscoveryError::InvalidPhysicalAddressWidth(
                physical_address_bits,
            ));
        }

        let address_mask = physical_address_mask(physical_address_bits);
        let allowed = address_mask | IA32_APIC_BASE_CONTROL_MASK;
        let reserved = apic_base_msr & !allowed;
        if reserved != 0 {
            return Err(ApicDiscoveryError::ReservedApicBaseBits(reserved));
        }

        let physical_base = apic_base_msr & address_mask;
        if physical_base == 0 {
            return Err(ApicDiscoveryError::InvalidApicBase);
        }

        let enabled = apic_base_msr & IA32_APIC_BASE_GLOBAL_ENABLE != 0;
        let x2_enabled = apic_base_msr & IA32_APIC_BASE_X2APIC_ENABLE != 0;
        if x2_enabled && !enabled {
            return Err(ApicDiscoveryError::X2ApicWithoutGlobalEnable);
        }
        if x2_enabled && !features.x2apic {
            return Err(ApicDiscoveryError::X2ApicWithoutCpuSupport);
        }

        let mode = if x2_enabled {
            ApicMode::X2Apic
        } else if enabled {
            ApicMode::XApic
        } else {
            ApicMode::Disabled
        };

        Ok(Self {
            base_msr: apic_base_msr,
            physical_base,
            mode,
            bootstrap_processor: apic_base_msr & IA32_APIC_BASE_BSP != 0,
            x2apic_available: features.x2apic,
        })
    }

    #[must_use]
    pub const fn physical_base(self) -> u64 {
        self.physical_base
    }

    #[must_use]
    pub const fn mode(self) -> ApicMode {
        self.mode
    }

    #[must_use]
    pub const fn is_bootstrap_processor(self) -> bool {
        self.bootstrap_processor
    }

    #[must_use]
    pub const fn x2apic_available(self) -> bool {
        self.x2apic_available
    }
}

const fn physical_address_mask(bits: u8) -> u64 {
    let width_mask = if bits == 64 {
        u64::MAX
    } else {
        (1_u64 << bits) - 1
    };
    width_mask & IA32_APIC_BASE_ADDRESS_MASK_52BIT
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalApicVersion {
    pub version: u8,
    pub maximum_lvt_entry: u8,
    pub eoi_broadcast_suppression: bool,
}

impl LocalApicVersion {
    #[must_use]
    pub const fn decode(raw: u32) -> Self {
        Self {
            version: raw as u8,
            maximum_lvt_entry: (raw >> 16) as u8,
            eoi_broadcast_suppression: raw & (1 << 24) != 0,
        }
    }
}

/// Access to the IA32_APIC_BASE MSR from an already privileged CPU context.
///
/// Implementations are responsible for containing any `RDMSR`/`WRMSR` unsafe
/// code, verifying execution at CPL0, and ensuring the operation applies to the
/// CPU represented by the associated [`LocalApic`].
pub trait ApicBaseMsrAccess {
    type Error;

    fn read_apic_base(&mut self) -> Result<u64, Self::Error>;
    fn write_apic_base(&mut self, value: u64) -> Result<(), Self::Error>;
}

/// Volatile xAPIC register access through an established uncached MMIO mapping.
///
/// Implementations must contain the unsafe pointer/volatile operations and
/// guarantee that the mapping covers the local-APIC page discovered for this
/// CPU. Offsets supplied by this module are aligned architectural registers.
pub trait XApicRegisterAccess {
    type Error;

    fn read(&mut self, offset: u32) -> Result<u32, Self::Error>;
    fn write(&mut self, offset: u32, value: u32) -> Result<(), Self::Error>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum LocalApicError<E> {
    InvalidState(InvalidControllerTransition),
    LocalApicDisabled,
    X2ApicModeUnsupported,
    ApicBaseEnableNotLatched { observed: u64 },
    InsufficientLvtEntries { observed: u8, required: u8 },
    Access(E),
}

/// Per-CPU local-APIC bring-up state.
pub struct LocalApic {
    discovery: LocalApicDiscovery,
    vectors: LocalApicVectors,
    state: ControllerStateMachine,
    apic_id: Option<u8>,
    version: Option<LocalApicVersion>,
}

impl LocalApic {
    #[must_use]
    pub fn discovered(discovery: LocalApicDiscovery, vectors: LocalApicVectors) -> Self {
        let mut state = ControllerStateMachine::new();
        // A newly-created machine is known to be Offline, so this cannot fail.
        let _ = state.mark_discovered();
        Self {
            discovery,
            vectors,
            state,
            apic_id: None,
            version: None,
        }
    }

    #[must_use]
    pub const fn state(&self) -> ControllerState {
        self.state.state()
    }

    #[must_use]
    pub const fn discovery(&self) -> LocalApicDiscovery {
        self.discovery
    }

    #[must_use]
    pub const fn apic_id(&self) -> Option<u8> {
        self.apic_id
    }

    #[must_use]
    pub const fn version(&self) -> Option<LocalApicVersion> {
        self.version
    }

    pub fn enable_xapic<M: ApicBaseMsrAccess>(
        &mut self,
        msr: &mut M,
    ) -> Result<(), LocalApicError<M::Error>> {
        self.require_state(ControllerState::Discovered)?;
        match self.discovery.mode {
            ApicMode::XApic => Ok(()),
            ApicMode::X2Apic => Err(LocalApicError::X2ApicModeUnsupported),
            ApicMode::Disabled => {
                let enabled = (self.discovery.base_msr | IA32_APIC_BASE_GLOBAL_ENABLE)
                    & !IA32_APIC_BASE_X2APIC_ENABLE;
                if let Err(error) = msr.write_apic_base(enabled) {
                    self.state.mark_faulted();
                    return Err(LocalApicError::Access(error));
                }
                let observed = match msr.read_apic_base() {
                    Ok(observed) => observed,
                    Err(error) => {
                        self.state.mark_faulted();
                        return Err(LocalApicError::Access(error));
                    }
                };
                let observed_base = observed & IA32_APIC_BASE_ADDRESS_MASK_52BIT;
                if observed & IA32_APIC_BASE_GLOBAL_ENABLE == 0
                    || observed & IA32_APIC_BASE_X2APIC_ENABLE != 0
                    || observed_base != self.discovery.physical_base
                {
                    self.state.mark_faulted();
                    return Err(LocalApicError::ApicBaseEnableNotLatched { observed });
                }
                self.discovery.base_msr = observed;
                self.discovery.mode = ApicMode::XApic;
                Ok(())
            }
        }
    }

    /// Mask all DW0-B LVT sources and capture controller identity/version.
    ///
    /// The local APIC remains software-disabled until [`Self::bring_online`],
    /// allowing the descriptor-table lane to install the approved vectors first.
    pub fn prepare<R: XApicRegisterAccess>(
        &mut self,
        registers: &mut R,
    ) -> Result<(), LocalApicError<R::Error>> {
        self.require_state(ControllerState::Discovered)?;
        match self.discovery.mode {
            ApicMode::XApic => {}
            ApicMode::Disabled => return Err(LocalApicError::LocalApicDisabled),
            ApicMode::X2Apic => return Err(LocalApicError::X2ApicModeUnsupported),
        }

        let result = self.prepare_inner(registers);
        if result.is_err() {
            self.state.mark_faulted();
        }
        result
    }

    fn prepare_inner<R: XApicRegisterAccess>(
        &mut self,
        registers: &mut R,
    ) -> Result<(), LocalApicError<R::Error>> {
        let raw_id = registers.read(APIC_ID).map_err(LocalApicError::Access)?;
        let version = LocalApicVersion::decode(
            registers
                .read(APIC_VERSION)
                .map_err(LocalApicError::Access)?,
        );
        if version.maximum_lvt_entry < MINIMUM_DW0_LVT_MAX_ENTRY {
            return Err(LocalApicError::InsufficientLvtEntries {
                observed: version.maximum_lvt_entry,
                required: MINIMUM_DW0_LVT_MAX_ENTRY,
            });
        }

        registers
            .write(APIC_TASK_PRIORITY, 0)
            .map_err(LocalApicError::Access)?;
        for offset in [
            APIC_LVT_TIMER,
            APIC_LVT_THERMAL,
            APIC_LVT_PERFORMANCE,
            APIC_LVT_LINT0,
            APIC_LVT_LINT1,
        ] {
            registers
                .write(offset, APIC_LVT_MASKED)
                .map_err(LocalApicError::Access)?;
        }
        registers
            .write(
                APIC_LVT_ERROR,
                APIC_LVT_MASKED | u32::from(self.vectors.error()),
            )
            .map_err(LocalApicError::Access)?;
        registers
            .write(APIC_ERROR_STATUS, 0)
            .map_err(LocalApicError::Access)?;
        let _ = registers
            .read(APIC_ERROR_STATUS)
            .map_err(LocalApicError::Access)?;

        self.apic_id = Some((raw_id >> 24) as u8);
        self.version = Some(version);
        self.state
            .mark_prepared()
            .map_err(LocalApicError::InvalidState)
    }

    /// Unmask only the local-APIC error vector and software-enable the APIC.
    pub fn bring_online<R: XApicRegisterAccess>(
        &mut self,
        registers: &mut R,
    ) -> Result<(), LocalApicError<R::Error>> {
        self.require_state(ControllerState::Prepared)?;
        let result = self.bring_online_inner(registers);
        if result.is_err() {
            self.state.mark_faulted();
        }
        result
    }

    fn bring_online_inner<R: XApicRegisterAccess>(
        &mut self,
        registers: &mut R,
    ) -> Result<(), LocalApicError<R::Error>> {
        registers
            .write(APIC_ERROR_STATUS, 0)
            .map_err(LocalApicError::Access)?;
        let _ = registers
            .read(APIC_ERROR_STATUS)
            .map_err(LocalApicError::Access)?;
        registers
            .write(APIC_LVT_ERROR, u32::from(self.vectors.error()))
            .map_err(LocalApicError::Access)?;
        registers
            .write(
                APIC_SPURIOUS,
                APIC_SOFTWARE_ENABLE | u32::from(self.vectors.spurious()),
            )
            .map_err(LocalApicError::Access)?;
        self.state
            .mark_online()
            .map_err(LocalApicError::InvalidState)
    }

    /// Signal end-of-interrupt after dispatch has completed.
    pub fn end_of_interrupt<R: XApicRegisterAccess>(
        &mut self,
        registers: &mut R,
    ) -> Result<(), LocalApicError<R::Error>> {
        self.require_state(ControllerState::Online)?;
        if let Err(error) = registers.write(APIC_EOI, 0) {
            self.state.mark_faulted();
            return Err(LocalApicError::Access(error));
        }
        Ok(())
    }

    fn require_state<E>(&self, expected: ControllerState) -> Result<(), LocalApicError<E>> {
        let observed = self.state.state();
        if observed == expected {
            return Ok(());
        }
        Err(LocalApicError::InvalidState(InvalidControllerTransition {
            from: observed,
            to: expected,
        }))
    }
}
