//! Architecture-neutral interrupt-controller state and vector ownership.
//!
//! DW0-B established controller bring-up and vector classes; F3 additionally
//! reserves the local-APIC timer vector. Timer service state, scheduler coupling,
//! device IRQ allocation, and userspace interrupt objects remain elsewhere.

/// CPU exception vectors installed by the descriptor-table implementation.
pub const EXCEPTION_VECTOR_RANGE: core::ops::RangeInclusive<u8> = 0x00..=0x1f;
/// Legacy PIC vectors remain reserved even though the PIC is masked in DW0-B.
pub const LEGACY_PIC_VECTOR_RANGE: core::ops::RangeInclusive<u8> = 0x20..=0x2f;
/// Pool reserved for later external and device interrupt allocation.
pub const EXTERNAL_VECTOR_RANGE: core::ops::RangeInclusive<u8> = 0x30..=0xdf;
/// Pool reserved for later timer, IPI, and other kernel-internal interrupts.
pub const INTERNAL_VECTOR_RANGE: core::ops::RangeInclusive<u8> = 0xe0..=0xfd;

pub const LOCAL_APIC_TIMER_VECTOR: u8 = 0xe0;
pub const LOCAL_APIC_ERROR_VECTOR: u8 = 0xfe;
pub const LOCAL_APIC_SPURIOUS_VECTOR: u8 = 0xff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VectorClass {
    Exception,
    LegacyPicReserved,
    ExternalUnallocated,
    InternalReserved,
    LocalApicTimer,
    LocalApicError,
    LocalApicSpurious,
}

#[must_use]
pub const fn classify_vector(vector: u8) -> VectorClass {
    match vector {
        0x00..=0x1f => VectorClass::Exception,
        0x20..=0x2f => VectorClass::LegacyPicReserved,
        0x30..=0xdf => VectorClass::ExternalUnallocated,
        LOCAL_APIC_TIMER_VECTOR => VectorClass::LocalApicTimer,
        0xe1..=0xfd => VectorClass::InternalReserved,
        LOCAL_APIC_ERROR_VECTOR => VectorClass::LocalApicError,
        LOCAL_APIC_SPURIOUS_VECTOR => VectorClass::LocalApicSpurious,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VectorLayoutError {
    ErrorVectorOutsidePolicy,
    SpuriousVectorOutsidePolicy,
    TimerVectorOutsidePolicy,
    DuplicateLocalApicVector,
}

/// Descriptor-table/APIC agreement for vectors owned by the local APIC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalApicVectors {
    timer: u8,
    error: u8,
    spurious: u8,
}

impl LocalApicVectors {
    pub const DW0: Self = Self {
        timer: LOCAL_APIC_TIMER_VECTOR,
        error: LOCAL_APIC_ERROR_VECTOR,
        spurious: LOCAL_APIC_SPURIOUS_VECTOR,
    };

    pub const fn new(timer: u8, error: u8, spurious: u8) -> Result<Self, VectorLayoutError> {
        if timer == error || timer == spurious || error == spurious {
            return Err(VectorLayoutError::DuplicateLocalApicVector);
        }
        if timer != LOCAL_APIC_TIMER_VECTOR {
            return Err(VectorLayoutError::TimerVectorOutsidePolicy);
        }
        if error != LOCAL_APIC_ERROR_VECTOR {
            return Err(VectorLayoutError::ErrorVectorOutsidePolicy);
        }
        if spurious != LOCAL_APIC_SPURIOUS_VECTOR {
            return Err(VectorLayoutError::SpuriousVectorOutsidePolicy);
        }
        Ok(Self {
            timer,
            error,
            spurious,
        })
    }

    #[must_use]
    pub const fn timer(self) -> u8 {
        self.timer
    }

    #[must_use]
    pub const fn error(self) -> u8 {
        self.error
    }

    #[must_use]
    pub const fn spurious(self) -> u8 {
        self.spurious
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerState {
    Offline,
    Discovered,
    Prepared,
    Online,
    Faulted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidControllerTransition {
    pub from: ControllerState,
    pub to: ControllerState,
}

/// Small explicit state machine used by per-CPU interrupt controllers.
///
/// It contains no global mutable state and therefore does not encode the DW0
/// one-vCPU boot profile as a correctness assumption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerStateMachine {
    state: ControllerState,
}

impl ControllerStateMachine {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: ControllerState::Offline,
        }
    }

    #[must_use]
    pub const fn state(self) -> ControllerState {
        self.state
    }

    pub fn mark_discovered(&mut self) -> Result<(), InvalidControllerTransition> {
        self.transition(ControllerState::Offline, ControllerState::Discovered)
    }

    pub fn mark_prepared(&mut self) -> Result<(), InvalidControllerTransition> {
        self.transition(ControllerState::Discovered, ControllerState::Prepared)
    }

    pub fn mark_online(&mut self) -> Result<(), InvalidControllerTransition> {
        self.transition(ControllerState::Prepared, ControllerState::Online)
    }

    pub fn mark_faulted(&mut self) {
        self.state = ControllerState::Faulted;
    }

    fn transition(
        &mut self,
        expected: ControllerState,
        next: ControllerState,
    ) -> Result<(), InvalidControllerTransition> {
        if self.state != expected {
            return Err(InvalidControllerTransition {
                from: self.state,
                to: next,
            });
        }
        self.state = next;
        Ok(())
    }
}

impl Default for ControllerStateMachine {
    fn default() -> Self {
        Self::new()
    }
}
