use deepwyrm_abi::DW_DEADLINE_INFINITE;

pub(crate) const ACPI_PM_TIMER_HZ: u64 = 3_579_545;
const NANOS_PER_SECOND: u128 = 1_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PmTimerWidth {
    Bits24,
    Bits32,
}

impl PmTimerWidth {
    pub(crate) const fn mask(self) -> u32 {
        match self {
            Self::Bits24 => (1_u32 << 24) - 1,
            Self::Bits32 => u32::MAX,
        }
    }

    pub(crate) const fn modulus(self) -> u64 {
        self.mask() as u64 + 1
    }

    pub(crate) const fn half_wrap_ticks(self) -> u64 {
        self.modulus() / 2
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PmTimerDescriptor {
    port: u16,
    width: PmTimerWidth,
}

impl PmTimerDescriptor {
    pub(crate) const fn new(port: u16, width: PmTimerWidth) -> Result<Self, PmTimerError> {
        if port == 0 {
            return Err(PmTimerError::InvalidPort);
        }
        Ok(Self { port, width })
    }

    pub(crate) const fn port(self) -> u16 {
        self.port
    }

    pub(crate) const fn width(self) -> PmTimerWidth {
        self.width
    }

    pub(crate) fn half_wrap_nanoseconds(self) -> Result<u64, PmTimerError> {
        ticks_to_nanoseconds(self.width.half_wrap_ticks())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PmTimerError {
    InvalidPort,
    SampleGapTooLarge,
    TickOverflow,
    NanosecondOverflow,
    MaintenanceOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MonotonicSample {
    pub(crate) nanoseconds: u64,
    pub(crate) maintenance_deadline: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PmTimerState {
    descriptor: PmTimerDescriptor,
    last_raw: u32,
    extended_ticks: u64,
}

impl PmTimerState {
    pub(crate) const fn new(descriptor: PmTimerDescriptor, initial_raw: u32) -> Self {
        Self {
            descriptor,
            last_raw: initial_raw & descriptor.width.mask(),
            extended_ticks: 0,
        }
    }

    pub(crate) const fn descriptor(self) -> PmTimerDescriptor {
        self.descriptor
    }

    pub(crate) fn sample(&mut self, raw: u32) -> Result<MonotonicSample, PmTimerError> {
        let mask = self.descriptor.width.mask();
        let current = raw & mask;
        let delta = u64::from(current.wrapping_sub(self.last_raw) & mask);
        if delta > self.descriptor.width.half_wrap_ticks() {
            return Err(PmTimerError::SampleGapTooLarge);
        }
        let extended_ticks = self
            .extended_ticks
            .checked_add(delta)
            .ok_or(PmTimerError::TickOverflow)?;
        let nanoseconds = ticks_to_nanoseconds(extended_ticks)?;
        let maintenance_delta = self.descriptor.half_wrap_nanoseconds()?;
        let maintenance_deadline = nanoseconds
            .checked_add(maintenance_delta)
            .filter(|value| *value < DW_DEADLINE_INFINITE.0)
            .ok_or(PmTimerError::MaintenanceOverflow)?;
        self.extended_ticks = extended_ticks;
        self.last_raw = current;
        Ok(MonotonicSample {
            nanoseconds,
            maintenance_deadline,
        })
    }
}

pub(crate) fn ticks_to_nanoseconds(ticks: u64) -> Result<u64, PmTimerError> {
    let value = u128::from(ticks)
        .checked_mul(NANOS_PER_SECOND)
        .ok_or(PmTimerError::NanosecondOverflow)?
        / u128::from(ACPI_PM_TIMER_HZ);
    u64::try_from(value)
        .ok()
        .filter(|value| *value < DW_DEADLINE_INFINITE.0)
        .ok_or(PmTimerError::NanosecondOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_is_checked_and_never_emits_infinite_sentinel() {
        assert_eq!(
            ticks_to_nanoseconds(ACPI_PM_TIMER_HZ).unwrap(),
            1_000_000_000
        );
        assert!(ticks_to_nanoseconds(u64::MAX).is_err());
    }

    #[test]
    fn twenty_four_bit_counter_extends_across_one_wrap() {
        let descriptor = PmTimerDescriptor::new(0x608, PmTimerWidth::Bits24).unwrap();
        let mut state = PmTimerState::new(descriptor, 0x00ff_fff0);
        let sample = state.sample(0x0000_0010).unwrap();
        assert_eq!(state.extended_ticks, 0x20);
        assert_eq!(sample.nanoseconds, ticks_to_nanoseconds(0x20).unwrap());
        assert!(sample.maintenance_deadline > sample.nanoseconds);
    }

    #[test]
    fn missed_half_wrap_sampling_window_fails_closed() {
        let descriptor = PmTimerDescriptor::new(0x608, PmTimerWidth::Bits24).unwrap();
        let mut state = PmTimerState::new(descriptor, 0);
        assert_eq!(
            state.sample((1 << 23) + 1),
            Err(PmTimerError::SampleGapTooLarge)
        );
    }
}
