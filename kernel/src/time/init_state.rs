//! Security state machine for one-shot F3 time-service initialization.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum TimeInitState {
    Uninitialized = 0,
    Preparing = 1,
    Faulted = 2,
    Initialized = 3,
}

impl TimeInitState {
    pub(crate) const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Uninitialized),
            1 => Some(Self::Preparing),
            2 => Some(Self::Faulted),
            3 => Some(Self::Initialized),
            _ => None,
        }
    }

    pub(crate) const fn byte(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preparation_failure_is_retryable_but_commit_failure_is_not() {
        assert_eq!(
            TimeInitState::from_u8(0),
            Some(TimeInitState::Uninitialized)
        );
        assert_eq!(TimeInitState::from_u8(1), Some(TimeInitState::Preparing));
        assert_eq!(TimeInitState::from_u8(2), Some(TimeInitState::Faulted));
        assert_eq!(TimeInitState::from_u8(3), Some(TimeInitState::Initialized));
        assert_eq!(TimeInitState::from_u8(4), None);
        assert_ne!(TimeInitState::Faulted, TimeInitState::Uninitialized);
    }
}
