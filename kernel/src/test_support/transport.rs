//! Test-only completion transport ordering and debug-exit encoding.

use super::protocol::{COMPLETION_RECORD_LEN, CompletionOutcome, CompletionRecord};

/// Raw value written to the configured QEMU `isa-debug-exit` test device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DebugExitValue(u32);

impl DebugExitValue {
    /// PASS value written by the guest.
    pub const PASS: Self = Self(0x10);
    /// FAIL value written by the guest.
    pub const FAIL: Self = Self(0x11);
    /// PANIC value written by the guest.
    pub const PANIC: Self = Self(0x12);

    /// Return the raw guest value for the debug-exit port.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl From<CompletionOutcome> for DebugExitValue {
    fn from(outcome: CompletionOutcome) -> Self {
        match outcome {
            CompletionOutcome::Pass => Self::PASS,
            CompletionOutcome::Fail => Self::FAIL,
            CompletionOutcome::Panic => Self::PANIC,
        }
    }
}

/// Expected host process status produced by QEMU's `(guest << 1) | 1` rule.
#[must_use]
pub const fn expected_host_exit_status(value: DebugExitValue) -> u8 {
    ((value.raw() << 1) | 1) as u8
}

/// Test-build completion transport.
///
/// Implementations must bound serial writes and configure the debug-exit path
/// only in the centralized test runner. Neither operation may accept ordinary
/// boot artifacts or production configuration.
pub trait CompletionTransport {
    /// Emit the exact machine-readable serial record.
    fn write_serial_record(&mut self, record: &[u8; COMPLETION_RECORD_LEN]);

    /// Signal the terminal outcome through the outcome-only debug-exit path.
    fn write_debug_exit(&mut self, value: DebugExitValue);

    /// Stop execution if the configured test environment did not terminate.
    fn halt(&mut self) -> !;
}

/// Emit the serial record first, then the outcome-only debug-exit value.
///
/// This split operation is host-testable. Production integration should call
/// [`complete`], which also enters the transport's terminal halt path.
pub fn emit_completion<T: CompletionTransport>(transport: &mut T, record: CompletionRecord) {
    let encoded = record.encode();
    transport.write_serial_record(encoded.as_bytes());
    transport.write_debug_exit(record.outcome.into());
}

/// Emit a terminal record and halt if QEMU does not exit.
pub fn complete<T: CompletionTransport>(transport: &mut T, record: CompletionRecord) -> ! {
    emit_completion(transport, record);
    transport.halt()
}

#[cfg(test)]
mod tests {
    use super::super::protocol::EncodedCompletionRecord;
    use super::*;

    struct CaptureTransport {
        record: Option<[u8; COMPLETION_RECORD_LEN]>,
        exit: Option<DebugExitValue>,
        order: [u8; 2],
        order_len: usize,
    }

    impl CaptureTransport {
        const fn new() -> Self {
            Self {
                record: None,
                exit: None,
                order: [0; 2],
                order_len: 0,
            }
        }
    }

    impl CompletionTransport for CaptureTransport {
        fn write_serial_record(&mut self, record: &[u8; COMPLETION_RECORD_LEN]) {
            self.order[self.order_len] = 1;
            self.order_len += 1;
            self.record = Some(*record);
        }

        fn write_debug_exit(&mut self, value: DebugExitValue) {
            self.order[self.order_len] = 2;
            self.order_len += 1;
            self.exit = Some(value);
        }

        fn halt(&mut self) -> ! {
            panic!("capture transport halt")
        }
    }

    #[test]
    fn every_outcome_has_a_distinct_host_status() {
        let cases = [
            (CompletionOutcome::Pass, DebugExitValue::PASS, 33),
            (CompletionOutcome::Fail, DebugExitValue::FAIL, 35),
            (CompletionOutcome::Panic, DebugExitValue::PANIC, 37),
        ];
        for (outcome, value, status) in cases {
            assert_eq!(DebugExitValue::from(outcome), value);
            assert_eq!(expected_host_exit_status(value), status);
        }
    }

    #[test]
    fn serial_record_precedes_debug_exit() {
        let record = CompletionRecord {
            outcome: CompletionOutcome::Fail,
            test_id: 7,
            detail: 9,
        };
        let mut transport = CaptureTransport::new();
        emit_completion(&mut transport, record);

        assert_eq!(transport.order, [1, 2]);
        assert_eq!(transport.exit, Some(DebugExitValue::FAIL));
        assert_eq!(
            EncodedCompletionRecord::parse(transport.record.as_ref().unwrap()),
            Ok(record)
        );
    }
}
