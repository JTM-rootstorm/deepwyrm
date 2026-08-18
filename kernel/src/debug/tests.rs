extern crate std;

use super::*;
use std::sync::{Mutex, MutexGuard};

static TEST_OUTPUT_LOCK: Mutex<()> = Mutex::new(());

fn lock_output_guard_test() -> MutexGuard<'static, ()> {
    TEST_OUTPUT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct FakePort {
    ready: bool,
    final_write_count_for_drain: Option<usize>,
    drain_polls_before_empty: usize,
    drain_poll_count: usize,
    writes: [(u16, u8); 1024],
    write_count: usize,
}

impl FakePort {
    const fn ready() -> Self {
        Self {
            ready: true,
            final_write_count_for_drain: None,
            drain_polls_before_empty: 0,
            drain_poll_count: 0,
            writes: [(0, 0); 1024],
            write_count: 0,
        }
    }

    const fn stalled() -> Self {
        Self {
            ready: false,
            final_write_count_for_drain: None,
            drain_polls_before_empty: 0,
            drain_poll_count: 0,
            writes: [(0, 0); 1024],
            write_count: 0,
        }
    }

    const fn ready_with_delayed_drain(
        final_write_count_for_drain: usize,
        drain_polls_before_empty: usize,
    ) -> Self {
        Self {
            ready: true,
            final_write_count_for_drain: Some(final_write_count_for_drain),
            drain_polls_before_empty,
            drain_poll_count: 0,
            writes: [(0, 0); 1024],
            write_count: 0,
        }
    }

    fn bytes(&self) -> [u8; 1024] {
        let mut bytes = [0; 1024];
        let mut index = 0;
        while index < self.write_count {
            bytes[index] = self.writes[index].1;
            index += 1;
        }
        bytes
    }
}

impl PortIo for FakePort {
    fn read_u8(&mut self, port: u16) -> u8 {
        assert_eq!(port, COM1_BASE + LINE_STATUS);
        if !self.ready {
            return 0;
        }

        let mut status = LINE_STATUS_THR_EMPTY;
        match self.final_write_count_for_drain {
            Some(final_write_count) if self.write_count >= final_write_count => {
                self.drain_poll_count += 1;
                if self.drain_poll_count > self.drain_polls_before_empty {
                    status |= LINE_STATUS_TRANSMITTER_EMPTY;
                }
            }
            Some(_) => {}
            None => status |= LINE_STATUS_TRANSMITTER_EMPTY,
        }
        status
    }

    fn write_u8(&mut self, port: u16, value: u8) {
        self.writes[self.write_count] = (port, value);
        self.write_count += 1;
    }
}

#[test]
fn initializes_com1_as_polling_8n1() {
    let mut serial = Com1::new(FakePort::ready());
    serial.initialize();
    let port = serial.io;
    assert_eq!(port.write_count, 7);
    assert_eq!(
        &port.writes[..7],
        &[
            (COM1_BASE + INTERRUPT_ENABLE, 0),
            (COM1_BASE + LINE_CONTROL, LINE_CONTROL_DLAB),
            (COM1_BASE + DIVISOR_LOW, 1),
            (COM1_BASE + DIVISOR_HIGH, 0),
            (COM1_BASE + LINE_CONTROL, LINE_CONTROL_8N1),
            (COM1_BASE + FIFO_CONTROL, FIFO_ENABLE_CLEAR_14),
            (COM1_BASE + MODEM_CONTROL, MODEM_DTR_RTS_OUT2),
        ]
    );
}

#[test]
fn translates_newlines_and_times_out_without_unbounded_polling() {
    let mut serial = Com1::new(FakePort::ready());
    serial.write_bytes(b"ok\n").unwrap();
    let port = serial.io;
    assert_eq!(&port.bytes()[..4], b"ok\r\n");

    let mut stalled = Com1::with_poll_limit(FakePort::stalled(), 3);
    assert_eq!(stalled.write_bytes(b"x"), Err(SerialError::TransmitTimeout));
    assert_eq!(stalled.io.write_count, 0);
}

#[test]
fn raw_completion_record_preserves_its_single_lf_byte() {
    const RECORD: &[u8] = b"DWTEST1|03|0123ABCD|DEADBEEF|C001D00D\n";
    assert_eq!(RECORD.len(), 38);

    let mut serial = Com1::new(FakePort::ready_with_delayed_drain(RECORD.len(), 2));
    write_bounded_raw_record(&mut serial, RECORD).unwrap();
    let port = serial.io;
    assert_eq!(port.write_count, RECORD.len());
    assert_eq!(&port.bytes()[..RECORD.len()], RECORD);
    assert_eq!(port.bytes()[RECORD.len() - 1], b'\n');
    assert_eq!(port.drain_poll_count, 3);
}

#[test]
fn raw_machine_records_are_bounded() {
    let record = [b'x'; MAX_RAW_RECORD_BYTES + 1];
    let mut serial = Com1::new(FakePort::ready());
    assert_eq!(
        write_bounded_raw_record(&mut serial, &record),
        Err(SerialError::RecordTooLong)
    );
    assert_eq!(serial.io.write_count, 0);
}

#[test]
fn raw_machine_record_reports_a_distinct_drain_timeout() {
    let mut serial = Com1::with_poll_limit(FakePort::ready_with_delayed_drain(1, usize::MAX), 3);
    assert_eq!(
        write_bounded_raw_record(&mut serial, b"\n"),
        Err(SerialError::TransmitDrainTimeout)
    );
    assert_eq!(serial.io.write_count, 1);
    assert_eq!(serial.io.drain_poll_count, 3);
}

#[test]
fn panic_records_are_structured_bounded_and_redactable() {
    let record = PanicRecord {
        reason: "kernel panic while validating boot information",
        cpu_id: Some(2),
        instruction_pointer: Some(0xffff_8000_0000_1234),
        fault_address: Some(0xffff_8000_0000_5678),
        backtrace_frames: &[0xffff_8000_0000_1111; MAX_BACKTRACE_FRAMES + 1],
    };
    let mut serial = Com1::new(FakePort::ready());
    render_panic_record(&mut serial, &record, false).unwrap();
    let port = serial.io;
    let bytes = port.bytes();
    let text = core::str::from_utf8(&bytes[..port.write_count]).unwrap();
    assert!(text.starts_with("[DW0][PANIC][kernel] reason="));
    assert!(text.contains("reason=redacted"));
    assert!(text.contains("cpu=2 ip=redacted fault=redacted"));
    assert!(text.contains("frames=redacted,redacted"));
    assert!(text.contains(",..."));
    assert!(!text.contains("ffff8000"));
}

#[test]
fn panic_reason_buffer_is_utf8_valid_and_bounded() {
    let mut reason = PanicReasonBuffer::new();
    reason
        .write_str(&"panic-\u{00e9}".repeat(MAX_PANIC_REASON_BYTES))
        .unwrap();
    assert!(reason.length <= MAX_PANIC_REASON_BYTES);
    assert!(reason.as_str().is_char_boundary(reason.as_str().len()));
    assert!(reason.as_str().starts_with("panic-\u{00e9}"));
}

#[test]
fn reentrant_output_fails_fast() {
    let _test_lock = lock_output_guard_test();
    let guard = OutputGuard::acquire().expect("test owns diagnostic output");
    assert!(OutputGuard::acquire().is_none());
    drop(guard);
    assert!(OutputGuard::acquire().is_some());
}

#[test]
fn ordinary_records_have_bounded_fields() {
    let _test_lock = lock_output_guard_test();
    let mut serial = Com1::new(FakePort::ready());
    let long = "x".repeat(MAX_DIAGNOSTIC_MESSAGE_BYTES + 1);
    emit_record(&mut serial, DiagnosticLevel::Info, "boot", &long).unwrap();
    let port = serial.io;
    let bytes = port.bytes();
    let text = core::str::from_utf8(&bytes[..port.write_count]).unwrap();
    assert!(text.starts_with("[DW0][INFO][boot] "));
    assert!(text.ends_with("...\r\n"));
}
