extern crate std;

use super::*;
use core::cell::{Cell, RefCell};
use output_gate::ContendedWait;
use std::string::String;
use std::sync::{Mutex, MutexGuard};
use std::vec::Vec;

static TEST_OUTPUT_LOCK: Mutex<()> = Mutex::new(());

/// Serialises the host tests that use the global output gate: off the target
/// every writer has the same identity, so two tests holding it at once would
/// see a record inside a record.
pub(crate) fn lock_output_for_test() -> MutexGuard<'static, ()> {
    TEST_OUTPUT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Has the global gate refuse one record (a record inside a record), which
/// adds one to [`records_dropped`]. The caller holds [`lock_output_for_test`].
pub(crate) fn drop_one_record_for_test() {
    let hold = acquire_output().expect("the test owns diagnostic output");
    assert!(acquire_output().is_none());
    drop(hold);
}

struct FakePort {
    ready: bool,
    final_write_count_for_drain: Option<usize>,
    drain_polls_before_empty: usize,
    drain_poll_count: usize,
    writes: [(u16, u8); 2048],
    write_count: usize,
}

impl FakePort {
    const fn ready() -> Self {
        Self {
            ready: true,
            final_write_count_for_drain: None,
            drain_polls_before_empty: 0,
            drain_poll_count: 0,
            writes: [(0, 0); 2048],
            write_count: 0,
        }
    }

    const fn stalled() -> Self {
        Self {
            ready: false,
            final_write_count_for_drain: None,
            drain_polls_before_empty: 0,
            drain_poll_count: 0,
            writes: [(0, 0); 2048],
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
            writes: [(0, 0); 2048],
            write_count: 0,
        }
    }

    fn bytes(&self) -> [u8; 2048] {
        let mut bytes = [0; 2048];
        let mut index = 0;
        while index < self.write_count {
            bytes[index] = self.writes[index].1;
            index += 1;
        }
        bytes
    }
}

impl crate::arch::x86_64::io_port::BytePortIo for FakePort {
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
fn test_evidence_writer_transmits_the_exact_85_byte_record() {
    const RECORD_BYTES: usize = 85;
    let record = [b'E'; RECORD_BYTES];
    let mut serial = Com1::new(FakePort::ready());
    write_bounded_test_evidence_record(&mut serial, &record).unwrap();
    let port = serial.io;
    assert_eq!(port.write_count, RECORD_BYTES);
    assert_eq!(&port.bytes()[..RECORD_BYTES], &record);
}

#[test]
fn one_com1_transaction_orders_fifteen_wrcap_records_before_dwtest1() {
    const WRCAP_BYTES: usize = 117;
    const WRCAP_COUNT: usize = 15;
    const TERMINAL: &[u8] = b"DWTEST1|01|00000018|00000000|00000000\n";
    let mut record = [b'0'; WRCAP_BYTES];
    record[..6].copy_from_slice(b"WRCAP1");
    record[WRCAP_BYTES - 1] = b'\n';

    let mut serial = Com1::new(FakePort::ready());
    for sequence in 0..WRCAP_COUNT {
        record[34] = b'0' + u8::try_from(sequence).unwrap();
        write_bounded_test_evidence_record(&mut serial, &record).unwrap();
    }
    write_bounded_raw_record(&mut serial, TERMINAL).unwrap();

    let port = serial.io;
    let bytes = port.bytes();
    assert_eq!(port.write_count, WRCAP_BYTES * WRCAP_COUNT + TERMINAL.len());
    for sequence in 0..WRCAP_COUNT {
        let start = sequence * WRCAP_BYTES;
        assert_eq!(&bytes[start..start + 6], b"WRCAP1");
        assert_eq!(bytes[start + WRCAP_BYTES - 1], b'\n');
    }
    assert_eq!(
        &bytes[WRCAP_BYTES * WRCAP_COUNT..port.write_count],
        TERMINAL
    );
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
fn panic_records_are_structured_bounded_and_complete() {
    let record = PanicRecord {
        reason: "kernel panic while validating boot information",
        cpu_id: Some(2),
        instruction_pointer: Some(0xffff_8000_0000_1234),
        fault_address: Some(0xffff_8000_0000_5678),
        backtrace_frames: &[0xffff_8000_0000_1111; MAX_BACKTRACE_FRAMES + 1],
    };
    let mut serial = Com1::new(FakePort::ready());
    render_panic_record(&mut serial, &record).unwrap();
    let port = serial.io;
    let bytes = port.bytes();
    let text = core::str::from_utf8(&bytes[..port.write_count]).unwrap();
    assert!(text.starts_with(
        "[DW0][PANIC][kernel] reason=kernel panic while validating boot information\r\n"
    ));
    assert!(text.contains("cpu=2 ip=0xffff800000001234 fault=0xffff800000005678"));
    assert!(text.contains("frames=0xffff800000001111,0xffff800000001111"));
    assert!(text.contains(",..."));
    assert!(!text.contains("redacted"));
}

#[test]
fn panic_records_fill_only_missing_cpu_identity_from_the_local_entry_record() {
    let missing = PanicRecord {
        reason: "terminal exception",
        cpu_id: None,
        instruction_pointer: None,
        fault_address: None,
        backtrace_frames: &[],
    };
    let populated = with_current_cpu_identity(&missing, Some(3));
    assert_eq!(populated.cpu_id, Some(3));

    let explicit = PanicRecord {
        cpu_id: Some(1),
        ..missing
    };
    let preserved = with_current_cpu_identity(&explicit, Some(3));
    assert_eq!(preserved.cpu_id, Some(1));
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

/// The global gate refuses a record inside a record at once and counts it;
/// once the outer record ends the gate is free again.
#[test]
fn reentrant_output_fails_fast_and_is_counted() {
    let _test_lock = lock_output_for_test();
    let before = records_dropped();
    let hold = acquire_output().expect("test owns diagnostic output");
    assert!(acquire_output().is_none());
    assert_eq!(records_dropped(), before + 1);
    drop(hold);
    assert!(acquire_output().is_some());
    assert_eq!(records_dropped(), before + 1);
}

/// A COM1 shared by every modelled CPU: always ready, every byte appended to
/// one wire in the order written.
struct SharedPort<'a>(&'a RefCell<Vec<u8>>);

impl crate::arch::x86_64::io_port::BytePortIo for SharedPort<'_> {
    fn read_u8(&mut self, port: u16) -> u8 {
        assert_eq!(port, COM1_BASE + LINE_STATUS);
        LINE_STATUS_THR_EMPTY | LINE_STATUS_TRANSMITTER_EMPTY
    }

    fn write_u8(&mut self, port: u16, value: u8) {
        assert_eq!(port, COM1_BASE + DATA);
        self.0.borrow_mut().push(value);
    }
}

fn wire_text(wire: &RefCell<Vec<u8>>) -> String {
    String::from_utf8(wire.borrow().clone()).unwrap()
}

/// A wait that must not be reached.
fn no_wait() -> impl FnMut() -> bool {
    || -> bool { panic!("this acquire must not wait") }
}

/// A wait over a fake clock that advances `step` ticks per read, bounded at
/// `ticks`, with an iteration backstop of `spin_cap`.
fn fake_clock_wait(
    clock: &Cell<u64>,
    step: u64,
    ticks: u64,
    spin_cap: u64,
) -> BoundedWait<impl FnMut() -> u64 + '_> {
    BoundedWait::new(
        move || {
            let now = clock.get();
            clock.set(now + step);
            now
        },
        ticks,
        spin_cap,
    )
}

/// DW2 §13.4 item 1: CPU 1's record, arriving while CPU 0 is halfway through
/// its own, waits, and is written whole after CPU 0's; neither is lost and
/// the two do not interleave. The old guard refused CPU 1 at once.
#[test]
fn a_second_cpus_record_waits_and_follows_the_first_whole() {
    let gate = OutputGate::new();
    let wire = RefCell::new(Vec::new());
    let cpu0 = WriterId::from_initial_apic_id(0);
    let cpu1 = WriterId::from_initial_apic_id(1);

    let mut first = Com1::new(SharedPort(&wire));
    let mut held = Some(gate.acquire(cpu0, &mut no_wait()).unwrap());
    first.write_bytes(b"[DW0][INFO][smp] cpu=1 ").unwrap();

    let mut waits = 0;
    let mut wait = || {
        waits += 1;
        if waits == 3 {
            // CPU 0 finishes its record while CPU 1 waits.
            first.write_bytes(b"apic=1 state=parked\n").unwrap();
            held = None;
        }
        true
    };
    let mut second = Com1::new(SharedPort(&wire));
    emit_record_through(
        &gate,
        cpu1,
        &mut wait,
        &mut second,
        DiagnosticLevel::Info,
        "x86",
        "smep and smap on",
    )
    .unwrap();

    assert!(held.is_none());
    assert_eq!(waits, 3);
    assert_eq!(
        wire_text(&wire),
        "[DW0][INFO][smp] cpu=1 apic=1 state=parked\r\n[DW0][INFO][x86] smep and smap on\r\n"
    );
    assert_eq!(gate.dropped(), 0);
}

/// A record inside a record on one CPU (a fault interrupting one) is refused
/// at once, without waiting, writes nothing and is counted.
#[test]
fn a_record_inside_a_record_on_one_cpu_is_refused_at_once_and_counted() {
    let gate = OutputGate::new();
    let wire = RefCell::new(Vec::new());
    let cpu0 = WriterId::from_initial_apic_id(0);
    let _outer = gate.acquire(cpu0, &mut no_wait()).unwrap();

    let mut serial = Com1::new(SharedPort(&wire));
    assert_eq!(
        emit_record_through(
            &gate,
            cpu0,
            &mut no_wait(),
            &mut serial,
            DiagnosticLevel::Error,
            "time",
            "inner",
        ),
        Err(SerialError::Busy)
    );
    assert!(wire.borrow().is_empty());
    assert_eq!(gate.dropped(), 1);
}

/// A holder that never releases is outwaited to the tick bound, then the
/// record is refused and counted once.
#[test]
fn a_holder_that_never_releases_is_outwaited_to_the_bound_and_counted_once() {
    let gate = OutputGate::new();
    let wire = RefCell::new(Vec::new());
    let _stalled = gate
        .acquire(WriterId::from_initial_apic_id(2), &mut no_wait())
        .unwrap();

    let clock = Cell::new(1_000);
    let mut wait = fake_clock_wait(&clock, 10, 100, 1_000_000);
    let mut serial = Com1::new(SharedPort(&wire));
    assert_eq!(
        emit_record_through(
            &gate,
            WriterId::from_initial_apic_id(1),
            &mut wait,
            &mut serial,
            DiagnosticLevel::Info,
            "steps",
            "records-dropped=0",
        ),
        Err(SerialError::Busy)
    );
    // It read the clock until 100 ticks had passed since its first read.
    assert_eq!(clock.get(), 1_000 + 110);
    assert!(wire.borrow().is_empty());
    assert_eq!(gate.dropped(), 1);
}

/// With a clock that never advances, the iteration backstop ends the wait.
#[test]
fn a_stuck_clock_is_bounded_by_the_iteration_backstop() {
    let gate = OutputGate::new();
    let _stalled = gate
        .acquire(WriterId::from_initial_apic_id(2), &mut no_wait())
        .unwrap();
    let clock = Cell::new(7);
    let mut wait = fake_clock_wait(&clock, 0, 100, 5);
    let mut reads = 0;
    let mut counted = || {
        reads += 1;
        wait.wait()
    };
    assert!(
        gate.acquire(WriterId::from_initial_apic_id(1), &mut counted)
            .is_none()
    );
    // Five spins, then the sixth wait reports the bound.
    assert_eq!(reads, 6);
    assert_eq!(gate.dropped(), 1);
}

/// The panic path waits out the bound like any record, then takes the gate
/// from the stalled CPU by force and writes its whole record; it is not
/// counted. Its release frees the gate, and the stalled CPU's own release, if
/// it ever comes, does not free a gate another CPU has taken since.
#[test]
fn the_panic_path_takes_the_gate_after_the_bound_and_is_not_counted() {
    let gate = OutputGate::new();
    let stalled = gate
        .acquire(WriterId::from_initial_apic_id(0), &mut no_wait())
        .unwrap();

    let clock = Cell::new(0);
    let mut wait = fake_clock_wait(&clock, 25, 100, 1_000_000);
    let mut serial = Com1::new(FakePort::ready());
    let record = PanicRecord {
        reason: "stalled holder",
        cpu_id: Some(1),
        instruction_pointer: None,
        fault_address: None,
        backtrace_frames: &[],
    };
    emit_panic_record_through(
        &gate,
        WriterId::from_initial_apic_id(1),
        &mut wait,
        &mut serial,
        &record,
    )
    .unwrap();
    assert!(clock.get() > 100, "the panic waited out the bound first");
    let port = serial.io;
    let bytes = port.bytes();
    let text = core::str::from_utf8(&bytes[..port.write_count]).unwrap();
    assert!(text.starts_with("[DW0][PANIC][kernel] reason=stalled holder\r\n"));
    assert!(text.ends_with("frames=\r\n"));
    assert_eq!(gate.dropped(), 0);

    // The panic's release freed the gate: CPU 2 takes it without waiting.
    let later = gate
        .acquire(WriterId::from_initial_apic_id(2), &mut no_wait())
        .unwrap();
    // The stalled CPU resumes and releases; CPU 2 still holds the gate.
    drop(stalled);
    assert!(
        gate.acquire(WriterId::from_initial_apic_id(3), &mut || false)
            .is_none()
    );
    drop(later);
    assert!(
        gate.acquire(WriterId::from_initial_apic_id(3), &mut no_wait())
            .is_some()
    );
}

/// A panic inside a record on its own CPU takes the gate at once, without
/// waiting, and is not counted.
#[test]
fn a_panic_inside_its_own_cpus_record_forces_the_gate_at_once() {
    let gate = OutputGate::new();
    let cpu0 = WriterId::from_initial_apic_id(0);
    let _outer = gate.acquire(cpu0, &mut no_wait()).unwrap();
    let mut serial = Com1::new(FakePort::ready());
    let record = PanicRecord {
        reason: "fault inside a record",
        cpu_id: Some(0),
        instruction_pointer: None,
        fault_address: None,
        backtrace_frames: &[],
    };
    emit_panic_record_through(&gate, cpu0, &mut no_wait(), &mut serial, &record).unwrap();
    assert!(serial.io.write_count > 0);
    assert_eq!(gate.dropped(), 0);
}

/// DW2 §13.4 item 3: the syscall layer's fail-stop record names the line.
#[test]
fn halt_line_messages_carry_the_whole_line_number() {
    assert_eq!(HaltLineMessage::new(0).as_str(), "halt line=0");
    assert_eq!(HaltLineMessage::new(2906).as_str(), "halt line=2906");
    assert_eq!(
        HaltLineMessage::new(u32::MAX).as_str(),
        "halt line=4294967295"
    );
}

#[test]
fn ordinary_records_have_bounded_fields() {
    let _test_lock = lock_output_for_test();
    let mut serial = Com1::new(FakePort::ready());
    let long = "x".repeat(MAX_DIAGNOSTIC_MESSAGE_BYTES + 1);
    emit_record(&mut serial, DiagnosticLevel::Info, "boot", &long).unwrap();
    let port = serial.io;
    let bytes = port.bytes();
    let text = core::str::from_utf8(&bytes[..port.write_count]).unwrap();
    assert!(text.starts_with("[DW0][INFO][boot] "));
    assert!(text.ends_with("...\r\n"));
}

/// F3A.6q. The last diagnostic boundary in the boot used to emit one sentence
/// for six distinct completion failures. The renderer must carry both the
/// cause's name and its number, and the number must be the full eight hex
/// digits: a WYR1 application status is `0xAF21_0B41`-shaped, and a truncated
/// or decimal rendering would cost the reader the encoding the product spent
/// nine revisions building.
#[test]
fn bootstrap_completion_records_carry_the_cause_and_its_detail() {
    let _test_lock = lock_output_for_test();
    let mut serial = Com1::new(FakePort::ready());
    emit_bootstrap_completion_record(
        &mut serial,
        DiagnosticLevel::Error,
        "nonzero-exit",
        0xAF21_0B41,
        None,
    )
    .unwrap();
    let port = serial.io;
    let bytes = port.bytes();
    let text = core::str::from_utf8(&bytes[..port.write_count]).unwrap();
    assert_eq!(
        text,
        "[DW0][ERROR][primordial] bootstrap nonzero-exit detail=AF210B41\r\n"
    );
}

/// F3A.6w. `DW_STATUS_NO_RESOURCES` is one ABI value for at least six
/// distinct kernel walls reachable from a single `address_region_map`. The
/// production Wyrmroot bootstrap exits on that status while mapping bootfs
/// (F3A.6u), so this record is the reader's only channel for *which* wall --
/// and the site byte says which boundary reported it, including the
/// handle-resolution boundary that has no typed error left to classify.
#[test]
fn a_capacity_record_names_the_resource_and_the_site() {
    let _test_lock = lock_output_for_test();
    let mut serial = Com1::new(FakePort::ready());
    emit_capacity_record(&mut serial, "page-table-frames", 0x06).unwrap();
    let port = serial.io;
    let bytes = port.bytes();
    let text = core::str::from_utf8(&bytes[..port.write_count]).unwrap();
    assert_eq!(
        text,
        "[DW0][ERROR][mm] capacity-exhausted resource=page-table-frames site=06\r\n"
    );
}

/// An unclassifiable wall still renders, or its absence would be read as "no
/// capacity failure happened" rather than "we could not name it".
#[test]
fn an_unclassified_capacity_record_still_renders() {
    let _test_lock = lock_output_for_test();
    let mut serial = Com1::new(FakePort::ready());
    emit_capacity_record(&mut serial, "unclassified", 0x01).unwrap();
    let port = serial.io;
    let bytes = port.bytes();
    let text = core::str::from_utf8(&bytes[..port.write_count]).unwrap();
    assert_eq!(
        text,
        "[DW0][ERROR][mm] capacity-exhausted resource=unclassified site=01\r\n"
    );
}

/// F3A.6t. A receive failure carries the exit disposition observed in the same
/// call, and the transcript must show both: `WouldBlock` alone says only that
/// nothing was queued, while `exit=exited code=AF010002` says the application
/// had already failed with a WYR1 status. The suffix is absent when the cause
/// *is* the exit, so its presence is what tells a reader the two facts are
/// independent.
#[test]
fn a_bootstrap_completion_renders_a_secondary_exit_observation() {
    let _test_lock = lock_output_for_test();
    let mut serial = Com1::new(FakePort::ready());
    emit_bootstrap_completion_record(
        &mut serial,
        DiagnosticLevel::Error,
        "ready-not-received",
        0x7100_0015,
        Some(("exited", 0xAF01_0002)),
    )
    .unwrap();
    let port = serial.io;
    let bytes = port.bytes();
    let text = core::str::from_utf8(&bytes[..port.write_count]).unwrap();
    assert_eq!(
        text,
        "[DW0][ERROR][primordial] bootstrap ready-not-received detail=71000015 \
exit=exited code=AF010002\r\n"
    );
}

/// A cause with no number of its own still renders a full-width zero rather
/// than an empty field, so a transcript is parseable by one rule.
#[test]
fn a_bootstrap_completion_cause_without_a_detail_still_renders_one() {
    let _test_lock = lock_output_for_test();
    let mut serial = Com1::new(FakePort::ready());
    emit_bootstrap_completion_record(
        &mut serial,
        DiagnosticLevel::Info,
        "completed normally",
        0,
        None,
    )
    .unwrap();
    let port = serial.io;
    let bytes = port.bytes();
    let text = core::str::from_utf8(&bytes[..port.write_count]).unwrap();
    assert_eq!(
        text,
        "[DW0][INFO][primordial] bootstrap completed normally detail=00000000\r\n"
    );
}

/// F3A.7h. The record exists so a production transcript can say what exited
/// and with what status, so the status is checked as a literal rather than as
/// "some hex": a run reads `application=` to tell a clean supervisor shutdown
/// from a failure status, and a field that rendered decimally, truncated, or
/// dropped its leading zeroes would be read wrong rather than not read.
#[test]
fn process_retirement_records_carry_the_exit_status_and_the_primordial_state() {
    let _test_lock = lock_output_for_test();

    let rendered = |application, reason, primordial_live, expected: &str| {
        let mut serial = Com1::new(FakePort::ready());
        emit_process_retirement_record(&mut serial, application, reason, primordial_live).unwrap();
        let port = serial.io;
        let bytes = port.bytes();
        assert_eq!(
            core::str::from_utf8(&bytes[..port.write_count]).unwrap(),
            expected
        );
    };

    rendered(
        0,
        1,
        true,
        "[DW0][INFO][task] retired application=00000000 reason=1 primordial=live\r\n",
    );
    // A supervisor that ended a session exits zero; one that failed carries
    // its own encoding, and `0xAF01_0005` is a real one from `system-init`.
    rendered(
        0xAF01_0005,
        1,
        false,
        "[DW0][INFO][task] retired application=AF010005 reason=1 primordial=retired\r\n",
    );
    // An unhandled exception leaves the status field meaningless, which is
    // exactly why the reason travels with it.
    rendered(
        0,
        3,
        false,
        "[DW0][INFO][task] retired application=00000000 reason=3 primordial=retired\r\n",
    );
}

#[test]
fn the_power_off_record_says_no_process_remains() {
    let _test_lock = lock_output_for_test();
    let mut serial = Com1::new(FakePort::ready());
    emit_system_empty_record(&mut serial).unwrap();
    let port = serial.io;
    let bytes = port.bytes();
    assert_eq!(
        core::str::from_utf8(&bytes[..port.write_count]).unwrap(),
        "[DW0][INFO][task] no process remains; powering off\r\n"
    );
}

#[test]
fn smp_records_identify_cpu_apic_and_state() {
    let _test_lock = lock_output_for_test();
    let mut serial = Com1::new(FakePort::ready());
    emit_cpu_state_record(&mut serial, 3, 17, "parked").unwrap();
    let port = serial.io;
    let bytes = port.bytes();
    let text = core::str::from_utf8(&bytes[..port.write_count]).unwrap();
    assert_eq!(text, "[DW0][INFO][smp] cpu=3 apic=17 state=parked\r\n");
}
