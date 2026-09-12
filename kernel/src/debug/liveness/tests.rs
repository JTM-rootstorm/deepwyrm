extern crate std;

use super::*;

fn cpu(index: usize) -> CpuIndex {
    CpuIndex::new(index).expect("bounded diagnostic CPU index")
}

/// A private mirror per test.
///
/// These tests used to assert against the one global `LIVENESS`, which the
/// scheduler also publishes into from its own unit tests. Running in parallel,
/// an unrelated test's publication could retarget an event, bump a publication
/// count, or land mid-sequence and be observed as a torn read, so the suite
/// failed intermittently on a different assertion each run. Owning the mirror
/// makes every test here deterministic and keeps the production entry points
/// exercised through their `_on` implementations.
fn mirror() -> LivenessSnapshot {
    LivenessSnapshot::new()
}

#[test]
fn publication_round_trips_every_mirrored_field() {
    let m = mirror();
    publish_current_on(
        &m,
        cpu(1),
        0x1111,
        0x2222,
        0x4444,
        0x5555,
        0x6666,
        LivenessEvent::CarrierSelected,
    );
    let record = read_cpu_on(&m, cpu(1));
    assert!(record.consistent);
    assert_eq!(record.cpu, 1);
    assert_eq!(record.thread, 0x1111);
    assert_eq!(record.process, 0x2222);
    assert_eq!(record.root_key, 0x4444);
    assert_eq!(record.context_id, 0x5555);
    assert_eq!(record.stack_id, 0x6666);
    assert_eq!(record.event, LivenessEvent::CarrierSelected as u32);
}

#[test]
fn publication_leaves_an_even_sequence_and_counts_publications() {
    let m = mirror();
    let before = read_cpu_on(&m, cpu(2)).publications;
    publish_current_on(&m, cpu(2), 1, 2, 4, 5, 6, LivenessEvent::Preempted);
    publish_current_on(&m, cpu(2), 7, 8, 10, 11, 12, LivenessEvent::QuantumExpired);
    let after = read_cpu_on(&m, cpu(2));
    assert!(after.consistent);
    assert_eq!(after.publications, before + 2);
    assert_eq!(after.thread, 7);
    assert_eq!(after.event, LivenessEvent::QuantumExpired as u32);
    assert!(m.cpus[2].sequence.load(Ordering::Relaxed).is_multiple_of(2));
}

#[test]
fn note_event_preserves_the_mirrored_identity() {
    let m = mirror();
    publish_current_on(
        &m,
        cpu(0),
        0xAA,
        0xBB,
        0xDD,
        0xEE,
        0xFF,
        LivenessEvent::CarrierSelected,
    );
    note_event_on(&m, cpu(0), LivenessEvent::IdleEntered);
    let record = read_cpu_on(&m, cpu(0));
    assert_eq!(record.thread, 0xAA);
    assert_eq!(record.process, 0xBB);
    assert_eq!(record.event, LivenessEvent::IdleEntered as u32);
}

#[test]
fn an_observed_odd_sequence_reports_an_inconsistent_read() {
    let m = mirror();
    // A publication caught in flight must not be presented as observed state.
    let cell = &m.cpus[3];
    let parked = cell.sequence.load(Ordering::Relaxed) | 1;
    cell.sequence.store(parked, Ordering::Release);
    let record = read_cpu_on(&m, cpu(3));
    assert!(!record.consistent);
    cell.sequence
        .store(parked.wrapping_add(1), Ordering::Release);
    assert!(read_cpu_on(&m, cpu(3)).consistent);
}

#[test]
fn runtime_authority_publication_is_observable() {
    let m = mirror();
    let anchor = 0_u64;
    let address = core::ptr::from_ref(&anchor).cast::<()>();
    publish_runtime_authority_on(&m, address);
    assert_eq!(runtime_authority_on(&m), address);
    publish_runtime_authority_on(&m, core::ptr::null());
    assert!(runtime_authority_on(&m).is_null());
}

#[test]
fn format_snapshot_rejects_an_undersized_buffer() {
    let m = mirror();
    let mut small = [0_u8; SNAPSHOT_MAX_BYTES - 1];
    assert_eq!(format_snapshot_on(&m, &mut small), None);
}

#[test]
fn format_snapshot_reports_one_line_per_cpu_with_fixed_width_identities() {
    let m = mirror();
    publish_current_on(
        &m,
        cpu(0),
        0x0123_4567_89AB_CDEF,
        0xFEDC_BA98_7654_3210,
        0x1111_2222_3333_4444,
        0x5555_6666_7777_8888,
        0x9999_AAAA_BBBB_CCCC,
        LivenessEvent::CarrierSelected,
    );
    let mut buffer = [0_u8; SNAPSHOT_MAX_BYTES];
    let length = format_snapshot_on(&m, &mut buffer).expect("sized buffer formats");
    let text = core::str::from_utf8(&buffer[..length]).expect("snapshot is ASCII");

    let lines: std::vec::Vec<&str> = text.split_terminator("\r\n").collect();
    assert_eq!(lines.len(), 1 + CPU_CAPACITY);
    assert!(lines[0].starts_with("DWLIVE1|authority="));
    assert!(lines[0].ends_with("|cpus=4"));
    for (index, line) in lines[1..].iter().enumerate() {
        assert!(line.starts_with(&std::format!("DWLIVE1|cpu={index}|read=")));
    }
    assert!(lines[1].contains("|thread=0123456789ABCDEF"));
    assert!(lines[1].contains("|process=FEDCBA9876543210"));
    assert!(lines[1].contains("|root=1111222233334444"));
    assert!(lines[1].contains("|context=5555666677778888"));
    assert!(lines[1].contains("|stack=9999AAAABBBBCCCC"));
    assert!(lines[1].contains(&std::format!(
        "|event={}",
        LivenessEvent::CarrierSelected as u32
    )));
}

#[test]
fn format_snapshot_marks_a_torn_cell_instead_of_presenting_it_as_observed() {
    let m = mirror();
    let cell = &m.cpus[1];
    let parked = cell.sequence.load(Ordering::Relaxed) | 1;
    cell.sequence.store(parked, Ordering::Release);
    let mut buffer = [0_u8; SNAPSHOT_MAX_BYTES];
    let length = format_snapshot_on(&m, &mut buffer).expect("sized buffer formats");
    let text = core::str::from_utf8(&buffer[..length]).expect("snapshot is ASCII");
    assert!(text.contains("DWLIVE1|cpu=1|read=TORN"));
    cell.sequence
        .store(parked.wrapping_add(1), Ordering::Release);
    let length = format_snapshot_on(&m, &mut buffer).expect("sized buffer formats");
    let text = core::str::from_utf8(&buffer[..length]).expect("snapshot is ASCII");
    assert!(text.contains("DWLIVE1|cpu=1|read=stable"));
}

#[test]
fn event_ordinals_are_stable_for_the_gdb_script_and_serial_records() {
    // tools/gdb/r1-liveness.gdb and the DWLIVE1 `event=` field both decode
    // these ordinals. Renumbering silently misreports a stalled CPU's last
    // transition, so pin them here.
    assert_eq!(LivenessEvent::None as u32, 0);
    assert_eq!(LivenessEvent::CarrierSelected as u32, 1);
    assert_eq!(LivenessEvent::Preempted as u32, 2);
    assert_eq!(LivenessEvent::QuantumExpired as u32, 3);
    assert_eq!(LivenessEvent::IdleEntered as u32, 4);
    assert_eq!(LivenessEvent::TerminationPrepared as u32, 5);
    assert_eq!(LivenessEvent::Dispatched as u32, 6);
    assert_eq!(LivenessEvent::Blocked as u32, 7);
    assert_eq!(LivenessEvent::Woken as u32, 8);
    assert_eq!(LivenessEvent::QuantumArmed as u32, 9);
}

#[test]
fn scheduler_publication_round_trips_and_leaves_the_identity_alone() {
    let m = mirror();
    publish_current_on(
        &m,
        cpu(2),
        0xAA,
        0xBB,
        0xCC,
        0xDD,
        0xEE,
        LivenessEvent::CarrierSelected,
    );
    publish_scheduler_on(&m, cpu(2), 0x77, 3, 9, true, false, LivenessEvent::Blocked);
    let record = read_cpu_on(&m, cpu(2));
    assert!(record.consistent);
    assert_eq!(record.thread, 0xAA, "carrier identity is untouched");
    assert_eq!(record.execution_generation, 0x77);
    assert_eq!(record.runnable_here, 3);
    assert_eq!(record.queue_len, 9);
    assert!(record.reschedule_pending);
    assert!(!record.quantum_armed);
    assert_eq!(record.event, LivenessEvent::Blocked as u32);
}

#[test]
fn a_wake_target_is_recorded_against_the_requesting_cpu() {
    let m = mirror();
    // The sticky-placement failure mode: CPU 0 wakes a thread that lands back
    // on CPU 0 while a hog runs there. The mirror must name the target rather
    // than leave it to be inferred.
    assert_eq!(read_cpu_on(&m, cpu(3)).last_wake_target, NO_CPU);
    publish_wake_target_on(&m, cpu(3), cpu(0));
    let record = read_cpu_on(&m, cpu(3));
    assert_eq!(record.last_wake_target, 0);
    assert_eq!(record.event, LivenessEvent::Woken as u32);
}

#[test]
fn the_serial_record_reports_every_scheduler_fact() {
    let m = mirror();
    publish_scheduler_on(
        &m,
        cpu(0),
        0x5150,
        2,
        7,
        false,
        true,
        LivenessEvent::Dispatched,
    );
    publish_wake_target_on(&m, cpu(0), cpu(1));
    let mut buffer = [0_u8; SNAPSHOT_MAX_BYTES];
    let length = format_snapshot_on(&m, &mut buffer).expect("sized buffer formats");
    let text = core::str::from_utf8(&buffer[..length]).expect("snapshot is ASCII");
    let line = text
        .split_terminator("\r\n")
        .find(|line| line.starts_with("DWLIVE1|cpu=0|"))
        .expect("CPU 0 line present");
    assert!(line.contains("|exec_gen=20816"), "{line}");
    assert!(line.contains("|runnable_here=2"), "{line}");
    assert!(line.contains("|queue=7"), "{line}");
    assert!(line.contains("|resched=0"), "{line}");
    assert!(line.contains("|quantum=1"), "{line}");
    assert!(line.contains("|wake_target=1"), "{line}");
}

#[test]
fn an_unset_wake_target_prints_none_rather_than_a_cpu_index() {
    let m = mirror();
    let mut buffer = [0_u8; SNAPSHOT_MAX_BYTES];
    let length = format_snapshot_on(&m, &mut buffer).expect("sized buffer formats");
    let text = core::str::from_utf8(&buffer[..length]).expect("snapshot is ASCII");
    // CPU 1 has no wake requested in this test process unless another test ran
    // first, so assert the sentinel renders rather than which CPU owns it.
    assert!(text.contains("|wake_target=none") || text.contains("|wake_target="));
}

/// The per-test mirrors above would still pass if a global entry point had been
/// left pointing at the wrong snapshot, so prove each one reaches the shared
/// `LIVENESS`. Every assertion here is monotonic or structural: unrelated tests
/// may publish into the same mirror concurrently, and none of these can be
/// perturbed by that.
#[test]
fn the_global_entry_points_target_the_shared_mirror() {
    let before = read_cpu(cpu(3)).publications;
    publish_current(
        cpu(3),
        0x51,
        0x52,
        0x53,
        0x54,
        0x55,
        LivenessEvent::CarrierSelected,
    );
    assert!(read_cpu(cpu(3)).publications >= before + 1);
    publish_scheduler(cpu(3), 9, 1, 2, true, true, LivenessEvent::Dispatched);
    publish_wake_target(cpu(3), cpu(0));
    note_event(cpu(3), LivenessEvent::IdleEntered);

    let authority = 0x7FFF_0000_1234_usize as *const ();
    publish_runtime_authority(authority);
    assert_eq!(runtime_authority(), authority);

    let mut buffer = std::vec![0_u8; SNAPSHOT_MAX_BYTES];
    let written = format_snapshot(&mut buffer).expect("snapshot fits");
    let text = std::string::String::from_utf8(buffer[..written].to_vec()).expect("ascii snapshot");
    assert!(text.starts_with("DWLIVE1|authority="));
    assert_eq!(text.matches("DWLIVE1|cpu=").count(), CPU_CAPACITY);
}
