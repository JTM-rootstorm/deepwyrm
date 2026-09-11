extern crate std;

use super::*;

fn cpu(index: usize) -> CpuIndex {
    CpuIndex::new(index).expect("bounded diagnostic CPU index")
}

#[test]
fn publication_round_trips_every_mirrored_field() {
    publish_current(
        cpu(1),
        0x1111,
        0x2222,
        0x4444,
        0x5555,
        0x6666,
        LivenessEvent::CarrierSelected,
    );
    let record = read_cpu(cpu(1));
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
    let before = read_cpu(cpu(2)).publications;
    publish_current(cpu(2), 1, 2, 4, 5, 6, LivenessEvent::Preempted);
    publish_current(cpu(2), 7, 8, 10, 11, 12, LivenessEvent::QuantumExpired);
    let after = read_cpu(cpu(2));
    assert!(after.consistent);
    assert_eq!(after.publications, before + 2);
    assert_eq!(after.thread, 7);
    assert_eq!(after.event, LivenessEvent::QuantumExpired as u32);
    assert!(
        LIVENESS.cpus[2]
            .sequence
            .load(Ordering::Relaxed)
            .is_multiple_of(2)
    );
}

#[test]
fn note_event_preserves_the_mirrored_identity() {
    publish_current(
        cpu(0),
        0xAA,
        0xBB,
        0xDD,
        0xEE,
        0xFF,
        LivenessEvent::CarrierSelected,
    );
    note_event(cpu(0), LivenessEvent::IdleEntered);
    let record = read_cpu(cpu(0));
    assert_eq!(record.thread, 0xAA);
    assert_eq!(record.process, 0xBB);
    assert_eq!(record.event, LivenessEvent::IdleEntered as u32);
}

#[test]
fn an_observed_odd_sequence_reports_an_inconsistent_read() {
    // A publication caught in flight must not be presented as observed state.
    let cell = &LIVENESS.cpus[3];
    let parked = cell.sequence.load(Ordering::Relaxed) | 1;
    cell.sequence.store(parked, Ordering::Release);
    let record = read_cpu(cpu(3));
    assert!(!record.consistent);
    cell.sequence
        .store(parked.wrapping_add(1), Ordering::Release);
    assert!(read_cpu(cpu(3)).consistent);
}

#[test]
fn runtime_authority_publication_is_observable() {
    let anchor = 0_u64;
    let address = core::ptr::from_ref(&anchor).cast::<()>();
    publish_runtime_authority(address);
    assert_eq!(runtime_authority(), address);
    publish_runtime_authority(core::ptr::null());
    assert!(runtime_authority().is_null());
}

#[test]
fn format_snapshot_rejects_an_undersized_buffer() {
    let mut small = [0_u8; SNAPSHOT_MAX_BYTES - 1];
    assert_eq!(format_snapshot(&mut small), None);
}

#[test]
fn format_snapshot_reports_one_line_per_cpu_with_fixed_width_identities() {
    publish_current(
        cpu(0),
        0x0123_4567_89AB_CDEF,
        0xFEDC_BA98_7654_3210,
        0x1111_2222_3333_4444,
        0x5555_6666_7777_8888,
        0x9999_AAAA_BBBB_CCCC,
        LivenessEvent::CarrierSelected,
    );
    let mut buffer = [0_u8; SNAPSHOT_MAX_BYTES];
    let length = format_snapshot(&mut buffer).expect("sized buffer formats");
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
    let cell = &LIVENESS.cpus[1];
    let parked = cell.sequence.load(Ordering::Relaxed) | 1;
    cell.sequence.store(parked, Ordering::Release);
    let mut buffer = [0_u8; SNAPSHOT_MAX_BYTES];
    let length = format_snapshot(&mut buffer).expect("sized buffer formats");
    let text = core::str::from_utf8(&buffer[..length]).expect("snapshot is ASCII");
    assert!(text.contains("DWLIVE1|cpu=1|read=TORN"));
    cell.sequence
        .store(parked.wrapping_add(1), Ordering::Release);
    let length = format_snapshot(&mut buffer).expect("sized buffer formats");
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
}
