extern crate std;

use super::*;
use crate::object::ObjectRegistry;
use deepwyrm_abi::DW_OBJECT_TYPE_PROCESS;

const NONCE: u64 = 0x0000_0000_5A70_0001;

/// Two distinct real registry Processes, following the selector-29 collector's
/// test pattern rather than inventing a test-only identity constructor.
fn processes() -> (ProcessKey, ProcessKey) {
    let mut registry = ObjectRegistry::<2>::new();
    let first = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    let second = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    (
        ProcessKey::from_object_id(first.id()),
        ProcessKey::from_object_id(second.id()),
    )
}

fn record(kind: u32, sequence: u64, nonce: u64) -> [u8; R1_EVIDENCE_RECORD_LEN] {
    let mut bytes = [0_u8; R1_EVIDENCE_RECORD_LEN];
    bytes[0..4].copy_from_slice(&MAGIC);
    bytes[4..6].copy_from_slice(&MAJOR.to_le_bytes());
    bytes[6..8].copy_from_slice(&MINOR.to_le_bytes());
    bytes[8..12].copy_from_slice(&kind.to_le_bytes());
    bytes[12..16].copy_from_slice(&(R1_EVIDENCE_RECORD_LEN as u32).to_le_bytes());
    bytes[16..24].copy_from_slice(&sequence.to_le_bytes());
    bytes[24..32].copy_from_slice(&nonce.to_le_bytes());
    bytes
}

/// A Process that is deliberately not the established reporter.
fn foreign() -> ProcessKey {
    processes().1
}

fn ready() -> (R1EvidenceCollector, ProcessKey) {
    let collector = R1EvidenceCollector::new();
    collector.configure(NONCE).expect("configure once");
    let (reporter, _other) = processes();
    collector.claim_reporter(reporter).expect("claim once");
    (collector, reporter)
}

#[test]
fn a_zero_nonce_is_refused_so_an_unconfigured_product_accepts_nothing() {
    let collector = R1EvidenceCollector::new();
    assert_eq!(collector.configure(0), Err(R1EvidenceError::Malformed));
    assert_eq!(
        collector.submit(processes().0, &record(RECORD_STEP, 1, NONCE)),
        Err(R1EvidenceError::Early)
    );
}

#[test]
fn configure_and_claim_are_each_once_only() {
    let collector = R1EvidenceCollector::new();
    collector.configure(NONCE).expect("configure once");
    assert_eq!(
        collector.configure(NONCE),
        Err(R1EvidenceError::ReporterClaimed)
    );
    collector.claim_reporter(processes().0).expect("claim once");
    assert_eq!(
        collector.claim_reporter(processes().1),
        Err(R1EvidenceError::ReporterClaimed)
    );
}

#[test]
fn claiming_before_configuration_is_refused() {
    let collector = R1EvidenceCollector::new();
    assert_eq!(
        collector.claim_reporter(processes().0),
        Err(R1EvidenceError::Early)
    );
}

#[test]
fn a_consecutive_stream_is_retained_in_order_and_closed_once() {
    let (collector, reporter) = ready();
    for sequence in 1..=4 {
        assert_eq!(
            collector.submit(reporter, &record(RECORD_STEP, sequence, NONCE)),
            Ok(sequence)
        );
    }
    assert_eq!(
        collector.submit(reporter, &record(RECORD_TERMINAL, 5, NONCE)),
        Ok(5)
    );
    assert_eq!(collector.len(), 5);
    assert!(collector.terminal_seen());
    for index in 0..5 {
        assert_eq!(
            collector.record(index).expect("retained").sequence,
            index as u64 + 1
        );
    }
    assert!(collector.record(5).is_none());
}

#[test]
fn only_the_established_reporter_may_submit() {
    let (collector, reporter) = ready();
    assert_eq!(
        collector.submit(foreign(), &record(RECORD_STEP, 1, NONCE)),
        Err(R1EvidenceError::WrongReporter)
    );
    assert_eq!(collector.len(), 0);
    assert_eq!(
        collector.submit(reporter, &record(RECORD_STEP, 1, NONCE)),
        Ok(1)
    );
}

#[test]
fn a_foreign_nonce_is_refused_without_retaining_the_record() {
    let (collector, reporter) = ready();
    assert_eq!(
        collector.submit(reporter, &record(RECORD_STEP, 1, NONCE ^ 1)),
        Err(R1EvidenceError::WrongNonce)
    );
    assert_eq!(collector.len(), 0);
}

#[test]
fn transport_framing_is_validated_field_by_field() {
    let (collector, reporter) = ready();
    let mut wrong_magic = record(RECORD_STEP, 1, NONCE);
    wrong_magic[0] = b'X';
    assert_eq!(
        collector.submit(reporter, &wrong_magic),
        Err(R1EvidenceError::Malformed)
    );

    let mut wrong_major = record(RECORD_STEP, 1, NONCE);
    wrong_major[4..6].copy_from_slice(&2_u16.to_le_bytes());
    assert_eq!(
        collector.submit(reporter, &wrong_major),
        Err(R1EvidenceError::Malformed)
    );

    let mut wrong_length = record(RECORD_STEP, 1, NONCE);
    wrong_length[12..16].copy_from_slice(&63_u32.to_le_bytes());
    assert_eq!(
        collector.submit(reporter, &wrong_length),
        Err(R1EvidenceError::Malformed)
    );

    let mut reserved_set = record(RECORD_STEP, 1, NONCE);
    reserved_set[60..64].copy_from_slice(&1_u32.to_le_bytes());
    assert_eq!(
        collector.submit(reporter, &reserved_set),
        Err(R1EvidenceError::Malformed)
    );

    let unknown_kind = record(7, 1, NONCE);
    assert_eq!(
        collector.submit(reporter, &unknown_kind),
        Err(R1EvidenceError::Malformed)
    );

    assert_eq!(collector.len(), 0, "no rejected record is retained");
}

#[test]
fn a_nonconsecutive_sequence_is_refused_in_both_directions() {
    let (collector, reporter) = ready();
    assert_eq!(
        collector.submit(reporter, &record(RECORD_STEP, 2, NONCE)),
        Err(R1EvidenceError::OutOfOrder)
    );
    assert_eq!(
        collector.submit(reporter, &record(RECORD_STEP, 1, NONCE)),
        Ok(1)
    );
    assert_eq!(
        collector.submit(reporter, &record(RECORD_STEP, 1, NONCE)),
        Err(R1EvidenceError::OutOfOrder)
    );
    assert_eq!(
        collector.submit(reporter, &record(RECORD_STEP, 3, NONCE)),
        Err(R1EvidenceError::OutOfOrder)
    );
}

#[test]
fn a_failed_probe_may_not_report_further_steps() {
    let (collector, reporter) = ready();
    assert_eq!(
        collector.submit(reporter, &record(RECORD_STEP, 1, NONCE)),
        Ok(1)
    );
    assert_eq!(
        collector.submit(reporter, &record(RECORD_FAILED, 2, NONCE)),
        Ok(2)
    );
    assert_eq!(
        collector.submit(reporter, &record(RECORD_STEP, 3, NONCE)),
        Err(R1EvidenceError::Framing)
    );
    assert_eq!(
        collector.submit(reporter, &record(RECORD_FAILED, 3, NONCE)),
        Err(R1EvidenceError::Framing)
    );
    // The terminal record still closes a failed run.
    assert_eq!(
        collector.submit(reporter, &record(RECORD_TERMINAL, 3, NONCE)),
        Ok(3)
    );
}

#[test]
fn nothing_follows_the_terminal_record() {
    let (collector, reporter) = ready();
    assert_eq!(
        collector.submit(reporter, &record(RECORD_TERMINAL, 1, NONCE)),
        Ok(1)
    );
    assert_eq!(
        collector.submit(reporter, &record(RECORD_STEP, 2, NONCE)),
        Err(R1EvidenceError::AfterTerminal)
    );
    assert_eq!(
        collector.submit(reporter, &record(RECORD_TERMINAL, 2, NONCE)),
        Err(R1EvidenceError::AfterTerminal)
    );
    assert_eq!(collector.len(), 1);
}

#[test]
fn the_bounded_buffer_refuses_an_overflowing_stream() {
    let (collector, reporter) = ready();
    for sequence in 1..=R1_EVIDENCE_RECORD_CAPACITY as u64 {
        assert_eq!(
            collector.submit(reporter, &record(RECORD_STEP, sequence, NONCE)),
            Ok(sequence)
        );
    }
    assert_eq!(
        collector.submit(
            reporter,
            &record(RECORD_STEP, R1_EVIDENCE_RECORD_CAPACITY as u64 + 1, NONCE)
        ),
        Err(R1EvidenceError::Full)
    );
    assert_eq!(collector.len(), R1_EVIDENCE_RECORD_CAPACITY);
}

#[test]
fn the_private_syscall_id_does_not_collide_with_another_selector() {
    // Allocated ids: ff19 wyr1, ff1a dw1b, ff1b wyr1b, ff1c dw1c, ff1d dw1d,
    // ff1e wyr1c, ff1f dw1e, ff20 wyr1d, ff21 wyr1e/e7/e8.
    const { assert!(R1_EVIDENCE_RAW_SYSCALL == 0xffff_ff22) };
    for taken in [
        0xffff_ff19_u32,
        0xffff_ff1a,
        0xffff_ff1b,
        0xffff_ff1c,
        0xffff_ff1d,
        0xffff_ff1e,
        0xffff_ff1f,
        0xffff_ff20,
        0xffff_ff21,
    ] {
        assert_ne!(R1_EVIDENCE_RAW_SYSCALL, taken);
    }
}
