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

/// The terminal record is what says whether the probe passed, so a transcript
/// without one must not be emitted as if it were complete.
#[test]
fn a_transcript_without_a_terminal_record_refuses_to_flush() {
    let (collector, reporter) = ready();
    match collector
        .submit_once(reporter, &record(RECORD_STEP, 1, NONCE))
        .expect("step accepted")
    {
        R1EvidenceSubmit::Accepted => {}
        R1EvidenceSubmit::Terminal(_) => panic!("a step must not mint a flush permit"),
    }
    // Reach the guard directly: only a terminal record mints a permit, so this
    // is the one path that can observe an incomplete transcript.
    let permit = R1EvidenceFlushPermit {
        collector: &collector,
    };
    assert_eq!(
        permit.flush(|_| Ok(())).unwrap_err(),
        R1EvidenceFlushError::Incomplete
    );
}

#[test]
fn the_terminal_record_mints_a_permit_that_flushes_every_record_in_order() {
    let (collector, reporter) = ready();
    collector
        .submit_once(reporter, &record(RECORD_STEP, 1, NONCE))
        .expect("step accepted");
    let permit = match collector
        .submit_once(reporter, &record(RECORD_TERMINAL, 2, NONCE))
        .expect("terminal accepted")
    {
        R1EvidenceSubmit::Terminal(permit) => permit,
        R1EvidenceSubmit::Accepted => panic!("the terminal record must mint a flush permit"),
    };
    let mut emitted = std::vec::Vec::new();
    permit
        .flush(|bytes| {
            emitted.push(*bytes);
            Ok(())
        })
        .expect("flush succeeds");
    assert_eq!(emitted.len(), 2);
    let sequences = emitted
        .iter()
        .map(|bytes| u64::from_le_bytes(bytes[16..24].try_into().unwrap()))
        .collect::<std::vec::Vec<_>>();
    assert_eq!(sequences, std::vec![1, 2]);
    let kinds = emitted
        .iter()
        .map(|bytes| u32::from_le_bytes(bytes[8..12].try_into().unwrap()))
        .collect::<std::vec::Vec<_>>();
    assert_eq!(kinds, std::vec![RECORD_STEP, RECORD_TERMINAL]);
}

/// A transport refusal must surface, not be swallowed into a partial emission
/// that the host would read as a complete certificate.
#[test]
fn a_transport_failure_stops_the_flush_and_is_reported() {
    let (collector, reporter) = ready();
    collector
        .submit_once(reporter, &record(RECORD_STEP, 1, NONCE))
        .expect("step accepted");
    let permit = match collector
        .submit_once(reporter, &record(RECORD_TERMINAL, 2, NONCE))
        .expect("terminal accepted")
    {
        R1EvidenceSubmit::Terminal(permit) => permit,
        R1EvidenceSubmit::Accepted => panic!("terminal mints a permit"),
    };
    let mut seen = 0_usize;
    let failure = permit
        .flush(|_| {
            seen += 1;
            Err(R1EvidenceFlushError::Transport)
        })
        .unwrap_err();
    assert_eq!(failure, R1EvidenceFlushError::Transport);
    assert_eq!(seen, 1, "the flush stops at the first refused record");
}

/// A failure record is retained and flushed alongside the terminal record, so a
/// failing run still reports which classification stopped it.
#[test]
fn a_failed_run_flushes_its_failure_record_with_the_terminal_record() {
    let (collector, reporter) = ready();
    collector
        .submit_once(reporter, &record(RECORD_STEP, 1, NONCE))
        .expect("step accepted");
    collector
        .submit_once(reporter, &record(RECORD_FAILED, 2, NONCE))
        .expect("failure accepted");
    let permit = match collector
        .submit_once(reporter, &record(RECORD_TERMINAL, 3, NONCE))
        .expect("terminal accepted")
    {
        R1EvidenceSubmit::Terminal(permit) => permit,
        R1EvidenceSubmit::Accepted => panic!("terminal mints a permit"),
    };
    let mut kinds = std::vec::Vec::new();
    permit
        .flush(|bytes| {
            kinds.push(u32::from_le_bytes(bytes[8..12].try_into().unwrap()));
            Ok(())
        })
        .expect("flush succeeds");
    assert_eq!(
        kinds,
        std::vec![RECORD_STEP, RECORD_FAILED, RECORD_TERMINAL]
    );
}

/// The permit is the only way in, and `submit` already refuses a second
/// terminal record, so the terminal serial path cannot be entered twice.
#[test]
fn a_second_terminal_record_is_refused_so_the_flush_path_is_single_entry() {
    let (collector, reporter) = ready();
    collector
        .submit_once(reporter, &record(RECORD_TERMINAL, 1, NONCE))
        .expect("terminal accepted");
    match collector.submit_once(reporter, &record(RECORD_TERMINAL, 2, NONCE)) {
        Err(error) => assert_eq!(error, R1EvidenceError::AfterTerminal),
        Ok(_) => panic!("a second terminal record must be refused"),
    }
}

/// A configured collector is ready without a boot-time `configure` call, so a
/// product cannot boot with a collector that silently accepts nothing.
#[test]
fn a_build_configured_collector_is_ready_and_rejects_a_foreign_nonce() {
    let collector = R1EvidenceCollector::new_configured(NONCE);
    // Already READY: configure is refused rather than able to replace the nonce.
    assert_eq!(
        collector.configure(NONCE ^ 0xFF),
        Err(R1EvidenceError::ReporterClaimed)
    );
    let (reporter, _other) = processes();
    collector.claim_reporter(reporter).expect("claim once");
    assert_eq!(
        collector.submit(reporter, &record(RECORD_STEP, 1, NONCE ^ 0xFF)),
        Err(R1EvidenceError::WrongNonce)
    );
    assert_eq!(
        collector.submit(reporter, &record(RECORD_STEP, 1, NONCE)),
        Ok(1)
    );
}

/// The build nonce is parsed at compile time from an uppercase 16-digit string.
#[test]
fn the_build_nonce_parser_accepts_the_canonical_form() {
    const { assert!(parse_build_nonce("8100000000000001") == 0x8100_0000_0000_0001) };
    const { assert!(parse_build_nonce("FFFFFFFFFFFFFFFF") == u64::MAX) };
    assert_eq!(parse_build_nonce("00000000000000FF"), 0xFF);
}

/// A terminal record that declares zero is the probe's pass value.
#[test]
fn a_passing_terminal_record_declares_no_failure() {
    let (collector, reporter) = ready();
    let permit = match collector
        .submit_once(reporter, &record(RECORD_TERMINAL, 1, NONCE))
        .expect("terminal accepted")
    {
        R1EvidenceSubmit::Terminal(permit) => permit,
        R1EvidenceSubmit::Accepted => panic!("the terminal record must mint a flush permit"),
    };
    assert_eq!(permit.declared_failure(), Ok(None));
}

/// The run-12 case. The transcript is well-formed and complete, and the probe
/// still says it failed. Reporting transport integrity as a pass here is what
/// let `DWTEST1|01|` certify a run whose terminal record carried ordinal 9.
#[test]
fn a_terminal_record_that_declares_a_failure_is_not_a_pass() {
    let (collector, reporter) = ready();
    collector
        .submit_once(reporter, &record(RECORD_STEP, 1, NONCE))
        .expect("step accepted");
    let mut terminal = record(RECORD_TERMINAL, 2, NONCE);
    terminal[TERMINAL_OUTCOME_OFFSET..TERMINAL_OUTCOME_OFFSET + 4]
        .copy_from_slice(&9_u32.to_le_bytes());
    let permit = match collector
        .submit_once(reporter, &terminal)
        .expect("terminal accepted")
    {
        R1EvidenceSubmit::Terminal(permit) => permit,
        R1EvidenceSubmit::Accepted => panic!("the terminal record must mint a flush permit"),
    };
    assert_eq!(permit.declared_failure(), Ok(Some(9)));
    // The records are still emitted: a failing run's transcript is the evidence.
    let mut emitted = 0_usize;
    permit
        .flush(|_| {
            emitted += 1;
            Ok(())
        })
        .expect("a declared failure still flushes its transcript");
    assert_eq!(emitted, 2);
}

/// The verdict is read from the terminal record, not from an earlier one.
#[test]
fn an_earlier_records_outcome_word_is_not_the_verdict() {
    let (collector, reporter) = ready();
    let mut step = record(RECORD_STEP, 1, NONCE);
    step[TERMINAL_OUTCOME_OFFSET..TERMINAL_OUTCOME_OFFSET + 4]
        .copy_from_slice(&7_u32.to_le_bytes());
    collector
        .submit_once(reporter, &step)
        .expect("step accepted");
    let permit = match collector
        .submit_once(reporter, &record(RECORD_TERMINAL, 2, NONCE))
        .expect("terminal accepted")
    {
        R1EvidenceSubmit::Terminal(permit) => permit,
        R1EvidenceSubmit::Accepted => panic!("the terminal record must mint a flush permit"),
    };
    assert_eq!(permit.declared_failure(), Ok(None));
}

/// Source contract for the terminal that no host test can execute.
///
/// `test_support/x86_64.rs` compiles only for the bare target, so the branch
/// that turns a declared failure into `DWTEST1|02|` cannot be run here. The
/// collector tests above prove the verdict is readable; this proves the
/// terminal actually reads it, in the shape the DW1-C/D/E gates already use.
#[test]
fn the_selector_34_terminal_refuses_to_certify_a_declared_failure() {
    const SOURCE: &str = include_str!("../x86_64.rs");
    let body = SOURCE
        .split("pub(crate) fn complete_r1_evidence(")
        .nth(1)
        .expect("selector 34 still has its evidence terminal")
        .split("\nfn claim_r1_terminal(")
        .next()
        .expect("the evidence terminal is still followed by its claim helper");

    let verdict = body
        .find("permit.declared_failure()")
        .expect("the terminal must read the probe's own verdict before certifying");
    let flush = body
        .find(".flush(")
        .expect("the terminal still flushes the transcript");
    assert!(
        verdict < flush,
        "the verdict must be read before the flush consumes the permit"
    );

    // The pass record must be reachable only through the no-failure arm. An
    // unconditional `completion_record(CompletionOutcome::Pass, 0)` is exactly
    // what certified run 12.
    assert!(
        body.contains("None => completion_record(CompletionOutcome::Pass, 0)"),
        "selector 34's pass record is no longer guarded by the absent-failure arm"
    );
    assert_eq!(
        body.matches("CompletionOutcome::Pass").count(),
        1,
        "selector 34's evidence terminal names Pass more than once, so one of \
         them is not the guarded arm"
    );
    assert!(
        body.contains("CompletionOutcome::Fail, 0x3411_0000"),
        "a declared failure must reach DWTEST1 as a Fail carrying its ordinal"
    );
    // Contention on the verdict must not read as a pass.
    assert!(
        body.contains("let Ok(declared_failure) = permit.declared_failure() else {"),
        "an unreadable verdict must fail stop rather than default to a pass"
    );
}
