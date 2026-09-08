// Host-only composition of Wyrmroot producer bytes with the actual collector.
// Included inside the collector's test module to reuse its reporter setup.

#[test]
#[ignore = "requires a fresh Wyrmroot producer prefix; run the root E8 fixture tool"]
fn e8_imported_producer_prefix() {
    extern crate std;
    use std::io::Read;

    const PREFIX_BYTES: usize = 24 * WYR1E_EVIDENCE_RECORD_LEN;
    let path = std::path::PathBuf::from(
        std::env::var_os("DEEPWYRM_E8_PRODUCER_PREFIX")
            .expect("DEEPWYRM_E8_PRODUCER_PREFIX is required"),
    );
    assert!(path.is_absolute(), "fixture path must be absolute");
    let metadata = std::fs::symlink_metadata(&path).expect("fixture metadata");
    assert!(metadata.file_type().is_file(), "fixture must be regular");
    assert_eq!(metadata.len(), PREFIX_BYTES as u64);
    let mut bytes = [0u8; PREFIX_BYTES];
    let mut file = std::fs::File::open(path).expect("open producer prefix");
    file.read_exact(&mut bytes)
        .expect("read exact producer prefix");
    assert_eq!(file.read(&mut [0u8; 1]).expect("fixture EOF"), 0);

    let nonce = read_u64(&bytes, 24);
    assert_ne!(nonce, 0);
    assert_eq!(
        nonce,
        parse_build_nonce(
            option_env!("DEEPWYRM_WYR1E8_EVIDENCE_NONCE")
                .expect("select the E8 host build with the producer nonce")
        )
    );
    let collector = Wyr1eEvidenceCollector::new_v1_1(nonce);
    let (reporter, thread, root) = subject();
    arm(&collector, reporter, thread, root);
    for (index, chunk) in bytes.chunks_exact(WYR1E_EVIDENCE_RECORD_LEN).enumerate() {
        let record: &[u8; WYR1E_EVIDENCE_RECORD_LEN] = chunk.try_into().unwrap();
        let decoded =
            decode_record(record, EvidenceVersion::V1_1).expect("producer record framing");
        let first_predicate = {
            let state = collector.transcript.lock();
            if index == 21 {
                let ready = decode_record(
                    bytes[20 * WYR1E_EVIDENCE_RECORD_LEN..21 * WYR1E_EVIDENCE_RECORD_LEN]
                        .try_into()
                        .unwrap(),
                    EvidenceVersion::V1_1,
                )
                .unwrap();
                assert_eq!(
                    (
                        state.count,
                        state.stage,
                        state.epoch_transactions,
                        state.last_transaction
                    ),
                    (21, 2, 0, 0)
                );
                assert_eq!(state.shell, Some(ready.shell));
                assert_eq!(state.failure, None);
                assert_eq!(decoded.record_type, RECORD_SHELLJOBS_TRANSACTION);
            } else if index == 22 {
                assert_eq!(
                    (state.count, state.stage, state.epoch_transactions),
                    (22, 2, 1)
                );
                assert!(state.shell.is_some());
                assert_eq!(decoded.record_type, RECORD_SHELL_EXITED);
            } else if index == 23 {
                assert_eq!(
                    (state.count, state.stage, state.epoch_transactions),
                    (23, 2, 1)
                );
                assert!(state.shell.is_none());
                assert_eq!(decoded.record_type, RECORD_SHELL_READY);
            }
            std::println!(
                "E8FIXTURE_PRESTATE index={} stage={} epoch_transactions={} last_transaction={} shell={:?}",
                index + 1,
                state.stage,
                state.epoch_transactions,
                state.last_transaction,
                state.shell,
            );
            // This explains a failure only; submit below remains authoritative.
            if decoded.sequence != state.count as u64 + 1 {
                "record sequence"
            } else if decoded.nonce != nonce {
                "build nonce"
            } else if !decoded.shell.all_nonzero() {
                "shell tuple contains zero"
            } else if decoded.record_type != RECORD_SHELLJOBS_TRANSACTION {
                "lifecycle record; collector relation is authoritative"
            } else if Some(decoded.shell) != state.shell {
                "current shell tuple"
            } else if !transaction_kind_matches(
                state.stage,
                state.epoch_transactions,
                decoded.message_kind,
                state.stage4_profile,
            ) {
                "stage/slot/protocol kind"
            } else if decoded.operation_transaction == 0 {
                "zero transaction"
            } else if decoded.operation_transaction <= state.last_transaction {
                "transaction watermark"
            } else if decoded.digest == [0; 32] {
                "zero digest"
            } else if matches!(state.stage, 2 | 3) && decoded.operation_job == 0 {
                "zero trigger job"
            } else {
                "no transaction relation predicate failed"
            }
        };
        match collector.submit(reporter, record) {
            Ok(Wyr1eEvidenceSubmit::Accepted) => {}
            Ok(Wyr1eEvidenceSubmit::Terminal(_)) => panic!("prefix unexpectedly terminal"),
            Err(error) => panic!(
                "producer record {} rejected: {error:?}; first predicate: {first_predicate}; bytes={record:02x?}",
                index + 1
            ),
        }
    }
    let state = collector.transcript.lock();
    assert_eq!(
        (state.count, state.stage, state.epoch_transactions),
        (24, 3, 0)
    );
    assert!(!state.terminal);
    assert_eq!(state.failure, None);
    std::println!("E8FIXTURE_COLLECTOR accepted=24 stage=3 epoch_transactions=0 terminal=false");
}
