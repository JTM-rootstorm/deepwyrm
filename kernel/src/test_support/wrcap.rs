//! Test-only bounded relay for Wyrmroot-owned WRCAP1 evidence.
//!
//! The kernel does not originate or reinterpret capability facts. It accepts
//! the ten canonical, handle-free records in exact order, preserves their raw
//! bytes, and authorizes one terminal reporter to relay them over COM1.

#![cfg_attr(
    not(target_os = "none"),
    allow(
        dead_code,
        reason = "host builds validate the selector-only target relay and its parser tests"
    )
)]

use core::sync::atomic::{AtomicU8, Ordering};

use crate::sync::SpinMutex;

pub(crate) const WRCAP_RECORD_LEN: usize = 117;
const WRCAP_RECORD_COUNT: usize = 10;
const CHECKSUM_OFFSET: usize = 108;

const EMPTY_RECORD: [u8; WRCAP_RECORD_LEN] = [0; WRCAP_RECORD_LEN];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WrcapRelayError {
    Malformed,
    OutOfOrder,
    Extra,
    Receive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WrcapFlushError {
    Incomplete,
    Malformed,
    OutOfOrder,
    Extra,
    Receive,
    ReporterClaimed,
    Busy,
    Transport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WrcapDrainAction {
    Drain,
    LeaveForReady,
    Reject,
}

struct Transcript {
    records: [[u8; WRCAP_RECORD_LEN]; WRCAP_RECORD_COUNT],
    seen: usize,
    count: usize,
    failure: Option<WrcapRelayError>,
}

impl Transcript {
    const fn new() -> Self {
        Self {
            records: [EMPTY_RECORD; WRCAP_RECORD_COUNT],
            seen: 0,
            count: 0,
            failure: None,
        }
    }

    fn latch(&mut self, error: WrcapRelayError) -> WrcapRelayError {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        error
    }
}

/// Fixed-capacity storage for the selector-local WRCAP1 transcript.
pub(crate) struct WrcapRelay {
    transcript: SpinMutex<Transcript>,
    reporter_claimed: AtomicU8,
}

impl WrcapRelay {
    pub(crate) const fn new() -> Self {
        Self {
            transcript: SpinMutex::new(Transcript::new()),
            reporter_claimed: AtomicU8::new(0),
        }
    }

    /// Whether the primordial join still expects another evidence datagram.
    pub(crate) fn expects_record(&self) -> bool {
        let transcript = self.transcript.lock();
        transcript.seen < WRCAP_RECORD_COUNT
    }

    /// Decide whether the selector-only primordial join consumes the head
    /// datagram. After ten records, every head is left to ordinary READY
    /// handling so an eleventh WRCAP1 record fails there as oversized input.
    pub(crate) fn drain_action(
        &self,
        required_bytes: u32,
        required_handles: u32,
    ) -> WrcapDrainAction {
        if !self.expects_record() {
            return WrcapDrainAction::LeaveForReady;
        }
        if required_handles != 0
            || usize::try_from(required_bytes)
                .map(|bytes| bytes > WRCAP_RECORD_LEN)
                .unwrap_or(true)
        {
            WrcapDrainAction::Reject
        } else {
            WrcapDrainAction::Drain
        }
    }

    /// Validate and preserve one controller-originated record byte-for-byte.
    pub(crate) fn record(&self, record: &[u8]) -> Result<(), WrcapRelayError> {
        let mut transcript = self.transcript.lock();
        if transcript.seen == WRCAP_RECORD_COUNT {
            return Err(transcript.latch(WrcapRelayError::Extra));
        }
        let expected_sequence = transcript.seen as u32;
        let expected_kind =
            u8::try_from(transcript.seen + 1).expect("the ten canonical WRCAP1 kinds fit u8");
        transcript.seen += 1;
        if let Some(error) = transcript.failure {
            return Err(error);
        }
        match validate_record(record, expected_sequence, expected_kind) {
            Ok(()) => {}
            Err(error) => return Err(transcript.latch(error)),
        }
        let index = transcript.count;
        transcript.records[index].copy_from_slice(record);
        transcript.count += 1;
        Ok(())
    }

    /// Latch a Channel-side rejection without manufacturing an evidence fact.
    pub(crate) fn reject_receive(&self) -> Result<(), WrcapRelayError> {
        let mut transcript = self.transcript.lock();
        Err(transcript.latch(WrcapRelayError::Receive))
    }

    /// Claim the one terminal transcript reporter.
    pub(crate) fn claim_reporter(&self) -> Result<WrcapFlushPermit<'_>, WrcapFlushError> {
        self.reporter_claimed
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| WrcapFlushError::ReporterClaimed)?;
        Ok(WrcapFlushPermit { relay: self })
    }
}

#[must_use]
pub(crate) struct WrcapFlushPermit<'a> {
    relay: &'a WrcapRelay,
}

impl WrcapFlushPermit<'_> {
    pub(crate) fn flush(
        self,
        mut emit: impl FnMut(&[u8; WRCAP_RECORD_LEN]) -> Result<(), WrcapFlushError>,
    ) -> Result<(), WrcapFlushError> {
        let transcript = self
            .relay
            .transcript
            .try_lock()
            .ok_or(WrcapFlushError::Busy)?;
        if let Some(error) = transcript.failure {
            return Err(flush_error(error));
        }
        if transcript.seen != WRCAP_RECORD_COUNT || transcript.count != WRCAP_RECORD_COUNT {
            return Err(WrcapFlushError::Incomplete);
        }
        let records = transcript.records;
        drop(transcript);
        for record in &records {
            emit(record)?;
        }
        Ok(())
    }
}

const fn flush_error(error: WrcapRelayError) -> WrcapFlushError {
    match error {
        WrcapRelayError::Malformed => WrcapFlushError::Malformed,
        WrcapRelayError::OutOfOrder => WrcapFlushError::OutOfOrder,
        WrcapRelayError::Extra => WrcapFlushError::Extra,
        WrcapRelayError::Receive => WrcapFlushError::Receive,
    }
}

fn validate_record(
    record: &[u8],
    expected_sequence: u32,
    expected_kind: u8,
) -> Result<(), WrcapRelayError> {
    if record.len() != WRCAP_RECORD_LEN
        || &record[..6] != b"WRCAP1"
        || record[6] != b'|'
        || &record[7..9] != b"01"
        || record[9] != b'|'
        || record[26] != b'|'
        || record[35] != b'|'
        || record[38] != b'|'
        || record[47] != b'|'
        || record[56] != b'|'
        || record[73] != b'|'
        || record[90] != b'|'
        || record[107] != b'|'
        || record[116] != b'\n'
    {
        return Err(WrcapRelayError::Malformed);
    }
    for range in [
        10..26,
        27..35,
        36..38,
        39..47,
        48..56,
        57..73,
        74..90,
        91..107,
        108..116,
    ] {
        if !record[range].iter().copied().all(is_upper_hex) {
            return Err(WrcapRelayError::Malformed);
        }
    }
    if record[10..26].iter().all(|byte| *byte == b'0') {
        return Err(WrcapRelayError::Malformed);
    }
    let sequence = parse_hex_u32(&record[27..35]).ok_or(WrcapRelayError::Malformed)?;
    let kind = parse_hex_u8(&record[36..38]).ok_or(WrcapRelayError::Malformed)?;
    if sequence != expected_sequence || kind != expected_kind {
        return Err(WrcapRelayError::OutOfOrder);
    }
    let checksum =
        parse_hex_u32(&record[CHECKSUM_OFFSET..116]).ok_or(WrcapRelayError::Malformed)?;
    if checksum != fnv1a32(&record[..CHECKSUM_OFFSET]) {
        return Err(WrcapRelayError::Malformed);
    }
    Ok(())
}

const fn is_upper_hex(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'A'..=b'F')
}

fn parse_hex_u8(bytes: &[u8]) -> Option<u8> {
    let value = parse_hex_u32(bytes)?;
    u8::try_from(value).ok()
}

fn parse_hex_u32(bytes: &[u8]) -> Option<u32> {
    let mut value = 0_u32;
    for byte in bytes {
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'A'..=b'F' => u32::from(byte - b'A' + 10),
            _ => return None,
        };
        value = value.checked_mul(16)?.checked_add(digit)?;
    }
    Some(value)
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut checksum = 0x811c_9dc5_u32;
    for byte in bytes {
        checksum ^= u32::from(*byte);
        checksum = checksum.wrapping_mul(0x0100_0193);
    }
    checksum
}

/// The selector-specialized collector. Production kernels do not compile it.
pub(crate) static WRCAP_RELAY: WrcapRelay = WrcapRelay::new();

#[cfg(test)]
mod tests {
    use super::*;

    fn write_hex(mut value: u64, output: &mut [u8]) {
        for byte in output.iter_mut().rev() {
            let digit = u8::try_from(value & 0xf).expect("hex digit fits u8");
            *byte = if digit < 10 {
                b'0' + digit
            } else {
                b'A' + digit - 10
            };
            value >>= 4;
        }
        assert_eq!(value, 0);
    }

    fn record(sequence: u32, kind: u8) -> [u8; WRCAP_RECORD_LEN] {
        let mut record = [0_u8; WRCAP_RECORD_LEN];
        record[..6].copy_from_slice(b"WRCAP1");
        for delimiter in [6, 9, 26, 35, 38, 47, 56, 73, 90, 107] {
            record[delimiter] = b'|';
        }
        record[7..9].copy_from_slice(b"01");
        record[10..26].copy_from_slice(b"0123456789ABCDEF");
        write_hex(u64::from(sequence), &mut record[27..35]);
        write_hex(u64::from(kind), &mut record[36..38]);
        write_hex(1, &mut record[39..47]);
        write_hex(1, &mut record[48..56]);
        write_hex(0x1000 + u64::from(sequence), &mut record[57..73]);
        write_hex(0x2000 + u64::from(sequence), &mut record[74..90]);
        write_hex(0x3000 + u64::from(sequence), &mut record[91..107]);
        let checksum = fnv1a32(&record[..CHECKSUM_OFFSET]);
        write_hex(u64::from(checksum), &mut record[108..116]);
        record[116] = b'\n';
        record
    }

    #[test]
    fn relay_preserves_ten_valid_records_byte_exactly() {
        let relay = WrcapRelay::new();
        let expected = core::array::from_fn(|sequence| {
            record(sequence as u32, u8::try_from(sequence + 1).unwrap())
        });
        for record in &expected {
            relay.record(record).unwrap();
        }
        assert!(!relay.expects_record());
        let mut observed = [[0_u8; WRCAP_RECORD_LEN]; WRCAP_RECORD_COUNT];
        let mut count = 0;
        relay
            .claim_reporter()
            .unwrap()
            .flush(|record| {
                observed[count] = *record;
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, WRCAP_RECORD_COUNT);
        assert_eq!(observed, expected);
    }

    #[test]
    fn relay_rejects_malformed_order_incomplete_and_extra() {
        let malformed = WrcapRelay::new();
        let mut bad_checksum = record(0, 1);
        bad_checksum[108] = b'0';
        assert_eq!(
            malformed.record(&bad_checksum),
            Err(WrcapRelayError::Malformed)
        );
        assert_eq!(
            malformed.claim_reporter().unwrap().flush(|_| Ok(())),
            Err(WrcapFlushError::Malformed)
        );

        let out_of_order = WrcapRelay::new();
        assert_eq!(
            out_of_order.record(&record(1, 2)),
            Err(WrcapRelayError::OutOfOrder)
        );

        let incomplete = WrcapRelay::new();
        incomplete.record(&record(0, 1)).unwrap();
        assert_eq!(
            incomplete.claim_reporter().unwrap().flush(|_| Ok(())),
            Err(WrcapFlushError::Incomplete)
        );

        let extra = WrcapRelay::new();
        for sequence in 0..WRCAP_RECORD_COUNT {
            extra
                .record(&record(sequence as u32, (sequence + 1) as u8))
                .unwrap();
        }
        assert_eq!(extra.record(&record(10, 11)), Err(WrcapRelayError::Extra));
        assert_eq!(
            extra.claim_reporter().unwrap().flush(|_| Ok(())),
            Err(WrcapFlushError::Extra)
        );
    }

    #[test]
    fn ten_records_leave_ready_and_an_eleventh_record_for_ordinary_fail_closed_receive() {
        let relay = WrcapRelay::new();
        for sequence in 0..WRCAP_RECORD_COUNT {
            assert_eq!(
                relay.drain_action(WRCAP_RECORD_LEN as u32, 0),
                WrcapDrainAction::Drain
            );
            relay
                .record(&record(sequence as u32, (sequence + 1) as u8))
                .unwrap();
        }
        assert_eq!(relay.drain_action(40, 0), WrcapDrainAction::LeaveForReady);
        assert_eq!(
            relay.drain_action(WRCAP_RECORD_LEN as u32, 0),
            WrcapDrainAction::LeaveForReady
        );

        fn ordinary_ready_receive(payload: &[u8]) -> Result<[u8; 40], ()> {
            let output: [u8; 40] = payload.try_into().map_err(|_| ())?;
            Ok(output)
        }
        assert!(ordinary_ready_receive(&[b'R'; 40]).is_ok());
        assert!(ordinary_ready_receive(&record(10, 11)).is_err());
    }

    #[test]
    fn partial_busy_and_transport_failures_never_claim_a_complete_transcript() {
        let partial = WrcapRelay::new();
        partial.record(&record(0, 1)).unwrap();
        assert_eq!(
            partial.claim_reporter().unwrap().flush(|_| Ok(())),
            Err(WrcapFlushError::Incomplete)
        );

        let busy = WrcapRelay::new();
        let guard = busy.transcript.lock();
        let permit = busy.claim_reporter().unwrap();
        assert_eq!(permit.flush(|_| Ok(())), Err(WrcapFlushError::Busy));
        drop(guard);

        let transport = WrcapRelay::new();
        for sequence in 0..WRCAP_RECORD_COUNT {
            transport
                .record(&record(sequence as u32, (sequence + 1) as u8))
                .unwrap();
        }
        let mut emitted = 0;
        assert_eq!(
            transport.claim_reporter().unwrap().flush(|_| {
                emitted += 1;
                if emitted == 4 {
                    Err(WrcapFlushError::Transport)
                } else {
                    Ok(())
                }
            }),
            Err(WrcapFlushError::Transport)
        );
        assert_eq!(emitted, 4);
    }

    #[test]
    fn relay_rejects_lowercase_zero_nonce_wrong_version_and_duplicate_reporter() {
        for mutate in [
            |record: &mut [u8; WRCAP_RECORD_LEN]| record[10] = b'a',
            |record: &mut [u8; WRCAP_RECORD_LEN]| record[8] = b'2',
        ] {
            let relay = WrcapRelay::new();
            let mut invalid = record(0, 1);
            mutate(&mut invalid);
            assert_eq!(relay.record(&invalid), Err(WrcapRelayError::Malformed));
        }

        let relay = WrcapRelay::new();
        let mut zero_nonce = record(0, 1);
        zero_nonce[10..26].fill(b'0');
        let checksum = fnv1a32(&zero_nonce[..CHECKSUM_OFFSET]);
        write_hex(u64::from(checksum), &mut zero_nonce[108..116]);
        assert_eq!(relay.record(&zero_nonce), Err(WrcapRelayError::Malformed));

        let relay = WrcapRelay::new();
        let _permit = relay.claim_reporter().unwrap();
        assert!(matches!(
            relay.claim_reporter(),
            Err(WrcapFlushError::ReporterClaimed)
        ));
    }
}
