//! Canonical machine-readable guest completion record.

const MAGIC: &[u8; 7] = b"DWTEST1";
const CHECKSUM_INPUT_LEN: usize = 29;
const FNV1A_OFFSET_BASIS: u32 = 0x811c_9dc5;
const FNV1A_PRIME: u32 = 0x0100_0193;

/// Exact encoded completion-record length, including the final newline.
pub const COMPLETION_RECORD_LEN: usize = 38;

/// Terminal test outcome carried by the completion record and exit transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CompletionOutcome {
    /// The selected guest test completed successfully.
    Pass = 0x01,
    /// The selected guest test completed with a deterministic failure.
    Fail = 0x02,
    /// Kernel panic handling reached the test completion boundary.
    Panic = 0x03,
}

impl CompletionOutcome {
    pub(crate) const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Pass),
            0x02 => Some(Self::Fail),
            0x03 => Some(Self::Panic),
            _ => None,
        }
    }
}

/// One terminal guest-test result.
///
/// `test_id` and `detail` are bounded test-build namespaces. They must never
/// contain pointers, secrets, production identifiers, or ordinary runtime
/// configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionRecord {
    /// Terminal result classification.
    pub outcome: CompletionOutcome,
    /// Stable test-build identifier selected by the central harness.
    pub test_id: u32,
    /// Bounded test-specific diagnostic code.
    pub detail: u32,
}

impl CompletionRecord {
    /// Encode the canonical record.
    ///
    /// The wire form is exactly
    /// `DWTEST1|KK|TTTTTTTT|DDDDDDDD|CCCCCCCC\n`, using uppercase hexadecimal.
    #[must_use]
    pub fn encode(self) -> EncodedCompletionRecord {
        let mut bytes = [0_u8; COMPLETION_RECORD_LEN];
        bytes[..MAGIC.len()].copy_from_slice(MAGIC);
        bytes[7] = b'|';
        encode_hex(self.outcome as u32, &mut bytes[8..10]);
        bytes[10] = b'|';
        encode_hex(self.test_id, &mut bytes[11..19]);
        bytes[19] = b'|';
        encode_hex(self.detail, &mut bytes[20..28]);
        bytes[28] = b'|';
        let checksum = fnv1a32(&bytes[..CHECKSUM_INPUT_LEN]);
        encode_hex(checksum, &mut bytes[29..37]);
        bytes[37] = b'\n';
        EncodedCompletionRecord(bytes)
    }
}

/// Canonically encoded completion record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodedCompletionRecord([u8; COMPLETION_RECORD_LEN]);

impl EncodedCompletionRecord {
    /// Borrow the exact bytes to send over the test serial channel.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; COMPLETION_RECORD_LEN] {
        &self.0
    }

    /// Parse one complete terminal record.
    ///
    /// The parser intentionally rejects lowercase hex, prefixes, suffixes, and
    /// concatenated terminal records. The checksum detects transport corruption;
    /// it is not an authentication mechanism.
    pub fn parse(input: &[u8]) -> Result<CompletionRecord, CompletionParseError> {
        if input.len() != COMPLETION_RECORD_LEN {
            return Err(CompletionParseError::InvalidLength);
        }
        if input[..MAGIC.len()] != MAGIC[..] {
            return Err(CompletionParseError::InvalidMagic);
        }
        if input[7] != b'|' || input[10] != b'|' || input[19] != b'|' || input[28] != b'|' {
            return Err(CompletionParseError::InvalidSeparator);
        }
        if input[37] != b'\n' {
            return Err(CompletionParseError::MissingNewline);
        }

        let outcome_value = decode_hex(&input[8..10])?;
        let outcome = CompletionOutcome::from_wire(
            u8::try_from(outcome_value).map_err(|_| CompletionParseError::InvalidOutcome)?,
        )
        .ok_or(CompletionParseError::InvalidOutcome)?;
        let test_id = decode_hex(&input[11..19])?;
        let detail = decode_hex(&input[20..28])?;
        let encoded_checksum = decode_hex(&input[29..37])?;
        if encoded_checksum != fnv1a32(&input[..CHECKSUM_INPUT_LEN]) {
            return Err(CompletionParseError::ChecksumMismatch);
        }

        Ok(CompletionRecord {
            outcome,
            test_id,
            detail,
        })
    }
}

/// Strict completion-record parse failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionParseError {
    /// Input was truncated or contained additional bytes/records.
    InvalidLength,
    /// The versioned `DWTEST1` marker did not match.
    InvalidMagic,
    /// A field delimiter was missing or misplaced.
    InvalidSeparator,
    /// The terminal newline was absent.
    MissingNewline,
    /// A hexadecimal field was malformed or used lowercase.
    InvalidHex,
    /// The outcome value was not PASS, FAIL, or PANIC.
    InvalidOutcome,
    /// The record was corrupted in transit.
    ChecksumMismatch,
}

fn encode_hex(value: u32, output: &mut [u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let width = output.len();
    for (index, byte) in output.iter_mut().enumerate() {
        let shift = (width - index - 1) * 4;
        *byte = HEX[((value >> shift) & 0x0f) as usize];
    }
}

fn decode_hex(input: &[u8]) -> Result<u32, CompletionParseError> {
    let mut value = 0_u32;
    for byte in input {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(CompletionParseError::InvalidHex),
        };
        value = value
            .checked_mul(16)
            .and_then(|current| current.checked_add(u32::from(digit)))
            .ok_or(CompletionParseError::InvalidHex)?;
    }
    Ok(value)
}

fn fnv1a32(input: &[u8]) -> u32 {
    input.iter().fold(FNV1A_OFFSET_BASIS, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(FNV1A_PRIME)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUTCOMES: [CompletionOutcome; 3] = [
        CompletionOutcome::Pass,
        CompletionOutcome::Fail,
        CompletionOutcome::Panic,
    ];

    fn sample(outcome: CompletionOutcome) -> CompletionRecord {
        CompletionRecord {
            outcome,
            test_id: 0x89ab_cdef,
            detail: 0x1020_3040,
        }
    }

    #[test]
    fn every_outcome_round_trips() {
        for outcome in OUTCOMES {
            let record = sample(outcome);
            let encoded = record.encode();
            assert_eq!(
                EncodedCompletionRecord::parse(encoded.as_bytes()),
                Ok(record)
            );
        }
    }

    #[test]
    fn canonical_vector_is_stable() {
        let encoded = sample(CompletionOutcome::Fail).encode();
        assert_eq!(
            encoded.as_bytes(),
            b"DWTEST1|02|89ABCDEF|10203040|253F5A85\n"
        );
    }

    #[test]
    fn every_truncation_is_rejected() {
        let encoded = sample(CompletionOutcome::Pass).encode();
        for length in 0..COMPLETION_RECORD_LEN {
            assert_eq!(
                EncodedCompletionRecord::parse(&encoded.as_bytes()[..length]),
                Err(CompletionParseError::InvalidLength)
            );
        }
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut bytes = *sample(CompletionOutcome::Pass).encode().as_bytes();
        bytes[0] = b'X';
        assert_eq!(
            EncodedCompletionRecord::parse(&bytes),
            Err(CompletionParseError::InvalidMagic)
        );
    }

    #[test]
    fn lowercase_hex_is_rejected() {
        let mut bytes = *sample(CompletionOutcome::Fail).encode().as_bytes();
        bytes[11] = b'a';
        assert_eq!(
            EncodedCompletionRecord::parse(&bytes),
            Err(CompletionParseError::InvalidHex)
        );
    }

    #[test]
    fn bad_separator_is_rejected() {
        let mut bytes = *sample(CompletionOutcome::Pass).encode().as_bytes();
        bytes[19] = b':';
        assert_eq!(
            EncodedCompletionRecord::parse(&bytes),
            Err(CompletionParseError::InvalidSeparator)
        );
    }

    #[test]
    fn bad_checksum_is_rejected() {
        let mut bytes = *sample(CompletionOutcome::Panic).encode().as_bytes();
        bytes[36] = if bytes[36] == b'0' { b'1' } else { b'0' };
        assert_eq!(
            EncodedCompletionRecord::parse(&bytes),
            Err(CompletionParseError::ChecksumMismatch)
        );
    }

    #[test]
    fn checksum_covers_the_record_prefix_and_final_delimiter() {
        let mut bytes = *sample(CompletionOutcome::Pass).encode().as_bytes();
        bytes[20] = b'2';
        assert_eq!(
            EncodedCompletionRecord::parse(&bytes),
            Err(CompletionParseError::ChecksumMismatch)
        );

        let bytes = sample(CompletionOutcome::Pass).encode();
        let encoded_checksum = decode_hex(&bytes.as_bytes()[29..37]).unwrap();
        assert_eq!(encoded_checksum, fnv1a32(&bytes.as_bytes()[..29]));
        assert_ne!(encoded_checksum, fnv1a32(&bytes.as_bytes()[..28]));
    }

    #[test]
    fn missing_terminal_newline_is_rejected() {
        let mut bytes = *sample(CompletionOutcome::Panic).encode().as_bytes();
        bytes[37] = b' ';
        assert_eq!(
            EncodedCompletionRecord::parse(&bytes),
            Err(CompletionParseError::MissingNewline)
        );
    }

    #[test]
    fn embedded_extra_terminal_record_is_rejected() {
        let encoded = sample(CompletionOutcome::Pass).encode();
        let mut duplicate = [0_u8; COMPLETION_RECORD_LEN * 2];
        duplicate[..COMPLETION_RECORD_LEN].copy_from_slice(encoded.as_bytes());
        duplicate[COMPLETION_RECORD_LEN..].copy_from_slice(encoded.as_bytes());
        assert_eq!(
            EncodedCompletionRecord::parse(&duplicate),
            Err(CompletionParseError::InvalidLength)
        );
    }

    #[test]
    fn unknown_outcome_is_rejected_before_checksum() {
        let mut bytes = *sample(CompletionOutcome::Pass).encode().as_bytes();
        bytes[8..10].copy_from_slice(b"04");
        assert_eq!(
            EncodedCompletionRecord::parse(&bytes),
            Err(CompletionParseError::InvalidOutcome)
        );
    }
}
