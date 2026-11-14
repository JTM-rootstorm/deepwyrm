//! The compiled fingerprint constants are the generated fingerprint record.

use deepwyrm_abi::{
    DW_ABI_FINGERPRINT, DW_ABI_FINGERPRINT_WORDS, DW_ABI_INFO_V1_SIZE, DW_ABI_NOTE_NAME,
    DW_ABI_NOTE_TYPE_FINGERPRINT, DwAbiInfoV1,
};

#[test]
fn the_fingerprint_bytes_are_the_generated_record_and_the_words_are_their_little_endian_form() {
    let record = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../abi/generated/abi_fingerprint.toml"),
    )
    .unwrap();
    let hex = record
        .lines()
        .find_map(|line| line.strip_prefix("fingerprint = \""))
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap();
    let bytes: Vec<u8> = (0..32)
        .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap())
        .collect();
    assert_eq!(bytes, DW_ABI_FINGERPRINT);
    let (chunks, _) = bytes.as_chunks::<8>();
    for (word, chunk) in DW_ABI_FINGERPRINT_WORDS.iter().zip(chunks) {
        assert_eq!(*word, u64::from_le_bytes(*chunk));
    }
    assert_eq!(&DW_ABI_NOTE_NAME, b"Deepwyrm\0");
    assert_eq!(DW_ABI_NOTE_TYPE_FINGERPRINT, 1);
}

#[test]
fn abi_info_carries_the_fingerprint_where_its_reserved_words_were() {
    assert_eq!(DW_ABI_INFO_V1_SIZE, 64);
    assert_eq!(core::mem::offset_of!(DwAbiInfoV1, abi_fingerprint), 32);
}
