use super::*;
use deepwyrm_abi::{
    DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE, DW_OBJECT_TYPE_PROCESS, DW_RIGHT_INSPECT,
    DW_TASK_STATE_EXITED, DW_TERMINATION_AUTHORIZED, DwAddressRegionMapFlags, DwExceptionType,
    DwMemoryProtection, DwObjectType, DwOffset, DwRights, DwSize, DwTaskState, DwTerminationReason,
    DwUserAddress,
};

#[test]
fn abi_info_encoding_is_padding_free_and_exact() {
    let bytes = encode_abi_info();
    assert_eq!(bytes.len(), 64);
    assert_eq!(&bytes[0..4], &64_u32.to_le_bytes());
    assert_eq!(&bytes[8..12], &DW_ABI_VERSION.to_le_bytes());
    assert_eq!(&bytes[12..16], &DW_BASE_PAGE_SIZE.to_le_bytes());
    assert_eq!(&bytes[16..24], &[0; 8]);
    assert_eq!(&bytes[32..64], &[0; 32]);
}

#[test]
fn basic_object_info_encoding_has_no_padding_leak() {
    let basic = encode_object_info(ObjectInfoResult::Basic(DwObjectInfoV1 {
        size: DW_OBJECT_INFO_V1_SIZE,
        version: 1,
        object_type: DW_OBJECT_TYPE_PROCESS,
        reserved0: 0,
        rights: DW_RIGHT_INSPECT,
        reserved: [0; 4],
    }));
    assert_eq!(basic.len(), DW_OBJECT_INFO_V1_SIZE as usize);
    assert_eq!(&basic.bytes()[24..], &[0; 32]);
}
#[test]
fn task_object_info_encoding_has_no_padding_leak() {
    let task = encode_object_info(ObjectInfoResult::TaskState(DwTaskTerminationInfoV1 {
        size: DW_TASK_TERMINATION_INFO_V1_SIZE,
        version: 1,
        state: DW_TASK_STATE_EXITED,
        reason: DW_TERMINATION_AUTHORIZED,
        application_code: 0,
        exception_type: DwExceptionType(0),
        detail: 7,
        reserved0: 0,
        fault_address: 0,
        reserved: [0; 3],
    }));
    assert_eq!(task.len(), 64);
    assert_eq!(&task.bytes()[40..], &[0; 24]);
}

#[test]
fn thread_start_decoder_follows_generated_offsets() {
    let mut thread = [0_u8; THREAD_START_BYTES];
    thread[0..4].copy_from_slice(&80_u32.to_le_bytes());
    thread[4..8].copy_from_slice(&1_u32.to_le_bytes());
    thread[8..16].copy_from_slice(&0x1122_u64.to_le_bytes());
    thread[16..24].copy_from_slice(&0x4000_u64.to_le_bytes());
    thread[24..32].copy_from_slice(&0x8000_u64.to_le_bytes());
    thread[32..40].copy_from_slice(&3_u64.to_le_bytes());
    thread[40..48].copy_from_slice(&4_u64.to_le_bytes());
    let decoded = decode_thread_start(&thread);
    assert_eq!(decoded.thread, DwHandle(0x1122));
    assert_eq!(decoded.entry, DwUserAddress(0x4000));
    assert_eq!(decoded.stack_pointer, DwUserAddress(0x8000));
    assert_eq!(decoded.startup_argument0, 3);
    assert_eq!(decoded.startup_argument1, 4);
}
#[test]
fn map_decoder_follows_generated_offsets() {
    assert_eq!(
        ADDRESS_REGION_MAP_BYTES,
        DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE as usize
    );
    let mut map = [0_u8; ADDRESS_REGION_MAP_BYTES];
    map[0..4].copy_from_slice(&72_u32.to_le_bytes());
    map[4..8].copy_from_slice(&1_u32.to_le_bytes());
    map[8..16].copy_from_slice(&0x1000_u64.to_le_bytes());
    map[16..24].copy_from_slice(&0x2000_u64.to_le_bytes());
    map[24..32].copy_from_slice(&0x4000_u64.to_le_bytes());
    map[32..36].copy_from_slice(&3_u32.to_le_bytes());
    map[36..40].copy_from_slice(&1_u32.to_le_bytes());
    let decoded = decode_address_region_map(&map);
    assert_eq!(decoded.memory_object_offset, DwOffset(0x1000));
    assert_eq!(decoded.byte_len, DwSize(0x2000));
    assert_eq!(decoded.requested_address, DwUserAddress(0x4000));
    assert_eq!(decoded.protections, DwMemoryProtection(3));
    assert_eq!(decoded.flags, DwAddressRegionMapFlags(1));
}

#[test]
fn scalar_encoders_are_exact_little_endian_values() {
    assert_eq!(
        encode_handle(DwHandle(0x1122_3344_5566_7788)),
        0x1122_3344_5566_7788_u64.to_le_bytes()
    );
    assert_eq!(
        encode_u64(0xaabb_ccdd_eeff_0011),
        0xaabb_ccdd_eeff_0011_u64.to_le_bytes()
    );
    let _ = (
        DwRights(0),
        DwObjectType(0),
        DwTaskState(0),
        DwTerminationReason(0),
    );
}
