use deepwyrm_abi::{
    DW_ABI_INFO_V1_SIZE, DW_ABI_VERSION, DW_BASE_PAGE_SIZE, DW_CHANNEL_MAX_HANDLES,
    DW_CHANNEL_MAX_PAYLOAD, DW_MEMORY_OBJECT_INFO_V1_SIZE, DW_OBJECT_INFO_V1_SIZE,
    DW_TASK_TERMINATION_INFO_V1_SIZE, DwAbiInfoV1, DwAddressRegionMapArgsV1, DwHandle,
    DwMemoryObjectInfoV1, DwObjectInfoV1, DwTaskTerminationInfoV1, DwThreadStartArgsV1,
};

use crate::service::ObjectInfoResult;

pub(crate) const MAX_OBJECT_INFO_BYTES: usize = DW_TASK_TERMINATION_INFO_V1_SIZE as usize;
pub(crate) const THREAD_START_BYTES: usize = 80;
pub(crate) const ADDRESS_REGION_MAP_BYTES: usize = 72;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EncodedObjectInfo {
    bytes: [u8; MAX_OBJECT_INFO_BYTES],
    len: usize,
}

impl EncodedObjectInfo {
    pub(crate) const fn bytes(&self) -> &[u8] {
        self.bytes.split_at(self.len).0
    }

    pub(crate) const fn len(&self) -> usize {
        self.len
    }
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn encode_abi_info() -> [u8; DW_ABI_INFO_V1_SIZE as usize] {
    let info = DwAbiInfoV1 {
        size: DW_ABI_INFO_V1_SIZE,
        version: 1,
        abi_version: DW_ABI_VERSION,
        page_size: DW_BASE_PAGE_SIZE,
        feature_bits: 0,
        max_channel_payload: DW_CHANNEL_MAX_PAYLOAD,
        max_channel_handles: DW_CHANNEL_MAX_HANDLES,
        reserved: [0; 4],
    };
    let mut bytes = [0; DW_ABI_INFO_V1_SIZE as usize];
    put_u32(&mut bytes, 0, info.size);
    put_u32(&mut bytes, 4, info.version);
    put_u32(&mut bytes, 8, info.abi_version);
    put_u32(&mut bytes, 12, info.page_size);
    put_u64(&mut bytes, 16, info.feature_bits);
    put_u32(&mut bytes, 24, info.max_channel_payload);
    put_u32(&mut bytes, 28, info.max_channel_handles);
    bytes
}

pub(crate) fn encode_handle(handle: DwHandle) -> [u8; 8] {
    handle.0.to_le_bytes()
}

pub(crate) fn encode_u64(value: u64) -> [u8; 8] {
    value.to_le_bytes()
}

pub(crate) fn encode_object_info(result: ObjectInfoResult) -> EncodedObjectInfo {
    let mut bytes = [0; MAX_OBJECT_INFO_BYTES];
    let len = match result {
        ObjectInfoResult::Basic(info) => {
            encode_basic_info(&mut bytes, info);
            DW_OBJECT_INFO_V1_SIZE as usize
        }
        ObjectInfoResult::TaskState(info) => {
            encode_task_info(&mut bytes, info);
            DW_TASK_TERMINATION_INFO_V1_SIZE as usize
        }
        ObjectInfoResult::MemoryObject(info) => {
            encode_memory_info(&mut bytes, info);
            DW_MEMORY_OBJECT_INFO_V1_SIZE as usize
        }
    };
    EncodedObjectInfo { bytes, len }
}

fn encode_basic_info(bytes: &mut [u8; MAX_OBJECT_INFO_BYTES], info: DwObjectInfoV1) {
    put_u32(bytes, 0, info.size);
    put_u32(bytes, 4, info.version);
    put_u32(bytes, 8, info.object_type.0);
    put_u32(bytes, 12, info.reserved0);
    put_u64(bytes, 16, info.rights.0);
    for (index, value) in info.reserved.into_iter().enumerate() {
        put_u64(bytes, 24 + index * 8, value);
    }
}

fn encode_task_info(bytes: &mut [u8; MAX_OBJECT_INFO_BYTES], info: DwTaskTerminationInfoV1) {
    put_u32(bytes, 0, info.size);
    put_u32(bytes, 4, info.version);
    put_u32(bytes, 8, info.state.0);
    put_u32(bytes, 12, info.reason.0);
    put_u32(bytes, 16, info.application_code);
    put_u32(bytes, 20, info.exception_type.0);
    put_u32(bytes, 24, info.detail);
    put_u32(bytes, 28, info.reserved0);
    put_u64(bytes, 32, info.fault_address);
    for (index, value) in info.reserved.into_iter().enumerate() {
        put_u64(bytes, 40 + index * 8, value);
    }
}

fn encode_memory_info(bytes: &mut [u8; MAX_OBJECT_INFO_BYTES], info: DwMemoryObjectInfoV1) {
    put_u32(bytes, 0, info.size);
    put_u32(bytes, 4, info.version);
    put_u64(bytes, 8, info.byte_size);
    for (index, value) in info.reserved.into_iter().enumerate() {
        put_u64(bytes, 16 + index * 8, value);
    }
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed u32 field"),
    )
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed u64 field"),
    )
}

pub(crate) fn decode_thread_start(bytes: &[u8; THREAD_START_BYTES]) -> DwThreadStartArgsV1 {
    DwThreadStartArgsV1 {
        size: get_u32(bytes, 0),
        version: get_u32(bytes, 4),
        thread: DwHandle(get_u64(bytes, 8)),
        entry: deepwyrm_abi::DwUserAddress(get_u64(bytes, 16)),
        stack_pointer: deepwyrm_abi::DwUserAddress(get_u64(bytes, 24)),
        startup_argument0: get_u64(bytes, 32),
        startup_argument1: get_u64(bytes, 40),
        flags: get_u64(bytes, 48),
        reserved: [get_u64(bytes, 56), get_u64(bytes, 64), get_u64(bytes, 72)],
    }
}

pub(crate) fn decode_address_region_map(
    bytes: &[u8; ADDRESS_REGION_MAP_BYTES],
) -> DwAddressRegionMapArgsV1 {
    DwAddressRegionMapArgsV1 {
        size: get_u32(bytes, 0),
        version: get_u32(bytes, 4),
        memory_object_offset: deepwyrm_abi::DwOffset(get_u64(bytes, 8)),
        byte_len: deepwyrm_abi::DwSize(get_u64(bytes, 16)),
        requested_address: deepwyrm_abi::DwUserAddress(get_u64(bytes, 24)),
        protections: deepwyrm_abi::DwMemoryProtection(get_u32(bytes, 32)),
        flags: deepwyrm_abi::DwAddressRegionMapFlags(get_u32(bytes, 36)),
        reserved: [
            get_u64(bytes, 40),
            get_u64(bytes, 48),
            get_u64(bytes, 56),
            get_u64(bytes, 64),
        ],
    }
}

#[cfg(test)]
mod tests;
