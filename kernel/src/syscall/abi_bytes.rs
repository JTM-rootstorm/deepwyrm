use deepwyrm_abi::{
    DW_ABI_INFO_V1_SIZE, DW_ABI_VERSION, DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE, DW_BASE_PAGE_SIZE,
    DW_CHANNEL_MAX_HANDLES, DW_CHANNEL_MAX_PAYLOAD, DW_CHANNEL_RECEIVE_RESULT_V1_SIZE,
    DW_HANDLE_TRANSFER_V1_SIZE, DW_MEMORY_OBJECT_INFO_V1_SIZE, DW_OBJECT_INFO_V1_SIZE,
    DW_PROCESS_CREATE_ARGS_V1_SIZE, DW_PROCESS_CREATE_RESULT_V1_SIZE,
    DW_RECEIVED_HANDLE_INFO_V1_SIZE, DW_TASK_TERMINATION_INFO_V1_SIZE,
    DW_THREAD_START_ARGS_V1_SIZE, DW_WAIT_ITEM_V1_SIZE, DW_WAIT_RESULT_V1_SIZE, DwAbiInfoV1,
    DwAddressRegionMapArgsV1, DwChannelReceiveResultV1, DwHandle, DwHandleTransferOperation,
    DwHandleTransferV1, DwMemoryObjectInfoV1, DwObjectInfoV1, DwProcessCreateArgsV1,
    DwProcessCreateResultV1, DwReceivedHandleInfoV1, DwRights, DwSignals, DwTaskTerminationInfoV1,
    DwThreadStartArgsV1, DwWaitItemV1, DwWaitResultV1,
};

use crate::service::ObjectInfoResult;

pub(crate) const MAX_OBJECT_INFO_BYTES: usize = DW_TASK_TERMINATION_INFO_V1_SIZE as usize;
pub(crate) const THREAD_START_BYTES: usize = DW_THREAD_START_ARGS_V1_SIZE as usize;
pub(crate) const ADDRESS_REGION_MAP_BYTES: usize = DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE as usize;
pub(crate) const PROCESS_CREATE_ARGS_BYTES: usize = DW_PROCESS_CREATE_ARGS_V1_SIZE as usize;
pub(crate) const HANDLE_TRANSFER_BYTES: usize = DW_HANDLE_TRANSFER_V1_SIZE as usize;
pub(crate) const WAIT_ITEM_BYTES: usize = DW_WAIT_ITEM_V1_SIZE as usize;

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

pub(crate) fn decode_process_create_args(
    bytes: &[u8; PROCESS_CREATE_ARGS_BYTES],
) -> DwProcessCreateArgsV1 {
    DwProcessCreateArgsV1 {
        size: get_u32(bytes, 0),
        version: get_u32(bytes, 4),
        task_group: DwHandle(get_u64(bytes, 8)),
        bootstrap_channel: DwHandle(get_u64(bytes, 16)),
        process_rights: DwRights(get_u64(bytes, 24)),
        root_region_rights: DwRights(get_u64(bytes, 32)),
        child_bootstrap_rights: DwRights(get_u64(bytes, 40)),
        flags: get_u64(bytes, 48),
        reserved: [
            get_u64(bytes, 56),
            get_u64(bytes, 64),
            get_u64(bytes, 72),
            get_u64(bytes, 80),
        ],
    }
}

pub(crate) fn encode_process_create_result(
    result: DwProcessCreateResultV1,
) -> [u8; DW_PROCESS_CREATE_RESULT_V1_SIZE as usize] {
    let mut bytes = [0; DW_PROCESS_CREATE_RESULT_V1_SIZE as usize];
    put_u32(&mut bytes, 0, result.size);
    put_u32(&mut bytes, 4, result.version);
    put_u64(&mut bytes, 8, result.process.0);
    put_u64(&mut bytes, 16, result.root_address_region.0);
    put_u64(&mut bytes, 24, result.child_bootstrap_handle.0);
    for (index, value) in result.reserved.into_iter().enumerate() {
        put_u64(&mut bytes, 32 + index * 8, value);
    }
    bytes
}

pub(crate) fn decode_handle_transfer(bytes: &[u8; HANDLE_TRANSFER_BYTES]) -> DwHandleTransferV1 {
    DwHandleTransferV1 {
        handle: DwHandle(get_u64(bytes, 0)),
        requested_rights: DwRights(get_u64(bytes, 8)),
        operation: DwHandleTransferOperation(get_u32(bytes, 16)),
        reserved0: get_u32(bytes, 20),
        reserved: [get_u64(bytes, 24), get_u64(bytes, 32)],
    }
}

pub(crate) fn encode_received_handle_info(
    info: DwReceivedHandleInfoV1,
) -> [u8; DW_RECEIVED_HANDLE_INFO_V1_SIZE as usize] {
    let mut bytes = [0; DW_RECEIVED_HANDLE_INFO_V1_SIZE as usize];
    put_u64(&mut bytes, 0, info.handle.0);
    put_u64(&mut bytes, 8, info.rights.0);
    put_u32(&mut bytes, 16, info.object_type.0);
    put_u32(&mut bytes, 20, info.reserved0);
    for (index, value) in info.reserved.into_iter().enumerate() {
        put_u64(&mut bytes, 24 + index * 8, value);
    }
    bytes
}

pub(crate) fn encode_channel_receive_result(
    result: DwChannelReceiveResultV1,
) -> [u8; DW_CHANNEL_RECEIVE_RESULT_V1_SIZE as usize] {
    let mut bytes = [0; DW_CHANNEL_RECEIVE_RESULT_V1_SIZE as usize];
    put_u32(&mut bytes, 0, result.size);
    put_u32(&mut bytes, 4, result.version);
    put_u32(&mut bytes, 8, result.actual_bytes);
    put_u32(&mut bytes, 12, result.actual_handles);
    put_u32(&mut bytes, 16, result.required_bytes);
    put_u32(&mut bytes, 20, result.required_handles);
    for (index, value) in result.reserved.into_iter().enumerate() {
        put_u64(&mut bytes, 24 + index * 8, value);
    }
    bytes
}

pub(crate) fn decode_wait_item(bytes: &[u8; WAIT_ITEM_BYTES]) -> DwWaitItemV1 {
    DwWaitItemV1 {
        handle: DwHandle(get_u64(bytes, 0)),
        signals: DwSignals(get_u64(bytes, 8)),
    }
}

pub(crate) fn encode_wait_result(result: DwWaitResultV1) -> [u8; DW_WAIT_RESULT_V1_SIZE as usize] {
    let mut bytes = [0; DW_WAIT_RESULT_V1_SIZE as usize];
    put_u32(&mut bytes, 0, result.size);
    put_u32(&mut bytes, 4, result.version);
    put_u32(&mut bytes, 8, result.index);
    put_u32(&mut bytes, 12, result.reserved0);
    put_u64(&mut bytes, 16, result.observed.0);
    for (index, value) in result.reserved.into_iter().enumerate() {
        put_u64(&mut bytes, 24 + index * 8, value);
    }
    bytes
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
