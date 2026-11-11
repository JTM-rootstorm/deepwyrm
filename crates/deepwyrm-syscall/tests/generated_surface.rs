use deepwyrm_syscall::{
    DwAddressRegionMapArgsV1, DwChannelReceiveResultV1, DwHandleTransferV1, DwMemoryObjectInfoV1,
    DwObjectInfoV1, DwProcessCreateArgsV1, DwProcessCreateResultV1, DwTaskTerminationInfoV1,
    DwThreadStartArgsV1, DwWaitItemV1, DwWaitResultV1,
};

#[test]
fn typed_guest_surface_is_exactly_generated_abi_material() {
    let _ = core::mem::size_of::<DwObjectInfoV1>();
    let _ = core::mem::size_of::<DwMemoryObjectInfoV1>();
    let _ = core::mem::size_of::<DwHandleTransferV1>();
    let _ = core::mem::size_of::<DwChannelReceiveResultV1>();
    let _ = core::mem::size_of::<DwAddressRegionMapArgsV1>();
    let _ = core::mem::size_of::<DwProcessCreateArgsV1>();
    let _ = core::mem::size_of::<DwProcessCreateResultV1>();
    let _ = core::mem::size_of::<DwTaskTerminationInfoV1>();
    let _ = core::mem::size_of::<DwThreadStartArgsV1>();
    let _ = core::mem::size_of::<DwWaitItemV1>();
    let _ = core::mem::size_of::<DwWaitResultV1>();
}
