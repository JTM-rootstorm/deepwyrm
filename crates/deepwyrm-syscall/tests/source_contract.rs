use deepwyrm_syscall::{
    DwAddressRegionMapArgsV1, DwChannelReceiveResultV1, DwHandleTransferV1, DwMemoryObjectInfoV1,
    DwObjectInfoV1,
};

const SOURCE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
const MANIFEST: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));

#[test]
fn public_wrappers_use_generated_ids_not_copied_numeric_values() {
    for generated_id in [
        "DW_SYSCALL_HANDLE_CLOSE",
        "DW_SYSCALL_OBJECT_GET_INFO_V1",
        "DW_SYSCALL_PROCESS_EXIT",
        "DW_SYSCALL_CHANNEL_SEND",
        "DW_SYSCALL_CHANNEL_RECEIVE",
        "DW_SYSCALL_ADDRESS_REGION_MAP",
        "DW_SYSCALL_ADDRESS_REGION_UNMAP",
    ] {
        assert!(
            SOURCE.contains(generated_id),
            "missing generated ID {generated_id}"
        );
    }
    assert!(
        !SOURCE.contains("0x"),
        "guest wrapper source must not copy numeric ABI values"
    );
}

#[test]
fn public_wrappers_use_generated_records_not_local_abi_redeclarations() {
    for generated_record in [
        "DwObjectInfoV1",
        "DwMemoryObjectInfoV1",
        "DwHandleTransferV1",
        "DwReceivedHandleInfoV1",
        "DwChannelReceiveResultV1",
        "DwAddressRegionMapArgsV1",
    ] {
        assert!(SOURCE.contains(generated_record));
    }
    assert!(SOURCE.contains("pub use deepwyrm_abi::*"));
    assert!(!SOURCE.contains("#[repr(C)]"));
    assert!(!SOURCE.contains("struct Dw"));
}

#[test]
fn generated_veneer_is_included_rather_than_retyped() {
    assert!(SOURCE.contains("global_asm!("));
    assert!(SOURCE.contains("syscall_veneer_x86_64.S"));
    assert!(SOURCE.contains("options(att_syntax)"));
    assert!(!SOURCE.contains("movq %rdi, %rax"));
}

#[test]
fn guest_crate_has_no_unix_or_libc_dependency_path() {
    assert!(!SOURCE.contains("cfg(unix)"));
    assert!(!MANIFEST.contains("libc"));
}

#[test]
fn typed_guest_surface_is_exactly_generated_abi_material() {
    let _ = core::mem::size_of::<DwObjectInfoV1>();
    let _ = core::mem::size_of::<DwMemoryObjectInfoV1>();
    let _ = core::mem::size_of::<DwHandleTransferV1>();
    let _ = core::mem::size_of::<DwChannelReceiveResultV1>();
    let _ = core::mem::size_of::<DwAddressRegionMapArgsV1>();
}
