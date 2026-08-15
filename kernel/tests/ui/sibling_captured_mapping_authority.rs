#![allow(dead_code)]

#[path = "frame_roles_stub.rs"]
mod memory;
#[path = "../../src/memory/vm.rs"]
mod vm;

mod sibling {
    use super::vm::object::CapturedMappingAuthority;

    fn retain_captured_authority(authority: CapturedMappingAuthority) {
        let _ = authority;
    }
}
