#![allow(dead_code)]

#[path = "../../src/memory/vm.rs"]
mod vm;

mod sibling {
    use super::vm::object::CapturedMappingAuthority;

    fn retain_captured_authority(authority: CapturedMappingAuthority) {
        let _ = authority;
    }
}
