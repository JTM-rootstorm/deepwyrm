#![allow(dead_code)]

#[path = "../../src/cpu.rs"]
mod cpu;
#[path = "../../src/handle/mod.rs"]
mod handle;
#[path = "frame_roles_stub.rs"]
mod memory;
#[path = "../../src/object/mod.rs"]
mod object;
#[path = "sync_stub.rs"]
mod sync;
#[path = "../../src/memory/vm.rs"]
mod vm;

mod sibling {
    use super::vm::object::CapturedMappingAuthority;

    fn retain_captured_authority(authority: CapturedMappingAuthority) {
        let _ = authority;
    }
}
