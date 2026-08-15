#![allow(dead_code)]

#[path = "frame_roles_stub.rs"]
mod memory;
#[path = "../../src/memory/vm.rs"]
mod vm;

mod sibling {
    use super::vm::object::MappingLease;

    fn retain_mapping_lease(lease: MappingLease) {
        let _ = lease;
    }
}
