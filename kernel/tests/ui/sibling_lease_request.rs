#![allow(dead_code)]

#[path = "frame_roles_stub.rs"]
mod memory;
#[path = "../../src/memory/vm.rs"]
mod vm;

mod sibling {
    use super::vm::object::LeaseRequest;

    fn construct_lease_request(request: LeaseRequest) {
        let _ = request;
    }
}
