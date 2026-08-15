#![allow(dead_code)]

#[path = "frame_roles_stub.rs"]
mod memory;
#[path = "../../src/memory/vm.rs"]
mod vm;

mod sibling {
    use super::vm::address_region::{AddressSpaceKey, RegionKey};
    use super::vm::object::MapAuthorization;

    fn capture_authority(
        authorization: MapAuthorization,
        address_space: AddressSpaceKey,
        region: RegionKey,
    ) {
        let _ = authorization.capture(address_space, region);
    }
}
