#![allow(dead_code)]

#[path = "frame_roles_stub.rs"]
mod memory;
#[path = "../../src/object/mod.rs"]
mod object;
#[path = "../../src/memory/vm.rs"]
mod vm;

mod sibling {
    use super::vm::address_region::{AddressSpaceKey, RegionKey};
    use super::vm::object::MemoryObjectAuthority;

    fn prepare_without_publication(
        authority: &mut MemoryObjectAuthority<1, 1>,
        address_space: AddressSpaceKey,
        region: RegionKey,
    ) {
        let _ = authority.prepare_replace::<1>(address_space, region, &[], &[]);
    }
}
