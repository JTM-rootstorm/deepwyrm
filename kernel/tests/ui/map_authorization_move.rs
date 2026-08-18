#![allow(dead_code)]

#[path = "frame_roles_stub.rs"]
mod memory;
#[path = "../../src/object/mod.rs"]
mod object;
#[path = "../../src/memory/vm.rs"]
mod vm;

use vm::address_region::{AddressRegion, AddressSpacePublisher, Protection};
use vm::object::{MapAuthorization, MemoryObjectAuthority, PAGE_SIZE};

fn reuse_after_map<
    const OBJECTS: usize,
    const LEASES: usize,
    const SLOTS: usize,
    const REGISTRY_OBJECTS: usize,
    P: AddressSpacePublisher,
>(
    region: &mut AddressRegion<SLOTS>,
    authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
    registry: &mut object::ObjectRegistry<REGISTRY_OBJECTS>,
    publisher: &mut P,
    authorization: MapAuthorization,
) {
    let _ = region.map(
        authority,
        registry,
        publisher,
        PAGE_SIZE,
        authorization,
        0,
        PAGE_SIZE,
        Protection::READ,
    );
    let _ = region.map(
        authority,
        registry,
        publisher,
        PAGE_SIZE * 2,
        authorization,
        0,
        PAGE_SIZE,
        Protection::READ,
    );
}
