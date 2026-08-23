#![allow(dead_code)]

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
    use super::vm::address_region::AddressRegion;

    fn extract_lease<const SLOTS: usize>(region: &AddressRegion<SLOTS>) {
        if let Some(mapping) = region.mappings()[0] {
            let _ = mapping.lease();
        }
    }
}
