#![allow(dead_code)]

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
