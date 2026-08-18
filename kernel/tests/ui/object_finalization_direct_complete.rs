extern crate deepwyrm_abi;
#[path = "object_payload_stubs.rs"]
mod memory;
#[path = "../../src/object/mod.rs"]
mod object;
use deepwyrm_abi::DW_OBJECT_TYPE_PROCESS;
use object::ObjectRegistry;
fn direct_complete() {
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    let release = registry.release_creation(creation).unwrap().unwrap();
    let _ = registry.complete_finalization(release);
}
