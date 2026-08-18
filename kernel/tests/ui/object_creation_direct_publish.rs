extern crate deepwyrm_abi;
#[path = "../../src/object/mod.rs"]
mod object;
use deepwyrm_abi::DW_OBJECT_TYPE_PROCESS;
use object::ObjectRegistry;
fn direct_publish() {
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    let _ = registry.creation_into_handle(creation);
}
