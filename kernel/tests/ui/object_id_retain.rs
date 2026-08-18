#![allow(dead_code)]

#[path = "../../src/object/mod.rs"]
mod object;

use deepwyrm_abi::DW_OBJECT_TYPE_PROCESS;
use object::ObjectRegistry;

fn retain_from_identity_only() {
    let mut registry = ObjectRegistry::<1>::new();
    let creation = registry.create(DW_OBJECT_TYPE_PROCESS).unwrap();
    let id = creation.id();
    let _ = registry.retain_handle(&id);
}
