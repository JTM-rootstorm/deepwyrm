#![allow(dead_code)]

#[path = "object_payload_stubs.rs"]
mod memory;

#[path = "../../src/object/mod.rs"]
mod object;

use deepwyrm_abi::DwObjectType;
use object::{HandleRef, ObjectId};

fn forge_handle(id: ObjectId, object_type: DwObjectType) -> HandleRef {
    HandleRef { id, object_type }
}
