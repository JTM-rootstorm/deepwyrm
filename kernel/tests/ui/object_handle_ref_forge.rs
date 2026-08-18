#![allow(dead_code)]

#[path = "../../src/object/mod.rs"]
mod object;

use deepwyrm_abi::DwObjectType;
use object::{HandleRef, ObjectId};

fn forge_handle(id: ObjectId, object_type: DwObjectType) -> HandleRef {
    HandleRef { id, object_type }
}
