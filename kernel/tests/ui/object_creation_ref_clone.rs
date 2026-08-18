#![allow(dead_code)]

#[path = "object_payload_stubs.rs"]
mod memory;

#[path = "../../src/object/mod.rs"]
mod object;

use object::CreationRef;

fn clone_creation(reference: &CreationRef) {
    let _ = <CreationRef as Clone>::clone(reference);
}
