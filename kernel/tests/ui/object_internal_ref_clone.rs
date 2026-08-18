#![allow(dead_code)]

#[path = "object_payload_stubs.rs"]
mod memory;

#[path = "../../src/object/mod.rs"]
mod object;

use object::InternalRef;

fn clone_internal(reference: &InternalRef) {
    let _ = <InternalRef as Clone>::clone(reference);
}
