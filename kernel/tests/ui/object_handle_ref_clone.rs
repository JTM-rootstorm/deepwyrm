#![allow(dead_code)]

#[path = "object_payload_stubs.rs"]
mod memory;

#[path = "../../src/object/mod.rs"]
mod object;

use object::HandleRef;

fn clone_handle(reference: &HandleRef) {
    let _ = <HandleRef as Clone>::clone(reference);
}
