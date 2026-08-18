#![allow(dead_code)]

#[path = "object_payload_stubs.rs"]
mod memory;

#[path = "../../src/object/mod.rs"]
mod object;

use object::FinalRelease;

fn clone_final_release(reference: &FinalRelease) {
    let _ = <FinalRelease as Clone>::clone(reference);
}
