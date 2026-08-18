#![allow(dead_code)]

#[path = "../../src/object/mod.rs"]
mod object;

use object::HandleRef;

fn clone_handle(reference: &HandleRef) {
    let _ = <HandleRef as Clone>::clone(reference);
}
