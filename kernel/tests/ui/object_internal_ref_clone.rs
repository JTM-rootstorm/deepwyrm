#![allow(dead_code)]

#[path = "../../src/object/mod.rs"]
mod object;

use object::InternalRef;

fn clone_internal(reference: &InternalRef) {
    let _ = <InternalRef as Clone>::clone(reference);
}
