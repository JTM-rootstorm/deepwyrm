#![allow(dead_code)]

#[path = "../../src/object/mod.rs"]
mod object;

use object::CreationRef;

fn clone_creation(reference: &CreationRef) {
    let _ = <CreationRef as Clone>::clone(reference);
}
