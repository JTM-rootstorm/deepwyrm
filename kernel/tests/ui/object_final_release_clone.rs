#![allow(dead_code)]

#[path = "../../src/object/mod.rs"]
mod object;

use object::FinalRelease;

fn clone_final_release(reference: &FinalRelease) {
    let _ = <FinalRelease as Clone>::clone(reference);
}
