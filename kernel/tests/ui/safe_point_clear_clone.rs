#![no_std]
#![allow(dead_code)]

include!("boundary_tokens_stub.rs");

use boundary_tokens::SafePointClear;

// One poll certifies one entry's usercopy window.
fn duplicate(clear: &SafePointClear) {
    let _ = <SafePointClear as Clone>::clone(clear);
}
