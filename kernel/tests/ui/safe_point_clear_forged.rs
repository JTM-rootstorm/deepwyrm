#![no_std]
#![allow(dead_code)]

include!("boundary_tokens_stub.rs");

use boundary_tokens::SafePointClear;

// Only the syscall entry's mailbox poll, having seen no Stop, may open the
// usercopy window.
fn forge() -> SafePointClear {
    SafePointClear::assume()
}
