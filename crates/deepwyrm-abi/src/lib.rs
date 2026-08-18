//! Generated, `no_std` Deepwyrm native ABI 0 definitions.
//!
//! The canonical source lives under `abi/schema`. Regenerate these definitions
//! with `cargo xtask abi generate` and reject drift with
//! `cargo xtask abi check`.

#![no_std]
#![forbid(unsafe_code)]

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../abi/generated/deepwyrm_abi.rs"
));

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../abi/generated/syscall_kernel.rs"
));
