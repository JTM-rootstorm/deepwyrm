#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

// The freestanding binary's entry symbol is supplied by the audited assembly
// object linked from build.rs. Importing the library supplies its Rust target.
#[cfg(target_os = "none")]
extern crate deepwyrm_kernel;

#[cfg(not(target_os = "none"))]
fn main() {}
