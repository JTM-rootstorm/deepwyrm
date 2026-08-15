#![no_std]

#[path = "../../src/boot/mod.rs"]
mod boot;
#[path = "../../src/memory/mod.rs"]
mod memory;

use memory::frame_roles::ZeroedGrant;

fn clone_grant(grant: &ZeroedGrant) {
    let _ = <ZeroedGrant as Clone>::clone(grant);
}
