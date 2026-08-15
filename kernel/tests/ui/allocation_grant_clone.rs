#![no_std]

#[path = "../../src/boot/mod.rs"]
mod boot;
#[path = "../../src/memory/mod.rs"]
mod memory;

use memory::frame_roles::AllocationGrant;

fn clone_grant(grant: &AllocationGrant) {
    let _ = <AllocationGrant as Clone>::clone(grant);
}
