#![no_std]

#[path = "../../src/boot/mod.rs"]
mod boot;
#[path = "../../src/object/mod.rs"]
mod object;
#[path = "../../src/handle/mod.rs"]
mod handle;
#[path = "../../src/memory/mod.rs"]
mod memory;

use memory::frame_roles::ObjectBackingGrant;

fn clone_grant(grant: &ObjectBackingGrant) {
    let _ = <ObjectBackingGrant as Clone>::clone(grant);
}
