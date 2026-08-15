#![no_std]

#[path = "../../src/boot/mod.rs"]
mod boot;
#[path = "../../src/memory/mod.rs"]
mod memory;

use memory::frame_roles::FrameRoleManager;

fn call_private_constructor() {
    let _ = FrameRoleManager::<1, 1>::new(panic!());
}
