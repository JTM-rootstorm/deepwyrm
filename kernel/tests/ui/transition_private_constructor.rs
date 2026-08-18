#![no_std]

#[path = "../../src/boot/mod.rs"]
mod boot;
#[path = "../../src/arch/x86_64/mm/mod.rs"]
mod mm;
#[path = "../../src/object/mod.rs"]
mod object;
#[path = "../../src/handle/mod.rs"]
mod handle;
#[path = "../../src/memory/mod.rs"]
mod memory;

use mm::LiveTransitionMapper;

fn sibling_cannot_construct_mapper() {
    let _ = LiveTransitionMapper::from_private_parts();
}
