#![no_std]

#[path = "../../src/boot/mod.rs"]
mod boot;
#[path = "../../src/arch/x86_64/mm/mod.rs"]
mod mm;
#[path = "../../src/memory/mod.rs"]
mod memory;

use mm::LiveTransitionMapper;

fn raw_frame_zeroing_is_not_exposed(mapper: &mut LiveTransitionMapper) {
    mapper.zero_frame();
}
