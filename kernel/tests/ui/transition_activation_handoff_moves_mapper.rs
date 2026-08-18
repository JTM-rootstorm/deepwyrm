#![no_std]

#[path = "../../src/boot/mod.rs"]
mod boot;
#[path = "../../src/arch/x86_64/mm/mod.rs"]
mod mm;
#[path = "../../src/object/mod.rs"]
mod object;
#[path = "../../src/memory/mod.rs"]
mod memory;

use mm::LiveTransitionMapper;

fn terminal_handoff_is_consuming(mapper: LiveTransitionMapper) {
    let _handoff = mapper.into_activation_handoff();
    drop(mapper);
}
