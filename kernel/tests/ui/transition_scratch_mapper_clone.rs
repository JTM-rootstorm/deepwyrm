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

fn clone_mapper(mapper: &LiveTransitionMapper) {
    let _ = <LiveTransitionMapper as Clone>::clone(mapper);
}
