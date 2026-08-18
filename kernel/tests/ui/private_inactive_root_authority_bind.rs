#![no_std]

#[path = "../../src/boot/mod.rs"]
mod boot;
#[path = "../../src/arch/x86_64/mm/mod.rs"]
mod mm;
#[path = "../../src/object/mod.rs"]
mod object;
#[path = "../../src/memory/mod.rs"]
mod memory;

use mm::InactiveRootAuthority;

fn cannot_fabricate_binding() {
    let _ = InactiveRootAuthority::<'static, 1, 1>::bind;
}
