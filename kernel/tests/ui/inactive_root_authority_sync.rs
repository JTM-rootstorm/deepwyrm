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

use mm::InactiveRootAuthority;

fn require_sync<T: Sync>() {}

fn authority_is_not_sync() {
    require_sync::<InactiveRootAuthority<'static, 1, 1>>();
}
