#![no_std]

#[path = "../../src/cpu.rs"]
mod cpu;
#[path = "../../src/sync/mod.rs"]
mod sync;

#[path = "../../src/boot/mod.rs"]
mod boot;
#[path = "../../src/object/mod.rs"]
mod object;
#[path = "../../src/handle/mod.rs"]
mod handle;
#[path = "../../src/memory/mod.rs"]
mod memory;

fn retain_raw_allocator(_allocator: memory::physical::PhysicalFrameAllocator<1>) {}
