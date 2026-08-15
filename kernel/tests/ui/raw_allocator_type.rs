#![no_std]

#[path = "../../src/boot/mod.rs"]
mod boot;
#[path = "../../src/memory/mod.rs"]
mod memory;

fn retain_raw_allocator(_allocator: memory::physical::PhysicalFrameAllocator<1>) {}
