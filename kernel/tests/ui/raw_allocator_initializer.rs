#![no_std]

#[path = "../../src/boot/mod.rs"]
mod boot;
#[path = "../../src/object/mod.rs"]
mod object;
#[path = "../../src/memory/mod.rs"]
mod memory;

use memory::boot_map::{BootstrapReservation, SanitizedBootMap};

fn initialize_raw_allocator(
    map: &SanitizedBootMap,
    reservations: &[BootstrapReservation],
) {
    let _ = memory::boot_map::initialize_frame_allocator::<1>(map, reservations);
}
