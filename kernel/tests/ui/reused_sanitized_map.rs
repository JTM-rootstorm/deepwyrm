#![no_std]

#[path = "../../src/boot/mod.rs"]
mod boot;
#[path = "../../src/memory/mod.rs"]
mod memory;

use memory::boot_map::{BootstrapReservation, SanitizedBootMap};
use memory::frame_roles::FrameRoleManager;

#[allow(unsafe_code)]
fn initialize_manager_twice(map: SanitizedBootMap, reservations: &[BootstrapReservation]) {
    let _first = unsafe { FrameRoleManager::<1, 1>::from_boot_map(map, reservations) };
    let _second = unsafe { FrameRoleManager::<1, 1>::from_boot_map(map, reservations) };
}
