#![no_std]

#[path = "../../src/boot/mod.rs"]
mod boot;
#[path = "../../src/object/mod.rs"]
mod object;
#[path = "../../src/handle/mod.rs"]
mod handle;
#[path = "../../src/memory/mod.rs"]
mod memory;

use memory::boot_map::{BootstrapReservation, SanitizedBootMap};
use memory::frame_roles::FrameRoleManager;

fn initialize_manager_safely(map: SanitizedBootMap, reservations: &[BootstrapReservation]) {
    let _ = FrameRoleManager::<1, 1>::from_boot_map(map, reservations);
}
