//! Private physical-ownership implementation boundary.
//!
//! The public memory facade reexports reviewed boot-map and physical-range
//! APIs, but allocator construction and mutation remain visible only to this
//! module's descendants. Unrelated memory siblings cannot mint a second raw
//! allocator or bypass the frame-role manager.

#[path = "boot_map.rs"]
pub mod boot_map;
#[path = "frame_roles.rs"]
pub(crate) mod frame_roles;
#[path = "physical.rs"]
pub mod physical;
