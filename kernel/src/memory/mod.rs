//! DW0-C physical-memory foundations.
//!
//! This module is intentionally limited to sanitized physical allocation
//! facts. Page-table publication remains an architecture-owned boundary, while
//! user ranges, exact copies, `MemoryObject`, and `AddressRegion` stay portable.

pub(crate) mod address_region;
pub mod boot_map;
pub(crate) mod object;
pub mod physical;
pub(crate) mod user_range;
pub(crate) mod usercopy;
