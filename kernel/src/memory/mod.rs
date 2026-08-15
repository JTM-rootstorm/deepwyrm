//! DW0-C physical-memory foundations.
//!
//! This module is intentionally limited to sanitized physical allocation
//! facts. Page-table publication remains an architecture-owned boundary, while
//! user ranges, exact copies, `MemoryObject`, and `AddressRegion` stay portable.

mod vm;

#[allow(
    unused_imports,
    reason = "the private VM facade precedes its architecture and handle consumers"
)]
pub(crate) use vm::address_region;
#[allow(
    unused_imports,
    reason = "the private VM facade precedes its architecture and handle consumers"
)]
pub(crate) use vm::object;
pub mod boot_map;
pub mod physical;
pub(crate) mod user_range;
pub(crate) mod usercopy;
