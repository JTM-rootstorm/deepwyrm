//! DW0-C physical-memory foundations.
//!
//! This module is intentionally limited to sanitized physical allocation
//! facts. Virtual mappings, page-table mutation, usercopy, `MemoryObject`, and
//! `AddressRegion` remain separate DW0-C integration work.

pub mod boot_map;
pub mod physical;
pub(crate) mod user_range;
pub(crate) mod usercopy;
