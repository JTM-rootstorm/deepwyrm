//! Private virtual-memory authority boundary.
//!
//! Keeping the address-region model and object lease accounting under one
//! private parent lets their transaction-only `pub(super)` seams remain
//! inaccessible to unrelated `memory` siblings.

#[path = "address_region.rs"]
pub(crate) mod address_region;
#[path = "object.rs"]
pub(crate) mod object;
