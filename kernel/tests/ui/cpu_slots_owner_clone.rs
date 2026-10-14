#![no_std]

include!("cpu_slots_stub.rs");

// An owner cannot be duplicated for a second holder.
pub(crate) fn duplicate(owners: &[CpuOwner; 2]) -> CpuOwner {
    owners[1].clone()
}
