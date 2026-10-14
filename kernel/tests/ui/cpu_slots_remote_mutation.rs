#![no_std]

include!("cpu_slots_stub.rs");

// Another CPU's slot is read-only: no CPU mutates a slot it does not own
// (rows 72 and 96: deferred current and wait control are owner-only).
pub(crate) fn remote_write(owners: &[CpuOwner; 2], slots: &mut CpuSlots<Slot, 2>) {
    let (_own, others) = slots.split(&owners[0]);
    others.get(cpu(1)).unwrap().wait_control = 1;
}
