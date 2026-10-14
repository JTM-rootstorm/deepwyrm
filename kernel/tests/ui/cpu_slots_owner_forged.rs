#![no_std]

include!("cpu_slots_stub.rs");

// No code outside `cpu_slots.rs` can build an owner, so none can take another
// CPU's slot mutably.
pub(crate) fn forge(slots: &mut CpuSlots<Slot, 2>) {
    let forged = CpuOwner { cpu: cpu(1) };
    let (own, _others) = slots.split(&forged);
    own.wait_control = 1;
}
