#![no_std]

include!("cpu_slots_stub.rs");

// The owner mutates its own slot, reads the others, and makes the one remote
// write; this must compile.
pub(crate) fn owner_only(owners: &[CpuOwner; 2], slots: &mut CpuSlots<Slot, 2>) -> u32 {
    let (own, mut others) = slots.split(&owners[0]);
    own.wait_control = 1;
    others.stage_remote(cpu(1), 7);
    let remote: Option<&Slot> = others.get(cpu(1));
    let _: &OtherCpus<'_, Slot> = &others;
    remote.map_or(0, |slot| slot.wait_control) + own.wait_control
}

pub(crate) fn mint() -> [CpuOwner; 2] {
    slots().mint_owners()
}
