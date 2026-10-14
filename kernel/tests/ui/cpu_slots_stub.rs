// Minimal crate context for the compile-fail fixtures that build
// `mm/activation/cpu_slots.rs` as a standalone crate (S2K-6). It needs only
// `crate::cpu::CpuIndex`; `cpu_slots.rs`'s `pub(super)` items are visible at
// this crate root. `Slot` stands in for the primordial `CpuSharedState`.

#[path = "../../src/cpu.rs"]
mod cpu;
#[path = "../../src/arch/x86_64/mm/activation/cpu_slots.rs"]
mod cpu_slots;

pub(crate) use cpu::CpuIndex;
pub(crate) use cpu_slots::{CpuOwner, CpuSlots, OtherCpus, RemotelyStaged};

pub(crate) struct Slot {
    pub(crate) wait_control: u32,
    pub(crate) pending: Option<u32>,
}

impl RemotelyStaged for Slot {
    type Staged = u32;

    fn stage_remote(&mut self, staged: u32) {
        self.pending = Some(staged);
    }
}

pub(crate) fn slots() -> CpuSlots<Slot, 2> {
    CpuSlots::new([const {
        Slot {
            wait_control: 0,
            pending: None,
        }
    }; 2])
}

pub(crate) fn cpu(index: usize) -> CpuIndex {
    CpuIndex::new(index).unwrap_or_else(|| panic!("CPU {index} out of range"))
}
