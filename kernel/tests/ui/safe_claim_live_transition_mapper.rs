#![no_std]

#[path = "../../src/cpu.rs"]
mod cpu;
#[path = "../../src/sync/mod.rs"]
mod sync;

#[path = "../../src/boot/mod.rs"]
mod boot;
// Mounted where the kernel mounts it: the module names itself through
// `crate::arch::x86_64::mm`.
#[path = "../../src/arch"]
mod arch {
    pub(crate) mod x86_64 {
        #[path = "mm/mod.rs"]
        pub(crate) mod mm;
    }
}
use arch::x86_64::mm;
#[path = "../../src/object/mod.rs"]
mod object;
#[path = "../../src/handle/mod.rs"]
mod handle;
#[path = "../../src/memory/mod.rs"]
mod memory;

use boot::ValidatedPagingHandoff;
use memory::frame_roles::FrameRoleManager;
use mm::claim_live_transition_mapper;

fn safe_sibling_cannot_claim(
    handoff: &ValidatedPagingHandoff,
    roles: &mut FrameRoleManager<1, 1>,
) {
    let _ = claim_live_transition_mapper(handoff, roles);
}
