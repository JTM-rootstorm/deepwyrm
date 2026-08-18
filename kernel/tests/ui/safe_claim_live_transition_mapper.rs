#![no_std]

#[path = "../../src/boot/mod.rs"]
mod boot;
#[path = "../../src/arch/x86_64/mm/mod.rs"]
mod mm;
#[path = "../../src/object/mod.rs"]
mod object;
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
