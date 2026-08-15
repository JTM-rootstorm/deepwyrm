#![no_std]

#[path = "../../src/boot/mod.rs"]
mod boot;
#[path = "../../src/arch/x86_64/mm/mod.rs"]
mod mm;
#[path = "../../src/memory/mod.rs"]
mod memory;

use memory::address_region::{AddressSpaceKey, RegionKey};
use memory::frame_roles::{FrameRoleManager, TableCandidateGrant, TableIdentity};
use mm::{AtomicPageTableTarget, PageTableRoot, X86AddressSpacePublisher};

fn construct_safely<T: AtomicPageTableTarget>(
    address_space: AddressSpaceKey,
    region: RegionKey,
    root: &PageTableRoot,
    root_identity: TableIdentity,
    roles: &mut FrameRoleManager<1, 1>,
    target: &mut T,
    candidates: &mut [Option<TableCandidateGrant>; 1],
) {
    let _ = X86AddressSpacePublisher::<T, 1, 1, 1, 1, 1>::new(
        address_space,
        region,
        root,
        root_identity,
        roles,
        target,
        candidates,
    );
}
