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
#[path = "../../src/object/mod.rs"]
mod object;
#[path = "../../src/handle/mod.rs"]
mod handle;
#[path = "../../src/memory/mod.rs"]
mod memory;

use memory::address_region::{AddressSpaceKey, RegionKey};
use memory::frame_roles::{FrameRoleManager, TableCandidateGrant, TableIdentity};
use arch::x86_64::mm::{
    AtomicPageTableTarget, JournalStorage, PageTableRoot, X86AddressSpacePublisher,
};

fn construct_safely<T: AtomicPageTableTarget>(
    address_space: AddressSpaceKey,
    region: RegionKey,
    root: &PageTableRoot,
    root_identity: TableIdentity,
    roles: &mut FrameRoleManager<1, 1>,
    target: &mut T,
    candidates: &mut [Option<TableCandidateGrant>; 1],
    storage: &mut JournalStorage<1, 1>,
) {
    let _ = X86AddressSpacePublisher::<T, 1, 1, 1, 1, 1>::new(
        address_space,
        region,
        root,
        root_identity,
        roles,
        target,
        candidates,
        storage,
    );
}
