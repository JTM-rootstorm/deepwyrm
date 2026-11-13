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

use mm::LiveTransitionMapper;

fn sibling_cannot_construct_mapper() {
    let _ = LiveTransitionMapper::from_private_parts();
}
