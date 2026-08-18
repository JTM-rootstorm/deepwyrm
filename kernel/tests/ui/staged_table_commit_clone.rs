#![no_std]

#[path = "../../src/boot/mod.rs"]
mod boot;
#[path = "../../src/object/mod.rs"]
mod object;
#[path = "../../src/memory/mod.rs"]
mod memory;

use memory::frame_roles::StagedTableCommit;

fn clone_commit(commit: &StagedTableCommit) {
    let _ = <StagedTableCommit as Clone>::clone(commit);
}
