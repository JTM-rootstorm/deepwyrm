#![no_std]

#[path = "../../src/boot/mod.rs"]
mod boot;
#[path = "../../src/memory/mod.rs"]
mod memory;

use memory::frame_roles::TableCandidateGrant;

fn clone_grant(grant: &TableCandidateGrant) {
    let _ = <TableCandidateGrant as Clone>::clone(grant);
}
