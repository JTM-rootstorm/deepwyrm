#![allow(dead_code)]

#[path = "../../src/sync/mod.rs"]
mod sync;
#[path = "../../src/cpu.rs"]
mod cpu;
#[path = "debug_stub.rs"]
mod debug;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThreadKey(u64);

#[path = "../../src/task/scheduler.rs"]
mod scheduler;

use scheduler::BlockToken;

fn clone_token(token: &BlockToken) {
    let _ = <BlockToken as Clone>::clone(token);
}
