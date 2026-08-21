#![allow(dead_code)]

#[path = "../../src/sync/mod.rs"]
mod sync;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThreadKey(u64);

#[path = "../../src/task/scheduler.rs"]
mod scheduler;

use scheduler::BlockReservation;

fn clone_reservation(reservation: &BlockReservation) {
    let _ = <BlockReservation as Clone>::clone(reservation);
}
