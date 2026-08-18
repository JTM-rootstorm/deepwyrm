#![allow(dead_code)]

#[path = "../../src/sync/mod.rs"]
mod sync;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ThreadKey(u64);

#[path = "../../src/task/scheduler.rs"]
mod scheduler;

use scheduler::SchedulerReservation;

fn clone_reservation(reservation: &SchedulerReservation) {
    let _ = <SchedulerReservation as Clone>::clone(reservation);
}
