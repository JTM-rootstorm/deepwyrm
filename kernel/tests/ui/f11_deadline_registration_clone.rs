#![allow(dead_code)]

mod task {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct BlockWakeKey(u64);
}

#[path = "../../src/time/deadline.rs"]
mod deadline;

use deadline::DeadlineRegistration;

fn clone_registration(registration: &DeadlineRegistration) {
    let _ = <DeadlineRegistration as Clone>::clone(registration);
}
