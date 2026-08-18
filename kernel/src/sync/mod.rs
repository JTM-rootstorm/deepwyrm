//! Minimal kernel synchronization used by DW0-E task execution.
//!
//! E3 deliberately provides only non-sleeping mutual exclusion. Native waits,
//! events, atomic wait/wake, and blocking synchronization remain DW0-F work.

mod spin;

pub(crate) use spin::SpinMutex;

#[cfg(test)]
mod tests;
