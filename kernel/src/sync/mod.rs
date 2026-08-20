//! Minimal kernel synchronization used by DW0-E task execution.
//!
//! E3 provides non-sleeping mutual exclusion and F3 adds a local-IRQ-safe
//! wrapper for timer/scheduler critical sections. Native waits, events, and
//! atomic wait/wake remain later DW0-F work.

mod irq;
mod spin;

pub(crate) use irq::IrqSpinMutex;
pub(crate) use spin::SpinMutex;

#[cfg(test)]
mod tests;
