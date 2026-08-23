//! Coalesced cross-CPU timer-service request and global fault publication.

use core::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TimerServiceFault;

/// A failed fixed-IPI send is architecturally ambiguous: the request may have
/// reached the destination even when the sender cannot prove success. Once a
/// mutation has committed, neither rollback nor AP-local halt is sufficient.
/// This latch therefore faults the global service permanently and is checked
/// by the BSP before it services either e1 or its next timer interrupt.
pub(crate) struct TimerServiceSignal {
    pending: AtomicBool,
    faulted: AtomicBool,
}

impl TimerServiceSignal {
    pub(crate) const fn new() -> Self {
        Self {
            pending: AtomicBool::new(false),
            faulted: AtomicBool::new(false),
        }
    }

    pub(crate) fn publish(&self) -> Result<(), TimerServiceFault> {
        self.ensure_healthy()?;
        self.pending.store(true, Ordering::Release);
        Ok(())
    }

    /// Permanently faults the global service after any ambiguous transport
    /// result. Release makes every prior queue mutation visible before fault.
    pub(crate) fn fail_transport(&self) {
        self.faulted.store(true, Ordering::Release);
    }

    /// Acquires fault before consuming a request. A late-delivered e1 can
    /// never clear a failure or make the BSP continue after ambiguity.
    pub(crate) fn take(&self) -> Result<bool, TimerServiceFault> {
        self.ensure_healthy()?;
        let pending = self.pending.swap(false, Ordering::AcqRel);
        self.ensure_healthy()?;
        Ok(pending)
    }

    pub(crate) fn ensure_healthy(&self) -> Result<(), TimerServiceFault> {
        if self.faulted.load(Ordering::Acquire) {
            Err(TimerServiceFault)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;

    #[test]
    fn rejected_or_ambiguous_transport_permanently_faults_pending_service() {
        let signal = TimerServiceSignal::new();
        signal.publish().unwrap();
        signal.fail_transport();
        assert_eq!(signal.take(), Err(TimerServiceFault));
        assert_eq!(signal.publish(), Err(TimerServiceFault));
        assert_eq!(signal.ensure_healthy(), Err(TimerServiceFault));
    }

    #[test]
    fn concurrent_late_delivery_cannot_clear_an_ambiguous_failure() {
        for _ in 0..4_000 {
            let signal = Arc::new(TimerServiceSignal::new());
            signal.publish().unwrap();
            let start = Arc::new(Barrier::new(3));
            let receiver_signal = Arc::clone(&signal);
            let receiver_start = Arc::clone(&start);
            let receiver = thread::spawn(move || {
                receiver_start.wait();
                receiver_signal.take()
            });
            let sender_signal = Arc::clone(&signal);
            let sender_start = Arc::clone(&start);
            let sender = thread::spawn(move || {
                sender_start.wait();
                sender_signal.fail_transport();
            });
            start.wait();
            sender.join().unwrap();
            let _possibly_serviced_before_fault = receiver.join().unwrap();
            assert_eq!(signal.ensure_healthy(), Err(TimerServiceFault));
            assert_eq!(signal.take(), Err(TimerServiceFault));
        }
    }
}
