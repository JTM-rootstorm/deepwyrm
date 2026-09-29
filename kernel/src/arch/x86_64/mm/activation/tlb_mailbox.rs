//! The CPU-private e2 TLB-shootdown mailbox used by `user_access.rs`.
//!
//! Split out of the target-only `user_access.rs` (S2K-0): it uses only
//! atomics, an `UnsafeCell` and the host-compiled `address_region` types, so
//! the host `test` build compiles it and its tests run.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

const TLB_MAILBOX_EMPTY: u8 = 0;
const TLB_MAILBOX_PUBLISHING: u8 = 1;
const TLB_MAILBOX_PUBLISHED: u8 = 2;
const TLB_MAILBOX_CONSUMING: u8 = 3;

/// One CPU-private, protocol-owned e2 mailbox.
///
/// The sender owns `PUBLISHING` and may only advance it to `PUBLISHED` after
/// fully writing the exact request and stationary coherency pointer.  The e2
/// handler owns `CONSUMING`; it copies those fields before local serialization
/// and never consults the mailbox after returning it to `EMPTY`.
pub(super) struct LiveTlbMailbox {
    state: AtomicU8,
    coherency: AtomicPtr<
        crate::memory::address_region::AddressSpaceCoherency<{ crate::cpu::CPU_CAPACITY }>,
    >,
    request: UnsafeCell<MaybeUninit<crate::memory::address_region::ShootdownRequest>>,
}

impl LiveTlbMailbox {
    pub(super) const fn new() -> Self {
        Self {
            state: AtomicU8::new(TLB_MAILBOX_EMPTY),
            coherency: AtomicPtr::new(core::ptr::null_mut()),
            request: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    pub(super) fn publish(
        &self,
        coherency: &crate::memory::address_region::AddressSpaceCoherency<
            { crate::cpu::CPU_CAPACITY },
        >,
        request: crate::memory::address_region::ShootdownRequest,
    ) {
        self.state
            .compare_exchange(
                TLB_MAILBOX_EMPTY,
                TLB_MAILBOX_PUBLISHING,
                Ordering::Acquire,
                Ordering::Acquire,
            )
            .unwrap_or_else(|state| {
                panic!("TLB shootdown target already has an outstanding mailbox: {state}")
            });
        #[allow(
            unsafe_code,
            reason = "the sender exclusively owns PUBLISHING until its Release publication"
        )]
        // SAFETY: this sender exclusively owns PUBLISHING. The request is
        // immutable after the following Release publication, and the handler
        // may read it only after it Acquire-observes PUBLISHED.
        unsafe {
            (*self.request.get()).write(request);
        }
        self.coherency
            .store(core::ptr::from_ref(coherency).cast_mut(), Ordering::Relaxed);
        self.state.store(TLB_MAILBOX_PUBLISHED, Ordering::Release);
    }

    pub(super) fn cancel_if_published(&self) {
        let _ = self.state.compare_exchange(
            TLB_MAILBOX_PUBLISHED,
            TLB_MAILBOX_EMPTY,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub(super) fn consume(
        &self,
    ) -> Option<(
        &crate::memory::address_region::AddressSpaceCoherency<{ crate::cpu::CPU_CAPACITY }>,
        crate::memory::address_region::ShootdownRequest,
    )> {
        self.state
            .compare_exchange(
                TLB_MAILBOX_PUBLISHED,
                TLB_MAILBOX_CONSUMING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;
        let coherency = self.coherency.load(Ordering::Relaxed);
        if coherency.is_null() {
            panic!("published TLB shootdown mailbox omitted coherency domain");
        }
        #[allow(
            unsafe_code,
            reason = "the handler exclusively owns CONSUMING after acquire-consuming the sender publication"
        )]
        // SAFETY: the successful AcqRel transition owns the immutable request
        // after the sender's Release publication, which initialized it.
        let request = unsafe { (*self.request.get()).assume_init_read() };
        #[allow(
            unsafe_code,
            reason = "the exact stationary coherency pointer is retained by its root binding until acknowledgement-gated reclaim"
        )]
        // SAFETY: the non-null pointer names the exact stationary root-binding
        // coherency object the sender published; binding teardown remains
        // gated by the acknowledgement this handler completes later.
        let coherency = unsafe { &*coherency };
        Some((coherency, request))
    }

    pub(super) fn release_after_local_serialization(&self) {
        self.state
            .compare_exchange(
                TLB_MAILBOX_CONSUMING,
                TLB_MAILBOX_EMPTY,
                Ordering::Release,
                Ordering::Acquire,
            )
            .unwrap_or_else(|state| {
                panic!("TLB shootdown mailbox ownership drifted after local flush: {state}")
            });
    }
}

#[allow(
    unsafe_code,
    reason = "mailbox state serializes the UnsafeCell request between one sender and one e2 handler"
)]
// SAFETY: the request cell is read only by the e2 CPU after acquire-consuming
// the state publication and before release-clearing its unique mailbox state.
unsafe impl Sync for LiveTlbMailbox {}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn e2_mailbox_releases_only_after_local_serialization_before_exact_ack() {
        let address_space = crate::memory::address_region::AddressSpaceKey::for_test(7, 11);
        let coherency = crate::memory::address_region::AddressSpaceCoherency::<
            { crate::cpu::CPU_CAPACITY },
        >::new(address_space);
        let cpu = crate::cpu::CpuIndex::new(1).unwrap();
        let _residency = coherency.enter(cpu).unwrap();
        let transaction = coherency
            .prepare_mutation(
                crate::memory::address_region::MappingMutation::Protect,
                crate::memory::address_region::InvalidationScope::pages(0x4000, 0x1000).unwrap(),
            )
            .unwrap();
        let barrier = transaction.publish();
        let request = barrier.request();
        let mailbox = LiveTlbMailbox::new();

        mailbox.publish(&coherency, request);
        let (received_coherency, received_request) = mailbox.consume().unwrap();
        assert_eq!(received_request, request);
        assert_eq!(
            received_coherency.request_for_cpu(cpu),
            Some(request),
            "the e2 target still has a pending exact generation before acknowledgement"
        );
        mailbox.release_after_local_serialization();
        received_coherency
            .acknowledge(cpu, received_request)
            .unwrap();
        assert!(barrier.try_complete().is_ok());
        assert_eq!(mailbox.state.load(Ordering::Acquire), TLB_MAILBOX_EMPTY);
    }

    #[test]
    fn e2_mailbox_rejects_overlapping_target_publication() {
        let address_space = crate::memory::address_region::AddressSpaceKey::for_test(9, 13);
        let coherency = crate::memory::address_region::AddressSpaceCoherency::<
            { crate::cpu::CPU_CAPACITY },
        >::new(address_space);
        let cpu = crate::cpu::CpuIndex::new(1).unwrap();
        let _residency = coherency.enter(cpu).unwrap();
        let transaction = coherency
            .prepare_mutation(
                crate::memory::address_region::MappingMutation::Map,
                crate::memory::address_region::InvalidationScope::pages(0x5000, 0x1000).unwrap(),
            )
            .unwrap();
        let barrier = transaction.publish();
        let mailbox = LiveTlbMailbox::new();
        mailbox.publish(&coherency, barrier.request());
        let overlap = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            mailbox.publish(&coherency, barrier.request());
        }));
        assert!(overlap.is_err());
        mailbox.cancel_if_published();
    }
}
