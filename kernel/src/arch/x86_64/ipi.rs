//! Narrow live transport boundary for the H2 rendezvous and H3 shootdown IPIs.
//!
//! The current local-APIC owner cannot safely be borrowed from an interrupt on
//! every CPU, so this module makes that ownership dependency explicit through
//! one immutable injected transport. Receive callbacks are intentionally
//! argument-free: the architecture layer does not lend task, address-space,
//! usercopy, finalization, or scheduling authority to interrupt context.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::interrupt::{SMP_RENDEZVOUS_VECTOR, TLB_SHOOTDOWN_VECTOR};

const UNBOUND: u8 = 0;
const BINDING: u8 = 1;
const BOUND: u8 = 2;

/// One of the two fixed vectors owned by the cross-CPU transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveIpiVector {
    Rendezvous,
    TlbShootdown,
}

impl LiveIpiVector {
    pub(crate) const fn vector(self) -> u8 {
        match self {
            Self::Rendezvous => SMP_RENDEZVOUS_VECTOR,
            Self::TlbShootdown => TLB_SHOOTDOWN_VECTOR,
        }
    }
}

/// Persistent authority required to emit a fixed IPI and acknowledge one on
/// the currently executing CPU.
///
/// An implementation must select CPU-private local-APIC state for EOI and
/// must not take a lock that an interrupted local execution can already hold.
pub(crate) trait LiveIpiTransport: Sync {
    fn send_fixed(&self, destination_apic_id: u8, vector: LiveIpiVector) -> bool;
    fn end_of_interrupt(&self) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveIpiBindError {
    AlreadyBindingOrBound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveIpiSendError {
    TransportUnbound,
    TransportRejected,
}

#[derive(Clone, Copy)]
struct TransportBinding {
    context: *const (),
    send: unsafe fn(*const (), u8, LiveIpiVector) -> bool,
    eoi: unsafe fn(*const ()) -> bool,
}

#[allow(
    unsafe_code,
    reason = "the erased pointer retains an immutable reference to a static Sync transport"
)]
unsafe impl Sync for TransportBinding {}

struct BindingSlot<T> {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
}

impl<T> BindingSlot<T> {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(UNBOUND),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn bind(&self, value: T) -> Result<(), LiveIpiBindError> {
        self.state
            .compare_exchange(UNBOUND, BINDING, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| LiveIpiBindError::AlreadyBindingOrBound)?;
        #[allow(
            unsafe_code,
            reason = "the successful one-shot binder exclusively initializes this slot before release publication"
        )]
        unsafe {
            (*self.value.get()).write(value);
        }
        self.state.store(BOUND, Ordering::Release);
        Ok(())
    }

    fn get(&self) -> Option<&T> {
        if self.state.load(Ordering::Acquire) != BOUND {
            return None;
        }
        #[allow(
            unsafe_code,
            reason = "Acquire observes the immutable value fully initialized before BOUND publication"
        )]
        Some(unsafe { (*self.value.get()).assume_init_ref() })
    }
}

#[allow(
    unsafe_code,
    reason = "one-shot release publication makes immutable Sync binding values safe to share"
)]
unsafe impl<T: Sync> Sync for BindingSlot<T> {}

static TRANSPORT: BindingSlot<TransportBinding> = BindingSlot::new();
static RENDEZVOUS_HANDLER: BindingSlot<fn()> = BindingSlot::new();
static TLB_SHOOTDOWN_HANDLER: BindingSlot<fn()> = BindingSlot::new();

/// Reports whether the immutable send/EOI transport has been published.
pub(crate) fn live_ipi_transport_is_bound() -> bool {
    TRANSPORT.get().is_some()
}

pub(crate) fn live_rendezvous_handler_is_bound() -> bool {
    RENDEZVOUS_HANDLER.get().is_some()
}

/// Publishes the persistent per-CPU-aware APIC transport exactly once.
pub(crate) fn bind_live_ipi_transport<T: LiveIpiTransport + 'static>(
    transport: &'static T,
) -> Result<(), LiveIpiBindError> {
    TRANSPORT.bind(TransportBinding {
        context: core::ptr::from_ref(transport).cast::<()>(),
        send: transport_send::<T>,
        eoi: transport_eoi::<T>,
    })
}

#[allow(
    unsafe_code,
    reason = "the context was erased together with the matching monomorphized shared-reference trampoline"
)]
unsafe fn transport_send<T: LiveIpiTransport>(
    context: *const (),
    destination_apic_id: u8,
    vector: LiveIpiVector,
) -> bool {
    let transport = unsafe { &*context.cast::<T>() };
    transport.send_fixed(destination_apic_id, vector)
}

#[allow(
    unsafe_code,
    reason = "the context was erased together with the matching monomorphized shared-reference trampoline"
)]
unsafe fn transport_eoi<T: LiveIpiTransport>(context: *const ()) -> bool {
    let transport = unsafe { &*context.cast::<T>() };
    transport.end_of_interrupt()
}

/// Publishes the bounded rendezvous receive callback exactly once.
///
/// The callback runs with `IF=0`, after local-APIC EOI, and receives no general
/// kernel capability. It may inspect only protocol-owned IRQ-safe state and
/// must not usercopy, finalize objects, or schedule.
pub(crate) fn bind_live_rendezvous_handler(handler: fn()) -> Result<(), LiveIpiBindError> {
    RENDEZVOUS_HANDLER.bind(handler)
}

/// Publishes the bounded TLB-shootdown receive callback exactly once.
///
/// Keeping the two protocol callbacks independently bindable prevents H4's
/// timer-service/idle-wake rendezvous from installing a false no-op shootdown
/// acknowledgement before H3's live root-coherency join is ready.
pub(crate) fn bind_live_tlb_shootdown_handler(handler: fn()) -> Result<(), LiveIpiBindError> {
    TLB_SHOOTDOWN_HANDLER.bind(handler)
}

/// Sends one fixed IPI through the installed persistent transport.
pub(crate) fn send_live_ipi(
    destination_apic_id: u8,
    vector: LiveIpiVector,
) -> Result<(), LiveIpiSendError> {
    let binding = TRANSPORT.get().ok_or(LiveIpiSendError::TransportUnbound)?;
    #[allow(
        unsafe_code,
        reason = "the immutable binding pairs its static context with the matching send trampoline"
    )]
    if unsafe { (binding.send)(binding.context, destination_apic_id, vector) } {
        Ok(())
    } else {
        Err(LiveIpiSendError::TransportRejected)
    }
}

fn dispatch(vector: LiveIpiVector) {
    let Some(transport) = TRANSPORT.get() else {
        halt_without_return();
    };
    #[allow(
        unsafe_code,
        reason = "the immutable binding pairs its static context with the matching EOI trampoline"
    )]
    let eoi_completed = unsafe { (transport.eoi)(transport.context) };
    if !eoi_completed {
        halt_without_return();
    }

    // EOI precedes the protocol callback. IF remains clear until IRETQ, so a
    // stop callback may wait for release without retaining APIC in-service
    // ownership. An unbound callback is a wake/no-request no-op; it never
    // publishes a logical Safe or shootdown acknowledgement.
    let handler = match vector {
        LiveIpiVector::Rendezvous => RENDEZVOUS_HANDLER.get(),
        LiveIpiVector::TlbShootdown => TLB_SHOOTDOWN_HANDLER.get(),
    };
    if let Some(handler) = handler {
        handler();
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "fixed symbol required by the audited returning rendezvous IPI assembly boundary"
)]
#[unsafe(no_mangle)]
pub(crate) extern "sysv64" fn dw_x86_64_rendezvous_ipi_dispatch() {
    dispatch(LiveIpiVector::Rendezvous);
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "fixed symbol required by the audited returning shootdown IPI assembly boundary"
)]
#[unsafe(no_mangle)]
pub(crate) extern "sysv64" fn dw_x86_64_tlb_shootdown_ipi_dispatch() {
    dispatch(LiveIpiVector::TlbShootdown);
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn halt_without_return() -> ! {
    loop {
        #[allow(
            unsafe_code,
            reason = "an unacknowledgeable fixed IPI cannot safely resume the interrupted context"
        )]
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}

#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
fn halt_without_return() -> ! {
    panic!("live IPI dispatch is unavailable on the host")
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU16, AtomicUsize};

    static LAST_SEND: AtomicU16 = AtomicU16::new(0);
    static EOI_COUNT: AtomicUsize = AtomicUsize::new(0);
    static HANDLER_COUNT: AtomicUsize = AtomicUsize::new(0);

    struct MockTransport;

    impl LiveIpiTransport for MockTransport {
        fn send_fixed(&self, destination_apic_id: u8, vector: LiveIpiVector) -> bool {
            LAST_SEND.store(
                (u16::from(destination_apic_id) << 8) | u16::from(vector.vector()),
                Ordering::Relaxed,
            );
            true
        }

        fn end_of_interrupt(&self) -> bool {
            EOI_COUNT.fetch_add(1, Ordering::Relaxed);
            true
        }
    }

    static MOCK_TRANSPORT: MockTransport = MockTransport;

    fn rendezvous_handler() {
        assert_eq!(EOI_COUNT.load(Ordering::Relaxed), 1);
        HANDLER_COUNT.fetch_add(1, Ordering::Relaxed);
    }

    fn shootdown_handler() {
        assert_eq!(EOI_COUNT.load(Ordering::Relaxed), 2);
        HANDLER_COUNT.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn vectors_are_exactly_the_reserved_h2_h3_pair() {
        assert_eq!(LiveIpiVector::Rendezvous.vector(), SMP_RENDEZVOUS_VECTOR);
        assert_eq!(LiveIpiVector::TlbShootdown.vector(), TLB_SHOOTDOWN_VECTOR);
        assert_ne!(
            LiveIpiVector::Rendezvous.vector(),
            LiveIpiVector::TlbShootdown.vector()
        );
    }

    #[test]
    fn bound_transport_sends_and_eois_before_each_protocol_callback() {
        assert!(!live_ipi_transport_is_bound());
        bind_live_ipi_transport(&MOCK_TRANSPORT).unwrap();
        assert!(live_ipi_transport_is_bound());
        bind_live_rendezvous_handler(rendezvous_handler).unwrap();
        bind_live_tlb_shootdown_handler(shootdown_handler).unwrap();

        send_live_ipi(7, LiveIpiVector::Rendezvous).unwrap();
        assert_eq!(
            LAST_SEND.load(Ordering::Relaxed),
            (7_u16 << 8) | u16::from(SMP_RENDEZVOUS_VECTOR)
        );
        dispatch(LiveIpiVector::Rendezvous);
        dispatch(LiveIpiVector::TlbShootdown);
        assert_eq!(EOI_COUNT.load(Ordering::Relaxed), 2);
        assert_eq!(HANDLER_COUNT.load(Ordering::Relaxed), 2);
        assert_eq!(
            bind_live_ipi_transport(&MOCK_TRANSPORT),
            Err(LiveIpiBindError::AlreadyBindingOrBound)
        );
    }
}
