//! Returning DW1-E external-vector dispatch seam.
//!
//! The selected q35 product installs only vector `0x30`. E2B owns the
//! complete ephemeral assembly frame and the EOI boundary; E2C later binds
//! the generation-exact q35 platform handler before it may unmask a route.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};

use super::ipi::end_current_live_interrupt;

const UNBOUND: u8 = 0;
const BINDING: u8 = 1;
const BOUND: u8 = 2;

/// The only policy authority lent to the returning vector entry.
///
/// The implementation must perform its bounded source snapshot, logical
/// delivery, and IRQ-safe wake publication before returning. It must not
/// retain the assembly frame or call finalization/object-registry paths. Its
/// returned completion retains only a generation-bound scalar token and runs
/// immediately after successful local-APIC EOI.
pub(crate) trait Q35ExternalInterruptHandler: Sync {
    fn handle_q35_com2_interrupt(&self) -> Q35ExternalInterruptCompletion;
}

/// One bounded post-EOI action for the exact source snapshot accepted by an
/// external-vector handler.
///
/// E2C uses this to decrement its generation-bound in-handler accounting only
/// after EOI. The entry keeps neither the interrupted assembly frame nor any
/// object reference across the EOI boundary.
#[derive(Clone, Copy)]
pub(crate) struct Q35ExternalInterruptCompletion {
    token: u64,
    complete: Option<fn(u64)>,
}

impl Q35ExternalInterruptCompletion {
    /// Represents an unbound/stale path with no in-handler snapshot to close.
    pub(crate) const fn none() -> Self {
        Self {
            token: 0,
            complete: None,
        }
    }

    /// Creates the completion for one exact E2C source/generation snapshot.
    pub(crate) const fn generation_bound(token: u64, complete: fn(u64)) -> Self {
        Self {
            token,
            complete: Some(complete),
        }
    }

    fn complete_after_eoi(self) {
        if let Some(complete) = self.complete {
            complete(self.token);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Q35ExternalInterruptBindError {
    AlreadyBindingOrBound,
}

#[derive(Clone, Copy)]
struct HandlerBinding {
    context: *const (),
    dispatch: unsafe fn(*const ()) -> Q35ExternalInterruptCompletion,
}

#[allow(
    unsafe_code,
    reason = "the erased pointer retains an immutable reference to a static Sync handler"
)]
unsafe impl Sync for HandlerBinding {}

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

    fn bind(&self, value: T) -> Result<(), Q35ExternalInterruptBindError> {
        self.state
            .compare_exchange(UNBOUND, BINDING, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Q35ExternalInterruptBindError::AlreadyBindingOrBound)?;
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

static HANDLER: BindingSlot<HandlerBinding> = BindingSlot::new();

/// Publishes E2C's immutable q35 handler exactly once before route unmask.
pub(crate) fn bind_q35_external_interrupt_handler<T: Q35ExternalInterruptHandler + 'static>(
    handler: &'static T,
) -> Result<(), Q35ExternalInterruptBindError> {
    HANDLER.bind(HandlerBinding {
        context: core::ptr::from_ref(handler).cast::<()>(),
        dispatch: dispatch_handler::<T>,
    })
}

/// Restores the erased handler reference and dispatches through it.
///
/// # Safety
///
/// `context` must be the `&'static T` that
/// `bind_q35_external_interrupt_handler::<T>` erased, for the same `T` this
/// trampoline was monomorphized for. `HandlerBinding` is constructed only
/// there, and it sets the pointer and this trampoline together, so no caller
/// can pair a context with the wrong `T`.
#[allow(
    unsafe_code,
    reason = "the context was erased together with the matching shared-reference dispatch trampoline"
)]
unsafe fn dispatch_handler<T: Q35ExternalInterruptHandler>(
    context: *const (),
) -> Q35ExternalInterruptCompletion {
    let handler = unsafe { &*context.cast::<T>() };
    handler.handle_q35_com2_interrupt()
}

/// Performs the bounded E2B order: optional exact platform dispatch, then
/// local-APIC EOI. An absent binding is an unexpected/masked-source delivery;
/// it wakes no userspace and is still EOIed before return.
fn dispatch_and_eoi_with(eoi: impl FnOnce() -> bool) -> bool {
    let completion = if let Some(handler) = HANDLER.get() {
        #[allow(
            unsafe_code,
            reason = "the immutable binding pairs its static context with the matching dispatch trampoline"
        )]
        unsafe {
            (handler.dispatch)(handler.context)
        }
    } else {
        Q35ExternalInterruptCompletion::none()
    };
    if !eoi() {
        return false;
    }
    completion.complete_after_eoi();
    true
}

fn dispatch_and_eoi() -> bool {
    dispatch_and_eoi_with(end_current_live_interrupt)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "fixed symbol required by the audited returning q35 external-vector assembly boundary"
)]
#[unsafe(no_mangle)]
pub(crate) extern "sysv64" fn dw_x86_64_q35_com2_interrupt_dispatch() {
    if !dispatch_and_eoi() {
        halt_without_return();
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn halt_without_return() -> ! {
    loop {
        #[allow(
            unsafe_code,
            reason = "an unacknowledgeable external interrupt cannot safely resume the interrupted context"
        )]
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static PRE_EOI_CALLS: AtomicUsize = AtomicUsize::new(0);
    static EOI_CALLS: AtomicUsize = AtomicUsize::new(0);
    static POST_EOI_CALLS: AtomicUsize = AtomicUsize::new(0);
    static LAST_TOKEN: AtomicUsize = AtomicUsize::new(0);

    struct MockHandler;

    impl Q35ExternalInterruptHandler for MockHandler {
        fn handle_q35_com2_interrupt(&self) -> Q35ExternalInterruptCompletion {
            assert_eq!(EOI_CALLS.load(Ordering::Relaxed), 1);
            PRE_EOI_CALLS.fetch_add(1, Ordering::Relaxed);
            Q35ExternalInterruptCompletion::generation_bound(0x31, complete_mock_snapshot)
        }
    }

    static MOCK_HANDLER: MockHandler = MockHandler;

    fn complete_mock_snapshot(token: u64) {
        assert_eq!(EOI_CALLS.load(Ordering::Relaxed), 2);
        LAST_TOKEN.store(token as usize, Ordering::Relaxed);
        POST_EOI_CALLS.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn handler_binding_and_completion_are_exactly_once_and_post_eoi() {
        assert!(HANDLER.get().is_none());
        assert!(dispatch_and_eoi_with(|| {
            EOI_CALLS.fetch_add(1, Ordering::Relaxed);
            true
        }));
        assert_eq!(PRE_EOI_CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(POST_EOI_CALLS.load(Ordering::Relaxed), 0);

        bind_q35_external_interrupt_handler(&MOCK_HANDLER).unwrap();
        assert!(HANDLER.get().is_some());
        assert_eq!(
            bind_q35_external_interrupt_handler(&MOCK_HANDLER),
            Err(Q35ExternalInterruptBindError::AlreadyBindingOrBound)
        );

        assert!(dispatch_and_eoi_with(|| {
            assert_eq!(PRE_EOI_CALLS.load(Ordering::Relaxed), 1);
            assert_eq!(POST_EOI_CALLS.load(Ordering::Relaxed), 0);
            EOI_CALLS.fetch_add(1, Ordering::Relaxed);
            true
        }));
        assert_eq!(POST_EOI_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(LAST_TOKEN.load(Ordering::Relaxed), 0x31);
    }
}
