#![allow(
    dead_code,
    reason = "F2 architecture helpers are target/source-contract surfaces before blocking syscalls consume them"
)]
#![cfg_attr(
    all(test, target_arch = "x86_64", not(target_os = "none")),
    allow(unsafe_code)
)]

//! Minimal x86_64 kernel-continuation switch contract for DW0-F2.
//!
//! This is deliberately separate from userspace `IRETQ` state. A suspended
//! Rust kernel frame is resumed only through the normal SysV callee-saved
//! register contract plus its exact saved kernel `RSP`.

use crate::memory::kernel_stack::KernelStackBounds;

pub(crate) const KERNEL_CONTEXT_R15_OFFSET: u64 = 0;
pub(crate) const KERNEL_CONTEXT_R14_OFFSET: u64 = 8;
pub(crate) const KERNEL_CONTEXT_R13_OFFSET: u64 = 16;
pub(crate) const KERNEL_CONTEXT_R12_OFFSET: u64 = 24;
pub(crate) const KERNEL_CONTEXT_RBP_OFFSET: u64 = 32;
pub(crate) const KERNEL_CONTEXT_RBX_OFFSET: u64 = 40;
pub(crate) const KERNEL_CONTEXT_RFLAGS_OFFSET: u64 = 48;
pub(crate) const KERNEL_CONTEXT_RETURN_RIP_OFFSET: u64 = 56;
pub(crate) const KERNEL_CONTEXT_FRAME_BYTES: u64 = 64;
pub(crate) const INITIAL_KERNEL_CONTEXT_BYTES: u64 = KERNEL_CONTEXT_FRAME_BYTES + 8;

pub(crate) const INITIAL_KERNEL_CONTINUATION_RFLAGS: u64 = 1 << 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InitialKernelContinuationError {
    StackGeometry,
    RflagsPolicy,
    EntryRipPolicy,
}

pub(crate) const fn initial_saved_rsp_is_within_stack(bounds: KernelStackBounds, rsp: u64) -> bool {
    if rsp == 0 || rsp & 0xf != 8 || rsp < bounds.bottom {
        return false;
    }
    match rsp.checked_add(INITIAL_KERNEL_CONTEXT_BYTES) {
        Some(end) => end <= bounds.top,
        None => false,
    }
}

pub(crate) const fn validate_initial_kernel_continuation_frame(
    bounds: KernelStackBounds,
    rsp: u64,
    rflags: u64,
    return_rip: u64,
    trusted_entry_rip: u64,
) -> Result<(), InitialKernelContinuationError> {
    if !initial_saved_rsp_is_within_stack(bounds, rsp) {
        return Err(InitialKernelContinuationError::StackGeometry);
    }
    if rflags != INITIAL_KERNEL_CONTINUATION_RFLAGS {
        return Err(InitialKernelContinuationError::RflagsPolicy);
    }
    if return_rip != trusted_entry_rip
        || return_rip < 0xffff_8000_0000_0000
        || trusted_entry_rip < 0xffff_8000_0000_0000
    {
        return Err(InitialKernelContinuationError::EntryRipPolicy);
    }
    Ok(())
}

pub(crate) const fn saved_rsp_is_within_stack(bounds: KernelStackBounds, rsp: u64) -> bool {
    if rsp == 0 || rsp & 0xf != 0 || rsp < bounds.bottom {
        return false;
    }
    match rsp.checked_add(KERNEL_CONTEXT_FRAME_BYTES) {
        Some(end) => end <= bounds.top,
        None => false,
    }
}

#[must_use = "a prepared first-run continuation must be consumed by an initial kernel switch"]
pub(crate) struct InitialKernelContinuation {
    rsp: u64,
    stack: KernelStackBounds,
}

impl InitialKernelContinuation {
    pub(crate) const fn rsp(&self) -> u64 {
        self.rsp
    }

    pub(crate) const fn stack(&self) -> KernelStackBounds {
        self.stack
    }
}

/// Constructs the exact synthetic frame consumed by the F2 switch assembly for
/// a never-run Thread. After the switch pops the seven saved words and executes
/// `ret`, RSP is 8 mod 16 as required at SysV function entry.
///
/// # Safety
///
/// `bounds` must describe writable, exclusively owned kernel-stack memory for
/// the destination Thread. `trusted_entry_rip` must name the fixed kernel
/// first-run entry and remain executable for the lifetime of the Thread.
#[allow(
    unsafe_code,
    reason = "F7 first-run setup writes the documented eight-word switch frame plus one ABI stack word into an exclusively owned kernel stack"
)]
pub(crate) unsafe fn prepare_initial_kernel_continuation(
    bounds: KernelStackBounds,
    trusted_entry_rip: u64,
) -> Result<InitialKernelContinuation, InitialKernelContinuationError> {
    let rsp = bounds
        .top
        .checked_sub(INITIAL_KERNEL_CONTEXT_BYTES)
        .ok_or(InitialKernelContinuationError::StackGeometry)?;
    validate_initial_kernel_continuation_frame(
        bounds,
        rsp,
        INITIAL_KERNEL_CONTINUATION_RFLAGS,
        trusted_entry_rip,
        trusted_entry_rip,
    )?;
    let frame = rsp as *mut u64;
    unsafe {
        for index in 0..6 {
            frame.add(index).write(0);
        }
        frame.add(6).write(INITIAL_KERNEL_CONTINUATION_RFLAGS);
        frame.add(7).write(trusted_entry_rip);
        // A never-returning first-run entry still receives the conventional
        // SysV stack phase and one inert would-be return word.
        frame.add(8).write(0);
    }
    Ok(InitialKernelContinuation { rsp, stack: bounds })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KernelContextPlanError {
    NullSaveSlot,
    MisalignedSaveSlot,
    InvalidNextStack,
}

#[derive(Debug)]
pub(crate) struct KernelSwitchPlan {
    current_rsp_out: *mut u64,
    next_rsp: u64,
    next_stack: KernelStackBounds,
}

impl KernelSwitchPlan {
    /// # Safety
    ///
    /// `current_rsp_out` must remain writable until the switch has stored the
    /// suspended continuation RSP. Its storage must not be reclaimed while the
    /// corresponding Thread remains blocked.
    #[allow(
        unsafe_code,
        reason = "the raw save-slot lifetime is an execution-owner invariant supplied by the scheduler/runtime"
    )]
    pub(crate) unsafe fn new(
        current_rsp_out: *mut u64,
        next_rsp: u64,
        next_stack: KernelStackBounds,
    ) -> Result<Self, KernelContextPlanError> {
        if current_rsp_out.is_null() {
            return Err(KernelContextPlanError::NullSaveSlot);
        }
        if (current_rsp_out as usize) & 7 != 0 {
            return Err(KernelContextPlanError::MisalignedSaveSlot);
        }
        if !saved_rsp_is_within_stack(next_stack, next_rsp) {
            return Err(KernelContextPlanError::InvalidNextStack);
        }
        Ok(Self {
            current_rsp_out,
            next_rsp,
            next_stack,
        })
    }

    /// Builds a switch plan from an already-prepared first-run continuation.
    ///
    /// # Safety
    ///
    /// `current_rsp_out` follows the same stationary save-slot contract as
    /// [`Self::new`]. The `initial` token proves the destination stack frame was
    /// constructed by [`prepare_initial_kernel_continuation`].
    #[allow(
        unsafe_code,
        reason = "the initial-continuation token proves the distinct SysV first-run stack geometry"
    )]
    pub(crate) unsafe fn new_initial(
        current_rsp_out: *mut u64,
        initial: InitialKernelContinuation,
    ) -> Result<Self, KernelContextPlanError> {
        if current_rsp_out.is_null() {
            return Err(KernelContextPlanError::NullSaveSlot);
        }
        if (current_rsp_out as usize) & 7 != 0 {
            return Err(KernelContextPlanError::MisalignedSaveSlot);
        }
        debug_assert!(initial_saved_rsp_is_within_stack(
            initial.stack,
            initial.rsp
        ));
        Ok(Self {
            current_rsp_out,
            next_rsp: initial.rsp,
            next_stack: initial.stack,
        })
    }

    pub(crate) const fn next_stack(&self) -> KernelStackBounds {
        self.next_stack
    }
    pub(crate) const fn next_rsp(&self) -> u64 {
        self.next_rsp
    }
    pub(crate) const fn current_rsp_out(&self) -> *mut u64 {
        self.current_rsp_out
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "the audited assembly saves/restores one SysV kernel continuation by exact saved RSP"
)]
pub(crate) unsafe fn switch_kernel_context(current_rsp_out: *mut u64, next_rsp: u64) {
    unsafe extern "sysv64" {
        fn dw_x86_64_switch_kernel_context(current_rsp_out: *mut u64, next_rsp: u64);
    }
    assert!(
        !current_rsp_out.is_null(),
        "kernel continuation output pointer is null"
    );
    assert_ne!(next_rsp, 0, "next kernel continuation RSP is zero");
    unsafe { dw_x86_64_switch_kernel_context(current_rsp_out, next_rsp) };
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "the plan was validated against exact owned stack bounds and the assembly switch is the audited F2 boundary"
)]
pub(crate) unsafe fn execute_kernel_switch(plan: KernelSwitchPlan) {
    unsafe { switch_kernel_context(plan.current_rsp_out(), plan.next_rsp()) };
}

#[cfg(all(test, target_arch = "x86_64", not(target_os = "none")))]
core::arch::global_asm!(include_str!("kernel_context.S"), options(att_syntax));

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn saved_rsp_validation_stays_inside_owned_kernel_stack() {
        let bounds = KernelStackBounds::new(0x1000, 0x2000, 0x12000).unwrap();
        assert!(saved_rsp_is_within_stack(bounds, 0x3000));
        assert!(!saved_rsp_is_within_stack(bounds, 0));
        assert!(!saved_rsp_is_within_stack(bounds, 0x2ff8));
        assert!(!saved_rsp_is_within_stack(bounds, bounds.bottom - 16));
        assert!(!saved_rsp_is_within_stack(bounds, bounds.top - 48));
    }

    #[test]
    fn synthetic_initial_frame_policy_rejects_hostile_rip_and_privileged_rflags() {
        let bounds = KernelStackBounds::new(0x1000, 0x2000, 0x12000).unwrap();
        let rsp = 0x3008;
        let entry = 0xffff_8000_0010_0000;
        assert_eq!(
            validate_initial_kernel_continuation_frame(
                bounds,
                rsp,
                INITIAL_KERNEL_CONTINUATION_RFLAGS,
                entry,
                entry,
            ),
            Ok(())
        );
        for hostile in [1 << 9, 1 << 10, 1 << 12, 1 << 13, 1 << 14, 1 << 18] {
            assert_eq!(
                validate_initial_kernel_continuation_frame(
                    bounds,
                    rsp,
                    INITIAL_KERNEL_CONTINUATION_RFLAGS | hostile,
                    entry,
                    entry,
                ),
                Err(InitialKernelContinuationError::RflagsPolicy)
            );
        }
        assert_eq!(
            validate_initial_kernel_continuation_frame(
                bounds,
                rsp,
                INITIAL_KERNEL_CONTINUATION_RFLAGS,
                entry + 16,
                entry,
            ),
            Err(InitialKernelContinuationError::EntryRipPolicy)
        );
        assert_eq!(
            validate_initial_kernel_continuation_frame(
                bounds,
                rsp,
                INITIAL_KERNEL_CONTINUATION_RFLAGS,
                0x1000,
                0x1000,
            ),
            Err(InitialKernelContinuationError::EntryRipPolicy)
        );
        assert_eq!(
            validate_initial_kernel_continuation_frame(
                bounds,
                bounds.top - 48,
                INITIAL_KERNEL_CONTINUATION_RFLAGS,
                entry,
                entry,
            ),
            Err(InitialKernelContinuationError::StackGeometry)
        );
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "the test gives the first-run builder one page-aligned process-owned byte region and inspects the exact frame it wrote"
    )]
    fn initial_builder_uses_sysv_entry_phase_and_trusted_frame_contents() {
        #[repr(align(4096))]
        struct Region([u8; 0x12_000]);
        let mut region = std::boxed::Box::new(Region([0; 0x12_000]));
        let base = region.0.as_mut_ptr() as u64;
        let bounds = KernelStackBounds::new(base, base + 0x1000, base + 0x11_000).unwrap();
        let entry = 0xffff_8000_0010_0000;
        let initial = unsafe { prepare_initial_kernel_continuation(bounds, entry) }.unwrap();
        assert_eq!(initial.rsp() & 0xf, 8);
        assert!(initial_saved_rsp_is_within_stack(bounds, initial.rsp()));
        assert!(!saved_rsp_is_within_stack(bounds, initial.rsp()));
        let frame = initial.rsp() as *const u64;
        unsafe {
            for index in 0..6 {
                assert_eq!(frame.add(index).read(), 0);
            }
            assert_eq!(frame.add(6).read(), INITIAL_KERNEL_CONTINUATION_RFLAGS);
            assert_eq!(frame.add(7).read(), entry);
            assert_eq!(frame.add(8).read(), 0);
        }
    }

    #[cfg(all(target_arch = "x86_64", not(target_os = "none")))]
    #[allow(
        unsafe_code,
        reason = "the serialized host test constructs and switches exact owned synthetic stacks"
    )]
    mod live_switch {
        extern crate std;

        use core::cell::UnsafeCell;
        use core::sync::atomic::{AtomicUsize, Ordering};
        use std::boxed::Box;
        use std::sync::Mutex;

        const TEST_STACK_BYTES: usize = 64 * 1024;
        static TEST_LOCK: Mutex<()> = Mutex::new(());
        static MARK: AtomicUsize = AtomicUsize::new(0);

        struct SharedCell(UnsafeCell<u64>);
        impl SharedCell {
            const fn new() -> Self {
                Self(UnsafeCell::new(0))
            }
            fn ptr(&self) -> *mut u64 {
                self.0.get()
            }
            unsafe fn get(&self) -> u64 {
                unsafe { *self.0.get() }
            }
            unsafe fn set(&self, value: u64) {
                unsafe { *self.0.get() = value };
            }
        }

        #[allow(
            unsafe_code,
            reason = "the test serializes all accesses through TEST_LOCK"
        )]
        unsafe impl Sync for SharedCell {}
        static ORIGINAL_RSP: SharedCell = SharedCell::new();
        static ALTERNATE_RSP: SharedCell = SharedCell::new();

        #[repr(align(16))]
        struct AlignedStack([u8; TEST_STACK_BYTES]);

        unsafe extern "sysv64" {
            fn dw_x86_64_switch_kernel_context(current_rsp_out: *mut u64, next_rsp: u64);
        }

        #[allow(
            unsafe_code,
            reason = "host test deliberately switches between two owned synthetic kernel stacks"
        )]
        unsafe extern "sysv64" fn alternate_entry() -> ! {
            MARK.store(1, Ordering::SeqCst);
            let original = unsafe { ORIGINAL_RSP.get() };
            unsafe { dw_x86_64_switch_kernel_context(ALTERNATE_RSP.ptr(), original) };

            MARK.store(2, Ordering::SeqCst);
            let original = unsafe { ORIGINAL_RSP.get() };
            unsafe { dw_x86_64_switch_kernel_context(ALTERNATE_RSP.ptr(), original) };

            loop {
                core::hint::spin_loop();
            }
        }

        #[allow(
            unsafe_code,
            reason = "the test constructs the exact documented switch frame in an owned aligned byte array"
        )]
        fn prepare_alternate_stack(stack: &mut AlignedStack) -> u64 {
            let top = stack.0.as_mut_ptr() as usize + stack.0.len();
            assert_eq!(top & 0xf, 0);
            let saved = top - 72;
            assert_eq!(saved & 0xf, 8);
            let saved = saved as *mut u64;
            unsafe {
                for index in 0..6 {
                    saved.add(index).write(0);
                }
                saved.add(6).write(0x202);
                saved
                    .add(7)
                    .write(alternate_entry as *const () as usize as u64);
                saved.add(8).write(0);
            }
            saved as u64
        }

        #[test]
        #[allow(
            unsafe_code,
            reason = "the test executes the audited kernel switch primitive on two process-owned host stacks"
        )]
        fn continuation_switches_away_and_resumes_twice() {
            let _serial = TEST_LOCK.lock().unwrap();
            MARK.store(0, Ordering::SeqCst);
            unsafe {
                ORIGINAL_RSP.set(0);
                ALTERNATE_RSP.set(0);
            }
            let mut alternate = Box::new(AlignedStack([0; TEST_STACK_BYTES]));
            let initial_alternate = prepare_alternate_stack(&mut alternate);

            unsafe {
                dw_x86_64_switch_kernel_context(ORIGINAL_RSP.ptr(), initial_alternate);
            }
            assert_eq!(MARK.load(Ordering::SeqCst), 1);
            let first_saved_alternate = unsafe { ALTERNATE_RSP.get() };
            assert_ne!(first_saved_alternate, 0);

            unsafe {
                dw_x86_64_switch_kernel_context(ORIGINAL_RSP.ptr(), first_saved_alternate);
            }
            assert_eq!(MARK.load(Ordering::SeqCst), 2);
            assert_ne!(unsafe { ALTERNATE_RSP.get() }, 0);

            unsafe {
                ORIGINAL_RSP.set(0);
                ALTERNATE_RSP.set(0);
            }
        }
    }
}

#[cfg(all(deepwyrm_e7_guest, target_os = "none", target_arch = "x86_64"))]
mod target_probe {
    use core::cell::UnsafeCell;
    use core::sync::atomic::{AtomicU8, Ordering};

    use super::switch_kernel_context;

    const STACK_BYTES: usize = 16 * 1024;

    struct SharedU64(UnsafeCell<u64>);
    #[allow(
        unsafe_code,
        reason = "the F2 selector probe is single-BSP and serializes every raw switch-slot access"
    )]
    unsafe impl Sync for SharedU64 {}

    impl SharedU64 {
        const fn new() -> Self {
            Self(UnsafeCell::new(0))
        }
        const fn ptr(&self) -> *mut u64 {
            self.0.get()
        }
    }

    #[repr(align(16))]
    struct ProbeStack(UnsafeCell<[u8; STACK_BYTES]>);
    #[allow(
        unsafe_code,
        reason = "the one-shot F2 selector probe exclusively owns its static alternate stack"
    )]
    unsafe impl Sync for ProbeStack {}

    static STACK: ProbeStack = ProbeStack(UnsafeCell::new([0; STACK_BYTES]));
    static MAIN_RSP: SharedU64 = SharedU64::new();
    static ALTERNATE_RSP: SharedU64 = SharedU64::new();
    static MARK: AtomicU8 = AtomicU8::new(0);

    #[allow(
        unsafe_code,
        reason = "the target probe deliberately resumes the exact audited kernel context on its owned alternate stack"
    )]
    unsafe extern "sysv64" fn alternate_entry() -> ! {
        MARK.store(1, Ordering::SeqCst);
        let main = unsafe { core::ptr::read_volatile(MAIN_RSP.ptr()) };
        unsafe { switch_kernel_context(ALTERNATE_RSP.ptr(), main) };

        MARK.store(2, Ordering::SeqCst);
        let main = unsafe { core::ptr::read_volatile(MAIN_RSP.ptr()) };
        unsafe { switch_kernel_context(ALTERNATE_RSP.ptr(), main) };
        loop {
            core::hint::spin_loop();
        }
    }

    #[allow(
        unsafe_code,
        reason = "the target-only probe constructs one synthetic initial SysV return frame, then validates two real suspended-continuation resumes"
    )]
    #[inline(never)]
    pub(super) fn run() -> bool {
        MARK.store(0, Ordering::SeqCst);
        unsafe {
            core::ptr::write_volatile(MAIN_RSP.ptr(), 0);
            core::ptr::write_volatile(ALTERNATE_RSP.ptr(), 0);
        }
        let base = STACK.0.get().cast::<u8>();
        let top = unsafe { base.add(STACK_BYTES) } as usize;
        if top & 0xf != 0 {
            return false;
        }
        let saved = top - 72;
        let frame = saved as *mut u64;
        unsafe {
            for index in 0..6 {
                frame.add(index).write(0);
            }
            frame.add(6).write(0x2);
            frame
                .add(7)
                .write(alternate_entry as *const () as usize as u64);
            frame.add(8).write(0);
            switch_kernel_context(MAIN_RSP.ptr(), saved as u64);
        }
        if MARK.load(Ordering::SeqCst) != 1 {
            return false;
        }
        let alternate = unsafe { core::ptr::read_volatile(ALTERNATE_RSP.ptr()) };
        if alternate == 0 || alternate & 0xf != 0 {
            return false;
        }
        unsafe {
            switch_kernel_context(MAIN_RSP.ptr(), alternate);
        }
        let passed = MARK.load(Ordering::SeqCst) == 2;
        unsafe {
            core::ptr::write_volatile(MAIN_RSP.ptr(), 0);
            core::ptr::write_volatile(ALTERNATE_RSP.ptr(), 0);
        }
        passed
    }
}

#[cfg(all(deepwyrm_e7_guest, target_os = "none", target_arch = "x86_64"))]
#[inline(never)]
pub(crate) fn validate_target_continuation_roundtrip() -> bool {
    target_probe::run()
}
