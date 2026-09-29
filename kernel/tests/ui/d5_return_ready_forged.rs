#![no_std]

include!("f11_full_kernel_modules.rs");

use syscall::native::{NativeSyscallResult, ReturnReady};

// A result that returns to userspace is `ReturnReady` only with the proof that
// the runtime's final releases were published (TSV row 76).
fn return_without_draining(result: NativeSyscallResult) -> ReturnReady {
    ReturnReady { result }
}
