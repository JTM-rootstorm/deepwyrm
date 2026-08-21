#![no_std]

include!("f11_full_kernel_modules.rs");

use atomic_wait::AtomicWaitOperation;

fn clone_operation(operation: &AtomicWaitOperation<()>) {
    let _ = <AtomicWaitOperation<()> as Clone>::clone(operation);
}
