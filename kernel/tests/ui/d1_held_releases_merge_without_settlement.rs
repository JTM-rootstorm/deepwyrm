#![no_std]

include!("f11_full_kernel_modules.rs");

// D1 option B2: held family-G releases reach the cleanup queue only on their
// shootdown's settlement.
fn merge(held: &mut syscall::HeldReleases<4>, cleanup: &mut syscall::CleanupQueue<4>) {
    held.merge(cleanup);
}
