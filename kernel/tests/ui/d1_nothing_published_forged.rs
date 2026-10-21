#![no_std]

include!("f11_full_kernel_modules.rs");

// D1 option B2: only a coherent publisher's `finish` proves that it published
// no shootdown, so held family-G releases cannot be merged on a forged proof.
fn forge() -> memory::address_region::ShootdownOutcome {
    memory::address_region::ShootdownOutcome::NothingPublished(
        memory::address_region::NothingPublished { _private: () },
    )
}
